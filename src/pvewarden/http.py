"""Streamable HTTP transport with per-client bearer tokens and request auditing."""

import hmac
import json

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from pvewarden.audit import AuditLog
from pvewarden.config import HTTPConfig


class BearerAuth:
    """ASGI middleware: require 'Authorization: Bearer <token>' of a client from [http.clients].

    Every tools/call is written to the audit log with the client name and source IP.
    The only thing served without a token is GET /ca.pem, the public CA certificate clients trust.
    """

    def __init__(self, app, clients: dict[str, str], audit: AuditLog, ca_pem: bytes | None = None):
        self.app = app
        self.clients = clients
        self.audit = audit
        self.ca_pem = ca_pem

    def client_for(self, headers: list[tuple[bytes, bytes]]) -> str | None:
        auth = dict(headers).get(b"authorization", b"").decode(errors="replace")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        found = None
        for name, secret in self.clients.items():  # compare against all, constant time each
            if hmac.compare_digest(token.encode(), secret.encode()):
                found = name
        return found

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.ca_pem is not None and scope["path"] == "/ca.pem" and scope["method"] in ("GET", "HEAD"):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/x-pem-file")],
                }
            )
            return await send({"type": "http.response.body", "body": b"" if scope["method"] == "HEAD" else self.ca_pem})
        ip = (scope.get("client") or ("?",))[0]
        client = self.client_for(scope["headers"])
        if client is None:
            self.audit.write("http_denied", ip=ip, path=scope["path"])
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")],
                }
            )
            return await send({"type": "http.response.body", "body": b"unauthorized"})

        # buffer the body to log the JSON-RPC call, then replay it to the app
        body, messages = b"", []
        while True:
            msg = await receive()
            messages.append(msg)
            body += msg.get("body", b"")
            if msg["type"] != "http.request" or not msg.get("more_body"):
                break
        try:
            calls = json.loads(body) if body else []
            for c in calls if isinstance(calls, list) else [calls]:
                if c.get("method") == "tools/call":
                    params = c.get("params", {})
                    self.audit.write(
                        "http_call", client=client, ip=ip, tool=params.get("name"), args=params.get("arguments")
                    )
        except (ValueError, AttributeError):
            pass

        async def replay():
            return messages.pop(0) if messages else await receive()

        await self.app(scope, replay, send)


def allowed_hosts(cfg: HTTPConfig) -> list[str]:
    """Host header values to accept (DNS-rebinding protection): the listen address and configured names."""
    return [h for host in (cfg.listen, *cfg.hostnames) for h in (host, f"{host}:{cfg.port}")]


def build_app(server: MCPServer, cfg: HTTPConfig, audit: AuditLog):
    if not cfg.clients:
        raise ValueError("no [http.clients] tokens configured")
    security = TransportSecuritySettings(allowed_hosts=allowed_hosts(cfg), allowed_origins=[])
    inner = server.streamable_http_app(host=cfg.listen, transport_security=security)
    ca_pem = cfg.tls_ca.read_bytes() if cfg.tls_ca else None
    return BearerAuth(inner, cfg.clients, audit, ca_pem)
