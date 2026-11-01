"""Streamable HTTP transport with per-client bearer tokens."""

import hmac

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from pvewarden.audit import AuditLog, DeniedLog
from pvewarden.config import HTTPConfig

CLIENT_KEY = "pvewarden.client"
# MCP requests are small JSON; anything much bigger is refused before the app reads it
MAX_BODY = 1 * 2**20


class BearerAuth:
    """ASGI middleware: require 'Authorization: Bearer <token>' of a client from [http.clients].

    The client name goes into the request scope; the tools write it to the audit log with every call.
    Refused requests are summarised per address (DeniedLog). The only thing served without a token
    is GET /ca.pem, the public CA certificate clients trust.
    """

    def __init__(self, app, clients: dict[str, str], audit: AuditLog, ca_pem: bytes | None = None):
        self.app = app
        self.clients = clients
        self.denied = DeniedLog(audit)
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
            self.denied.denied(ip, scope["path"])
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")],
                }
            )
            return await send({"type": "http.response.body", "body": b"unauthorized"})

        self.denied.flush()
        length = dict(scope["headers"]).get(b"content-length", b"0")
        if not length.isdigit() or int(length) > MAX_BODY:
            return await self.plain(send, 413, b"request too large")
        received = 0

        async def limited():
            # without (or despite) Content-Length: stop reading past the limit
            nonlocal received
            msg = await receive()
            received += len(msg.get("body", b""))
            if received > MAX_BODY:
                return {"type": "http.disconnect"}
            return msg

        scope[CLIENT_KEY] = client  # tools read it from the HTTP request (pvewarden.tools.client_name)
        await self.app(scope, limited, send)

    @staticmethod
    async def plain(send, status: int, body: bytes) -> None:
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": body})


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
