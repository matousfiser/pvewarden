import json

import httpx
import pytest

from pvewarden.audit import AuditLog
from pvewarden.http import BearerAuth

TOKEN_A = "a" * 40
TOKEN_B = "b" * 40


async def echo_app(scope, receive, send):
    """Inner ASGI app: echoes the request body, so we can check it was replayed intact."""
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def client(audit):
    app = BearerAuth(echo_app, {"alice": TOKEN_A, "bob": TOKEN_B}, audit)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def entries(audit):
    return [json.loads(line) for line in audit.path.read_text().splitlines()]


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN_A}"}, {"Authorization": "Bearer "}],
)
async def test_rejects_without_valid_token(client, audit, headers):
    r = await client.post("/mcp", content=b"{}", headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert entries(audit)[-1]["action"] == "http_denied"


async def test_passes_body_through_and_audits_tool_calls(client, audit):
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_guests", "arguments": {}}}
    body = json.dumps(call).encode()
    r = await client.post("/mcp", content=body, headers={"Authorization": f"Bearer {TOKEN_B}"})
    assert r.status_code == 200 and r.content == body
    (entry,) = entries(audit)
    assert entry["action"] == "http_call"
    assert (entry["client"], entry["tool"], entry["args"]) == ("bob", "list_guests", {})


async def test_other_methods_and_garbage_are_not_audited(client, audit):
    for body in (b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}', b"not json", b"[1, 2]"):
        r = await client.post("/mcp", content=body, headers={"Authorization": f"bearer {TOKEN_A}"})
        assert r.status_code == 200
    assert not audit.path.exists()


def test_allowed_hosts_include_configured_names():
    from pvewarden.config import HTTPConfig
    from pvewarden.http import allowed_hosts

    cfg = HTTPConfig(listen="192.0.2.10", port=8765, hostnames=("warden.lan",))
    assert allowed_hosts(cfg) == ["192.0.2.10", "192.0.2.10:8765", "warden.lan", "warden.lan:8765"]


async def test_serves_the_public_ca_without_a_token(audit):
    app = BearerAuth(echo_app, {"alice": TOKEN_A}, audit, ca_pem=b"-----BEGIN CERTIFICATE-----\nX\n")
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    r = await c.get("/ca.pem")
    assert r.status_code == 200 and r.content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert (await c.post("/ca.pem")).status_code == 401  # only GET/HEAD
    assert (await c.get("/mcp")).status_code == 401  # everything else still needs a token


async def test_no_ca_configured_means_no_ca_endpoint(client):
    assert (await client.get("/ca.pem")).status_code == 401
