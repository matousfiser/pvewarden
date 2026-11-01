import asyncio
import json
import socket

import httpx
import pytest
import uvicorn
from conftest import GUESTS, FakeProxmox, FakeRunner, make_config
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from pvewarden.app import App
from pvewarden.audit import AuditLog, DeniedLog
from pvewarden.config import parse
from pvewarden.http import BearerAuth, build_app
from pvewarden.tools import create_server

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


async def test_passes_the_body_through_untouched_and_names_the_client(client, audit):
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_guests", "arguments": {}}}
    body = json.dumps(call).encode()
    r = await client.post("/mcp", content=body, headers={"Authorization": f"Bearer {TOKEN_B}"})
    assert r.status_code == 200 and r.content == body
    assert not audit.path.exists()  # the tools write the audit records (with outcome), not the transport


def test_refused_requests_are_summarised_per_address(audit):
    now = [0.0]
    denied = DeniedLog(audit, window=60, max_sources=2, clock=lambda: now[0])
    for _ in range(500):
        denied.denied("192.0.2.66", "/mcp")
    assert [e["action"] for e in entries(audit)] == ["http_denied"]  # one line, not 500
    now[0] = 61
    denied.denied("192.0.2.66", "/mcp")  # next window: the summary of the last one, then a new first line
    summary = [e for e in entries(audit) if e["action"] == "http_denied_summary"]
    assert summary[0]["ip"] == "192.0.2.66" and summary[0]["count"] == 500
    for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):  # beyond max_sources: one shared entry
        denied.denied(ip, "/mcp")
    assert len(denied.sources) == 3 and denied.sources["*"]["count"] == 2  # max_sources + one shared
    denied.flush(force=True)


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


async def test_tools_learn_which_client_called(tmp_path, audit):
    """End to end over real HTTP: the token's name reaches the tool (snapshot descriptions)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = App(parse(make_config(tmp_path, http={"listen": "127.0.0.1", "port": port, "clients": {"alice": TOKEN_A}})))
    app.pve, app.runner = FakeProxmox(GUESTS), FakeRunner()
    server = uvicorn.Server(
        uvicorn.Config(build_app(create_server(app), app.cfg.http, audit), port=port, log_level="error")
    )
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:  # noqa: ASYNC110 - uvicorn offers no event for this
            await asyncio.sleep(0.05)
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {TOKEN_A}"})
        async with Client(streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http)) as client:
            res = await client.call_tool("snapshot_guest", {"vmid": 101, "description": "by hand"})
        assert not res.is_error
        assert app.pve.snaps[101][0]["description"] == "by hand (client: alice)"
        # the audit trail of the call: who, from where, what, the outcome; one call id throughout
        log = [json.loads(line) for line in app.audit.path.read_text().splitlines()]
        call, snap, result = log
        assert (call["action"], call["tool"], call["client"], call["ip"]) == ("tool_call", "snapshot_guest", "alice",
                                                                              "127.0.0.1")  # fmt: skip
        assert call["args"] == {"vmid": 101, "description": "by hand"}
        assert snap["action"] == "snapshot" and result["action"] == "tool_result" and result["outcome"] == "ok"
        assert call["call"] == snap["call"] == result["call"] and "ms" in result
    finally:
        server.should_exit = True
        await task
