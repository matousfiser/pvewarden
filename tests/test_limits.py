"""Limits: a guest or a client sending too much must not exhaust the server."""

from pathlib import Path

import httpx
import pytest

from pvewarden.audit import AuditLog
from pvewarden.config import SSHConfig
from pvewarden.errors import GuestError
from pvewarden.guest import GuestRunner
from pvewarden.http import MAX_BODY, BearerAuth

ROOT = Path(__file__).parent.parent


def runner_running(shell: str, max_output: int) -> GuestRunner:
    r = GuestRunner(SSHConfig(), Path("/nonexistent/known_hosts"))
    r.max_output = max_output
    r.ssh_args = lambda address, command, key, alias=None: ["sh", "-c", shell]
    return r


async def test_too_much_output_from_a_guest_is_refused(tmp_path):
    r = runner_running("exec yes pvewarden", max_output=2**20)  # exec: kill hits it, like ssh
    with pytest.raises(GuestError, match="more than 1 MiB of output"):
        await r.run("192.0.2.1", "status", timeout=30, key=tmp_path / "k", log=tmp_path / "run.log")
    assert (tmp_path / "run.log").stat().st_size <= 2**20  # the run log stays bounded too


async def test_one_endless_line_does_not_break_reading(tmp_path):
    r = runner_running("head -c 300000 /dev/zero | tr '\\0' x; echo; echo done", max_output=2**20)
    rc, out = await r.run("192.0.2.1", "status", timeout=30, key=tmp_path / "k")
    assert rc == 0 and out.endswith("done\n") and len(out) == 300000 + 6


async def test_output_split_inside_a_utf8_character_is_decoded_whole(tmp_path):
    r = runner_running("printf 'a\\303'; sleep 0.2; printf '\\251b\\n'", max_output=2**20)
    rc, out = await r.run("192.0.2.1", "status", timeout=30, key=tmp_path / "k")
    assert out == "aéb\n"


async def echo_body(scope, receive, send):
    body = b""
    while True:
        msg = await receive()
        if msg["type"] == "http.disconnect":
            body = b"DISCONNECTED"
            break
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture
def client(tmp_path):
    app = BearerAuth(echo_body, {"a": "t" * 40}, AuditLog(tmp_path / "audit.jsonl"))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_a_large_request_is_refused_before_it_is_read(client):
    r = await client.post("/mcp", content=b"x" * (MAX_BODY + 1), headers={"Authorization": "Bearer " + "t" * 40})
    assert r.status_code == 413


async def test_a_streamed_request_is_cut_off_at_the_limit(client):
    async def chunks():
        for _ in range(MAX_BODY // 65536 + 2):
            yield b"x" * 65536

    r = await client.post("/mcp", content=chunks(), headers={"Authorization": "Bearer " + "t" * 40})
    assert r.content == b"DISCONNECTED"


def test_logs_are_rotated_and_old_run_logs_removed():
    install = (ROOT / "deploy/install-server.sh").read_text()
    assert "/etc/logrotate.d/pvewarden" in install and "/usr/lib/tmpfiles.d/pvewarden.conf" in install
    assert "/var/lib/pvewarden/audit.jsonl" in (ROOT / "deploy/pvewarden.logrotate").read_text()
    assert "e /var/lib/pvewarden/runs - - - 180d" in (ROOT / "deploy/pvewarden.tmpfiles").read_text()


# --- supply chain -------------------------------------------------------------------------------


def test_every_dependency_is_pinned_with_hashes():
    lock = (ROOT / "requirements.lock").read_text()
    reqs = [line for line in lock.splitlines() if line and not line.startswith((" ", "#"))]
    assert reqs and all("==" in r and r.endswith("\\") for r in reqs), reqs  # each pin continues with hashes
    assert lock.count("--hash=sha256:") >= len(reqs)


def test_the_server_installs_only_hash_checked_wheels_and_builds_nothing():
    install = (ROOT / "deploy/install-server.sh").read_text()
    assert "--require-hashes --only-binary=:all:" in install
    assert "--upgrade pip" not in install  # no unpinned pip from the live index
    assert 'pip" install -q --no-deps' not in install  # pvewarden is copied, not built
