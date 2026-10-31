import ssl

import httpx
import pytest
from conftest import STATUS_OUT

from pvewarden.doctor import check_guests, check_local, check_proxmox, explain_proxmox_error, render, run_checks
from pvewarden.errors import ProxmoxError

FULL = {"VM.Audit", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.PowerMgmt", "VM.GuestAgent.Audit"}


@pytest.fixture
def healthy(app, tmp_path):
    app.cfg.ssh.key.write_text("key")
    app.cfg.ssh.key.chmod(0o600)
    app.pve.privs = {f"/vms/{v}": set(FULL) for v in (101, 102, 103, 104)}
    app.pve.privs["/pool/pvewarden"] = set(FULL)
    return app


def by_title(results):
    return {r.title: r for r in results}


async def test_healthy_setup_has_no_failures(healthy):
    results = await run_checks(healthy)
    assert [r for r in results if r.status != "ok"] == []
    titles = by_title(results)
    assert "Proxmox VE 9.0.10" in titles["Proxmox API"].detail
    assert titles["Guest 101 web"].detail == (
        "192.0.2.11, Ubuntu 24.04.1 LTS, allowed: update, reboot, automatic updates on (no snapshots)"
    )
    assert titles["Guest 103 readonly"].detail.endswith("allowed: read-only, automatic updates on (no snapshots)")
    assert "Guest 104 off" not in titles  # stopped guests are not contacted
    assert "[FAIL]" not in render(results)


async def test_pve8_monitor_privilege_is_accepted_for_the_guest_agent(healthy):
    healthy.pve.privs["/vms/102"] = (FULL - {"VM.GuestAgent.Audit"}) | {"VM.Monitor"}
    assert by_title(await check_proxmox(healthy))["Token privileges"].status == "ok"


async def test_missing_privileges_are_listed_per_guest(healthy):
    healthy.pve.privs["/vms/101"] = FULL - {"VM.Snapshot"}
    healthy.pve.privs["/vms/102"] = FULL - {"VM.GuestAgent.Audit"}  # qemu: needs the agent privilege
    healthy.pve.privs["/vms/104"] = FULL - {"VM.GuestAgent.Audit"}  # lxc: does not
    r = by_title(await check_proxmox(healthy))["Token privileges"]
    assert r.status == "fail"
    assert "101: VM.Snapshot" in r.detail and "102: VM.GuestAgent.Audit" in r.detail and "104" not in r.detail


async def test_overprivileged_token_is_flagged(healthy):
    healthy.pve.privs["/"] = {"Sys.Modify", "VM.Allocate"}
    r = by_title(await check_proxmox(healthy))["Token scope"]
    assert r.status == "warn" and "Sys.Modify" in r.detail


async def test_empty_pool(healthy):
    healthy.pve._guests = {}
    r = by_title(await check_proxmox(healthy))["Guests"]
    assert r.status == "warn" and "pool" in r.hint


async def test_unverified_tls_is_a_warning(healthy):
    healthy.pve.cfg = healthy.pve.cfg.__class__(host="h", token_id="t", token_secret="s", verify_tls=False)
    assert by_title(await check_proxmox(healthy))["Proxmox API"].status == "warn"


async def test_api_failure_is_explained(healthy):
    async def denied():
        raise ProxmoxError("GET /version: HTTP 401 Unauthorized")

    healthy.pve.version = denied
    (r,) = await check_proxmox(healthy)
    assert r.status == "fail" and "token_id" in r.hint


def test_tls_failure_is_explained():
    try:
        try:
            raise ssl.SSLCertVerificationError("certificate verify failed: IP address mismatch")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]") from inner
    except httpx.ConnectError as outer:
        e = ProxmoxError(f"GET /version: {outer}")
        e.__cause__ = outer
    assert "pve-root-ca.pem" in explain_proxmox_error(e)


@pytest.mark.parametrize(
    "ssh_output, hint",
    [
        ("pvewarden@192.0.2.12: Permission denied (publickey).", "enroll"),
        ("Host key verification failed.", "known_hosts"),
        ("ssh: connect to host 192.0.2.12 port 22: Connection timed out", "sshd"),
    ],
)
async def test_ssh_failures_are_explained(healthy, ssh_output, hint):
    healthy.runner.responses["status"] = lambda addr: (255, ssh_output) if addr == "192.0.2.12" else (0, STATUS_OUT)
    results = by_title(await check_guests(healthy))
    assert results["Guest 102 db"].status == "fail" and hint in results["Guest 102 db"].hint
    assert results["Guest 101 web"].status == "ok"


def test_local_checks(app, tmp_path):
    results = by_title(check_local(app))
    assert results["SSH key"].status == "fail" and "ssh-keygen" in results["SSH key"].hint
    app.cfg.ssh.key.write_text("key")
    app.cfg.ssh.key.chmod(0o644)
    assert by_title(check_local(app))["SSH key"].status == "fail"  # world-readable
    app.cfg.ssh.key.chmod(0o600)
    assert by_title(check_local(app))["SSH key"].status == "ok"
    assert by_title(check_local(app))["State directory"].status == "ok"


def test_listen_address_must_exist(app):
    from dataclasses import replace

    from pvewarden.config import HTTPConfig

    app.cfg = replace(app.cfg, http=HTTPConfig(listen="192.0.2.254", clients={"a": "x" * 40}))
    assert by_title(check_local(app))["Listen address"].status == "warn"
    app.cfg = replace(app.cfg, http=HTTPConfig(listen="127.0.0.1", clients={"a": "x" * 40}))
    assert "Listen address" not in by_title(check_local(app))


async def test_verbose_shows_what_each_check_saw(healthy):
    healthy.pve.privs["/vms/101"] = FULL - {"VM.Snapshot"}
    results = await run_checks(healthy)
    quiet, verbose = render(results), render(results, verbose=True)
    assert "| " not in quiet
    assert "| /vms/101: VM.Audit, VM.GuestAgent.Audit, VM.PowerMgmt, VM.Snapshot.Rollback" in verbose
    assert "| ACL /pool/pvewarden: " in verbose
    assert "| 101 " in verbose and "tags=" in verbose
    assert "| ssh pvewarden@192.0.2.11 status -> exit 0" in verbose
    assert "s3cret" not in verbose and "token_secret" not in verbose  # never the secret
