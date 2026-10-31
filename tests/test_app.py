from dataclasses import replace

import pytest
from conftest import RBT, UPD, FakeRunner

from pvewarden.app import SNAPSHOT_PREFIX, App
from pvewarden.config import parse
from pvewarden.errors import (
    GuestError,
    GuestTimeoutError,
    InvalidRequestError,
    NotFoundError,
    PolicyError,
    ProxmoxError,
)

# --- inventory, permissions, addresses -----------------------------------------------------


async def test_describe_permissions(app):
    g = await app.guest(101)
    assert app.describe(g) | {} == {
        "vmid": 101,
        "name": "web",
        "type": "lxc",
        "node": "pve1",
        "status": "running",
        "tags": [UPD, RBT],
        "may_update": True,
        "may_reboot": True,
        "source": "proxmox",
    }
    assert app.describe(await app.guest(103))["may_update"] is False


async def test_unknown_guest(app):
    with pytest.raises(NotFoundError):
        await app.guest(999)


async def test_address_skips_loopback_and_prefers_subnet(app):
    assert await app.address(await app.guest(101)) == "192.0.2.11"


async def test_address_override_and_dns_fallback(app):
    app.cfg.addresses[102] = "198.51.100.7"
    assert await app.address(await app.guest(102)) == "198.51.100.7"
    del app.pve.ips[103]  # no guest agent: fall back to the guest name
    assert await app.address(await app.guest(103)) == "readonly"


async def test_address_outside_subnet_is_not_used(app):
    app.pve.ips[103] = ["10.9.9.9"]
    assert await app.address(await app.guest(103)) == "readonly"


# --- check_updates -------------------------------------------------------------------------


async def test_check_updates_summary(app):
    results = {r["vmid"]: r for r in await app.check_updates()}
    assert set(results) == {101, 102, 103}  # 104 is stopped
    r = results[101]
    assert (r["pending"], r["pending_security"], r["pending_official"]) == (3, 1, 2)
    assert [p["name"] for p in r["third_party_report_only"]] == ["docker-ce"]
    assert r["os"] == "Ubuntu 24.04.1 LTS"
    assert r["reboot_required"] is False
    assert r["auto_updates"] is True


async def test_check_updates_isolates_failing_guest(app):
    app.runner.responses["check"] = lambda addr: (255, "Permission denied") if addr == "192.0.2.12" else (0, "")
    results = {r["vmid"]: r for r in await app.check_updates([101, 102])}
    assert "Permission denied" in results[102]["error"]
    assert results[101]["pending"] == 0


async def test_check_updates_detects_outdated_client(app):
    app.runner.responses["check"] = (0, "openssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\n")
    (r,) = await app.check_updates([101])
    assert "outdated" in r["error"]


async def test_check_updates_unknown_vmid(app):
    with pytest.raises(NotFoundError):
        await app.check_updates([101, 999])


# --- apply_updates -------------------------------------------------------------------------


async def test_apply_updates_requires_tag(app):
    with pytest.raises(PolicyError, match=UPD):
        await app.apply_updates(103)
    assert app.runner.calls == []


async def test_apply_updates_snapshots_first_then_upgrades(app):
    res = await app.apply_updates(101, "all")
    assert res["ok"] is True
    assert res["snapshot"].startswith(SNAPSHOT_PREFIX)
    assert app.pve.events == [("snapshot", 101, res["snapshot"])]
    assert app.runner.commands() == ["services", "upgrade-all", "status", "services"]
    assert res["newly_failed_services"] == []
    log = app.runs_dir / res["log"].rsplit("/", 1)[1]
    assert log.read_text() == "All upgrades installed\n"


async def test_apply_updates_aborts_when_snapshot_fails(app):
    app.pve.fail_snapshot = True
    with pytest.raises(ProxmoxError):
        await app.apply_updates(101)
    assert app.runner.calls == []


async def test_apply_updates_reports_newly_failed_services(app):
    outputs = iter(
        [
            (0, "system=running\nfailed=old.service\n"),
            (0, "system=degraded\nfailed=old.service\nfailed=nginx.service\n"),
        ]
    )
    app.runner.responses["services"] = lambda addr: next(outputs)
    res = await app.apply_updates(101, snapshot=False)
    assert res["snapshot"] is None and app.pve.events == []
    assert res["newly_failed_services"] == ["nginx.service"]


async def test_apply_updates_refuses_stopped_guest_and_bad_mode(app):
    with pytest.raises(GuestError, match="stopped"):
        await app.apply_updates(104)
    with pytest.raises(InvalidRequestError):
        await app.apply_updates(101, mode="dist-upgrade")


async def test_apply_updates_is_audited(app):
    await app.apply_updates(101)
    actions = [line for line in app.audit.path.read_text().splitlines()]
    assert any('"action": "apply_updates"' in a and '"vmid": 101' in a for a in actions)


# --- reboot, snapshots, rollback ------------------------------------------------------------


async def test_reboot_requires_reboot_tag(app):
    with pytest.raises(PolicyError, match=RBT):
        await app.reboot(102)
    assert app.pve.events == []


async def test_reboot_waits_until_guest_answers(app):
    attempts = iter([(255, "Connection refused"), (0, "kernel=6.8.0-2\nreboot_required=no\n")])
    app.runner.responses["status"] = lambda addr: next(attempts)
    res = await app.reboot(101, interval=0)
    assert app.pve.events == [("reboot", 101)]
    assert res["back_online"] is True and res["kernel"] == "6.8.0-2"


async def test_reboot_gives_up(app):
    app.runner.responses["status"] = (255, "Connection refused")
    res = await app.reboot(101, wait_s=0.03, interval=0.01)
    assert res["back_online"] is False


async def test_rollback_only_own_snapshots_and_starts_guest(app):
    with pytest.raises(PolicyError):
        await app.rollback(101, "manual-before-upgrade")
    with pytest.raises(NotFoundError):
        await app.rollback(101, SNAPSHOT_PREFIX + "20260101_000000")
    assert app.pve.events == []
    app.pve.snaps[101] = [{"name": SNAPSHOT_PREFIX + "20260101_000000", "snaptime": 1_767_225_600}]
    # like after a reboot: the result comes once SSH answers again, not while the guest still boots
    attempts = iter([(255, "Connection refused"), (0, "kernel=6.8.0-2\nreboot_required=no\n")])
    app.runner.responses["status"] = lambda addr: next(attempts)
    res = await app.rollback(101, SNAPSHOT_PREFIX + "20260101_000000", interval=0)
    assert res["started_after_rollback"] is True and res["back_online"] is True
    assert [e[0] for e in app.pve.events] == ["rollback", "start"]


async def test_delete_old_snapshots_only_touches_old_own_snapshots_on_tagged_guests(app):
    old, new = 1_000_000_000, 4_000_000_000  # 2001 and 2096
    app.pve.snaps[101] = [
        {"name": SNAPSHOT_PREFIX + "old", "snaptime": old},
        {"name": SNAPSHOT_PREFIX + "new", "snaptime": new},
        {"name": "manual", "snaptime": old},
    ]
    app.pve.snaps[103] = [{"name": SNAPSHOT_PREFIX + "old", "snaptime": old}]  # untagged guest
    deleted = await app.delete_old_snapshots(older_than_days=7)
    assert deleted == [{"vmid": 101, "snapshot": SNAPSHOT_PREFIX + "old"}]
    assert [s["name"] for s in app.pve.snaps[101]] == [SNAPSHOT_PREFIX + "new", "manual"]
    assert len(app.pve.snaps[103]) == 1


async def test_list_snapshots_marks_own(app):
    app.pve.snaps[101] = [{"name": SNAPSHOT_PREFIX + "x", "snaptime": 1_000_000_000}, {"name": "manual"}]
    snaps = await app.list_snapshots(101)
    assert [(s["name"], s["pvewarden"]) for s in snaps] == [(SNAPSHOT_PREFIX + "x", True), ("manual", False)]
    assert snaps[1]["created"] is None


# --- static inventory (no Proxmox) ----------------------------------------------------------


@pytest.fixture
def static_app(tmp_path):
    a = App(
        parse(
            {
                "state_dir": str(tmp_path),
                "ssh": {"key": "/k"},
                "static_guests": [{"vmid": 1, "name": "t", "address": "192.0.2.50", "tags": [UPD, RBT]}],
            }
        )
    )
    a.runner = FakeRunner()
    return a


async def test_static_mode_updates_without_snapshot(static_app):
    res = await static_app.apply_updates(1, snapshot=False)
    assert res["ok"] and static_app.runner.calls[0][0] == "192.0.2.50"
    assert static_app.describe(await static_app.guest(1))["source"] == "static-config"


async def test_static_mode_has_no_proxmox_operations(static_app):
    for op in (static_app.apply_updates(1), static_app.reboot(1), static_app.list_snapshots(1)):
        with pytest.raises(ProxmoxError, match="not configured"):
            await op


# --- Proxmox locks (backups) -------------------------------------------------------------------


def lock(app, vmid, what="backup"):
    app.pve._guests[vmid] = replace(app.pve._guests[vmid], lock=what)


async def test_locked_guest_is_left_alone(app):
    lock(app, 101)
    app.pve.snaps[101] = [{"name": SNAPSHOT_PREFIX + "x", "snaptime": 1}]
    for op in (app.apply_updates(101), app.snapshot(101), app.reboot(101), app.rollback(101, SNAPSHOT_PREFIX + "x")):
        with pytest.raises(GuestError, match="backed up by Proxmox right now.*Do not skip the snapshot"):
            await op
    assert app.runner.calls == [] and app.pve.events == []
    lock(app, 101, "migrate")
    with pytest.raises(GuestError, match="lock 'migrate'"):
        await app.apply_updates(101)


async def test_snapshot_refused_by_a_backup_that_just_started(app):
    async def locked(*args):
        raise ProxmoxError("task UPID:...:vzsnapshot:101: failed: CT is locked (backup)")

    app.pve.create_snapshot = locked
    with pytest.raises(GuestError, match="being backed up"):
        await app.apply_updates(101)
    assert app.runner.calls == []


async def test_failed_snapshot_says_not_to_skip_it(app):
    app.pve.fail_snapshot = True
    with pytest.raises(ProxmoxError, match="do not retry without a snapshot"):
        await app.apply_updates(101)


async def test_check_updates_reports_locks_and_running_backups(app):
    lock(app, 103)  # the backup job is copying 103; 101 and 102 are on the same node
    results = {r["vmid"]: r for r in await app.check_updates([101, 103])}
    assert results[103]["lock"] == "backup" and results[103]["backup_running"] is True
    assert "lock" not in results[101] and results[101]["backup_running"] is True
    app.pve._guests[103] = replace(app.pve._guests[103], lock=None)
    assert "backup_running" not in (await app.check_updates([101]))[0]


# --- updates that outlast the wait ---------------------------------------------------------------


def slow_upgrade(addr):
    raise GuestTimeoutError("upgrade-security on 192.0.2.11: no result after 1800s")


async def test_update_keeps_running_and_is_picked_up_later(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    res = await app.apply_updates(101)
    assert res["still_running"] is True and res["ok"] is None and res["snapshot"]
    assert "update_result" in res["hint"]
    # meanwhile: no second update, no reboot, no rollback
    for op in (app.apply_updates(101), app.reboot(101), app.rollback(101, res["snapshot"])):
        with pytest.raises(GuestError, match="still running"):
            await op

    app.runner.responses["upgrade-follow"] = (0, "Setting up openssl ...\nAll upgrades installed\n")
    done = await app.update_result(101)
    assert done["ok"] is True and done["snapshot"] == res["snapshot"] and done["newly_failed_services"] == []
    assert "All upgrades installed" in (app.runs_dir / done["log"].rsplit("/", 1)[1]).read_text()
    with pytest.raises(InvalidRequestError, match="nothing to wait for"):
        await app.update_result(101)
    await app.apply_updates(101)  # free again


async def test_update_result_with_an_old_guest_client(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.responses["upgrade-follow"] = (1, "pvewarden: command not allowed\n")
    with pytest.raises(GuestError, match="older"):
        await app.update_result(101)
    assert not app.pending_dir.joinpath("101.json").exists()


async def test_update_already_running_on_the_guest(app):
    app.runner.responses["upgrade-security"] = (75, "pvewarden: an update is already running on this guest\n")
    with pytest.raises(GuestError, match="already running"):
        await app.apply_updates(101)
    assert not app.pending_dir.joinpath("101.json").exists()
