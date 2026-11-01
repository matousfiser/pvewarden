import asyncio
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
    assert app.runner.commands() == ["check", "services", "upgrade-all", "status", "services"]
    assert res["planned"] == ["openssl", "vim"]  # not docker-ce: third-party
    assert res["newly_failed_services"] == []
    log = app.runs_dir / res["log"].rsplit("/", 1)[1]
    assert log.read_text().endswith("All upgrades installed\n")
    assert "pvewarden-run" not in res["output_tail"]


async def test_apply_updates_aborts_when_snapshot_fails(app):
    app.pve.fail_snapshot = True
    with pytest.raises(ProxmoxError):
        await app.apply_updates(101)
    assert app.runner.commands() == ["check"]


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


async def test_rollback_checks_the_guest_also_when_it_kept_running(app):
    # a guest that is still running after the rollback (a snapshot with RAM) is checked as well
    app.pve.snaps[101] = [{"name": SNAPSHOT_PREFIX + "20260101_000000", "snaptime": 1_767_225_600}]

    async def rollback_keeps_running(g, name):
        app.pve.events.append(("rollback", g.vmid, name))

    app.pve.rollback = rollback_keeps_running
    res = await app.rollback(101, SNAPSHOT_PREFIX + "20260101_000000", interval=0)
    assert res["started_after_rollback"] is False and res["back_online"] is True and "kernel" in res
    assert "status" in app.runner.commands()


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
    assert app.runner.commands() == ["check"]


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


async def test_update_result_with_an_old_guest_client_keeps_the_fence(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.responses["upgrade-follow"] = (1, "pvewarden: command not allowed\n")
    with pytest.raises(GuestError, match="needs a human.*pvewarden pending clear 101"):
        await app.update_result(101)
    assert app.fence.pending(101)["state"] == "unknown"


async def test_update_already_running_on_the_guest(app):
    app.runner.responses["upgrade-security"] = (75, "pvewarden: an update is already running on this guest\n")
    with pytest.raises(GuestError, match="already running"):
        await app.apply_updates(101)
    assert not app.pending_dir.joinpath("101.json").exists()


# --- nothing to install: no snapshot ------------------------------------------------------------

ONLY_REGULAR = "vim\t2:9.1-1\t2:9.1-2\tUbuntu:noble-updates\t-\n"
HELD = "openssl\t3.0.13-1\t3.0.13-2\tUbuntu:noble-security\theld\n"
THIRD_PARTY = "docker-ce\t5:29.9.1-1\t5:29.9.2-1\tDocker:noble\t-\n"


@pytest.mark.parametrize(
    "check,mode",
    [("", "all"), (ONLY_REGULAR, "security"), (HELD, "all"), (THIRD_PARTY, "all")],
)
async def test_nothing_to_install_means_no_snapshot(app, check, mode):
    app.runner.responses["check"] = (0, check)
    res = await app.apply_updates(101, mode)
    assert res == {"vmid": 101, "name": "web", "ok": True, "nothing_to_install": True, "snapshot": None}
    assert app.pve.events == [] and app.runner.commands() == ["check"]


async def test_security_mode_plans_only_security_updates(app):
    res = await app.apply_updates(101, "security")
    assert res["planned"] == ["openssl"] and res["snapshot"]


async def test_failing_check_stops_the_update(app):
    app.runner.responses["check"] = (100, "E: Could not get lock /var/lib/apt/lists/lock")
    with pytest.raises(GuestError, match="Could not get lock"):
        await app.apply_updates(101)
    assert app.pve.events == []


async def test_snapshot_description_names_the_client(app):
    await app.apply_updates(101, client="claude")
    await app.snapshot(101, "manual check")
    first, second = app.pve.snaps[101]
    assert first["description"] == "before security updates (client: claude)"
    assert second["description"] == "manual check"


# --- one change per guest; the fence and its four outcomes ---------------------------------------


async def test_two_changes_to_one_guest_at_the_same_time(app):
    started, release = asyncio.Event(), asyncio.Event()

    real_run = app.runner.run

    async def run(address, command, *args, **kwargs):
        if command == "upgrade-security" and address == "192.0.2.11":  # only guest 101 is slow
            started.set()
            await release.wait()
        return await real_run(address, command, *args, **kwargs)

    app.runner.run = run
    first = asyncio.create_task(app.apply_updates(101))
    await started.wait()
    # while the first update runs: every other change to 101 is refused at once, nothing interleaves
    for op in (app.apply_updates(101), app.snapshot(101), app.reboot(101), app.update_result(101)):
        with pytest.raises(GuestError, match="another pvewarden operation on guest 101"):
            await op
    snaps_during = list(app.pve.events)
    await app.apply_updates(102)  # other guests are not blocked
    release.set()
    res = await first
    assert res["ok"] is True
    assert [e for e in snaps_during if e[0] == "snapshot"] == [("snapshot", 101, res["snapshot"])]  # one snapshot
    assert app.fence.pending(101) is None  # finished by the run that started it


async def test_a_failed_snapshot_lifts_the_fence(app):
    app.pve.fail_snapshot = True
    with pytest.raises(ProxmoxError):
        await app.apply_updates(101)
    assert app.fence.pending(101) is None


async def test_unreachable_guest_at_start_lifts_the_fence(app):
    app.runner.responses["upgrade-security"] = (255, "ssh: connect to host 192.0.2.11 port 22: Connection refused\n")
    with pytest.raises(GuestError, match="cannot reach guest 101.*nothing was started"):
        await app.apply_updates(101)
    assert app.fence.pending(101) is None


async def test_a_dropped_connection_after_the_start_keeps_the_fence(app):
    app.runner.responses["upgrade-security"] = (255, "Connection to 192.0.2.11 closed by remote host.\n")
    res = await app.apply_updates(101)
    assert res["still_running"] is True
    p = app.fence.pending(101)
    assert p["state"] == "started" and p["guest_run"] == "1700000000-42-123"


async def test_restart_while_preparing_proves_nothing_ran(app):
    # the server died after the fence went up but before the update command was sent
    app.fence.begin(101, mode="security", snapshot=None, log=str(app.runs_dir / "x.log"), planned=["openssl"])
    res = await app.update_result(101)
    assert res["never_started"] is True and app.fence.pending(101) is None
    assert app.runner.calls == []  # nothing to ask the guest


async def test_restart_during_the_update_picks_up_the_same_run(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    # a new server process: no lock, only the pending file and the run log are left
    from pvewarden.app import App

    fresh = App(app.cfg)
    fresh.pve, fresh.runner, fresh.keys = app.pve, app.runner, app.keys
    app.runner.responses["upgrade-follow"] = (0, "All upgrades installed\n")
    done = await fresh.update_result(101)
    assert done["ok"] is True and fresh.fence.pending(101) is None


async def test_result_of_another_run_keeps_the_fence(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.guest_run = "1800000000-7-999"  # the guest's last run is not ours
    app.runner.responses["upgrade-follow"] = (0, "All upgrades installed\n")
    with pytest.raises(GuestError, match="cannot tell whether"):
        await app.update_result(101)
    assert app.fence.pending(101)["state"] == "unknown"
    with pytest.raises(GuestError, match="needs a human"):  # and every change stays refused
        await app.reboot(101)


async def test_an_interrupted_update_keeps_the_fence_for_a_human(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.responses["upgrade-follow"] = (1, "pvewarden: the update process ended without reporting a result\n")
    with pytest.raises(GuestError, match="ended without a result"):
        await app.update_result(101)
    assert app.fence.pending(101)["state"] == "interrupted"
    for op in (app.apply_updates(101), app.rollback(101, "pvewarden_x"), app.snapshot(101)):
        with pytest.raises(GuestError, match="needs a human"):
            await op


async def test_no_run_seen_and_none_on_the_guest_proves_nothing_ran(app):
    app.runner.guest_run = None  # the start never got as far as printing an id
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.responses["upgrade-follow"] = (4, "pvewarden: no update has run on this guest yet\n")
    res = await app.update_result(101)
    assert res["never_started"] is True and app.fence.pending(101) is None


async def test_the_fence_is_removed_only_by_its_own_run(app):
    p = app.fence.begin(101, mode="security", snapshot=None, log="x", planned=[])
    assert app.fence.finish(101, "someone-else") is False and app.fence.pending(101) is not None
    assert app.fence.finish(101, p["run_id"]) is True and app.fence.pending(101) is None


def test_the_pending_file_is_written_atomically(app):
    app.fence.begin(101, mode="security", snapshot=None, log="x", planned=[])
    assert [f.name for f in app.fence.pending_dir.iterdir()] == ["101.json"]  # no temp files left
    (app.fence.pending_dir / "101.json").write_text("{half")
    assert app.fence.pending(101)["state"] == "unreadable"  # a broken file still fences


async def test_an_unreachable_guest_while_following_keeps_the_fence_as_it_is(app):
    app.runner.responses["upgrade-security"] = slow_upgrade
    await app.apply_updates(101)
    app.runner.responses["upgrade-follow"] = (255, "ssh: connect to host 192.0.2.11 port 22: No route to host\n")
    res = await app.update_result(101)
    assert res["still_running"] is True and app.fence.pending(101)["state"] == "started"  # not "needs a human"


def test_a_human_clears_the_fence_from_the_command_line(app, tmp_path, capsys):
    from pvewarden.cli import main

    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'state_dir = "{app.cfg.state_dir}"\n[proxmox]\nhost = "h"\ntoken_id = "u@pve!t"\ntoken_secret = "s"\n'
    )
    p = app.fence.begin(101, mode="security", snapshot="pvewarden_x", log="l", planned=[])
    app.fence.update(101, p, state="interrupted", reason="r")
    main(["-c", str(cfg_file), "pending", "list"])
    assert capsys.readouterr().out.startswith("101 interrupted r")
    main(["-c", str(cfg_file), "pending", "clear", "101"])
    assert app.fence.pending(101) is None
    assert '"pending_cleared_by_admin"' in (app.cfg.state_dir / "audit.jsonl").read_text()
