"""Tools as the agent sees them: through a real MCP client connected in memory."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import UPD
from mcp import Client
from mcp_types import ElicitResult

from pvewarden.config import StaticGuest
from pvewarden.tools import create_server

EXPECTED_TOOLS = {
    "list_guests": True,
    "check_updates": True,
    "check_services": True,
    "list_snapshots": True,
    "snapshot_guest": False,
    "apply_updates": False,
    "update_result": True,
    "reboot_guest": False,
    "rollback_snapshot": False,
    "delete_snapshot": False,
    "delete_old_snapshots": False,
}


def text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


async def test_tool_list_and_read_only_hints(app):
    async with Client(create_server(app)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert {name: t.annotations.read_only_hint for name, t in tools.items()} == EXPECTED_TOOLS
    assert tools["rollback_snapshot"].annotations.destructive_hint is True
    assert UPD in tools["apply_updates"].description  # configured tag names are in the descriptions


async def test_expected_errors_reach_the_agent_with_their_reason(app):
    async with Client(create_server(app)) as client:
        res = await client.call_tool("apply_updates", {"vmid": 103})
    assert res.is_error
    assert "missing the Proxmox tag 'pvewarden-update'" in text(res)


async def test_unexpected_errors_stay_generic(app):
    async def boom(*args, **kwargs):
        raise RuntimeError("internal detail /etc/secret")

    app.check_services = boom
    async with Client(create_server(app)) as client:
        res = await client.call_tool("check_services", {"vmid": 101})
    assert res.is_error
    assert "internal detail" not in text(res)


def audit_entries(app) -> list[dict]:
    return [json.loads(line) for line in app.audit.path.read_text().splitlines()]


def test_every_changing_tool_is_audited_before_it_runs():
    from pvewarden.tools import CHANGING_TOOLS

    assert {name for name, read_only in EXPECTED_TOOLS.items() if not read_only} <= CHANGING_TOOLS
    assert "update_result" in CHANGING_TOOLS  # it can lift a guest's block


async def test_a_refused_call_is_audited_with_its_reason(app):
    async with Client(create_server(app)) as client:
        await client.call_tool("apply_updates", {"vmid": 103})
    call, result = audit_entries(app)
    assert (call["action"], call["tool"], call["args"]) == ("tool_call", "apply_updates", {"vmid": 103})
    assert result["action"] == "tool_result" and result["outcome"] == "error"
    assert "missing the Proxmox tag" in result["error"] and call["call"] == result["call"]


async def test_a_cancelled_call_still_gets_its_result_record(app):
    import asyncio

    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError

    app.check_services = cancelled
    with pytest.raises(asyncio.CancelledError):
        await create_server(app).call_tool("check_services", {"vmid": 101})
    call, result = audit_entries(app)
    assert result["outcome"] == "cancelled" and result["call"] == call["call"]


async def test_no_change_without_an_audit_record(app):
    app.audit.path.mkdir()  # the audit log cannot be written
    async with Client(create_server(app)) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101})
        assert res.is_error and "audit log cannot be written" in text(res)
        assert app.runner.calls == [] and app.pve.events == []  # nothing ran
        read = await client.call_tool("check_updates", {"vmids": [101]})
    assert not read.is_error  # reading goes on (and is reported in the server log)


async def test_list_guests_result(app):
    async with Client(create_server(app)) as client:
        res = await client.call_tool("list_guests", {})
    assert not res.is_error
    guests = res.structured_content["result"] if res.structured_content else json.loads(text(res))
    assert {g["vmid"] for g in guests} == {101, 102, 103, 104}


@pytest.mark.parametrize("static", [False, True])
async def test_instructions_mention_static_mode(app, static):
    if static:
        app.pve = None
    server = create_server(app)
    assert ("static inventory" in server.instructions) is static


# --- confirmation of destructive actions (MCP elicitation) -------------------------------------

SNAP = "pvewarden_20261031_001243"


def answer(confirmed: bool | None):
    """A client that answers every elicitation: True/False = ticked or not, None = user cancelled."""
    asked = []

    async def callback(context, params):
        asked.append(params.message)
        if confirmed is None:
            return ElicitResult(action="cancel")
        return ElicitResult(action="accept", content={"confirm": confirmed})

    return callback, asked


@pytest.fixture
def snap_app(app):
    app.pve.snaps[101] = [{"name": SNAP, "description": "before security updates", "snaptime": 1_790_000_000}]
    return app


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_rollback_asks_the_user_and_runs_after_yes(snap_app, mode):
    callback, asked = answer(True)
    async with Client(create_server(snap_app), mode=mode, elicitation_callback=callback) as client:
        res = await client.call_tool("rollback_snapshot", {"vmid": 101, "snapshot": SNAP})
    assert not res.is_error, text(res)
    assert len(asked) == 1 and SNAP in asked[0] and "web" in asked[0] and "before security updates" in asked[0]
    assert [e[0] for e in snap_app.pve.events] == ["rollback", "start"]


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("confirmed", [False, None])
async def test_rollback_declined_changes_nothing(snap_app, mode, confirmed):
    callback, asked = answer(confirmed)
    async with Client(create_server(snap_app), mode=mode, elicitation_callback=callback) as client:
        res = await client.call_tool("rollback_snapshot", {"vmid": 101, "snapshot": SNAP})
    assert res.is_error and "did not confirm" in text(res)
    assert asked and snap_app.pve.events == []


async def test_rollback_refused_when_the_client_cannot_ask(snap_app):
    async with Client(create_server(snap_app)) as client:  # no elicitation support
        res = await client.call_tool("rollback_snapshot", {"vmid": 101, "snapshot": SNAP})
    assert res.is_error and "cannot ask the user" in text(res)
    assert snap_app.pve.events == []


@pytest.mark.parametrize("setting", ["if-supported", "off"])
async def test_confirmation_can_be_relaxed(snap_app, setting):
    snap_app.cfg = replace(snap_app.cfg, policy=replace(snap_app.cfg.policy, confirm_destructive=setting))
    async with Client(create_server(snap_app)) as client:
        res = await client.call_tool("rollback_snapshot", {"vmid": 101, "snapshot": SNAP})
    assert not res.is_error, text(res)
    assert [e[0] for e in snap_app.pve.events] == ["rollback", "start"]


async def test_policy_errors_come_before_the_question(snap_app):
    callback, asked = answer(True)
    async with Client(create_server(snap_app), elicitation_callback=callback) as client:
        res = await client.call_tool("rollback_snapshot", {"vmid": 103, "snapshot": SNAP})  # untagged guest
    assert res.is_error and "pvewarden-update" in text(res)
    assert asked == []  # the user is not asked to confirm something that would be refused anyway


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_delete_old_snapshots_lists_what_it_deletes_and_asks(snap_app, mode):
    callback, asked = answer(False)
    async with Client(create_server(snap_app), mode=mode, elicitation_callback=callback) as client:
        res = await client.call_tool("delete_old_snapshots", {"older_than_days": 0})
        assert res.is_error and SNAP in asked[0]
        assert len(snap_app.pve.snaps[101]) == 1
        nothing = await client.call_tool("delete_old_snapshots", {"older_than_days": 99999})
    assert not nothing.is_error and len(asked) == 1  # nothing to delete: no question


# --- updates without a snapshot need the user ------------------------------------------------


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_update_without_snapshot_asks_the_user(app, mode):
    callback, asked = answer(True)
    async with Client(create_server(app), mode=mode, elicitation_callback=callback) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101, "snapshot": False})
    assert not res.is_error, text(res)
    assert len(asked) == 1 and "WITHOUT a snapshot" in asked[0] and "web" in asked[0]
    assert "upgrade-security" in app.runner.commands() and app.pve.events == []


@pytest.mark.parametrize("confirmed", [False, None])
async def test_update_without_snapshot_declined_runs_nothing(app, confirmed):
    callback, asked = answer(confirmed)
    async with Client(create_server(app), elicitation_callback=callback) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101, "snapshot": False})
    assert res.is_error and "did not confirm" in text(res)
    # only the read-only check ran (on 2026-07-28 once per round trip), never an upgrade
    assert asked and set(app.runner.commands()) == {"check"} and app.pve.events == []


async def test_update_without_snapshot_refused_when_the_client_cannot_ask(app):
    async with Client(create_server(app)) as client:  # no elicitation support
        res = await client.call_tool("apply_updates", {"vmid": 101, "snapshot": False})
    assert res.is_error and "cannot ask the user" in text(res)
    assert app.runner.commands() == ["check"]


async def test_nothing_to_install_asks_nothing(app):
    app.runner.responses["check"] = (0, "")
    callback, asked = answer(False)
    async with Client(create_server(app), elicitation_callback=callback) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101, "snapshot": False})
    assert not res.is_error and "nothing_to_install" in text(res)
    assert asked == [] and app.runner.commands() == ["check"]


async def test_update_with_snapshot_asks_nothing(app):
    callback, asked = answer(False)
    async with Client(create_server(app), elicitation_callback=callback) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101})
    assert not res.is_error, text(res)
    assert asked == [] and [e[0] for e in app.pve.events] == ["snapshot"]


async def test_update_without_snapshot_checks_policy_before_asking(app):
    callback, asked = answer(True)
    app.pve._guests[101] = replace(app.pve._guests[101], lock="backup")
    async with Client(create_server(app), elicitation_callback=callback) as client:
        res = await client.call_tool("apply_updates", {"vmid": 101, "snapshot": False})
    assert res.is_error and "backed up" in text(res)
    assert asked == [] and app.runner.calls == []


async def test_static_inventory_updates_without_asking(app):
    app.pve = None
    ssh = replace(app.cfg.ssh, key=Path("/etc/pvewarden/id_ed25519"))  # admin-set address: shared key allowed
    app.cfg = replace(app.cfg, ssh=ssh, static_guests=(StaticGuest(1, "t", "192.0.2.50", tags=(UPD,)),))
    async with Client(create_server(app)) as client:  # no elicitation, and nothing to ask about
        res = await client.call_tool("apply_updates", {"vmid": 1, "snapshot": False})
    assert not res.is_error, text(res)


# --- deleting one snapshot -------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_delete_snapshot_asks_and_deletes_only_that_one(snap_app, mode):
    other = {"name": "pvewarden_20261031_193944", "description": "x", "snaptime": 1_790_000_100}
    snap_app.pve.snaps[101].append(other)
    callback, asked = answer(True)
    async with Client(create_server(snap_app), mode=mode, elicitation_callback=callback) as client:
        res = await client.call_tool("delete_snapshot", {"vmid": 101, "snapshot": SNAP})
    assert not res.is_error, text(res)
    assert len(asked) == 1 and SNAP in asked[0] and "before security updates" in asked[0]
    assert snap_app.pve.snaps[101] == [other]


async def test_delete_snapshot_declined_or_foreign(snap_app):
    callback, asked = answer(False)
    snap_app.pve.snaps[101].append({"name": "manual", "snaptime": 1})
    async with Client(create_server(snap_app), elicitation_callback=callback) as client:
        res = await client.call_tool("delete_snapshot", {"vmid": 101, "snapshot": SNAP})
        assert res.is_error and "did not confirm" in text(res)
        res = await client.call_tool("delete_snapshot", {"vmid": 101, "snapshot": "manual"})
        assert res.is_error and "only snapshots created by pvewarden can be deleted" in text(res)
    assert len(asked) == 1 and len(snap_app.pve.snaps[101]) == 2 and snap_app.pve.events == []
