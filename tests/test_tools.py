"""Tools as the agent sees them: through a real MCP client connected in memory."""

import json

import pytest
from conftest import UPD
from mcp import Client

from pvewarden.tools import create_server

EXPECTED_TOOLS = {
    "list_guests": True,
    "check_updates": True,
    "check_services": True,
    "list_snapshots": True,
    "snapshot_guest": False,
    "apply_updates": False,
    "reboot_guest": False,
    "rollback_snapshot": False,
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
