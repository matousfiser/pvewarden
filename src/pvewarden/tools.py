"""MCP tool definitions. Thin wrappers around App; descriptions are written for the agent."""

from typing import Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from mcp_types import InputRequiredResult

from pvewarden import __version__
from pvewarden.app import App
from pvewarden.confirm import confirm
from pvewarden.errors import WardenError

READ_ONLY = ToolAnnotations(readOnlyHint=True)
CHANGES = ToolAnnotations(readOnlyHint=False, destructiveHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)


async def expose(awaitable):
    """Show expected errors (missing tag, unknown guest, ...) to the agent; crashes stay generic."""
    try:
        return await awaitable
    except WardenError as e:
        raise ToolError(str(e)) from e


def create_server(app: App) -> MCPServer:
    upd, rbt = app.cfg.policy.tag_update, app.cfg.policy.tag_reboot
    confirm_mode = app.cfg.policy.confirm_destructive
    asks = confirm_mode != "off"
    instructions = (
        "Patch management for Linux guests on Proxmox VE. Typical flow: check_updates -> apply_updates "
        "(snapshots first) -> reboot_guest if reboot_required -> report. "
        f"Permissions come from Proxmox tags: '{upd}' allows updates, snapshots and rollback, "
        f"'{rbt}' allows reboots; guests without tags are read-only. If a tool refuses, report it to the "
        "user instead of looking for a workaround. Never roll back unless the user explicitly asks. "
        "Never update without a snapshot on your own: if the snapshot fails (e.g. the guest is being backed "
        "up), report it and let the user decide."
    )
    if asks:
        instructions += (
            " Rollback and snapshot deletion are confirmed by the user in a dialog that pvewarden opens in "
            "the client; if the user declines, report that and do not retry."
        )
    if app.pve is None:
        instructions += (
            " Proxmox API is not connected (static inventory): snapshots, reboots and rollbacks are "
            "unavailable and vmid/node/status values are placeholders. This is expected."
        )
    mcp = MCPServer("pvewarden", version=__version__, instructions=instructions)

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "List guests pvewarden can see, with status, Proxmox tags and permissions "
            f"(may_update = tag '{upd}', may_reboot = tag '{rbt}'). source='static-config' means Proxmox "
            "is not connected and guests come from the server config; that is expected, not an error."
        ),
    )
    async def list_guests() -> list[dict]:
        return [app.describe(g) for g in (await expose(app.guests())).values()]

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "Refresh package lists and report pending updates and reboot state. Each package has "
            "'official' (from the distribution archives) and 'security' flags. Updates from third-party "
            "repositories are listed in 'third_party_report_only': apply_updates never installs them; "
            "report them to the user, especially major version jumps. 'held' = apt-mark hold, also skipped. "
            "auto_updates=true means the guest also installs updates by itself every day (unattended-upgrades) "
            "without a pvewarden snapshot; mention it to the user, it explains updates nobody asked for. "
            "'lock' is a Proxmox lock on the guest (e.g. 'backup'): updates, snapshots and reboots wait until "
            "it is gone. backup_running=true: a Proxmox backup runs on that node now, updates would be much "
            "slower; suggest waiting until it is done. Without vmids, checks every running guest. Read-only."
        ),
    )
    async def check_updates(vmids: list[int] | None = None) -> list[dict]:
        return await expose(app.check_updates(vmids))

    @mcp.tool(
        annotations=READ_ONLY,
        description="systemd state of a guest: overall state (running, degraded, ...) and failed units.",
    )
    async def check_services(vmid: int) -> dict:
        return await expose(app.check_services(vmid))

    @mcp.tool(
        annotations=READ_ONLY,
        description="List snapshots of a guest; 'pvewarden' marks snapshots created by pvewarden.",
    )
    async def list_snapshots(vmid: int) -> list[dict]:
        return await expose(app.list_snapshots(vmid))

    @mcp.tool(
        annotations=CHANGES,
        description=f"Create a Proxmox snapshot of a guest (requires tag '{upd}'). Returns the snapshot name.",
    )
    async def snapshot_guest(vmid: int, description: str = "") -> str:
        return await expose(app.snapshot(vmid, description))

    @mcp.tool(
        annotations=CHANGES,
        description=(
            f"Install updates on a guest (requires tag '{upd}'). Can take 10-20 minutes. Only the "
            "distribution's official archives are used: mode='security' installs security updates, "
            "mode='all' also regular updates. Third-party repositories and held packages are never "
            "installed; updates that would need them are skipped. No release upgrades. May auto-remove "
            "unused old kernels. If nothing is pending for the mode, returns nothing_to_install=true without "
            "a snapshot. 'planned' lists the packages it set out to install. "
            "Takes a snapshot first and aborts if that fails: then tell the user, do not "
            "retry with snapshot=false on your own. snapshot=false "
            + ("asks the user to confirm in the client. " if asks else "skips the snapshot. ")
            + "Refused while Proxmox locks the guest (e.g. during a backup). Does not reboot. If the result "
            "has still_running=true, the update goes on in the guest: call update_result. Report "
            "'newly_failed_services' if not empty. Full output is in the file in 'log', a path on the "
            "pvewarden server (its container), not on the Proxmox host or the guest."
        ),
    )
    async def apply_updates(
        vmid: int, ctx: Context, mode: Literal["security", "all"] = "security", snapshot: bool = True
    ) -> dict | InputRequiredResult:
        g = await expose(app.update_plan(vmid, mode))
        planned = await expose(app.to_install(g, mode))
        if planned and not snapshot and app.pve is not None:  # without Proxmox there are no snapshots to skip
            message = (
                f"Install {mode} updates on {g.name} (VMID {vmid}) WITHOUT a snapshot? "
                "If something breaks, there is no snapshot to roll back to."
            )
            asked = await expose(confirm(ctx, confirm_mode, message, f"nosnapshot:{vmid}:{mode}"))
            if asked is not None:
                return asked
        return await expose(app.apply_updates(vmid, mode, snapshot, planned))

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "Wait for an update that apply_updates reported as still_running and return its result, in "
            "the same form as apply_updates (waits up to 30 minutes, then reports still_running again)."
        ),
    )
    async def update_result(vmid: int) -> dict:
        return await expose(app.update_result(vmid))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            f"Reboot a guest through Proxmox (requires tag '{rbt}') and wait until it answers again "
            "(up to 5 minutes). Returns kernel and uptime after the reboot."
        ),
    )
    async def reboot_guest(vmid: int) -> dict:
        return await expose(app.reboot(vmid))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            f"Roll a guest back to a pvewarden snapshot and start it (requires tag '{upd}'). DISCARDS ALL "
            "CHANGES made since the snapshot, including application data. Use only when the user "
            "explicitly asks for it. If the guest had to be started, waits until it answers again "
            "(back_online), like reboot_guest."
            + (" pvewarden asks the user to confirm in the client; if they decline, nothing changes." if asks else "")
        ),
    )
    async def rollback_snapshot(vmid: int, snapshot: str, ctx: Context) -> dict | InputRequiredResult:
        plan = await expose(app.rollback_plan(vmid, snapshot))
        created = (plan["created"] or "?")[:16].replace("T", " ")
        message = (
            f"Roll back {plan['name']} (VMID {vmid}) to snapshot {snapshot}, taken {created} UTC"
            + (f" ({plan['description']})" if plan["description"] else "")
            + "? Everything written on the guest since then is lost."
        )
        asked = await expose(confirm(ctx, confirm_mode, message, f"rollback:{vmid}:{snapshot}"))
        if asked is not None:
            return asked
        return await expose(app.rollback(vmid, snapshot))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Delete pvewarden snapshots older than N days; other snapshots are never touched. "
            f"Without vmid, cleans all guests tagged '{upd}'."
            + (" pvewarden asks the user to confirm in the client; if they decline, nothing changes." if asks else "")
        ),
    )
    async def delete_old_snapshots(
        ctx: Context, older_than_days: int = 7, vmid: int | None = None
    ) -> list[dict] | InputRequiredResult:
        doomed = await expose(app.old_snapshots(older_than_days, vmid))
        if not doomed:
            return []
        listing = ", ".join(f"{d['name']}: {d['snapshot']}" for d in doomed[:10])
        more = f" and {len(doomed) - 10} more" if len(doomed) > 10 else ""
        message = f"Delete {len(doomed)} pvewarden snapshot(s) older than {older_than_days} days? {listing}{more}"
        state = f"delete:{older_than_days}:{vmid}:" + ",".join(f"{d['vmid']}/{d['snapshot']}" for d in doomed)
        asked = await expose(confirm(ctx, confirm_mode, message, state))
        if asked is not None:
            return asked
        return await expose(app.delete_old_snapshots(older_than_days, vmid))

    return mcp
