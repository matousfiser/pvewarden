"""MCP tool definitions. Thin wrappers around App; descriptions are written for the agent."""

import asyncio
import logging
import secrets
import time
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from mcp_types import InputRequiredResult
from pydantic import Field

from pvewarden import __version__
from pvewarden.app import App
from pvewarden.audit import CALL_ID
from pvewarden.confirm import confirm
from pvewarden.errors import WardenError
from pvewarden.http import CLIENT_KEY

READ_ONLY = ToolAnnotations(readOnlyHint=True)
CHANGES = ToolAnnotations(readOnlyHint=False, destructiveHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)


# tools that change something (or lift a guest's block): their call is not run unless it is in the audit log
CHANGING_TOOLS = frozenset(
    {
        "snapshot_guest",
        "apply_updates",
        "update_result",
        "reboot_guest",
        "rollback_snapshot",
        "delete_snapshot",
        "delete_old_snapshots",
    }
)
log = logging.getLogger(__name__)

# parameters as the agent sees them in the tool schema
VMID = Annotated[int, Field(description="Proxmox VMID of the guest, e.g. 101 (see list_guests).")]
SNAPSHOT = Annotated[
    str,
    Field(
        description="Snapshot name as list_snapshots shows it. pvewarden snapshots are named "
        "pvewarden_YYYYMMDD_HHMMSS (UTC); only those can be used here."
    ),
]


def _scope(ctx: Context | None) -> dict:
    try:
        request = getattr(ctx.request_context, "request", None) if ctx else None
    except (ValueError, AttributeError):  # outside a request
        return {}
    return getattr(request, "scope", None) or {}


def client_name(ctx: Context) -> str | None:
    """Name of the token the call came with ([http.clients]); None over stdio."""
    return _scope(ctx).get(CLIENT_KEY)


class AuditedServer(MCPServer):
    """Every tool call: 'tool_call' (who, from where, arguments) before it runs, 'tool_result'
    (ok / error / asked the user / cancelled, duration) after; records in between carry the same call id.
    A changing tool does not run if its 'tool_call' record cannot be written."""

    def __init__(self, app: App, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = app

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Context | None = None):
        call_id = secrets.token_hex(6)
        token = CALL_ID.set(call_id)
        scope = _scope(context)
        ip = (scope.get("client") or (None,))[0]
        try:
            try:
                self.app.audit.write(
                    "tool_call",
                    must=name in CHANGING_TOOLS,
                    tool=name,
                    client=scope.get(CLIENT_KEY),
                    ip=ip,
                    args=arguments,
                )
            except OSError as e:
                raise ToolError(f"the audit log cannot be written ({e}); nothing was done. Tell the user.") from e
            start = time.monotonic()
            try:
                result = await super().call_tool(name, arguments, context)
            except Exception as e:
                self._result(name, start, outcome="error", error=str(e)[:500])
                raise
            except BaseException as e:  # cancelled (client gone, server stopping): still say how it ended
                self._result(name, start, outcome="cancelled", error=type(e).__name__)
                raise
            if isinstance(result, InputRequiredResult):
                self._result(name, start, outcome="asked_user")
            elif getattr(result, "is_error", False):
                text = " ".join(getattr(c, "text", "") for c in result.content)
                self._result(name, start, outcome="error", error=text[:500])
            else:
                self._result(name, start, outcome="ok")
            return result
        finally:
            CALL_ID.reset(token)

    def _result(self, name: str, start: float, **fields) -> None:
        self.app.audit.write("tool_result", tool=name, ms=round((time.monotonic() - start) * 1000), **fields)


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
            " Rollback, snapshot deletion and updates without a snapshot are confirmed by the user in a "
            "dialog that pvewarden opens in "
            "the client; if the user declines, report that and do not retry."
        )
    if app.pve is None:
        instructions += (
            " Proxmox API is not connected (static inventory): snapshots, reboots and rollbacks are "
            "unavailable and vmid/node/status values are placeholders. This is expected."
        )
    mcp = AuditedServer(app, "pvewarden", version=__version__, instructions=instructions)

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "List guests pvewarden can see, with VMID, name, status, Proxmox tags and permissions "
            f"(may_update = tag '{upd}', may_reboot = tag '{rbt}'). Start here: it is how you find the "
            "VMIDs the other tools take and what each guest allows. Does not contact the guests; "
            "check_updates does. source='static-config' means Proxmox "
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
            "slower; suggest waiting until it is done. Without vmids, checks every running guest. Read-only: "
            "use it to see what is pending, apply_updates to install. "
            "Returns {guests: [...], pvewarden: {...}}. 'pvewarden' is about pvewarden itself: if it has "
            "'new_version', tell the user that a newer pvewarden is out and how to upgrade ('upgrade'); "
            "security_fix=true means the newer release fixes a security problem: say so first. You cannot "
            "upgrade pvewarden yourself."
        ),
    )
    async def check_updates(
        vmids: Annotated[
            list[int] | None, Field(description="Proxmox VMIDs to check, e.g. [101, 102]; omit for all running guests.")
        ] = None,
    ) -> dict:
        guests, pvewarden = await asyncio.gather(expose(app.check_updates(vmids)), app.release.notice())
        return {"guests": guests, "pvewarden": pvewarden}

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "systemd state of one guest: overall state (running, degraded, ...) and the failed units. Use it "
            "to look at a guest's health, e.g. before an update or when the user reports a problem; "
            "apply_updates and reboot_guest already compare it themselves. Read-only. Refused for a guest "
            "that is not running (list_guests shows the status)."
        ),
    )
    async def check_services(vmid: VMID) -> dict:
        return await expose(app.check_services(vmid))

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "List the Proxmox snapshots of one guest with name, creation time and description. "
            "pvewarden=true marks snapshots pvewarden took (named pvewarden_YYYYMMDD_HHMMSS); only those "
            "can be rolled back to or deleted with pvewarden. Call it to get the exact name before "
            "rollback_snapshot or delete_snapshot. Read-only."
        ),
    )
    async def list_snapshots(vmid: VMID) -> list[dict]:
        return await expose(app.list_snapshots(vmid))

    @mcp.tool(
        annotations=CHANGES,
        description=(
            f"Create a Proxmox snapshot of a guest now (requires tag '{upd}'), named "
            "pvewarden_YYYYMMDD_HHMMSS (UTC); returns the name. Not needed before apply_updates, which takes "
            "its own snapshot. Snapshots use storage until deleted (delete_snapshot, delete_old_snapshots). "
            "Refused while Proxmox locks the guest (e.g. during a backup)."
        ),
    )
    async def snapshot_guest(
        vmid: VMID,
        ctx: Context,
        description: Annotated[
            str, Field(description="Why the snapshot is taken; stored in Proxmox next to your client name.")
        ] = "",
    ) -> str:
        return await expose(app.snapshot(vmid, description, client_name(ctx)))

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
        vmid: VMID,
        ctx: Context,
        mode: Annotated[
            Literal["security", "all"],
            Field(description="'security': security updates only; 'all': also regular updates."),
        ] = "security",
        snapshot: Annotated[
            bool, Field(description="Take a snapshot first. Keep true; false needs the user's consent.")
        ] = True,
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
        return await expose(app.apply_updates(vmid, mode, snapshot, planned, client_name(ctx)))

    @mcp.tool(
        annotations=READ_ONLY,
        description=(
            "Wait for an update that apply_updates reported as still_running and return its result, in "
            "the same form as apply_updates (waits up to 30 minutes, then reports still_running again). "
            "Pass the vmid of that apply_updates call. "
            "never_started=true means nothing was installed. If pvewarden cannot tell what happened, it "
            "keeps the guest blocked and says a human must check it: tell the user, do not retry."
        ),
    )
    async def update_result(vmid: VMID) -> dict:
        return await expose(app.update_result(vmid))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            f"Reboot a guest through Proxmox (requires tag '{rbt}') and wait until it answers again "
            "(up to 5 minutes). Returns kernel and uptime after the reboot. Use it when check_updates or "
            "apply_updates report reboot_required. Refused while Proxmox locks the guest."
        ),
    )
    async def reboot_guest(vmid: VMID) -> dict:
        return await expose(app.reboot(vmid))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            f"Roll a guest back to a pvewarden snapshot and start it (requires tag '{upd}'). DISCARDS ALL "
            "CHANGES made since the snapshot, including application data. Use only when the user "
            "explicitly asks for it. Get the snapshot name from list_snapshots. If the guest had to be "
            "started, waits until it answers again "
            "(back_online), like reboot_guest."
            + (" pvewarden asks the user to confirm in the client; if they decline, nothing changes." if asks else "")
        ),
    )
    async def rollback_snapshot(vmid: VMID, snapshot: SNAPSHOT, ctx: Context) -> dict | InputRequiredResult:
        plan = await expose(app.rollback_plan(vmid, snapshot))
        message = snapshot_question(
            f"Roll back {plan['name']} (VMID {vmid}) to snapshot {snapshot}",
            plan,
            "Everything written on the guest since then is lost.",
        )
        asked = await expose(confirm(ctx, confirm_mode, message, f"rollback:{vmid}:{snapshot}"))
        if asked is not None:
            return asked
        return await expose(app.rollback(vmid, snapshot))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            f"Delete one pvewarden snapshot of a guest by name (requires tag '{upd}'); other snapshots are "
            "never touched. Get the name from list_snapshots. Use it to remove specific snapshots; "
            "delete_old_snapshots removes by age."
            + (" pvewarden asks the user to confirm in the client; if they decline, nothing changes." if asks else "")
        ),
    )
    async def delete_snapshot(vmid: VMID, snapshot: SNAPSHOT, ctx: Context) -> dict | InputRequiredResult:
        plan = await expose(app.rollback_plan(vmid, snapshot, "deleted"))
        message = snapshot_question(
            f"Delete snapshot {snapshot} of {plan['name']} (VMID {vmid})", plan, "It can no longer be rolled back to."
        )
        asked = await expose(confirm(ctx, confirm_mode, message, f"delete-one:{vmid}:{snapshot}"))
        if asked is not None:
            return asked
        return await expose(app.delete_snapshot(vmid, snapshot))

    @mcp.tool(
        annotations=DESTRUCTIVE,
        description=(
            "Delete pvewarden snapshots older than N days (default 7); other snapshots are never touched. "
            f"Without vmid, cleans all guests tagged '{upd}'. Returns the deleted snapshots; an empty list "
            "means none were old enough. To delete one specific snapshot, use delete_snapshot."
            + (" pvewarden asks the user to confirm in the client; if they decline, nothing changes." if asks else "")
        ),
    )
    async def delete_old_snapshots(
        ctx: Context,
        older_than_days: Annotated[
            int, Field(ge=0, description="Delete snapshots older than this many days; 0 = all pvewarden snapshots.")
        ] = 7,
        vmid: Annotated[
            int | None, Field(description="Proxmox VMID of one guest; omit for every guest that allows updates.")
        ] = None,
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


def snapshot_question(action: str, plan: dict, consequence: str) -> str:
    """The confirmation question for one snapshot: what, when it was taken, and what it means."""
    created = (plan["created"] or "?")[:16].replace("T", " ")
    described = f" ({plan['description']})" if plan["description"] else ""
    return f"{action}, taken {created} UTC{described}? {consequence}"
