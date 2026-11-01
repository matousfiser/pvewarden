"""Operations behind the MCP tools: inventory, policy checks, snapshots, updates, reboots."""

import asyncio
import dataclasses
import ipaddress
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pvewarden.audit import AuditLog
from pvewarden.config import Config
from pvewarden.errors import (
    GuestError,
    GuestTimeoutError,
    InvalidRequestError,
    NotFoundError,
    PolicyError,
    ProxmoxError,
)
from pvewarden.fence import Fence
from pvewarden.guest import GuestRunner, clean_tail, parse_services, parse_status, parse_upgradable
from pvewarden.keys import KeyStore
from pvewarden.proxmox import Guest, ProxmoxClient

SNAPSHOT_PREFIX = "pvewarden_"
MODES = ("security", "all")


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.audit = AuditLog(cfg.state_dir / "audit.jsonl")
        self.pve = ProxmoxClient(cfg.proxmox) if cfg.proxmox else None
        self.runner = GuestRunner(cfg.ssh, cfg.state_dir / "known_hosts")
        self.keys = KeyStore(cfg.state_dir / "keys")
        self.runs_dir = cfg.state_dir / "runs"
        self.fence = Fence(cfg.state_dir)  # one change per guest at a time; updates still running
        self.pending_dir = self.fence.pending_dir

    # --- inventory and policy ------------------------------------------------------------

    async def guests(self) -> dict[int, Guest]:
        if self.pve is None:
            return {g.vmid: Guest(g.vmid, g.name, g.type, None, "unknown", g.tags) for g in self.cfg.static_guests}
        return {g.vmid: g for g in await self.pve.guests()}

    async def guest(self, vmid: int) -> Guest:
        g = (await self.guests()).get(vmid)
        if g is None:
            raise NotFoundError(f"guest {vmid} not found (or not in the pvewarden pool)")
        return g

    def describe(self, g: Guest) -> dict:
        return {
            "vmid": g.vmid,
            "name": g.name,
            "type": g.type,
            "node": g.node,
            "status": g.status,
            "tags": list(g.tags),
            "may_update": self.cfg.policy.tag_update in g.tags,
            "may_reboot": self.cfg.policy.tag_reboot in g.tags,
            "source": "proxmox" if self.pve else "static-config",
        }

    def require(self, g: Guest, tag: str) -> None:
        if tag not in g.tags:
            raise PolicyError(
                f"Guest {g.vmid} ({g.name}) is missing the Proxmox tag '{tag}'. "
                "Only the user can grant this by adding the tag in Proxmox."
            )

    def require_proxmox(self) -> ProxmoxClient:
        if self.pve is None:
            raise ProxmoxError("Proxmox API is not configured (static inventory): this operation is unavailable.")
        return self.pve

    @staticmethod
    def _running(g: Guest) -> None:
        if g.status not in ("running", "unknown"):
            raise GuestError(f"guest {g.vmid} ({g.name}) is {g.status}")

    @staticmethod
    def _unlocked(g: Guest) -> None:
        """Refuse while Proxmox holds a lock on the guest, e.g. during a backup."""
        if g.lock == "backup":
            raise GuestError(
                f"guest {g.vmid} ({g.name}) is being backed up by Proxmox right now (lock 'backup'); nothing was "
                "changed. Try again after the backup has finished. Do not skip the snapshot to get around this."
            )
        if g.lock:
            raise GuestError(
                f"guest {g.vmid} ({g.name}) is locked in Proxmox (lock '{g.lock}'): another operation is running "
                "or was interrupted. Nothing was changed; tell the user."
            )

    def _no_update_running(self, g: Guest) -> None:
        p = self.fence.pending(g.vmid)
        if p is None:
            return
        if p.get("state") in ("interrupted", "unreadable", "unknown"):
            raise GuestError(self._needs_human(g, p.get("reason", "its state is unclear")))
        raise GuestError(
            f"an update started by pvewarden is still running on guest {g.vmid} ({g.name}); "
            "call update_result to wait for it first"
        )

    def _hold(self, g: Guest, pending: dict, state: str, reason: str) -> None:
        """Keep the fence (marked for a human) and refuse."""
        self.fence.update(g.vmid, pending, state=state, reason=reason)
        self.audit.write("apply_updates_needs_human", vmid=g.vmid, run=pending["run_id"], state=state, reason=reason)
        raise GuestError(self._needs_human(g, reason))

    @staticmethod
    def _needs_human(g: Guest, reason: str) -> str:
        return (
            f"guest {g.vmid} ({g.name}): the last pvewarden update needs a human: {reason}. pvewarden keeps "
            "refusing changes to this guest until the user has looked at it (e.g. 'dpkg --audit' in the guest) "
            f"and cleared it on the server: pvewarden pending clear {g.vmid}. Tell the user; do not try to "
            "work around it."
        )

    # --- talking to guests ---------------------------------------------------------------

    async def address(self, g: Guest) -> str:
        if g.vmid in self.cfg.addresses:
            return self.cfg.addresses[g.vmid]
        if self.pve is None:
            return next(s.address for s in self.cfg.static_guests if s.vmid == g.vmid)
        try:
            ips = await self.pve.guest_ips(g)
        except ProxmoxError:
            ips = []
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_link_local:
                continue
            if not self.cfg.ssh.subnets or any(addr in net for net in self.cfg.ssh.subnets):
                return ip
        return g.name  # fall back to DNS

    def address_is_pinned(self, vmid: int) -> bool:
        """The admin set this guest's address in the config; the guest cannot redirect us."""
        return vmid in self.cfg.addresses or self.pve is None

    def key_for(self, g: Guest, new: bool = False) -> Path:
        """The SSH key for this guest. new=True: the key being enrolled (pvewarden key verify)."""
        if new:
            key = self.keys.pending(g.vmid)
            if key is None:
                raise GuestError(f"guest {g.vmid} ({g.name}) has no key being enrolled (pvewarden key new {g.vmid})")
            return key
        key = self.keys.active(g.vmid)
        if key is not None:
            return key
        # An address reported by the guest (guest agent, container interfaces) is under the guest's
        # control. A shared key would let one guest send us to another, so only admin-set addresses
        # may use it.
        if self.address_is_pinned(g.vmid):
            if self.cfg.ssh.key is not None:
                return self.cfg.ssh.key
            raise GuestError(
                f"guest {g.vmid} ({g.name}) has no SSH key: set [ssh] key or run: pvewarden key new {g.vmid}"
            )
        raise GuestError(
            f"guest {g.vmid} ({g.name}) has no pvewarden key of its own yet; nothing was done. "
            f"Enroll it again on the Proxmox host: pvewarden-enroll {g.vmid}"
        )

    async def run(self, g: Guest, command: str, new_key: bool = False, **kwargs) -> tuple[int, str]:
        key = self.key_for(g, new=new_key)
        return await self.runner.run(
            await self.address(g), command, key=key, alias=f"pvewarden-vmid-{g.vmid}", **kwargs
        )

    async def status(self, g: Guest) -> dict:
        rc, out = await self.run(g, "status", timeout=60)
        if rc != 0:
            raise GuestError(f"status failed on {g.vmid} ({g.name}): {out.strip()[-500:]}")
        return parse_status(out)

    async def services(self, g: Guest) -> dict | None:
        """None if the guest runs an older client without the 'services' command."""
        rc, out = await self.run(g, "services", timeout=60)
        if "command not allowed" in out:
            return None
        if rc != 0:
            raise GuestError(f"services failed on {g.vmid} ({g.name}): {out.strip()[-500:]}")
        return parse_services(out)

    # --- operations ----------------------------------------------------------------------

    async def check_updates(self, vmids: list[int] | None = None) -> list[dict]:
        guests = await self.guests()
        if vmids:
            missing = [v for v in vmids if v not in guests]
            if missing:
                raise NotFoundError(f"guests not found: {missing}")
            targets = [guests[v] for v in vmids]
        else:
            targets = [g for g in guests.values() if g.status in ("running", "unknown")]

        # a backup job locks the guest it is copying; seeing that on any guest means a job runs on that node
        backup_nodes = {x.node for x in guests.values() if x.lock == "backup"}

        async def one(g: Guest) -> dict:
            res = {"vmid": g.vmid, "name": g.name, **{k: self.describe(g)[k] for k in ("may_update", "may_reboot")}}
            if g.lock:
                res["lock"] = g.lock
            if g.node in backup_nodes:
                res["backup_running"] = True
            try:
                rc, out = await self.run(g, "check", timeout=600)
                if rc != 0:
                    return res | {"error": out.strip()[-500:]}
                pkgs = parse_upgradable(out)
                if not pkgs and out.strip():
                    return res | {"error": "unexpected 'check' output: the guest runs an outdated pvewarden client"}
                st = await self.status(g)
            except Exception as e:  # report per guest, keep checking the others
                return res | {"error": str(e)}
            third_party = [p for p in pkgs if not p["official"]]
            return res | {
                "os": st.get("os"),
                "pending": len(pkgs),
                "pending_security": sum(p["security"] for p in pkgs),
                "pending_official": len(pkgs) - len(third_party),
                "third_party_report_only": [
                    {k: p[k] for k in ("name", "from", "to", "origin", "held")} for p in third_party
                ],
                "packages": pkgs,
                "reboot_required": st["reboot_required"],
                "reboot_pkgs": st["reboot_pkgs"],
                "auto_updates": st["auto_updates"],
            }

        results = await asyncio.gather(*(one(g) for g in targets))
        self.audit.write("check_updates", vmids=[g.vmid for g in targets])
        return list(results)

    async def check_services(self, vmid: int) -> dict:
        g = await self.guest(vmid)
        res = await self.services(g)
        if res is None:
            raise GuestError(f"guest {vmid} runs an outdated pvewarden client without 'services'; re-enroll it")
        return {"vmid": vmid, "name": g.name, **res}

    async def _snapshot(self, g: Guest, description: str, client: str | None = None) -> str:
        pve = self.require_proxmox()
        name = SNAPSHOT_PREFIX + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        # who asked for it, visible in the Proxmox UI too (the audit log has the details)
        description = (description or "pvewarden") + (f" (client: {client})" if client else "")
        try:
            await pve.create_snapshot(g, name, description)
        except ProxmoxError as e:
            if "locked (backup)" in str(e):
                self._unlocked(replace_lock(g, "backup"))
            raise ProxmoxError(
                f"snapshot of guest {g.vmid} ({g.name}) failed: {e}. Nothing else was done. Tell the user; "
                "do not retry without a snapshot unless the user asks for that."
            ) from e
        self.audit.write("snapshot", vmid=g.vmid, snapshot=name, client=client)
        return name

    async def snapshot(self, vmid: int, description: str = "", client: str | None = None) -> str:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        with self.fence.lock(vmid, g.name):
            self._unlocked(g)
            self._no_update_running(g)
            return await self._snapshot(g, description, client)

    async def update_plan(self, vmid: int, mode: str = "security") -> Guest:
        """Check an update may start now, without changing anything."""
        if mode not in MODES:
            raise InvalidRequestError(f"mode must be one of {MODES}")
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        self._running(g)
        self._unlocked(g)
        self._no_update_running(g)
        return g

    async def to_install(self, g: Guest, mode: str) -> list[str]:
        """Packages apply_updates would install: official, not held, security only in mode 'security'."""
        rc, out = await self.run(g, "check", timeout=600)
        if rc != 0:
            raise GuestError(f"checking for updates failed on {g.vmid} ({g.name}): {out.strip()[-500:]}")
        pkgs = parse_upgradable(out)
        if not pkgs and out.strip():
            raise GuestError(f"guest {g.vmid} ({g.name}) runs an outdated pvewarden client; re-enroll it")
        return [p["name"] for p in pkgs if p["official"] and not p["held"] and (mode == "all" or p["security"])]

    async def apply_updates(
        self,
        vmid: int,
        mode: str = "security",
        snapshot: bool = True,
        planned: list[str] | None = None,
        client: str | None = None,
    ) -> dict:
        g = await self.guest(vmid)
        with self.fence.lock(vmid, g.name):
            g = await self.update_plan(vmid, mode)  # checked again under the lock
            if planned is None:
                planned = await self.to_install(g, mode)
            if not planned:  # no snapshot, no apt run: nothing would change
                self.audit.write("apply_updates_nothing", vmid=vmid, mode=mode)
                return {"vmid": vmid, "name": g.name, "ok": True, "nothing_to_install": True, "snapshot": None}
            log = self.runs_dir / f"{datetime.now(UTC):%Y%m%d_%H%M%S}_{vmid}_{g.name}_{mode}.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            # the fence goes up before anything changes and outlives this process
            p = self.fence.begin(vmid, mode=mode, snapshot=None, log=str(log), planned=planned)
            try:
                snap = await self._snapshot(g, f"before {mode} updates", client) if snapshot else None
                before = await self.services(g)
                # 'started' is written before the command is sent: 'preparing' proves nothing ran
                p = self.fence.update(vmid, p, state="started", snapshot=snap, services_before=before)
            except BaseException:
                self.fence.finish(vmid, p["run_id"])
                raise
            self.audit.write("apply_updates_start", vmid=vmid, mode=mode, snapshot=snap, log=str(log), run=p["run_id"])
            return await self._finish_update(g, p, f"upgrade-{mode}", "a")

    async def update_result(self, vmid: int) -> dict:
        """Wait for an update that was still running when apply_updates returned, and report it."""
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        with self.fence.lock(vmid, g.name):
            p = self.fence.pending(vmid)
            if p is None:
                raise InvalidRequestError(f"no pvewarden update is running on guest {vmid}; nothing to wait for")
            if p.get("state") == "preparing":
                # stopped before the update command was sent: provably nothing was installed
                self.fence.finish(vmid, p["run_id"])
                self.audit.write("apply_updates_never_started", vmid=vmid, run=p["run_id"])
                return {
                    "vmid": vmid,
                    "name": g.name,
                    "ok": None,
                    "never_started": True,
                    "snapshot": p.get("snapshot"),
                    "hint": "pvewarden stopped before the update was sent to the guest; nothing was installed. "
                    "It may have taken a snapshot first (list_snapshots).",
                }
            if p.get("state") != "started":
                raise GuestError(self._needs_human(g, p.get("reason", "its state is unclear")))
            return await self._finish_update(g, p, "upgrade-follow", "w")

    async def _finish_update(self, g: Guest, pending: dict, command: str, log_mode: str) -> dict:
        """Start (upgrade-*) or follow (upgrade-follow) the update and report it. The fence is lifted only
        when the result provably belongs to this run, or nothing provably ran; when in doubt it stays."""
        log = Path(pending["log"])
        starting = command != "upgrade-follow"
        run_id = pending["run_id"]
        base = {
            "vmid": g.vmid,
            "name": g.name,
            "snapshot": pending["snapshot"],
            "planned": pending.get("planned"),
            "log": str(log),
        }
        # the guest's id of our run, as far as we saw it (following rewrites the log)
        ours = pending.get("guest_run") or guest_run_id(log)
        try:
            rc, out = await self.run(g, command, log=log, log_mode=log_mode)
        except GuestTimeoutError:
            seen = guest_run_id(log)
            if seen and not pending.get("guest_run"):
                self.fence.update(g.vmid, pending, guest_run=seen)
            self.audit.write("apply_updates_waiting", vmid=g.vmid, run=run_id)
            return base | {"ok": None, "still_running": True, "hint": STILL_RUNNING_HINT}
        except BaseException:
            if starting and not guest_run_id(log):  # the command never reached the guest
                self.fence.finish(g.vmid, run_id)
            raise
        theirs = guest_run_id(out)

        if rc == 255:  # ssh failed
            if starting and theirs is None and SSH_NOT_CONNECTED.search(out):
                self.fence.finish(g.vmid, run_id)  # it never logged in: nothing ran
                raise GuestError(
                    f"cannot reach guest {g.vmid} ({g.name}) over SSH; nothing was started: {out.strip()[-300:]}"
                )
            # the connection broke (or could not be made to follow): the update goes on detached
            seen = ours or theirs
            if seen and not pending.get("guest_run"):
                self.fence.update(g.vmid, pending, guest_run=seen)
            self.audit.write("apply_updates_waiting", vmid=g.vmid, run=run_id, ssh=out.strip()[-200:])
            return base | {"ok": None, "still_running": True, "hint": STILL_RUNNING_HINT}

        if starting:
            if rc == 75 and "already running" in out:  # someone else's run: ours never started
                self.fence.finish(g.vmid, run_id)
                raise GuestError(f"an update is already running on guest {g.vmid} ({g.name}); nothing new was started")
            ours = ours or theirs
        else:
            if rc == 4 and ours is None and "no update has run" in out:
                # the guest never ran any update and we never saw ours start: provably nothing ran
                self.fence.finish(g.vmid, run_id)
                self.audit.write("apply_updates_never_started", vmid=g.vmid, run=run_id)
                return base | {
                    "ok": None,
                    "never_started": True,
                    "hint": "the update never started on the guest; nothing was installed",
                }
            if ours is None or theirs != ours:
                why = (
                    "pvewarden cannot tell whether the guest's last update is the one it started"
                    if theirs or ours
                    else "the guest cannot report the update's result (outdated client, or its result is gone)"
                )
                self._hold(g, pending, "unknown", why)

        if "ended without reporting a result" in out:
            self._hold(
                g,
                pending,
                "interrupted",
                "the update process on the guest ended without a result "
                "(was the guest rebooted or the process killed while dpkg ran?)",
            )

        self.fence.finish(g.vmid, run_id)
        st = await self.status(g)
        before, after = pending["services_before"], await self.services(g)
        newly_failed = sorted(set(after["failed"]) - set(before["failed"])) if before and after else None
        self.audit.write(
            "apply_updates",
            vmid=g.vmid,
            mode=pending["mode"],
            snapshot=pending["snapshot"],
            rc=rc,
            reboot_required=st["reboot_required"],
            newly_failed_services=newly_failed,
        )
        return base | {
            "ok": rc == 0,
            "reboot_required": st["reboot_required"],
            "reboot_pkgs": st["reboot_pkgs"],
            "services_after": after,
            "newly_failed_services": newly_failed,
            "output_tail": clean_tail(out),
        }

    async def reboot(self, vmid: int, wait_s: int = 300, interval: float = 5) -> dict:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_reboot)
        with self.fence.lock(vmid, g.name):
            self._unlocked(g)
            self._no_update_running(g)
            await self.require_proxmox().reboot(g)
            self.audit.write("reboot", vmid=vmid)
            return {"vmid": vmid, "name": g.name, **await self._wait_online(g, wait_s, interval)}

    async def _wait_online(self, g: Guest, wait_s: int, interval: float, check_first: bool = False) -> dict:
        """Wait until the guest answers over SSH again. After a reboot the first check waits:
        right after the request the old system may still answer; after a fresh start it need not."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while loop.time() < deadline:
            if not check_first:
                await asyncio.sleep(interval)
            check_first = False
            try:
                return {"back_online": True, **await self.status(g)}
            except Exception:
                continue
        return {"back_online": False}

    async def list_snapshots(self, vmid: int) -> list[dict]:
        g = await self.guest(vmid)
        return [
            {
                "name": s["name"],
                "description": s.get("description", "").strip(),
                "created": datetime.fromtimestamp(s["snaptime"], UTC).isoformat() if s.get("snaptime") else None,
                "pvewarden": s["name"].startswith(SNAPSHOT_PREFIX),
            }
            for s in await self.require_proxmox().snapshots(g)
        ]

    async def rollback_plan(self, vmid: int, snapshot: str, what: str = "rolled back") -> dict:
        """Check a rollback (or deletion) is allowed and the snapshot exists, without changing anything."""
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        if not snapshot.startswith(SNAPSHOT_PREFIX):
            raise PolicyError(f"only snapshots created by pvewarden can be {what}")
        self._unlocked(g)
        self._no_update_running(g)
        found = next((s for s in await self.list_snapshots(vmid) if s["name"] == snapshot), None)
        if found is None:
            raise NotFoundError(f"guest {vmid} has no snapshot {snapshot!r}")
        return {"vmid": vmid, "name": g.name, **{k: found[k] for k in ("description", "created")}, "snapshot": snapshot}

    async def rollback(self, vmid: int, snapshot: str, wait_s: int = 300, interval: float = 5) -> dict:
        g = await self.guest(vmid)
        with self.fence.lock(vmid, g.name):
            return await self._rollback(vmid, snapshot, wait_s, interval)

    async def _rollback(self, vmid: int, snapshot: str, wait_s: int, interval: float) -> dict:
        await self.rollback_plan(vmid, snapshot)  # checked again under the lock
        g = await self.guest(vmid)
        pve = self.require_proxmox()
        await pve.rollback(g, snapshot)
        started = False
        if await pve.status(g) != "running":
            await pve.start(g)
            started = True
        self.audit.write("rollback", vmid=vmid, snapshot=snapshot)
        res = {"vmid": vmid, "name": g.name, "rolled_back_to": snapshot, "started_after_rollback": started}
        # always: report once the guest answers again (and its state), not while it still boots
        res |= await self._wait_online(g, wait_s, interval, check_first=True)
        return res

    async def delete_snapshot(self, vmid: int, snapshot: str) -> dict:
        g = await self.guest(vmid)
        with self.fence.lock(vmid, g.name):
            await self.rollback_plan(vmid, snapshot, "deleted")  # checked again under the lock
            await self.require_proxmox().delete_snapshot(g, snapshot)
            self.audit.write("delete_snapshot", vmid=vmid, snapshot=snapshot)
            return {"vmid": vmid, "name": g.name, "deleted": snapshot}

    async def old_snapshots(self, older_than_days: int = 7, vmid: int | None = None) -> list[dict]:
        """pvewarden snapshots older than N days that delete_old_snapshots would remove."""
        pve = self.require_proxmox()
        if vmid is not None:
            g = await self.guest(vmid)
            self.require(g, self.cfg.policy.tag_update)
            targets = [g]
        else:
            targets = [g for g in (await self.guests()).values() if self.cfg.policy.tag_update in g.tags]
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        out = []
        for g in targets:
            for s in await pve.snapshots(g):
                taken = datetime.fromtimestamp(s.get("snaptime", 0), UTC)
                if s["name"].startswith(SNAPSHOT_PREFIX) and taken < cutoff:
                    out.append({"vmid": g.vmid, "name": g.name, "snapshot": s["name"], "created": taken.isoformat()})
        return out

    async def delete_old_snapshots(self, older_than_days: int = 7, vmid: int | None = None) -> list[dict]:
        pve = self.require_proxmox()
        guests = await self.guests()
        deleted, skipped = [], []
        for item in await self.old_snapshots(older_than_days, vmid):
            g = guests[item["vmid"]]
            try:
                with self.fence.lock(g.vmid, g.name):
                    self._unlocked(g)
                    self._no_update_running(g)
                    await pve.delete_snapshot(g, item["snapshot"])
            except GuestError as e:  # busy guest: leave its snapshots, go on with the others
                skipped.append({"vmid": g.vmid, "snapshot": item["snapshot"], "skipped": str(e)})
                continue
            deleted.append({"vmid": item["vmid"], "snapshot": item["snapshot"]})
        self.audit.write("delete_old_snapshots", older_than_days=older_than_days, deleted=deleted, skipped=skipped)
        return deleted + skipped


STILL_RUNNING_HINT = (
    "The update keeps running on the guest. Call update_result to wait for it and get the result. "
    "Do not reboot or roll back the guest meanwhile."
)
# ssh's own errors before it logged in: the command was certainly not run
SSH_NOT_CONNECTED = re.compile(
    r"Connection refused|Connection timed out|No route to host|Could not resolve|Permission denied|"
    r"Host key verification failed|Network is unreachable|connect to host .* port"
)
GUEST_RUN_RE = re.compile(r"^pvewarden-run: (\S+)$", re.M)


def guest_run_id(source: str | Path) -> str | None:
    """The run id the guest prints first when it starts or follows an update."""
    if isinstance(source, Path):
        try:
            with open(source) as f:
                source = f.read(4096)
        except OSError:
            return None
    m = GUEST_RUN_RE.search(source)
    return m.group(1) if m else None


def replace_lock(g: Guest, lock: str) -> Guest:
    return dataclasses.replace(g, lock=lock)
