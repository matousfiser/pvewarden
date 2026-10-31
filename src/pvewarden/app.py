"""Operations behind the MCP tools: inventory, policy checks, snapshots, updates, reboots."""

import asyncio
import dataclasses
import ipaddress
import json
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
from pvewarden.guest import GuestRunner, clean_tail, parse_services, parse_status, parse_upgradable
from pvewarden.proxmox import Guest, ProxmoxClient

SNAPSHOT_PREFIX = "pvewarden_"
MODES = ("security", "all")


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.audit = AuditLog(cfg.state_dir / "audit.jsonl")
        self.pve = ProxmoxClient(cfg.proxmox) if cfg.proxmox else None
        self.runner = GuestRunner(cfg.ssh, cfg.state_dir / "known_hosts")
        self.runs_dir = cfg.state_dir / "runs"
        self.pending_dir = cfg.state_dir / "pending"  # updates still running on a guest

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
        if self._pending_file(g.vmid).exists():
            raise GuestError(
                f"an update started by pvewarden is still running on guest {g.vmid} ({g.name}); "
                "call update_result to wait for it first"
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

    async def run(self, g: Guest, command: str, **kwargs) -> tuple[int, str]:
        return await self.runner.run(await self.address(g), command, **kwargs)

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

    async def _snapshot(self, g: Guest, description: str) -> str:
        pve = self.require_proxmox()
        name = SNAPSHOT_PREFIX + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        try:
            await pve.create_snapshot(g, name, description or "pvewarden")
        except ProxmoxError as e:
            if "locked (backup)" in str(e):
                self._unlocked(replace_lock(g, "backup"))
            raise ProxmoxError(
                f"snapshot of guest {g.vmid} ({g.name}) failed: {e}. Nothing else was done. Tell the user; "
                "do not retry without a snapshot unless the user asks for that."
            ) from e
        self.audit.write("snapshot", vmid=g.vmid, snapshot=name)
        return name

    async def snapshot(self, vmid: int, description: str = "") -> str:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        self._unlocked(g)
        return await self._snapshot(g, description)

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
        self, vmid: int, mode: str = "security", snapshot: bool = True, planned: list[str] | None = None
    ) -> dict:
        g = await self.update_plan(vmid, mode)
        if planned is None:
            planned = await self.to_install(g, mode)
        if not planned:  # no snapshot, no apt run: nothing would change
            self.audit.write("apply_updates_nothing", vmid=vmid, mode=mode)
            return {"vmid": vmid, "name": g.name, "ok": True, "nothing_to_install": True, "snapshot": None}
        snap = await self._snapshot(g, f"before {mode} updates") if snapshot else None
        before = await self.services(g)
        log = self.runs_dir / f"{datetime.now(UTC):%Y%m%d_%H%M%S}_{vmid}_{g.name}_{mode}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        pending = {"mode": mode, "snapshot": snap, "services_before": before, "log": str(log), "planned": planned}
        self._pending_file(vmid).parent.mkdir(parents=True, exist_ok=True)
        self._pending_file(vmid).write_text(json.dumps(pending))
        self.audit.write("apply_updates_start", vmid=vmid, mode=mode, snapshot=snap, log=str(log))
        return await self._finish_update(g, pending, f"upgrade-{mode}", "a")

    async def update_result(self, vmid: int) -> dict:
        """Wait for an update that was still running when apply_updates returned, and report it."""
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        f = self._pending_file(vmid)
        if not f.exists():
            raise InvalidRequestError(f"no pvewarden update is running on guest {vmid}; nothing to wait for")
        return await self._finish_update(g, json.loads(f.read_text()), "upgrade-follow", "w")

    def _pending_file(self, vmid: int) -> Path:
        return self.pending_dir / f"{vmid}.json"

    async def _finish_update(self, g: Guest, pending: dict, command: str, log_mode: str) -> dict:
        log = Path(pending["log"])
        base = {
            "vmid": g.vmid,
            "name": g.name,
            "snapshot": pending["snapshot"],
            "planned": pending.get("planned"),
            "log": str(log),
        }
        try:
            rc, out = await self.run(g, command, log=log, log_mode=log_mode)
        except GuestTimeoutError:
            self.audit.write("apply_updates_waiting", vmid=g.vmid)
            return base | {
                "ok": None,
                "still_running": True,
                "hint": "The update keeps running on the guest. Call update_result to wait for it and get "
                "the result. Do not reboot or roll back the guest meanwhile.",
            }
        if command == "upgrade-follow" and ("command not allowed" in out or rc == 4):
            self._pending_file(g.vmid).unlink(missing_ok=True)
            raise GuestError(
                f"guest {g.vmid} ({g.name}) cannot report the update's result (its pvewarden client is older or "
                "the result is gone). Check it with check_updates; re-enrolling updates the client."
            )
        if rc == 75 and "already running" in out:
            self._pending_file(g.vmid).unlink(missing_ok=True)
            raise GuestError(f"an update is already running on guest {g.vmid} ({g.name}); nothing new was started")
        self._pending_file(g.vmid).unlink(missing_ok=True)
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

    async def rollback_plan(self, vmid: int, snapshot: str) -> dict:
        """Check a rollback is allowed and the snapshot exists, without changing anything."""
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        if not snapshot.startswith(SNAPSHOT_PREFIX):
            raise PolicyError("only snapshots created by pvewarden can be rolled back")
        self._unlocked(g)
        self._no_update_running(g)
        found = next((s for s in await self.list_snapshots(vmid) if s["name"] == snapshot), None)
        if found is None:
            raise NotFoundError(f"guest {vmid} has no snapshot {snapshot!r}")
        return {"vmid": vmid, "name": g.name, **{k: found[k] for k in ("description", "created")}, "snapshot": snapshot}

    async def rollback(self, vmid: int, snapshot: str, wait_s: int = 300, interval: float = 5) -> dict:
        await self.rollback_plan(vmid, snapshot)
        g = await self.guest(vmid)
        pve = self.require_proxmox()
        await pve.rollback(g, snapshot)
        started = False
        if await pve.status(g) != "running":
            await pve.start(g)
            started = True
        self.audit.write("rollback", vmid=vmid, snapshot=snapshot)
        res = {"vmid": vmid, "name": g.name, "rolled_back_to": snapshot, "started_after_rollback": started}
        if started:  # like a reboot: report once the guest answers again, not while it still boots
            res |= await self._wait_online(g, wait_s, interval, check_first=True)
        return res

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
        deleted = []
        for item in await self.old_snapshots(older_than_days, vmid):
            await pve.delete_snapshot(guests[item["vmid"]], item["snapshot"])
            deleted.append({"vmid": item["vmid"], "snapshot": item["snapshot"]})
        self.audit.write("delete_old_snapshots", older_than_days=older_than_days, deleted=deleted)
        return deleted


def replace_lock(g: Guest, lock: str) -> Guest:
    return dataclasses.replace(g, lock=lock)
