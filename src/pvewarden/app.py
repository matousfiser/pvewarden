"""Operations behind the MCP tools: inventory, policy checks, snapshots, updates, reboots."""

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta

from pvewarden.audit import AuditLog
from pvewarden.config import Config
from pvewarden.errors import GuestError, InvalidRequestError, NotFoundError, PolicyError, ProxmoxError
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

        async def one(g: Guest) -> dict:
            res = {"vmid": g.vmid, "name": g.name, **{k: self.describe(g)[k] for k in ("may_update", "may_reboot")}}
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
        await pve.create_snapshot(g, name, description or "pvewarden")
        self.audit.write("snapshot", vmid=g.vmid, snapshot=name)
        return name

    async def snapshot(self, vmid: int, description: str = "") -> str:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        return await self._snapshot(g, description)

    async def apply_updates(self, vmid: int, mode: str = "security", snapshot: bool = True) -> dict:
        if mode not in MODES:
            raise InvalidRequestError(f"mode must be one of {MODES}")
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        self._running(g)
        snap = await self._snapshot(g, f"before {mode} updates") if snapshot else None
        before = await self.services(g)
        log = self.runs_dir / f"{datetime.now(UTC):%Y%m%d_%H%M%S}_{vmid}_{g.name}_{mode}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        self.audit.write("apply_updates_start", vmid=vmid, mode=mode, snapshot=snap, log=str(log))
        rc, out = await self.run(g, f"upgrade-{mode}", log=log)
        st = await self.status(g)
        after = await self.services(g)
        newly_failed = sorted(set(after["failed"]) - set(before["failed"])) if before and after else None
        self.audit.write(
            "apply_updates",
            vmid=vmid,
            mode=mode,
            snapshot=snap,
            rc=rc,
            reboot_required=st["reboot_required"],
            newly_failed_services=newly_failed,
        )
        return {
            "vmid": vmid,
            "name": g.name,
            "ok": rc == 0,
            "snapshot": snap,
            "reboot_required": st["reboot_required"],
            "reboot_pkgs": st["reboot_pkgs"],
            "services_after": after,
            "newly_failed_services": newly_failed,
            "log": str(log),
            "output_tail": clean_tail(out),
        }

    async def reboot(self, vmid: int, wait_s: int = 300, interval: float = 5) -> dict:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_reboot)
        await self.require_proxmox().reboot(g)
        self.audit.write("reboot", vmid=vmid)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while loop.time() < deadline:
            await asyncio.sleep(interval)
            try:
                return {"vmid": vmid, "name": g.name, "back_online": True, **await self.status(g)}
            except Exception:
                continue
        return {"vmid": vmid, "name": g.name, "back_online": False}

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

    async def rollback(self, vmid: int, snapshot: str) -> dict:
        g = await self.guest(vmid)
        self.require(g, self.cfg.policy.tag_update)
        if not snapshot.startswith(SNAPSHOT_PREFIX):
            raise PolicyError("only snapshots created by pvewarden can be rolled back")
        pve = self.require_proxmox()
        await pve.rollback(g, snapshot)
        started = False
        if await pve.status(g) != "running":
            await pve.start(g)
            started = True
        self.audit.write("rollback", vmid=vmid, snapshot=snapshot)
        return {"vmid": vmid, "name": g.name, "rolled_back_to": snapshot, "started_after_rollback": started}

    async def delete_old_snapshots(self, older_than_days: int = 7, vmid: int | None = None) -> list[dict]:
        pve = self.require_proxmox()
        if vmid is not None:
            g = await self.guest(vmid)
            self.require(g, self.cfg.policy.tag_update)
            targets = [g]
        else:
            targets = [g for g in (await self.guests()).values() if self.cfg.policy.tag_update in g.tags]
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        deleted = []
        for g in targets:
            for s in await pve.snapshots(g):
                taken = datetime.fromtimestamp(s.get("snaptime", 0), UTC)
                if s["name"].startswith(SNAPSHOT_PREFIX) and taken < cutoff:
                    await pve.delete_snapshot(g, s["name"])
                    deleted.append({"vmid": g.vmid, "snapshot": s["name"]})
        self.audit.write("delete_old_snapshots", older_than_days=older_than_days, deleted=deleted)
        return deleted
