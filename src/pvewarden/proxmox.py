"""Minimal async client for the Proxmox VE API, limited to what pvewarden needs."""

import asyncio
import re
import ssl
from dataclasses import dataclass

import httpx

from pvewarden.config import ProxmoxConfig
from pvewarden.errors import ProxmoxError


@dataclass(frozen=True)
class Guest:
    vmid: int
    name: str
    type: str  # "qemu" or "lxc"
    node: str | None
    status: str
    tags: tuple[str, ...]

    @property
    def api_path(self) -> str:
        return f"/nodes/{self.node}/{self.type}/{self.vmid}"


def split_tags(raw: str) -> tuple[str, ...]:
    return tuple(t for t in re.split(r"[;, ]+", raw or "") if t)


class ProxmoxClient:
    def __init__(self, cfg: ProxmoxConfig):
        self.cfg = cfg
        verify = cfg.verify_tls
        if isinstance(verify, str):
            verify = ssl.create_default_context(cafile=verify)
            # Python 3.13 enables strict X.509 checks by default; the Proxmox root CA has no key usage
            # extension and fails them. The CA is pinned to this one file, so the relaxed check is safe.
            verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
        self._verify = verify

    async def request(self, method: str, path: str, /, **params):
        async with httpx.AsyncClient(
            base_url=f"https://{self.cfg.host}:{self.cfg.port}/api2/json",
            headers={"Authorization": f"PVEAPIToken={self.cfg.token_id}={self.cfg.token_secret}"},
            verify=self._verify,
            timeout=30,
        ) as client:
            try:
                if method == "GET":
                    r = await client.get(path, params=params)
                else:
                    r = await client.request(method, path, data=params)
            except httpx.HTTPError as e:
                raise ProxmoxError(f"{method} {path}: {e}") from e
        if r.status_code >= 400:
            raise ProxmoxError(f"{method} {path}: HTTP {r.status_code} {r.reason_phrase} {r.text[:300]}")
        return r.json()["data"]

    async def wait_task(self, node: str, upid: str, timeout: int = 900, interval: float = 2) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            st = await self.request("GET", f"/nodes/{node}/tasks/{upid}/status")
            if st["status"] == "stopped":
                if st.get("exitstatus") != "OK":
                    raise ProxmoxError(f"task {upid} failed: {st.get('exitstatus')}")
                return
            await asyncio.sleep(interval)
        raise ProxmoxError(f"task {upid} timed out after {timeout}s")

    async def version(self) -> str:
        return (await self.request("GET", "/version"))["version"]

    async def permissions(self, path: str | None = None) -> dict[str, set[str]]:
        """Effective privileges of this token: for one path (inherited ones included) or per ACL path."""
        data = await self.request("GET", "/access/permissions", **({"path": path} if path else {}))
        # a listed privilege is granted; its value is only the ACL's propagate flag (0 when inherited from a pool)
        return {path: set(privs) for path, privs in data.items()}

    async def guests(self) -> list[Guest]:
        out = []
        for r in await self.request("GET", "/cluster/resources", type="vm"):
            if r.get("template"):
                continue
            out.append(
                Guest(
                    vmid=r["vmid"],
                    name=r.get("name", str(r["vmid"])),
                    type=r["type"],
                    node=r["node"],
                    status=r["status"],
                    tags=split_tags(r.get("tags", "")),
                )
            )
        return out

    async def guest_ips(self, guest: Guest) -> list[str]:
        """IPv4 addresses reported by the qemu guest agent or the LXC interface list."""
        if guest.type == "qemu":
            data = await self.request("GET", f"{guest.api_path}/agent/network-get-interfaces")
            return [
                a["ip-address"]
                for iface in data["result"]
                for a in iface.get("ip-addresses", [])
                if a.get("ip-address-type") == "ipv4"
            ]
        return [
            i["inet"].split("/")[0] for i in await self.request("GET", f"{guest.api_path}/interfaces") if i.get("inet")
        ]

    async def snapshots(self, guest: Guest) -> list[dict]:
        return [s for s in await self.request("GET", f"{guest.api_path}/snapshot") if s["name"] != "current"]

    async def create_snapshot(self, guest: Guest, name: str, description: str) -> None:
        upid = await self.request("POST", f"{guest.api_path}/snapshot", snapname=name, description=description)
        await self.wait_task(guest.node, upid)

    async def delete_snapshot(self, guest: Guest, name: str) -> None:
        await self.wait_task(guest.node, await self.request("DELETE", f"{guest.api_path}/snapshot/{name}"))

    async def rollback(self, guest: Guest, name: str) -> None:
        upid = await self.request("POST", f"{guest.api_path}/snapshot/{name}/rollback")
        await self.wait_task(guest.node, upid)

    async def status(self, guest: Guest) -> str:
        return (await self.request("GET", f"{guest.api_path}/status/current"))["status"]

    async def reboot(self, guest: Guest) -> None:
        await self.wait_task(guest.node, await self.request("POST", f"{guest.api_path}/status/reboot"), 600)

    async def start(self, guest: Guest) -> None:
        await self.wait_task(guest.node, await self.request("POST", f"{guest.api_path}/status/start"), 600)
