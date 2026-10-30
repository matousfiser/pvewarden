"""Shared fakes: an in-memory Proxmox and a scripted guest runner."""

from dataclasses import replace
from pathlib import Path

import pytest

from pvewarden.app import App
from pvewarden.config import ProxmoxConfig, parse
from pvewarden.errors import ProxmoxError
from pvewarden.proxmox import Guest

UPD = "pvewarden-update"
RBT = "pvewarden-reboot"

CHECK_OUT = (
    "openssl\t3.0.13-0ubuntu3.4\t3.0.13-0ubuntu3.5\tUbuntu:noble-security,Ubuntu:noble-updates\t-\n"
    "vim\t2:9.1.0016-1ubuntu7.3\t2:9.1.0016-1ubuntu7.4\tUbuntu:noble-updates\t-\n"
    "docker-ce\t5:29.9.1-1\t5:29.9.2-1\tDocker:noble\t-\n"
)
STATUS_OUT = "os=Ubuntu 24.04.1 LTS\nkernel=6.8.0-1-generic\nuptime_s=100.0\nreboot_required=no\n"
SERVICES_OUT = "system=running\n"


class FakeRunner:
    """Replaces GuestRunner: returns scripted (rc, output) per command, records every call."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.responses: dict[str, tuple[int, str]] = {
            "check": (0, CHECK_OUT),
            "status": (0, STATUS_OUT),
            "services": (0, SERVICES_OUT),
            "upgrade-security": (0, "All upgrades installed\n"),
            "upgrade-all": (0, "All upgrades installed\n"),
        }

    async def run(self, address, command, timeout=1800, log: Path | None = None):
        self.calls.append((address, command))
        resp = self.responses[command]
        rc, out = resp(address) if callable(resp) else resp
        if log:
            log.write_text(out)
        return rc, out

    def commands(self) -> list[str]:
        return [c for _, c in self.calls]


class FakeProxmox:
    """Replaces ProxmoxClient with in-memory guests and snapshots."""

    def __init__(self, guests: list[Guest]):
        self.cfg = ProxmoxConfig(host="pve.test", token_id="pvewarden@pve!t", token_secret="s", verify_tls="/ca.pem")
        self.pve_version = "9.0.10"
        self.privs: dict[str, set[str]] = {}
        self._guests = {g.vmid: g for g in guests}
        self.ips: dict[int, list[str]] = {}
        self.snaps: dict[int, list[dict]] = {g.vmid: [] for g in guests}
        self.events: list[tuple] = []
        self.fail_snapshot = False

    async def version(self):
        return self.pve_version

    async def permissions(self, path=None):
        if path:
            return {path: self.privs.get(path, set())}
        return dict(self.privs)

    async def guests(self):
        return list(self._guests.values())

    async def guest_ips(self, g):
        if g.vmid not in self.ips:
            raise ProxmoxError("guest agent not running")
        return self.ips[g.vmid]

    async def snapshots(self, g):
        return list(self.snaps[g.vmid])

    async def create_snapshot(self, g, name, description):
        if self.fail_snapshot:
            raise ProxmoxError("snapshot feature is not available")
        self.snaps[g.vmid].append({"name": name, "description": description, "snaptime": 2_000_000_000})
        self.events.append(("snapshot", g.vmid, name))

    async def delete_snapshot(self, g, name):
        self.snaps[g.vmid] = [s for s in self.snaps[g.vmid] if s["name"] != name]
        self.events.append(("delete", g.vmid, name))

    async def rollback(self, g, name):
        self._guests[g.vmid] = replace(self._guests[g.vmid], status="stopped")
        self.events.append(("rollback", g.vmid, name))

    async def status(self, g):
        return self._guests[g.vmid].status

    async def reboot(self, g):
        self.events.append(("reboot", g.vmid))

    async def start(self, g):
        self._guests[g.vmid] = replace(self._guests[g.vmid], status="running")
        self.events.append(("start", g.vmid))


def make_config(tmp_path: Path, **extra) -> dict:
    return {
        "state_dir": str(tmp_path / "state"),
        "proxmox": {"host": "pve.test", "token_id": "pvewarden@pve!t", "token_secret": "s3cret"},
        "ssh": {"key": str(tmp_path / "id_ed25519"), "subnets": ["192.0.2.0/24"]},
        **extra,
    }


GUESTS = [
    Guest(101, "web", "lxc", "pve1", "running", (UPD, RBT)),
    Guest(102, "db", "qemu", "pve1", "running", (UPD,)),
    Guest(103, "readonly", "qemu", "pve1", "running", ()),
    Guest(104, "off", "lxc", "pve1", "stopped", (UPD,)),
]


@pytest.fixture
def app(tmp_path):
    a = App(parse(make_config(tmp_path)))
    a.pve = FakeProxmox(GUESTS)
    a.pve.ips = {101: ["127.0.0.1", "192.0.2.11"], 102: ["192.0.2.12"], 103: ["192.0.2.13"], 104: ["192.0.2.14"]}
    a.runner = FakeRunner()
    return a
