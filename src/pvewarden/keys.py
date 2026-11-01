"""One SSH client key per guest (VMID).

A guest's authorized_keys holds only the public half of its own key, so a connection made for VMID A
can never log in to guest B, whatever address the guests report. Keys live in state_dir/keys:

    <vmid>, <vmid>.pub          the active key the server uses for that guest
    <vmid>.new, <vmid>.new.pub  a key being enrolled: made by `new`, tried by `verify`, made active
                                by `activate` (an atomic rename) once the guest accepts only it

If enrolling stops halfway, the guest and the server disagree and the server refuses the guest
until it is enrolled again. It never falls back to another key.
"""

import os
import re
import socket
import subprocess
from pathlib import Path


class KeyStoreError(Exception):
    pass


class KeyStore:
    def __init__(self, path: Path):
        self.path = path

    def _file(self, vmid: int, suffix: str = "") -> Path:
        return self.path / f"{int(vmid)}{suffix}"

    def active(self, vmid: int) -> Path | None:
        f = self._file(vmid)
        return f if f.exists() else None

    def pending(self, vmid: int) -> Path | None:
        f = self._file(vmid, ".new")
        return f if f.exists() else None

    def vmids(self) -> list[int]:
        if not self.path.is_dir():
            return []
        return sorted(int(f.name) for f in self.path.iterdir() if re.fullmatch(r"\d+", f.name))

    def new(self, vmid: int) -> str:
        """Make a new key for the guest (replacing an unfinished one) and return its public half."""
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = self._file(vmid, ".new")
        for f in (key, key.with_name(key.name + ".pub")):
            f.unlink(missing_ok=True)
        comment = f"pvewarden-vmid-{int(vmid)}@{socket.gethostname()}"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key)],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        return key.with_name(key.name + ".pub").read_text().strip()

    def activate(self, vmid: int) -> None:
        """Make the enrolled key the guest's key. The rename of the private key is the switch."""
        key = self.pending(vmid)
        if key is None:
            raise KeyStoreError(f"guest {vmid} has no new key to activate (run: pvewarden key new {vmid})")
        pub = key.with_name(key.name + ".pub")
        if pub.exists():
            os.replace(pub, self._file(vmid, ".pub"))
        os.replace(key, self._file(vmid))

    def remove(self, vmid: int) -> None:
        for suffix in ("", ".pub", ".new", ".new.pub"):
            self._file(vmid, suffix).unlink(missing_ok=True)
