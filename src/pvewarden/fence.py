"""Guards against two changes to one guest at a time, also across server restarts.

- A lock per VMID (flock on state_dir/locks/<vmid>.lock) is held for the whole of every change:
  snapshot, update, waiting for an update, reboot, rollback, snapshot deletion. A second change
  for the same guest is refused at once instead of interleaving. The lock is gone when the process
  ends, so it only covers changes this process is making.
- A pending update (state_dir/pending/<vmid>.json) is the fence that outlives the process: written
  before an update starts, it blocks every other change to the guest until the update's result is
  known. It carries a random run_id; only the run that wrote it may remove it. Writes are atomic.
"""

import contextlib
import fcntl
import json
import os
import secrets
import time
from pathlib import Path

from pvewarden.errors import GuestError


class Fence:
    def __init__(self, state_dir: Path):
        self.locks_dir = state_dir / "locks"
        self.pending_dir = state_dir / "pending"

    # --- the per-guest lock ------------------------------------------------------------------

    @contextlib.contextmanager
    def lock(self, vmid: int, name: str = ""):
        self.locks_dir.mkdir(parents=True, exist_ok=True)
        with open(self.locks_dir / f"{int(vmid)}.lock", "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                label = f"{vmid} ({name})" if name else str(vmid)
                raise GuestError(
                    f"another pvewarden operation on guest {label} is in progress; nothing was done. "
                    "Wait for it to finish (one change per guest at a time)."
                ) from None
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    # --- the pending update ------------------------------------------------------------------

    def _file(self, vmid: int) -> Path:
        return self.pending_dir / f"{int(vmid)}.json"

    def pending(self, vmid: int) -> dict | None:
        try:
            return json.loads(self._file(vmid).read_text())
        except FileNotFoundError:
            return None
        except ValueError:  # unreadable: treat as a fence that needs a human
            return {"run_id": None, "state": "unreadable"}

    def begin(self, vmid: int, **fields) -> dict:
        """Write a new pending update (state 'preparing'). Refuses if one exists."""
        if self._file(vmid).exists():
            raise GuestError(f"guest {vmid} already has a pvewarden update pending; call update_result first")
        p = {"run_id": secrets.token_hex(8), "state": "preparing", "created": time.time(), **fields}
        self._write(vmid, p)
        return p

    def update(self, vmid: int, pending: dict, **fields) -> dict:
        current = self.pending(vmid)
        if current is None or current.get("run_id") != pending["run_id"]:
            raise GuestError(f"the pending update of guest {vmid} changed underneath; nothing was done")
        p = pending | fields
        self._write(vmid, p)
        return p

    def finish(self, vmid: int, run_id: str | None) -> bool:
        """Remove the pending update, but only if it is still the one of run_id."""
        current = self.pending(vmid)
        if current is None or current.get("run_id") != run_id:
            return False
        self._file(vmid).unlink(missing_ok=True)
        self._sync_dir()
        return True

    def clear(self, vmid: int) -> dict | None:
        """For a human (pvewarden pending clear): remove whatever is pending."""
        current = self.pending(vmid)
        self._file(vmid).unlink(missing_ok=True)
        if self.pending_dir.is_dir():
            self._sync_dir()
        return current

    def vmids(self) -> list[int]:
        if not self.pending_dir.is_dir():
            return []
        return sorted(int(f.stem) for f in self.pending_dir.glob("*.json") if f.stem.isdigit())

    def _write(self, vmid: int, data: dict) -> None:
        if not self.pending_dir.is_dir():
            self.pending_dir.mkdir(parents=True, exist_ok=True)
            _fsync_dir(self.pending_dir.parent)  # the new directory's own entry
        tmp = self.pending_dir / f".{int(vmid)}.{secrets.token_hex(4)}.tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._file(vmid))
        self._sync_dir()

    def _sync_dir(self) -> None:
        """Flush a rename or unlink in pending/ to disk, so that on a file system that honours fsync
        the fence is still there (or still gone) after a power loss."""
        _fsync_dir(self.pending_dir)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
