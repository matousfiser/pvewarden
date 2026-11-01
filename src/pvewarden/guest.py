"""Talking to guests: SSH to the restricted pvewarden account and parsing its output.

The guest side (guest/pvewarden-gate) accepts exactly the commands in COMMANDS; anything else is
refused there. The check here only catches programming errors early.
"""

import asyncio
import codecs
import contextlib
import re
from pathlib import Path

from pvewarden.config import SSHConfig
from pvewarden.errors import GuestError, GuestTimeoutError

COMMANDS = frozenset({"check", "status", "services", "upgrade-security", "upgrade-all", "upgrade-follow"})


class GuestRunner:
    # A compromised guest controls its output: more than this is refused (memory and run logs).
    # A full apt run with many packages stays far below it.
    max_output = 16 * 2**20

    def __init__(self, cfg: SSHConfig, known_hosts: Path):
        self.cfg = cfg
        self.known_hosts = known_hosts
        self._slots = asyncio.Semaphore(cfg.parallel)

    def ssh_args(self, address: str, command: str, key: Path, alias: str | None = None) -> list[str]:
        """alias: the name the guest's host key is remembered under (one per VMID, not per address)."""
        return [
            "ssh",
            "-i", str(key),
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.cfg.connect_timeout}",
            "-o", "LogLevel=ERROR",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "StrictHostKeyChecking=accept-new",
            *(["-o", f"HostKeyAlias={alias}"] if alias else []),
            f"{self.cfg.user}@{address}",
            command,
        ]  # fmt: skip

    async def run(
        self,
        address: str,
        command: str,
        timeout: int = 1800,
        log: Path | None = None,
        log_mode: str = "a",
        *,
        key: Path,
        alias: str | None = None,
    ) -> tuple[int, str]:
        """Run an allowed command; stream output into `log` as it arrives if given.

        On timeout only the local SSH client is stopped. Updates run detached on the guest and go on."""
        if command not in COMMANDS:
            raise ValueError(f"unknown guest command {command!r}")
        async with self._slots:
            proc = await asyncio.create_subprocess_exec(
                *self.ssh_args(address, command, key, alias),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            chunks: list[str] = []
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

            async def pump() -> None:
                received = 0
                with open(log, log_mode) if log else contextlib.nullcontext() as f:
                    # in blocks, not lines: a guest that sends one endless line must not break this
                    while block := await proc.stdout.read(65536):
                        received += len(block)
                        if received > self.max_output:
                            raise GuestError(
                                f"{command} on {address}: the guest sent more than "
                                f"{self.max_output // 2**20} MiB of output; stopped reading"
                            )
                        text = decoder.decode(block)
                        chunks.append(text)
                        if f:
                            f.write(text)
                            f.flush()
                    chunks.append(decoder.decode(b"", final=True))
                await proc.wait()

            try:
                await asyncio.wait_for(pump(), timeout)
            except TimeoutError:
                await stop(proc)
                raise GuestTimeoutError(f"{command} on {address}: no result after {timeout}s") from None
            except BaseException:
                await stop(proc)
                raise
        return proc.returncode, "".join(chunks)


async def stop(proc: asyncio.subprocess.Process) -> None:
    """Stop the local ssh client (never the update on the guest) and reap it."""
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(proc.wait(), 5)


# --- output parsers -------------------------------------------------------------------------

OFFICIAL_ORIGINS = ("Ubuntu", "Debian")


def parse_upgradable(text: str) -> list[dict]:
    """Parse `check`: name, installed, candidate, origin:archive[,...], held (tab separated)."""
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        name, old, new, origins, held = parts
        origins = [o for o in origins.split(",") if o]
        official = any(o.split(":")[0].startswith(OFFICIAL_ORIGINS) for o in origins)
        pkgs.append(
            {
                "name": name,
                "from": old,
                "to": new,
                "official": official,
                "security": official and any(o.split(":", 1)[-1].endswith("-security") for o in origins),
                "origin": origins,
                "held": held == "held",
            }
        )
    return pkgs


def parse_status(text: str) -> dict:
    """Parse `status`: key=value lines; reboot_pkg may repeat."""
    st: dict = {"reboot_pkgs": []}
    for line in text.splitlines():
        key, sep, val = line.partition("=")
        if not sep:
            continue
        if key == "reboot_pkg":
            if val not in st["reboot_pkgs"]:
                st["reboot_pkgs"].append(val)
        else:
            st[key] = val
    st["reboot_required"] = st.get("reboot_required") == "yes"
    # None: an older guest client that does not report it
    st["auto_updates"] = {"yes": True, "no": False}.get(st.get("auto_updates", ""))
    return st


def parse_services(text: str) -> dict:
    """Parse `services`: system=<state> and failed=<unit> lines."""
    res: dict = {"system": None, "failed": []}
    for line in text.splitlines():
        key, sep, val = line.partition("=")
        if key == "failed" and sep:
            res["failed"].append(val)
        elif key == "system" and sep:
            res["system"] = val
    return res


NOISE_RE = re.compile(r"^\s*$|^\(Reading database \.\.\.|^pvewarden-run: ")


def clean_tail(text: str, lines: int = 60) -> str:
    """Last N meaningful lines of apt/dpkg output, without progress noise."""
    kept = [line for line in text.splitlines() if not NOISE_RE.match(line)]
    return "\n".join(kept[-lines:])
