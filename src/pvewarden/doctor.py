"""`pvewarden doctor`: check a setup end to end and explain what is wrong."""

import asyncio
import os
import socket
import ssl
import stat
import tempfile
from dataclasses import dataclass

from pvewarden.app import App
from pvewarden.errors import ProxmoxError

REQUIRED_PRIVS = {"VM.Audit", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.PowerMgmt"}
# reading guest IPs from the qemu guest agent: VM.Monitor up to PVE 8, VM.GuestAgent.Audit from PVE 9
AGENT_PRIVS = {"VM.Monitor", "VM.GuestAgent.Audit"}
# more than pvewarden needs: worth a warning
DANGEROUS_PRIVS = {
    "Sys.Modify",
    "Sys.Console",
    "Permissions.Modify",
    "Realm.Allocate",
    "User.Modify",
    "VM.Allocate",
    "VM.Config.Disk",
    "VM.Config.Options",
    "VM.Console",
    "VM.GuestAgent.Unrestricted",
    "Datastore.Allocate",
}


@dataclass
class Result:
    status: str  # ok | warn | fail
    title: str
    detail: str = ""
    hint: str = ""


def ok(title, detail=""):
    return Result("ok", title, detail)


def warn(title, detail="", hint=""):
    return Result("warn", title, detail, hint)


def fail(title, detail="", hint=""):
    return Result("fail", title, detail, hint)


def check_local(app: App) -> list[Result]:
    cfg = app.cfg
    out = []
    try:
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cfg.state_dir):
            pass
        out.append(ok("State directory", str(cfg.state_dir)))
    except OSError as e:
        out.append(fail("State directory", str(e), "it must be writable by the user running pvewarden"))

    key = cfg.ssh.key
    if not key.exists():
        out.append(fail("SSH key", f"{key} does not exist", "generate it: ssh-keygen -t ed25519 -N '' -f " + str(key)))
    elif not os.access(key, os.R_OK):
        out.append(fail("SSH key", f"{key} is not readable", "run doctor as the pvewarden service user"))
    elif key.stat().st_mode & stat.S_IWOTH or key.stat().st_mode & stat.S_IROTH:
        out.append(fail("SSH key", f"{key} is readable or writable by everyone", f"chmod 0640 {key}"))
    else:
        out.append(ok("SSH key", str(key)))

    if cfg.http:
        h = cfg.http
        detail = f"{h.scheme}://{h.listen}:{h.port}/mcp, {len(h.clients)} client token(s)"
        if not h.clients:
            out.append(fail("HTTP", detail, "add a token to [http.clients]"))
        else:
            out.append(ok("HTTP", detail))
        for f in (h.tls_cert, h.tls_key):
            if f and not os.access(f, os.R_OK):
                out.append(fail("TLS", f"{f} is missing or not readable"))
        try:
            with socket.socket(socket.AF_INET6 if ":" in h.listen else socket.AF_INET) as sock:
                sock.bind((h.listen, 0))
        except OSError:
            out.append(
                warn(
                    "Listen address",
                    f"{h.listen} is not an address of this machine",
                    "is the VPN interface up? the server cannot start until the address exists",
                )
            )
    return out


def explain_proxmox_error(e: Exception) -> str:
    text = str(e)
    cause = e.__cause__
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            return (
                "TLS verification failed: point verify_tls to the Proxmox CA (/etc/pve/pve-root-ca.pem) and use "
                "a host name that is in the certificate (map it in /etc/hosts if needed)"
            )
        cause = cause.__cause__ or cause.__context__
    if "CERTIFICATE_VERIFY_FAILED" in text or "hostname mismatch" in text.lower():
        return (
            "TLS verification failed: point verify_tls to the Proxmox CA (/etc/pve/pve-root-ca.pem) and use "
            "a host name that is in the certificate (map it in /etc/hosts if needed)"
        )
    if "401" in text:
        return "authentication failed: check token_id and token_secret"
    if "ConnectError" in text or "refused" in text or "timed out" in text.lower():
        return "cannot reach the API: check host, port 8006 and the network"
    return ""


async def check_proxmox(app: App) -> list[Result]:
    try:
        return await _check_proxmox(app)
    except ProxmoxError as e:
        return [fail("Proxmox API", str(e), explain_proxmox_error(e))]


async def _check_proxmox(app: App) -> list[Result]:
    pve = app.pve
    if pve is None:
        return [warn("Proxmox", "not configured: static inventory, no snapshots or reboots")]
    out = []
    target = f"{pve.cfg.host}:{pve.cfg.port}"
    tls = "TLS verified" if pve.cfg.verify_tls else "TLS NOT verified"
    try:
        version = await pve.version()
    except ProxmoxError as e:
        return [fail("Proxmox API", f"{target}: {e}", explain_proxmox_error(e))]
    if pve.cfg.verify_tls:
        out.append(ok("Proxmox API", f"Proxmox VE {version} at {target} ({tls})"))
    else:
        out.append(
            warn(
                "Proxmox API",
                f"Proxmox VE {version} at {target} ({tls})",
                "set verify_tls to a copy of /etc/pve/pve-root-ca.pem",
            )
        )

    guests = await pve.guests()
    if not guests:
        out.append(
            warn(
                "Guests",
                "the token sees no guests",
                "add guests to the pvewarden pool; check the role is granted on /pool/pvewarden",
            )
        )
        return out
    upd, rbt = app.cfg.policy.tag_update, app.cfg.policy.tag_reboot
    n_upd = sum(upd in g.tags for g in guests)
    n_rbt = sum(rbt in g.tags for g in guests)
    out.append(ok("Guests", f"{len(guests)} visible, {n_upd} tagged {upd}, {n_rbt} tagged {rbt}"))

    missing = {}
    for g in guests:
        privs = (await pve.permissions(f"/vms/{g.vmid}")).get(f"/vms/{g.vmid}", set())
        need = set(REQUIRED_PRIVS)
        lacking = need - privs
        if g.type == "qemu" and not privs & AGENT_PRIVS:
            lacking.add("VM.GuestAgent.Audit (PVE 9) / VM.Monitor (PVE 8)")
        if lacking:
            missing[g.vmid] = sorted(lacking)
    if missing:
        detail = "; ".join(f"{vmid}: {', '.join(p)}" for vmid, p in missing.items())
        out.append(fail("Token privileges", detail, "update the Warden role (see the installation docs)"))
    else:
        out.append(ok("Token privileges", "all required privileges present"))

    extra = set()
    for privs in (await pve.permissions()).values():
        extra |= privs & DANGEROUS_PRIVS
    if extra:
        out.append(
            warn(
                "Token scope",
                f"the token has more rights than pvewarden needs: {', '.join(sorted(extra))}",
                "use a dedicated role with only the required privileges, granted only on the pool",
            )
        )
    return out


def explain_ssh_error(text: str) -> str:
    if "Permission denied" in text:
        return "key not accepted: enroll the guest (pvewarden-enroll) and check FROM matches this server's address"
    if "Host key verification failed" in text or "REMOTE HOST IDENTIFICATION HAS CHANGED" in text:
        return "the guest's host key changed: if expected, remove its line from known_hosts in the state directory"
    if "timed out" in text or "No route" in text or "Connection refused" in text:
        return "cannot reach the guest over SSH: check its address, firewall and that sshd runs"
    if "Could not resolve" in text:
        return "no usable IP found and the guest name does not resolve: install the guest agent or set [addresses]"
    return ""


async def check_guests(app: App) -> list[Result]:
    try:
        guests = [g for g in (await app.guests()).values() if g.status in ("running", "unknown")]
    except ProxmoxError:
        return []

    async def one(g) -> Result:
        title = f"Guest {g.vmid} {g.name}"
        try:
            address = await app.address(g)
            rc, out = await app.run(g, "status", timeout=30)
        except Exception as e:
            return fail(title, str(e))
        if rc != 0:
            return fail(title, f"{address}: {out.strip()[-200:]}", explain_ssh_error(out))
        os_name = next((line[3:] for line in out.splitlines() if line.startswith("os=")), "?")
        d = app.describe(g)
        allowed = [name for name, on in (("update", d["may_update"]), ("reboot", d["may_reboot"])) if on]
        return ok(title, f"{address}, {os_name}, allowed: {', '.join(allowed) or 'read-only'}")

    return list(await asyncio.gather(*(one(g) for g in guests)))


async def run_checks(app: App) -> list[Result]:
    results = check_local(app)
    results += await check_proxmox(app)
    results += await check_guests(app)
    return results


MARK = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}


def render(results: list[Result]) -> str:
    width = max(len(r.title) for r in results)
    lines = []
    for r in results:
        lines.append(f"{MARK[r.status]} {r.title.ljust(width)}  {r.detail}")
        if r.hint:
            lines.append(f"       {' ' * width}  -> {r.hint}")
    return "\n".join(lines)
