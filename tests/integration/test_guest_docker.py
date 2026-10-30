"""The real guest client in a container: install.sh, sshd forced command, sudoers, apt.

Run with: pytest -m integration   (needs Docker and network access for apt)
"""

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from pvewarden.config import SSHConfig
from pvewarden.guest import GuestRunner, parse_services, parse_status, parse_upgradable

pytestmark = pytest.mark.integration
ROOT = Path(__file__).parent.parent.parent


def sh(*args, check=True, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=check, **kwargs)


@pytest.fixture(scope="module", params=["ubuntu:24.04", "ubuntu:22.04"])
def guest(request, tmp_path_factory):
    if not shutil.which("docker") or sh("docker", "info", check=False).returncode != 0:
        pytest.skip("docker not available")
    image = request.param
    tag = f"pvewarden-test-guest:{image.replace(':', '-')}"
    ctx = tmp_path_factory.mktemp("ctx")
    shutil.copytree(ROOT / "guest", ctx / "guest")
    shutil.copy(Path(__file__).parent / "Dockerfile", ctx / "Dockerfile")
    sh("docker", "build", "-q", "--build-arg", f"IMAGE={image}", "-t", tag, str(ctx))

    name = f"pvewarden-test-{uuid.uuid4().hex[:8]}"
    sh("docker", "run", "-d", "--name", name, tag)
    try:
        fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}}{{end}}"
        address, gateway = sh("docker", "inspect", "-f", fmt, name).stdout.split()
        keydir = tmp_path_factory.mktemp("key")
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keydir / "id_ed25519"))
        pubkey = (keydir / "id_ed25519.pub").read_text().strip()
        # the host reaches the container from the bridge gateway address
        install = sh(
            "docker", "exec", name, "/opt/pvewarden-guest/install.sh", pubkey, gateway, check=False, timeout=600
        )
        assert install.returncode == 0, install.stdout + install.stderr
        runner = GuestRunner(SSHConfig(key=keydir / "id_ed25519", connect_timeout=5), keydir / "known_hosts")
        yield {"name": name, "address": address, "runner": runner, "key": keydir / "id_ed25519", "image": image}
    finally:
        sh("docker", "rm", "-f", name, check=False)


def raw_ssh(guest, command=None, options=()):
    return sh(
        "ssh", "-i", str(guest["key"]), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", *options, f"pvewarden@{guest['address']}",
        *([command] if command else []),
        check=False, timeout=60,
    )  # fmt: skip


async def test_status(guest):
    rc, out = await guest["runner"].run(guest["address"], "status", timeout=60)
    assert rc == 0, out
    st = parse_status(out)
    assert st["os"].startswith("Ubuntu") and "kernel" in st


async def test_services_runs_without_root(guest):
    rc, out = await guest["runner"].run(guest["address"], "services", timeout=60)
    assert rc == 0, out
    assert "system" in parse_services(out)  # no systemd in the container: state is empty, but no error


async def test_check_lists_packages_in_the_expected_format(guest):
    rc, out = await guest["runner"].run(guest["address"], "check", timeout=300)
    assert rc == 0, out
    pkgs = parse_upgradable(out)
    assert bool(pkgs) == bool(out.strip())  # every line parsed
    assert all(p["official"] for p in pkgs)  # base image has only Ubuntu repositories


@pytest.mark.parametrize("command", ["id", "check; id", "bash -i", "cat /etc/shadow", "sudo -l"])
def test_anything_else_is_refused(guest, command):
    r = raw_ssh(guest, command)
    assert r.returncode == 1 and "not allowed" in r.stderr
    assert "uid=" not in r.stdout and "root:" not in r.stdout


def test_no_shell_no_tunnel(guest):
    assert "not allowed" in raw_ssh(guest, options=["-T"]).stderr
    assert raw_ssh(guest, options=["-W", "127.0.0.1:22"]).returncode != 0


def test_sudo_allows_only_the_four_commands(guest):
    r = sh("docker", "exec", "-u", "pvewarden", guest["name"], "sudo", "-n", "id", check=False)
    assert r.returncode != 0
    r = sh("docker", "exec", "-u", "pvewarden", guest["name"], "sudo", "-n", "-l", check=False)
    allowed = [line.strip() for line in r.stdout.splitlines() if "pvewarden-guest" in line]
    assert len(allowed) == 1 and allowed[0].count("/usr/local/sbin/pvewarden-guest") == 4


def test_reinstall_is_idempotent_and_uninstall_cleans_up(guest):
    key = (guest["key"].with_suffix(".pub")).read_text().strip()
    gw = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", guest["name"]).stdout
    r = sh("docker", "exec", guest["name"], "/opt/pvewarden-guest/install.sh", key, gw.strip(), check=False)
    assert r.returncode == 0, r.stderr
    assert raw_ssh(guest, "status").returncode == 0

    r = sh("docker", "exec", guest["name"], "/opt/pvewarden-guest/install.sh", "--uninstall", check=False)
    assert r.returncode == 0, r.stderr
    assert raw_ssh(guest, "status").returncode == 255  # key no longer accepted
    leftovers = sh(
        "docker", "exec", guest["name"], "sh", "-c",
        "id pvewarden; ls /usr/local/sbin/pvewarden-* /etc/sudoers.d/pvewarden",
        check=False,
    )  # fmt: skip
    assert leftovers.stdout.strip() == ""
