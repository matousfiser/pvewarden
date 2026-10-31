"""The real guest client in a container: install.sh, sshd forced command, sudoers, apt.

Run with: pytest -m integration   (needs Docker and network access for apt)
"""

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from pvewarden.config import SSHConfig
from pvewarden.errors import GuestTimeoutError
from pvewarden.guest import GuestRunner, parse_services, parse_status, parse_upgradable

pytestmark = pytest.mark.integration
ROOT = Path(__file__).parent.parent.parent


def sh(*args, check=True, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=check, **kwargs)


@pytest.fixture(scope="module", params=["ubuntu:24.04", "ubuntu:22.04", "debian:12", "debian:13"])
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
    assert st["os"].split()[0] == guest["image"].split(":")[0].capitalize() and "kernel" in st


async def test_status_reports_auto_updates(guest):
    rc, out = await guest["runner"].run(guest["address"], "status", timeout=60)
    assert rc == 0, out
    assert parse_status(out)["auto_updates"] in (True, False), out


async def test_services_runs_without_root(guest):
    rc, out = await guest["runner"].run(guest["address"], "services", timeout=60)
    assert rc == 0, out
    assert "system" in parse_services(out)  # no systemd in the container: state is empty, but no error


async def test_check_lists_packages_in_the_expected_format(guest):
    rc, out = await guest["runner"].run(guest["address"], "check", timeout=300)
    assert rc == 0, out
    pkgs = parse_upgradable(out)
    assert bool(pkgs) == bool(out.strip())  # every line parsed
    assert all(p["official"] for p in pkgs)  # base image has only the distribution repositories


@pytest.mark.parametrize("command", ["id", "check; id", "bash -i", "cat /etc/shadow", "sudo -l"])
def test_anything_else_is_refused(guest, command):
    r = raw_ssh(guest, command)
    assert r.returncode == 1 and "not allowed" in r.stderr
    assert "uid=" not in r.stdout and "root:" not in r.stdout


def test_no_shell_no_tunnel(guest):
    assert "not allowed" in raw_ssh(guest, options=["-T"]).stderr
    assert raw_ssh(guest, options=["-W", "127.0.0.1:22"]).returncode != 0


def test_sudo_allows_only_the_five_commands(guest):
    r = sh("docker", "exec", "-u", "pvewarden", guest["name"], "sudo", "-n", "id", check=False)
    assert r.returncode != 0
    r = sh("docker", "exec", "-u", "pvewarden", guest["name"], "sudo", "-n", "-l", check=False)
    allowed = [line.strip() for line in r.stdout.splitlines() if "pvewarden-guest" in line]
    assert len(allowed) == 1 and allowed[0].count("/usr/local/sbin/pvewarden-guest") == 5


# A third-party repository that names its suite after the distribution, like Docker's does.
THIRD_PARTY_REPO = r"""
set -e
. /etc/os-release
mkdir -p /srv/repo
for v in 1.0 2.0; do
  d=$(mktemp -d); mkdir "$d/DEBIAN"
  printf 'Package: pvewarden-dummy\nVersion: %s\nArchitecture: all\nMaintainer: t <t@example.com>\nDescription: d\n' "$v" > "$d/DEBIAN/control"
  dpkg-deb -b "$d" "/srv/repo/pvewarden-dummy_${v}_all.deb" >/dev/null
done
cd /srv/repo
apt-ftparchive packages . > Packages
apt-ftparchive -o APT::FTPArchive::Release::Origin=Thirdparty -o APT::FTPArchive::Release::Label=Thirdparty \
  -o APT::FTPArchive::Release::Suite="$VERSION_CODENAME" -o APT::FTPArchive::Release::Codename="$VERSION_CODENAME" \
  release . > Release
echo "deb [trusted=yes] file:/srv/repo ./" > /etc/apt/sources.list.d/thirdparty.list
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pvewarden-dummy=1.0 >/dev/null
"""


async def test_upgrade_all_never_installs_third_party_packages(guest):
    setup = sh("docker", "exec", guest["name"], "bash", "-c", THIRD_PARTY_REPO, check=False, timeout=300)
    assert setup.returncode == 0, setup.stderr

    rc, out = await guest["runner"].run(guest["address"], "check", timeout=300)
    dummy = {p["name"]: p for p in parse_upgradable(out)}["pvewarden-dummy"]
    assert (dummy["from"], dummy["to"], dummy["official"]) == ("1.0", "2.0", False)

    rc, out = await guest["runner"].run(guest["address"], "upgrade-all", timeout=900)
    assert rc == 0, out[-2000:]
    installed = sh("docker", "exec", guest["name"], "dpkg-query", "-W", "-f=${Version}", "pvewarden-dummy").stdout
    assert installed == "1.0"

    rc, out = await guest["runner"].run(guest["address"], "check", timeout=300)
    official_left = [p["name"] for p in parse_upgradable(out) if p["official"]]
    assert official_left == [], f"official updates not installed: {official_left}"


# An update must survive the SSH connection: dpkg cut off halfway can leave the guest broken.
SLOW_UPGRADE = r"""
set -e
cp /usr/local/sbin/pvewarden-guest /root/pvewarden-guest.orig
# make the real work slow, keep everything else as it is
sed -i 's|^  now-upgrade-security)$|  now-upgrade-security)\n    echo started; sleep 6; echo finished-slowly|' /usr/local/sbin/pvewarden-guest
"""


async def test_update_goes_on_when_the_connection_drops_and_can_be_followed(guest):
    setup = sh("docker", "exec", guest["name"], "bash", "-c", SLOW_UPGRADE, check=False)
    assert setup.returncode == 0, setup.stderr
    try:
        with pytest.raises(GuestTimeoutError):
            await guest["runner"].run(guest["address"], "upgrade-security", timeout=2)  # SSH client killed

        # still running on the guest: a second update is refused, following it waits for the end
        rc, out = await guest["runner"].run(guest["address"], "upgrade-security", timeout=60)
        assert rc == 75 and "already running" in out
        rc, out = await guest["runner"].run(guest["address"], "upgrade-follow", timeout=300)
        assert rc == 0, out[-2000:]
        assert out.startswith("started") and "finished-slowly" in out

        # afterwards follow reports the finished run again
        rc, again = await guest["runner"].run(guest["address"], "upgrade-follow", timeout=60)
        assert rc == 0 and "finished-slowly" in again
    finally:
        sh("docker", "exec", guest["name"], "cp", "/root/pvewarden-guest.orig", "/usr/local/sbin/pvewarden-guest")


# must stay last: it removes the client from the shared container
def test_reinstall_is_idempotent_and_uninstall_cleans_up(guest):
    key = (guest["key"].with_suffix(".pub")).read_text().strip()
    gw = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", guest["name"]).stdout
    r = sh(
        "docker", "exec", guest["name"], "/opt/pvewarden-guest/install.sh", "--auto-updates=off", key, gw.strip(),
        check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert "automatic updates: off" in r.stdout
    status = raw_ssh(guest, "status")
    assert status.returncode == 0 and "auto_updates=no" in status.stdout

    r = sh("docker", "exec", guest["name"], "/opt/pvewarden-guest/install.sh", "--uninstall", check=False)
    assert r.returncode == 0, r.stderr
    assert raw_ssh(guest, "status").returncode == 255  # key no longer accepted
    leftovers = sh(
        "docker", "exec", guest["name"], "sh", "-c",
        "id pvewarden; ls -d /usr/local/sbin/pvewarden-* /etc/sudoers.d/pvewarden /etc/apt/apt.conf.d/52pvewarden* /var/lib/pvewarden",
        check=False,
    )  # fmt: skip
    assert leftovers.stdout.strip() == ""
