"""Shell scripts, run against stub commands (pct, qm, pvesh, pveum, sudo, systemctl)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


def write_exe(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


# --- pvewarden-gate ------------------------------------------------------------------------


@pytest.fixture
def gate(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_exe(bin_dir / "sudo", 'echo "SUDO $*"\n')
    write_exe(
        bin_dir / "systemctl",
        'case "$1" in is-system-running) echo degraded;; list-units) echo "nginx.service loaded failed failed x";; esac\n',
    )

    def run(original_command):
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin"}
        if original_command is not None:
            env["SSH_ORIGINAL_COMMAND"] = original_command
        return subprocess.run(["bash", ROOT / "guest/pvewarden-gate"], env=env, capture_output=True, text=True)

    return run


@pytest.mark.parametrize("cmd", ["check", "status", "upgrade-security", "upgrade-all"])
def test_gate_allows_the_four_root_commands(gate, cmd):
    r = gate(cmd)
    assert r.returncode == 0
    assert r.stdout.strip() == f"SUDO -n /usr/local/sbin/pvewarden-guest {cmd}"


def test_gate_services_without_root(gate):
    r = gate("services")
    assert r.returncode == 0
    assert r.stdout.splitlines() == ["system=degraded", "failed=nginx.service"]


@pytest.mark.parametrize(
    "cmd",
    [None, "", "id", "check; id", "check && id", "check id", "check\nid", "$(id)", "upgrade-all --force", " check"],
)
def test_gate_refuses_everything_else(gate, cmd):
    r = gate(cmd)
    assert r.returncode == 1
    assert "not allowed" in r.stderr
    assert "SUDO" not in r.stdout


# --- install.sh (dry run only: a real install needs root) ------------------------------------


def run_install(*args):
    return subprocess.run(["bash", ROOT / "guest/install.sh", *args], capture_output=True, text=True)


def test_install_dry_run_shows_exact_changes():
    r = run_install("--dry-run", "ssh-ed25519 AAAATEST srv", "192.0.2.10")
    if r.returncode == 3:
        pytest.skip("test host is not a supported distribution")
    assert r.returncode == 0, r.stderr
    assert 'restrict,from="192.0.2.10",command="/usr/local/sbin/pvewarden-gate" ssh-ed25519 AAAATEST srv' in r.stdout
    assert "NOPASSWD: /usr/local/sbin/pvewarden-guest check, " in r.stdout
    assert all(line.startswith("would: ") for line in r.stdout.splitlines())
    assert "auto-upgrades" not in r.stdout  # keep (default) leaves the guest's setting alone


def test_install_dry_run_auto_updates_off():
    r = run_install("--dry-run", "--auto-updates=off", "ssh-ed25519 AAAATEST srv", "192.0.2.10")
    if r.returncode == 3:
        pytest.skip("test host is not a supported distribution")
    assert "would: write /etc/apt/apt.conf.d/52pvewarden-auto-upgrades: automatic updates off" in r.stdout
    assert run_install("--dry-run", "--auto-updates=maybe", "ssh-ed25519 A k", "192.0.2.10").returncode == 2


@pytest.mark.parametrize(
    "args, code",
    [
        (["--dry-run", "not-a-key", "192.0.2.10"], 1),
        (["--dry-run", "ssh-ed25519 AAAA"], 2),
        (["ssh-ed25519 AAAA k", "192.0.2.10"], 1),  # real run as non-root
    ],
)
def test_install_rejects_bad_input(args, code):
    if os.geteuid() == 0:
        pytest.skip("must not run as root")
    assert run_install(*args).returncode == code


# --- pvewarden-enroll ----------------------------------------------------------------------


@pytest.fixture
def enroll(tmp_path):
    """Run pvewarden-enroll with a stub install.sh and stub Proxmox commands."""
    proj = tmp_path / "proj"
    shutil.copytree(ROOT / "proxmox", proj / "proxmox")
    (proj / "guest").mkdir()
    write_exe(proj / "guest/install.sh", 'echo "INSTALL $*"\n')
    pve = tmp_path / "pve"
    for f in ("lxc/201.conf", "qemu-server/202.conf", "qemu-server/203.conf"):
        (pve / f).parent.mkdir(parents=True, exist_ok=True)
        (pve / f).touch()
    conf = tmp_path / "enroll.conf"
    conf.write_text('PUBKEY="ssh-ed25519 AAAATEST srv"\nFROM="192.0.2.10"\n')

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_exe(
        bin_dir / "pct",
        'case "$1" in status) echo "status: running";; exec) shift 3; "$@";; '
        'config) echo "tags: other;pvewarden-update";; set) echo "SET pct $*";; esac\n',
    )
    write_exe(
        bin_dir / "qm",
        """case "$1" in
  status) echo "status: running" ;;
  agent) [ "$2" = 203 ] && exit 1; exit 0 ;;
  guest) shift 2; while [ "$1" != "--" ]; do shift; done; shift
         out=$("$@" 2>/dev/null); rc=$?
         python3 -c 'import json,sys; print(json.dumps({"exited":1,"exitcode":int(sys.argv[1]),"out-data":sys.argv[2]+"\\n"}))' "$rc" "$out" ;;
  config) ;;
  set) echo "SET qm $*" ;;
esac
""",
    )
    write_exe(bin_dir / "pvesh", """echo '{"members":[{"vmid":201},{"vmid":202},{"storage":"local"}]}'\n""")
    write_exe(bin_dir / "pveum", 'echo "PVEUM $*"\n')

    def run(*args, **extra_env):
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "PVE_ETC": str(pve),
            "PVEWARDEN_ENROLL_CONF": str(conf),
            **extra_env,
        }
        return subprocess.run([proj / "proxmox/pvewarden-enroll", *args], env=env, capture_output=True, text=True)

    return run


def test_enroll_lxc_and_vm_with_pool_and_tags(enroll):
    r = enroll("--pool", "--tags", "pvewarden-update,pvewarden-reboot", "201", "202")
    assert r.returncode == 0, r.stderr
    assert r.stdout.count("INSTALL ssh-ed25519 AAAATEST srv 192.0.2.10") == 2
    assert "SET pct set 201 --tags other;pvewarden-reboot;pvewarden-update" in r.stdout  # merged, nothing lost
    assert "SET qm set 202 --tags pvewarden-reboot;pvewarden-update" in r.stdout
    assert r.stdout.rstrip().endswith("OK: 201 202")


def test_enroll_continues_after_failures(enroll):
    r = enroll("203", "999", "201")
    assert r.returncode == 1
    assert "qemu-guest-agent not responding" in r.stderr
    assert "VMID 999 not found" in r.stderr
    assert "FAILED: 203 999" in r.stdout
    assert "INSTALL" in r.stdout  # 201 still enrolled


def test_enroll_dry_run_changes_nothing(enroll):
    r = enroll("--dry-run", "--pool", "--tags", "pvewarden-reboot", "201")
    assert r.returncode == 0, r.stderr
    assert "INSTALL --dry-run ssh-ed25519 AAAATEST srv 192.0.2.10" in r.stdout
    assert "would: set tags" in r.stdout
    assert "SET " not in r.stdout and "PVEUM" not in r.stdout


def test_enroll_passes_auto_updates_only_when_changing_it(enroll):
    r = enroll("--auto-updates", "off", "201")
    assert "INSTALL --auto-updates=off ssh-ed25519 AAAATEST srv 192.0.2.10" in r.stdout
    r = enroll("--auto-updates", "keep", "201")
    assert "INSTALL ssh-ed25519 AAAATEST srv 192.0.2.10" in r.stdout  # older clients understand this
    assert enroll("--auto-updates", "maybe", "201").returncode == 2


def test_enroll_all_and_uninstall(enroll):
    r = enroll("--all")
    assert "=== 201" in r.stdout and "=== 202" in r.stdout and "local" not in r.stdout
    r = enroll("--uninstall", "201")
    assert "INSTALL --uninstall" in r.stdout


def test_enroll_usage(enroll):
    assert enroll().returncode == 2
    assert enroll("--bogus").returncode == 2


def test_enroll_shows_signs_of_life_during_a_slow_guest(enroll, tmp_path):
    write_exe(tmp_path / "proj/guest/install.sh", 'sleep 2.5; echo "INSTALL $*"\n')
    r = enroll("201", PVEWARDEN_TICK="1")
    assert r.returncode == 0, r.stderr
    assert "... still working (1s)" in r.stderr and "... still working (2s)" in r.stderr
