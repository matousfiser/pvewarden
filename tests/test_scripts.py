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


@pytest.mark.parametrize("cmd", ["check", "status", "upgrade-security", "upgrade-all", "upgrade-follow"])
def test_gate_allows_the_root_commands(gate, cmd):
    r = gate(cmd)
    assert r.returncode == 0
    assert r.stdout.strip() == f"SUDO -n /usr/local/sbin/pvewarden-guest {cmd}"


def test_gate_services_without_root(gate):
    r = gate("services")
    assert r.returncode == 0
    assert r.stdout.splitlines() == ["system=degraded", "failed=nginx.service"]


@pytest.mark.parametrize(
    "cmd",
    [
        None,
        "",
        "id",
        "check; id",
        "check && id",
        "check id",
        "check\nid",
        "$(id)",
        "upgrade-all --force",
        " check",
        "run upgrade-all",
        "now-upgrade-all",
    ],
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
    """Run pvewarden-enroll with a stub install.sh, a stub pvewarden server and stub Proxmox commands."""
    proj = tmp_path / "proj"
    shutil.copytree(ROOT / "proxmox", proj / "proxmox")
    (proj / "guest").mkdir()
    write_exe(proj / "guest/install.sh", 'echo "INSTALL $*"; echo "INSTALL $*" >> "$LOG"\n')
    pve = tmp_path / "pve"
    for f in ("lxc/201.conf", "qemu-server/202.conf", "qemu-server/203.conf"):
        (pve / f).parent.mkdir(parents=True, exist_ok=True)
        (pve / f).touch()
    conf = tmp_path / "enroll.conf"
    conf.write_text('SERVER_CT=120\nFROM="192.0.2.10"\n')

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # the server container (120) runs 'pvewarden key ...'; FAIL_AT=<action> makes that action fail
    write_exe(
        bin_dir / "pct",
        """case "$1" in
  status) echo "status: running" ;;
  exec)
    if [ "$2" = 120 ]; then
      shift 3
      [ "$*" = "runuser -u pvewarden -- /usr/local/bin/pvewarden key ${*: -2}" ] || { echo "bad server call: $*" >&2; exit 9; }
      action=${*: -2:1}
      echo "SERVER key $action ${*: -1}" >> "$LOG"
      [ "$action" = "${FAIL_AT:-}" ] && exit 1
      [ "$action" = new ] && echo "ssh-ed25519 AAAANEW${*: -1} pvewarden-vmid-${*: -1}"
      exit 0
    fi
    shift 3; "$@" ;;
  config) echo "tags: other;pvewarden-update" ;;
  set) echo "SET pct $*" ;;
esac
""",
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
    write_exe(
        bin_dir / "pvesh",
        """if [ -n "${POOL_JSON:-}" ]; then echo "$POOL_JSON"
else echo '{"members":[{"vmid":201},{"vmid":202},{"storage":"local"}]}'; fi
""",
    )
    write_exe(bin_dir / "pveum", 'echo "PVEUM $*"; echo "PVEUM $*" >> "$LOG"\n')
    log = tmp_path / "steps.log"

    def run(*args, **extra_env):
        log.write_text("")
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "PVE_ETC": str(pve),
            "PVEWARDEN_ENROLL_CONF": str(conf),
            "LOG": str(log),
            **extra_env,
        }
        r = subprocess.run([proj / "proxmox/pvewarden-enroll", *args], env=env, capture_output=True, text=True)
        r.steps = log.read_text().splitlines()
        return r

    run.conf = conf
    return run


def test_enroll_switches_each_guest_to_its_own_key_in_order(enroll):
    r = enroll("--pool", "--tags", "pvewarden-update,pvewarden-reboot", "201", "202", POOL_JSON='{"members":[]}')
    assert r.returncode == 0, r.stderr
    for id_ in ("201", "202"):
        key = f"ssh-ed25519 AAAANEW{id_} pvewarden-vmid-{id_}"
        steps = [s for s in r.steps if id_ in s or key in s]
        assert steps == [
            f"SERVER key new {id_}",
            f"INSTALL --keep-keys {key} 192.0.2.10",  # added next to the old key
            f"PVEUM pool modify pvewarden --vms {id_}",  # the server can only see pool members
            f"SERVER key verify {id_}",  # the server logs in with the new key
            f"INSTALL --keys-only {key} 192.0.2.10",  # then only the new key is left
            f"SERVER key activate {id_}",  # and only then the server switches
        ], steps
    assert "SET pct set 201 --tags other;pvewarden-reboot;pvewarden-update" in r.stdout  # merged, nothing lost
    assert "SET qm set 202 --tags pvewarden-reboot;pvewarden-update" in r.stdout
    assert r.stdout.rstrip().endswith("OK: 201 202")


@pytest.mark.parametrize(
    "fail_at, done",
    [
        ("new", ["new"]),  # the server could not make a key: the guest was not touched
        ("verify", ["new", "INSTALL --keep-keys", "verify"]),  # the guest keeps its old key, nothing switched
        ("activate", ["new", "INSTALL --keep-keys", "verify", "INSTALL --keys-only", "activate"]),
    ],
)
def test_enroll_stops_at_a_failed_step_and_never_switches_halfway(enroll, fail_at, done):
    r = enroll("201", FAIL_AT=fail_at)
    assert r.returncode == 1 and "FAILED: 201" in r.stdout
    steps = [s.replace("SERVER key ", "").split(" 201")[0].split(" ssh-")[0] for s in r.steps]
    assert steps == done
    assert "SET " not in r.stdout  # no tags for a guest that did not finish
    if fail_at == "activate":
        assert "run pvewarden-enroll 201 again" in r.stderr


def test_enroll_continues_after_failures(enroll):
    r = enroll("203", "999", "201")
    assert r.returncode == 1
    assert "qemu-guest-agent not responding" in r.stderr
    assert "VMID 999 not found" in r.stderr
    assert "FAILED: 203 999" in r.stdout
    assert "SERVER key activate 201" in r.steps  # 201 still enrolled


def test_enroll_dry_run_changes_nothing(enroll):
    r = enroll("--dry-run", "--pool", "--tags", "pvewarden-reboot", "201")
    assert r.returncode == 0, r.stderr
    assert r.steps == ["INSTALL --dry-run --keep-keys ssh-ed25519 DRYRUN 192.0.2.10"]
    assert "would: set tags" in r.stdout and "would: make a key for 201" in r.stdout


def test_enroll_passes_auto_updates_only_when_changing_it(enroll):
    r = enroll("--auto-updates", "off", "201")
    assert "INSTALL --auto-updates=off --keep-keys ssh-ed25519 AAAANEW201 pvewarden-vmid-201 192.0.2.10" in r.steps
    r = enroll("--auto-updates", "keep", "201")
    assert "INSTALL --keep-keys ssh-ed25519 AAAANEW201 pvewarden-vmid-201 192.0.2.10" in r.steps
    assert enroll("--auto-updates", "maybe", "201").returncode == 2


def test_enroll_all_and_uninstall(enroll):
    r = enroll("--all")
    assert "=== 201" in r.stdout and "=== 202" in r.stdout and "local" not in r.stdout
    r = enroll("--uninstall", "201")
    assert r.returncode == 0, r.stderr
    assert r.steps == ["INSTALL --uninstall", "SERVER key remove 201"]


def test_enroll_needs_the_server_in_its_config(enroll):
    enroll.conf.write_text('PUBKEY="ssh-ed25519 AAAAOLD srv"\nFROM="192.0.2.10"\n')  # a 0.1.1 config
    r = enroll("201")
    assert r.returncode == 1 and "SERVER_CT missing" in r.stderr and "pvewarden-setup upgrade" in r.stderr
    assert r.steps == []


def test_enroll_with_a_server_command_instead_of_a_container(enroll, tmp_path):
    fake = tmp_path / "server"
    write_exe(fake, 'echo "SERVER $*" >> "$LOG"; [ "$2" = new ] && echo "ssh-ed25519 AAAAX m"; exit 0\n')
    enroll.conf.write_text(f'SERVER_CMD="{fake}"\nFROM="192.0.2.10"\n')
    r = enroll("201")
    assert r.returncode == 0, r.stderr
    assert [s for s in r.steps if s.startswith("SERVER")] == ["SERVER key new 201", "SERVER key verify 201",
                                                              "SERVER key activate 201"]  # fmt: skip


def test_enroll_usage(enroll):
    assert enroll().returncode == 2
    assert enroll("--bogus").returncode == 2


def test_enroll_shows_signs_of_life_during_a_slow_guest(enroll, tmp_path):
    write_exe(tmp_path / "proj/guest/install.sh", 'sleep 2.5; echo "INSTALL $*"\n')
    r = enroll("201", PVEWARDEN_TICK="1")
    assert r.returncode == 0, r.stderr
    assert "... still working (1s)" in r.stderr and "... still working (2s)" in r.stderr
