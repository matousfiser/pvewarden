"""pvewarden-setup against a fake Proxmox host: every pct/pvesh/pveum/pveam call is stubbed and logged."""

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from pvewarden.config import parse

ROOT = Path(__file__).parent.parent
SECRET = "0f1e2d3c-SECRET-TOKEN-VALUE"
PUBKEY = "ssh-ed25519 AAAASERVERKEY pvewarden@pvewarden"

STUBS = {
    "id": 'if [ "$1" = -u ]; then echo 0; else /usr/bin/id "$@"; fi\n',
    "pveversion": 'echo "pve-manager/${FAKE_PVE_VERSION:-9.0.3}/abcdef (running kernel: 6.14.8-2-pve)"\n',
    "hostname": 'if [ "$1" = -I ]; then echo "192.0.2.1"; else echo pve1; fi\n',
    "pvesm": """echo "Name Type Status Total Used Available %"
case "$*" in
  *rootdir*) echo "local-zfs zfspool active 1 1 1 1%"; echo "tank zfspool active 1 1 1 1%" ;;
  *vztmpl*) echo "local dir active 1 1 1 1%" ;;
esac
""",
    "dpkg": 'echo "${FAKE_ARCH:-amd64}"\n',
    "pveam": """case "$1" in
  available) printf 'system          %s\\n' debian-12-standard_12.7-1_amd64.tar.zst debian-13-standard_13.1-1_amd64.tar.zst \\
    debian-13-standard_13.0-1_amd64.tar.zst debian-13-standard_13.6-1_arm64.tar.zst ;;
  list) echo "NAME SIZE" ;;
esac
""",
    "pvesh": """case "$1 $2" in
  "get /cluster/nextid") echo 120 ;;
  "get /cluster/resources") cat "$FAKE/resources.json" ;;
  "get /pools/pvewarden") [ -f "$FAKE/pool" ] && echo '{"members":[{"vmid":101},{"vmid":102}]}' || exit 2 ;;
  "get /access/users/pvewarden@pve") [ -f "$FAKE/user" ] || exit 2 ;;
  "get /access/users/pvewarden@pve/token/server") [ -f "$FAKE/token" ] || exit 2 ;;
  get\\ /nodes/*/status/current) exit 2 ;;
  *) exit 0 ;;
esac
""",
    "pveum": """case "$1 $2" in
  "role list") [ -f "$FAKE/role" ] && echo '[{"roleid":"Warden"}]' || echo '[{"roleid":"PVEAdmin"}]' ;;
  "user token") [ "$3" = add ] && echo '{"full-tokenid":"pvewarden@pve!server","value":"'"$FAKE_SECRET"'"}' ;;
esac
""",
    "pct": """case "$1" in
  start) [ -z "$FAKE_START_FAILS" ] || { echo "startup for container '$2' failed" >&2; exit 1; } ;;
  create) while [ $# -gt 0 ]; do [ "$1" = --ssh-public-keys ] && cp "$2" "$FAKE/ct_authorized_keys"; shift; done ;;
  status) [ -f "$FAKE/ct" ] && echo "status: running" || exit 2 ;;
  push) mkdir -p "$FAKE/pushed"; cp "$3" "$FAKE/pushed/$(echo "$4" | tr / _)" ;;
  exec)
    shift 3
    case "$*" in
      *chpasswd*) cat > "$FAKE/chpasswd.stdin" ;;
      "ip -4 -o addr show dev eth0") echo "2: eth0    inet 192.0.2.50/24 brd 192.0.2.255 scope global eth0" ;;
      *python3*) echo "192.0.2.0/24" ;;
      "cat /etc/pvewarden/id_ed25519.pub") echo "$FAKE_PUBKEY" ;;
      "/usr/local/bin/pvewarden token "*) echo "NEW-TOKEN-FOR-${@: -1}"; echo "noise on stderr" >&2 ;;
      "test -f /etc/pvewarden/tls.crt") true ;;
      *fingerprint*) echo "sha256 Fingerprint=AA:BB:CC" ;;
    esac ;;
esac
""",
    "whiptail": 'echo "whiptail must not be called with --yes" >&2; exit 1\n',
    "curl": """url=${@: -1}
case "$url" in
  https://github.com/alice.keys) cat "$FAKE/alice.keys" ;;
  https://gitlab.com/empty.keys) ;;
  https://example.com/garbage) echo "<html>not a key</html>" ;;
  *) exit 22 ;;
esac
""",
    "ip": """case "$*" in
  *"route show default"*) echo "default via 192.0.2.254 dev vmbr0" ;;
  *"addr show dev"*) echo "3: vmbr0    inet 192.0.2.1/24 scope global vmbr0" ;;
esac
""",
}

LOGGED = ("pct", "pvesh", "pveum", "pveam", "curl")


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    """Real public keys: the installer validates every key with ssh-keygen."""
    d = tmp_path_factory.mktemp("keys")
    out = {}
    for name in ("admin", "alice1", "alice2", "pasted"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", d / name], check=True)
        out[name] = (d / f"{name}.pub").read_text().strip()
    return out


@pytest.fixture
def host(tmp_path, keys):
    """A fake Proxmox host. host.run(*args, **env) runs pvewarden-setup and returns the result."""
    fake = tmp_path / "fake"
    bin_dir = tmp_path / "bin"
    for d in (fake, bin_dir):
        d.mkdir()
    log = fake / "calls.log"
    for name, body in STUBS.items():
        prefix = f'echo "{name} $*" >> "$FAKE/calls.log"\n' if name in LOGGED else ""
        (bin_dir / name).write_text("#!/bin/bash\n" + prefix + body)
        (bin_dir / name).chmod(0o755)
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    enroll = sbin / "pvewarden-enroll"
    enroll.write_text('#!/bin/bash\necho "ENROLL $*" >> "$FAKE/calls.log"\n')
    enroll.chmod(0o755)
    (fake / "resources.json").write_text(
        '[{"vmid":101,"name":"web","type":"lxc","status":"running"},'
        '{"vmid":120,"name":"pvewarden","type":"lxc","status":"running"},'
        '{"vmid":9000,"name":"tpl","type":"qemu","status":"stopped","template":1},'
        '{"vmid":102,"name":"db","type":"qemu","status":"running"}]'
    )
    pve_etc = tmp_path / "pve"
    (pve_etc / "nodes/pve1").mkdir(parents=True)
    (pve_etc / "pve-root-ca.pem").write_text("-----BEGIN CERTIFICATE-----\nfake\n")
    keyfile = tmp_path / "admin.pub"
    keyfile.write_text(keys["admin"] + "\n")
    (fake / "alice.keys").write_text(keys["alice1"] + "\n" + keys["alice2"] + "\n")

    class Host:
        path = tmp_path
        calls_log = log
        pushed = fake / "pushed"
        admin_keys = keyfile
        state = tmp_path / "etc"

        def run(self, *args, **env):
            full_env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "FAKE": str(fake),
                "FAKE_SECRET": SECRET,
                "FAKE_PUBKEY": PUBKEY,
                "PVEWARDEN_HOST_DIR": str(tmp_path / "opt"),
                "PVEWARDEN_HOST_ETC": str(tmp_path / "etc"),
                "PVEWARDEN_SBIN": str(sbin),
                "PVE_ETC": str(pve_etc),
                **{k: str(v) for k, v in env.items()},
            }
            return subprocess.run(
                ["bash", ROOT / "proxmox/pvewarden-setup", *args, "--source", str(ROOT)],
                env=full_env,
                capture_output=True,
                text=True,
                timeout=120,
            )

        def calls(self) -> list[str]:
            return log.read_text().splitlines() if log.exists() else []

        def mark(self, *names):
            for n in names:
                (fake / n).touch()

    return Host()


INSTALL_ENV = {"PVEWARDEN_IP": "192.0.2.50/24", "PVEWARDEN_ROOT_PASSWORD": "correct horse"}


def test_install_creates_everything_and_never_shows_the_token_secret(host):
    r = host.run("install", "--yes", **INSTALL_ENV, PVEWARDEN_SSH_KEYS=host.admin_keys)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = host.calls()

    create = next(c for c in calls if c.startswith("pct create"))
    assert "pct create 120 local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst" in create  # newest Debian 13
    for part in (
        "--hostname pvewarden",
        "--rootfs local-zfs:4",
        "--net0 name=eth0,bridge=",
        "ip=192.0.2.50/24,gw=192.0.2.254",
        "--unprivileged 1",
        "--tags pvewarden-server",
        "--ssh-public-keys ",
    ):
        assert part in create, part

    assert (
        "pveum role add Warden --privs VM.Audit,VM.Snapshot,VM.Snapshot.Rollback,VM.PowerMgmt,VM.GuestAgent.Audit"
        in calls
    )
    assert "pveum acl modify /pool/pvewarden --users pvewarden@pve --roles Warden" in calls
    assert "pveum user token add pvewarden@pve server --privsep 0 --output-format json" in calls

    # secrets: password only via stdin, token secret only in the pushed config
    assert (host.path / "fake/chpasswd.stdin").read_text() == "root:correct horse\n"
    assert (host.path / "fake/ct_authorized_keys").read_text() == host.admin_keys.read_text()
    everything_visible = r.stdout + r.stderr + "\n".join(calls)
    assert "correct horse" not in everything_visible
    assert SECRET not in everything_visible

    config = (host.pushed / "_etc_pvewarden_config.toml").read_text()
    assert f'token_secret = "{SECRET}"' in config
    cfg = parse(tomllib.loads(config))  # the generated config is valid for the server
    assert cfg.proxmox.host == "pve1" and cfg.proxmox.verify_tls == "/etc/pvewarden/pve-root-ca.pem"
    assert cfg.http.listen == "192.0.2.50" and cfg.http.scheme == "https"
    assert [str(n) for n in cfg.ssh.subnets] == ["192.0.2.0/24"]
    agent_token = cfg.http.clients["agent"]
    assert agent_token in r.stdout  # the agent token is shown once, at the end
    assert "claude mcp add --scope user --transport http pvewarden https://192.0.2.50:8765/mcp" in r.stdout
    # pct exec has no /usr/local/bin in PATH: printed commands must use the full path
    assert "-- runuser -u pvewarden -- /usr/local/bin/pvewarden doctor" in r.stdout

    enroll_conf = (host.state / "enroll.conf").read_text()
    assert "AAAASERVERKEY" in enroll_conf and "FROM=192.0.2.50" in enroll_conf
    assert (host.path / "opt/proxmox/pvewarden-enroll").exists()


def test_role_name_is_allowed_by_proxmox():
    # Proxmox rejects role IDs starting with "PVE" (any case): that prefix is reserved for built-in roles
    role = re.search(r"^ROLE=(\S+)", (ROOT / "proxmox/pvewarden-setup").read_text(), re.M).group(1)
    assert not role.lower().startswith("pve")


def test_pve8_gets_the_old_guest_agent_privilege_and_debian_12(host):
    r = host.run("install", "--yes", **INSTALL_ENV, FAKE_PVE_VERSION="8.2.7")
    assert r.returncode == 0, r.stderr
    calls = host.calls()
    assert any("debian-12-standard_12.7-1" in c for c in calls if c.startswith("pct create"))
    assert any(c.endswith("VM.PowerMgmt,VM.Monitor") for c in calls if c.startswith("pveum role add"))


def test_existing_role_is_updated_not_duplicated(host):
    host.mark("role", "pool", "user")
    assert host.run("install", "--yes", **INSTALL_ENV).returncode == 0
    calls = host.calls()
    assert any(c.startswith("pveum role modify Warden") for c in calls)
    assert not any(c.startswith(("pveum role add", "pveum pool add", "pveum user add")) for c in calls)


def test_custom_listen_address_without_tls(host):
    r = host.run(
        "install",
        "--yes",
        **INSTALL_ENV,
        PVEWARDEN_ACCESS="custom",
        PVEWARDEN_LISTEN="10.8.0.5",
        PVEWARDEN_USE_TLS="no",
    )
    assert r.returncode == 0, r.stderr
    cfg = parse(tomllib.loads((host.pushed / "_etc_pvewarden_config.toml").read_text()))
    assert cfg.http.listen == "10.8.0.5" and cfg.http.scheme == "http"
    assert not any("openssl req" in c for c in host.calls())
    assert "http://10.8.0.5:8765/mcp" in r.stdout


def test_dry_run_changes_nothing(host):
    r = host.run("install", "--yes", "--dry-run", **INSTALL_ENV)
    assert r.returncode == 0, r.stderr
    changing = (
        "pct create",
        "pct start",
        "pct push",
        "pct exec",
        "pveum role add",
        "pveum user add",
        "pveum acl",
        "pveum user token add",
        "pveam download",
    )
    assert not [c for c in host.calls() if c.startswith(changing)]
    assert "would run: pct create 120" in r.stdout
    assert not host.state.exists() and not (host.path / "opt").exists()
    assert "nothing was changed" in r.stdout and "Bearer" not in r.stdout


def test_template_matches_the_host_architecture(host):
    assert host.run("install", "--yes", **INSTALL_ENV, FAKE_ARCH="arm64").returncode == 0
    assert any("debian-13-standard_13.6-1_arm64" in c for c in host.calls() if c.startswith("pct create"))
    r = host.run("install", "--yes", **INSTALL_ENV, FAKE_ARCH="riscv64")
    assert r.returncode != 0 and "no Debian 13 template for riscv64" in r.stderr


def test_failed_install_says_what_it_left_behind(host):
    r = host.run("install", "--yes", **INSTALL_ENV, FAKE_START_FAILS="1")
    assert r.returncode != 0
    assert "container 120 was already created" in r.stderr and "pct destroy 120" in r.stderr


def test_refuses_short_password(host):
    r = host.run("install", "--yes", PVEWARDEN_IP="dhcp", PVEWARDEN_ROOT_PASSWORD="abc")
    assert r.returncode == 1 and "at least 5 characters" in r.stderr
    assert not any(c.startswith("pct create") for c in host.calls())


def pushed_keys(host, r) -> str:
    """Content of the key file handed to pct create (copied before the installer cleans up)."""
    assert r.returncode == 0, r.stdout + r.stderr
    create = next(c for c in host.calls() if c.startswith("pct create"))
    return re.search(r"--ssh-public-keys (\S+)", create).group(1)


def test_pasted_ssh_key_is_used(host, keys):
    r = host.run("install", "--yes", **INSTALL_ENV, PVEWARDEN_SSH_KEYS=keys["pasted"])
    assert pushed_keys(host, r).endswith("/authorized_keys")
    assert "1 key(s)" in r.stdout and "(ED25519)" in r.stdout


def test_ssh_keys_from_github_and_a_file_with_fingerprints_in_the_summary(host, keys):
    r = host.run("install", "--yes", **INSTALL_ENV, PVEWARDEN_SSH_KEYS=f"gh:alice {host.admin_keys}")
    pushed_keys(host, r)
    assert (host.path / "fake/ct_authorized_keys").read_text().splitlines() == [
        keys["alice1"],
        keys["alice2"],
        keys["admin"],
    ]
    assert "curl -fsSL --max-time 20 https://github.com/alice.keys" in host.calls()
    assert "3 key(s) from gh:alice" in r.stdout
    for name in ("alice1", "alice2", "admin"):
        fingerprint = subprocess.run(
            ["ssh-keygen", "-lf", "-"], input=keys[name], capture_output=True, text=True
        ).stdout.split()[1]
        assert fingerprint in r.stdout  # the user sees exactly which keys get root


@pytest.mark.parametrize(
    "source, error",
    [
        ("gh:nobody", "could not fetch SSH keys from https://github.com/nobody.keys"),
        ("gl:empty", "no SSH public keys found at https://gitlab.com/empty.keys"),
        ("https://example.com/garbage", "not an SSH public key: <html>"),
        ("http://example.com/keys", "plain http"),
        ("not-a-file", "not a key source"),
        ("ssh-ed25519 AAAAbroken x", "invalid SSH public key"),
    ],
)
def test_bad_ssh_key_sources_stop_before_any_change(host, source, error):
    r = host.run("install", "--yes", **INSTALL_ENV, PVEWARDEN_SSH_KEYS=source)
    assert r.returncode == 1 and error in r.stderr, r.stderr
    assert not any(c.startswith(("pct create", "pveum")) for c in host.calls())


def test_install_refuses_when_already_installed(host):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\n")
    host.mark("ct")
    r = host.run("install", "--yes", **INSTALL_ENV)
    assert r.returncode == 1 and "already installed" in r.stderr


@pytest.mark.parametrize(
    "level, tags",
    [("readonly", None), ("update", "pvewarden-update"), ("reboot", "pvewarden-update,pvewarden-reboot")],
)
def test_enroll_levels(host, level, tags):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\n")
    r = host.run("enroll", "--yes", PVEWARDEN_ENROLL="101 102", PVEWARDEN_LEVEL=level)
    assert r.returncode == 0, r.stderr
    (call,) = [c for c in host.calls() if c.startswith("ENROLL")]
    expected = "ENROLL --pool" + (f" --tags {tags}" if tags else "") + " 101 102"
    assert call == expected


def test_uninstall_removes_access_and_keeps_container_unless_asked(host):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\n")
    host.mark("ct", "pool", "user", "role")
    r = host.run("uninstall", "--yes")
    assert r.returncode == 0, r.stderr
    calls = host.calls()
    assert "ENROLL --uninstall --all" in calls
    assert "pveum user delete pvewarden@pve" in calls and "pveum role delete Warden" in calls
    assert "pveum pool modify pvewarden --vms 101,102 --delete 1" in calls and "pveum pool delete pvewarden" in calls
    assert not any(c.startswith("pct destroy") for c in calls)
    assert "container 120 was kept" in r.stdout
    assert not host.state.exists()

    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\n")
    host.run("uninstall", "--yes", PVEWARDEN_DESTROY_CT="yes")
    assert "pct destroy 120 --purge 1" in host.calls()


def test_requires_proxmox_8(host):
    r = host.run("install", "--yes", FAKE_PVE_VERSION="7.4.3")
    assert r.returncode == 1 and "Proxmox VE 8 or newer" in r.stderr


def test_not_root(host, tmp_path):
    (tmp_path / "bin/id").write_text("#!/bin/bash\necho 1000\n")
    r = host.run("install", "--yes")
    assert r.returncode == 1 and "run as root" in r.stderr


SCRIPTED_WHIPTAIL = """#!/bin/bash
# answers come from $FAKE/answers, one per dialog; dialogs are logged to $FAKE/dialogs.log
kind=""
for a in "$@"; do case "$a" in --yesno|--msgbox|--menu|--inputbox|--passwordbox|--checklist) kind=$a ;; esac; done
echo "$kind $*" >> "$FAKE/dialogs.log"
[ "$kind" = --msgbox ] && exit 0
answer=$(head -1 "$FAKE/answers"); sed -i 1d "$FAKE/answers"
case "$kind" in
  --yesno) [ "$answer" = yes ] ;;
  *) [ "$answer" = "<cancel>" ] && exit 1; echo "$answer" >&2 ;;
esac
"""


def test_interactive_advanced_install_uses_every_answer(host, keys):
    (host.path / "bin/whiptail").write_text(SCRIPTED_WHIPTAIL)
    answers = [
        "advanced",  # mode
        "130", "warden", "tank", "8", "2", "1024", "0",  # id, hostname, storage, disk, cores, memory, swap
        "docker0", "20",  # bridge, vlan
        "192.0.2.60/24", "192.0.2.254", "auto", "192.0.2.53", "lan", "0",  # ip, gw, ipv6, dns, search, onboot
        "s3cret-pass", "s3cret-pass",  # root password twice
        "paste", keys["pasted"], "done",  # ssh keys: source menu, the key, finish
        "https", "claude",  # access, agent name
        "yes",  # confirm summary
        "no",  # enroll now?
    ]  # fmt: skip
    (host.path / "fake/answers").write_text("\n".join(answers) + "\n")
    r = host.run("install")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (host.path / "fake/answers").read_text() == ""  # every answer consumed, no extra dialog

    create = next(c for c in host.calls() if c.startswith("pct create"))
    for part in (
        "pct create 130 ",
        "--hostname warden",
        "--cores 2",
        "--memory 1024",
        "--swap 0",
        "--rootfs tank:8",
        "ip=192.0.2.60/24,gw=192.0.2.254,tag=20,ip6=auto",
        "--onboot 0",
        "--nameserver 192.0.2.53",
        "--searchdomain lan",
    ):
        assert part in create, part
    assert "s3cret-pass" not in create
    assert (host.path / "fake/chpasswd.stdin").read_text() == "root:s3cret-pass\n"
    cfg = parse(tomllib.loads((host.pushed / "_etc_pvewarden_config.toml").read_text()))
    assert list(cfg.http.clients) == ["claude"] and cfg.http.hostnames == ("warden",)


def test_interactive_cancel_stops_before_any_change(host):
    (host.path / "bin/whiptail").write_text(SCRIPTED_WHIPTAIL)
    (host.path / "fake/answers").write_text("default\n<cancel>\n")  # cancel at the IP question
    r = host.run("install")
    assert r.returncode == 1 and "cancelled" in r.stderr
    assert not [c for c in host.calls() if c.startswith(("pct create", "pveum"))]


def test_upgrade(host):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\nCT_IP=192.0.2.50\n")
    host.mark("ct")
    r = host.run("upgrade", "--yes")
    assert r.returncode == 0, r.stderr
    calls = host.calls()
    assert "pct exec 120 -- bash /root/pvewarden-src/deploy/install-server.sh 192.0.2.50" in calls
    assert "pct exec 120 -- systemctl restart pvewarden" in calls
    assert "ENROLL --all" in calls
    assert not any(c.startswith(("pct create", "pveum user token")) for c in calls)  # keeps the existing token
    assert (host.path / "opt/proxmox/pvewarden-setup").exists()


def test_interactive_ssh_keys_one_source_at_a_time_with_errors_shown(host, keys):
    (host.path / "bin/whiptail").write_text(SCRIPTED_WHIPTAIL)
    answers = [
        "default", "192.0.2.50/24", "192.0.2.254",  # mode, ip, gateway
        "", "",  # no root password
        "github", "nobody",  # a typo: shown as an error, back to the menu
        "github", "  alice ",  # the right name (spaces trimmed)
        "file", str(host.admin_keys),
        "done",
        "https", "agent", "yes", "no",
    ]  # fmt: skip
    (host.path / "fake/answers").write_text("\n".join(answers) + "\n")
    r = host.run("install")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (host.path / "fake/answers").read_text() == ""
    assert (host.path / "fake/ct_authorized_keys").read_text().splitlines() == [
        keys["alice1"], keys["alice2"], keys["admin"],
    ]  # fmt: skip
    dialogs = (host.path / "fake/dialogs.log").read_text()
    assert "could not fetch SSH keys from https://github.com/nobody.keys" in dialogs
    assert "Added 2 key(s)" in dialogs and "Added 1 key(s)" in dialogs
    assert "Added so far: 3 key(s) from gh:alice, " in dialogs
    summary = dialogs[dialogs.index("  SSH keys   ") + 2 :]  # the confirmation shows every fingerprint
    assert summary.startswith("SSH keys             3 key(s) from gh:alice")
    assert summary.count("(ED25519)") == 3


def test_token_rotation(host):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\nCT_IP=192.0.2.50\n")
    r = host.run("token", "--yes", PVEWARDEN_CLIENT="claude")
    assert r.returncode == 0, r.stderr
    calls = host.calls()
    assert "pct exec 120 -- /usr/local/bin/pvewarden token claude" in calls
    assert calls.index("pct exec 120 -- /usr/local/bin/pvewarden token claude") < calls.index(
        "pct exec 120 -- systemctl restart pvewarden"
    )
    assert "NEW-TOKEN-FOR-claude" in r.stdout and "noise" not in r.stdout
    assert "claude mcp remove --scope user pvewarden" in r.stdout
    assert "https://192.0.2.50:8765/mcp" in r.stdout and 'Bearer NEW-TOKEN-FOR-claude"' in r.stdout


@pytest.mark.parametrize("name", ["a b", "x;rm", "../x"])
def test_token_rotation_rejects_odd_names(host, name):
    host.state.mkdir()
    (host.state / "setup.conf").write_text("CTID=120\nLISTEN=192.0.2.50\nCT_IP=192.0.2.50\n")
    r = host.run("token", "--yes", PVEWARDEN_CLIENT=name)
    assert r.returncode != 0 and not [c for c in host.calls() if "pvewarden token" in c]
