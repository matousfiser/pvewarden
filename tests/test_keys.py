"""One SSH key per guest: a guest that reports another guest's address must not get us onto it."""

import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import give_key

from pvewarden.cli import main
from pvewarden.errors import GuestError
from pvewarden.keys import KeyStore, KeyStoreError

# --- choosing the key ---------------------------------------------------------------------------


async def test_the_key_follows_the_vmid_not_the_address(app):
    # guest 101 (tag update) is compromised and reports guest 102's address
    app.pve.ips[101] = ["192.0.2.12"]
    await app.apply_updates(101)
    used = {key for command, key in app.runner.keys}
    # every connection made for 101 uses 101's key, which only guest 101 accepts: on guest 102 the
    # login fails (proved against a real sshd in tests/integration)
    assert used == {"101"}
    assert {address for address, _ in app.runner.calls} == {"192.0.2.12"}


async def test_a_guest_without_its_own_key_is_refused_without_connecting(app):
    (app.keys.path / "102").unlink()
    with pytest.raises(GuestError, match="no pvewarden key of its own.*pvewarden-enroll 102"):
        await app.apply_updates(102)
    assert app.runner.calls == []


async def test_the_shared_key_is_never_used_for_addresses_a_guest_reports(app, tmp_path):
    (app.keys.path / "102").unlink()
    app.cfg = replace(app.cfg, ssh=replace(app.cfg.ssh, key=tmp_path / "shared"))
    [res] = await app.check_updates([102])
    assert "no pvewarden key of its own" in res["error"]
    assert app.runner.calls == []


async def test_the_shared_key_works_for_an_admin_set_address(app, tmp_path):
    (app.keys.path / "102").unlink()
    app.cfg = replace(app.cfg, ssh=replace(app.cfg.ssh, key=tmp_path / "shared"), addresses={102: "192.0.2.12"})
    await app.check_updates([102])
    assert app.runner.keys[0] == ("check", "shared")


async def test_the_own_key_wins_over_the_shared_key(app, tmp_path):
    app.cfg = replace(app.cfg, ssh=replace(app.cfg.ssh, key=tmp_path / "shared"), addresses={102: "192.0.2.12"})
    await app.check_updates([102])
    assert app.runner.keys[0] == ("check", "102")


async def test_host_keys_are_remembered_per_vmid(app):
    seen = []

    async def run(address, command, timeout=1800, log=None, log_mode="a", *, key, alias=None):
        seen.append(alias)
        return 0, "os=Debian\nreboot_required=no\n"

    app.runner.run = run
    await app.status(await app.guest(101))
    assert seen == ["pvewarden-vmid-101"]


def test_ssh_uses_only_the_given_key_and_the_vmid_host_key_alias(app):
    from pvewarden.guest import GuestRunner

    args = GuestRunner(app.cfg.ssh, Path("/kh")).ssh_args("192.0.2.12", "status", Path("/k/101"), "pvewarden-vmid-101")
    joined = " ".join(args)
    assert "-i /k/101" in joined and "IdentitiesOnly=yes" in joined and "IdentityAgent=none" in joined
    assert "HostKeyAlias=pvewarden-vmid-101" in joined


async def test_verifying_uses_the_key_being_enrolled(app):
    store = app.keys
    (store.path / "101.new").write_text("new private key")
    g = await app.guest(101)
    await app.run(g, "status", new_key=True)
    assert app.runner.keys == [("status", "101.new")]
    (store.path / "101.new").unlink()
    with pytest.raises(GuestError, match="no key being enrolled"):
        await app.run(g, "status", new_key=True)


# --- the key store: enrolling, half-done enrolling, rotation ------------------------------------


@pytest.fixture
def store(tmp_path):
    return KeyStore(tmp_path / "keys")


def test_new_key_is_private_and_not_yet_active(store):
    pub = store.new(101)
    assert pub.startswith("ssh-ed25519 ") and pub.endswith("pvewarden-vmid-101@" + os.uname().nodename)
    assert store.active(101) is None and store.pending(101) is not None
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.pending(101).stat().st_mode) == 0o600


def test_activate_switches_atomically_to_the_new_key(store):
    store.new(101)
    pending = store.pending(101).read_bytes()
    store.activate(101)
    assert store.active(101).read_bytes() == pending and store.pending(101) is None
    assert store.vmids() == [101]


def test_rotation_keeps_the_old_key_until_activated(store):
    store.new(101)
    store.activate(101)
    old = store.active(101).read_bytes()
    store.new(101)  # rotation started, guest not switched yet
    assert store.active(101).read_bytes() == old  # still the key the guest accepts
    store.activate(101)
    assert store.active(101).read_bytes() != old


def test_an_unfinished_new_key_is_replaced_by_the_next_attempt(store):
    first = store.new(101)
    second = store.new(101)
    assert first != second and store.pending(101) is not None


def test_activate_without_a_new_key_fails(store):
    with pytest.raises(KeyStoreError, match="no new key"):
        store.activate(101)


def test_remove(store):
    store.new(101)
    store.activate(101)
    store.new(101)
    store.remove(101)
    assert list(store.path.iterdir()) == []


# --- pvewarden key (what pvewarden-enroll calls) ------------------------------------------------


@pytest.fixture
def config_file(tmp_path):
    f = tmp_path / "config.toml"
    f.write_text(
        f'state_dir = "{tmp_path / "state"}"\n[proxmox]\nhost = "h"\ntoken_id = "u@pve!t"\ntoken_secret = "s"\n'
    )
    return f


def test_cli_new_activate_list_remove(config_file, tmp_path, capsys):
    main(["-c", str(config_file), "key", "new", "101"])
    assert capsys.readouterr().out.startswith("ssh-ed25519 ")
    main(["-c", str(config_file), "key", "list"])
    assert capsys.readouterr().out == ""  # not active yet
    main(["-c", str(config_file), "key", "activate", "101"])
    main(["-c", str(config_file), "key", "list"])
    assert capsys.readouterr().out == "101\n"
    main(["-c", str(config_file), "key", "remove", "101"])
    main(["-c", str(config_file), "key", "list"])
    assert capsys.readouterr().out == ""


def test_cli_activate_without_new_key_fails_cleanly(config_file):
    with pytest.raises(SystemExit) as e:
        main(["-c", str(config_file), "key", "activate", "101"])
    assert "no new key" in str(e.value.code)


def test_cli_rejects_a_vmid_that_is_not_a_number(config_file):
    r = subprocess.run(
        ["uv", "run", "pvewarden", "-c", str(config_file), "key", "new", "../x"], capture_output=True, text=True
    )
    assert r.returncode == 2


def test_give_key_helper_matches_the_store_layout(app):
    give_key(app, 999)
    assert app.keys.active(999) == app.keys.path / "999"


def test_cli_new_key_waits_for_an_update_result(config_file, tmp_path):
    from pvewarden.fence import Fence

    Fence(tmp_path / "state").begin(101)
    with pytest.raises(SystemExit) as e:
        main(["-c", str(config_file), "key", "new", "101"])
    assert "result is not known yet" in str(e.value.code)


def test_cli_key_steps_wait_for_a_change_in_progress(config_file, tmp_path):
    from pvewarden.fence import Fence

    with Fence(tmp_path / "state").lock(101):
        for action in ("new", "activate", "remove"):
            with pytest.raises(SystemExit) as e:
                main(["-c", str(config_file), "key", action, "101"])
            assert "in progress" in str(e.value.code)
