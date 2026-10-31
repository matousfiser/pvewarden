import tomllib
from pathlib import Path

import pytest

from pvewarden.config import TOKEN_SECRET_ENV, ConfigError, load, parse, set_client_token

ROOT = Path(__file__).parent.parent


def minimal(**extra):
    return {"ssh": {"key": "/k"}, "static_guests": [{"vmid": 1, "name": "a", "address": "192.0.2.1"}], **extra}


def test_minimal_static_config_defaults():
    cfg = parse(minimal())
    assert cfg.proxmox is None
    assert cfg.ssh.user == "pvewarden"
    assert cfg.policy.tag_update == "pvewarden-update"
    assert cfg.policy.tag_reboot == "pvewarden-reboot"
    assert cfg.policy.confirm_destructive == "required"
    assert cfg.static_guests[0].type == "qemu"


def test_needs_proxmox_or_static_guests():
    with pytest.raises(ConfigError, match="static_guests"):
        parse({"ssh": {"key": "/k"}})


@pytest.mark.parametrize(
    "data, message",
    [
        (minimal(bogus=1), "unknown top-level"),
        (minimal(ssh={"key": "/k", "port": 22}), r"\[ssh\]: unknown keys"),
        ({"static_guests": [{"vmid": 1, "name": "a", "address": "x"}]}, r"\[ssh\]: missing keys"),
        (minimal(ssh={"key": "/k", "subnets": ["not-a-net"]}), "subnets"),
        (minimal(static_guests=[{"vmid": 1, "name": "a", "address": "x", "tag": []}]), "static_guests"),
        (minimal(policy={"confirm_destructive": "yes"}), "confirm_destructive"),
    ],
)
def test_rejects_invalid(data, message):
    with pytest.raises(ConfigError, match=message):
        parse(data)


@pytest.mark.parametrize("secret", ["", "CHANGE_ME"])
def test_proxmox_secret_required(secret, monkeypatch):
    monkeypatch.delenv(TOKEN_SECRET_ENV, raising=False)
    with pytest.raises(ConfigError, match="token_secret"):
        parse(minimal(proxmox={"host": "h", "token_id": "u@pve!t", "token_secret": secret}))


def test_proxmox_secret_from_env(monkeypatch):
    monkeypatch.setenv(TOKEN_SECRET_ENV, "from-env")
    cfg = parse(minimal(proxmox={"host": "h", "token_id": "u@pve!t"}))
    assert cfg.proxmox.token_secret == "from-env"
    assert cfg.proxmox.verify_tls is True


@pytest.mark.parametrize("token", ["short", "CHANGE_ME"])
def test_http_rejects_weak_tokens(token):
    with pytest.raises(ConfigError, match="32 characters"):
        parse(minimal(http={"listen": "192.0.2.1", "clients": {"agent": token}}))


def test_addresses_keys_become_ints():
    cfg = parse(minimal(addresses={"108": "192.0.2.45"}))
    assert cfg.addresses == {108: "192.0.2.45"}


def test_load_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml")
    with pytest.raises(ConfigError, match="bad.toml"):
        load(bad)


def test_example_config_is_valid_once_secrets_are_filled():
    text = (ROOT / "config.example.toml").read_text().replace("CHANGE_ME", "x" * 40)
    cfg = parse(tomllib.loads(text))
    assert cfg.proxmox is not None
    assert cfg.http is not None and "agent" in cfg.http.clients


def test_http_tls_needs_cert_and_key():
    with pytest.raises(ConfigError, match="tls_cert and tls_key"):
        parse(minimal(http={"listen": "192.0.2.1", "tls_cert": "/c.pem"}))
    cfg = parse(minimal(http={"listen": "192.0.2.1", "tls_cert": "/c", "tls_key": "/k", "hostnames": ["w.lan"]}))
    assert cfg.http.scheme == "https" and cfg.http.hostnames == ("w.lan",)
    assert parse(minimal(http={"listen": "192.0.2.1"})).http.scheme == "http"


def filled_example(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv(TOKEN_SECRET_ENV, "s" * 36)
    path = tmp_path / "config.toml"
    path.write_text((ROOT / "config.example.toml").read_text().replace('agent = "CHANGE_ME"', f'agent = "{"a" * 43}"'))
    path.chmod(0o640)
    return path


def test_token_rotation_replaces_only_that_client(tmp_path, monkeypatch, capsys):
    from pvewarden.cli import main

    path = filled_example(tmp_path, monkeypatch)
    before = path.read_text()
    main(["-c", str(path), "token"])
    new = capsys.readouterr().out.strip()
    assert len(new) >= 32 and new != "a" * 43
    after = path.read_text()
    assert load(path).http.clients == {"agent": new}
    assert after.replace(new, "a" * 43) == before  # comments and layout untouched
    assert path.stat().st_mode & 0o777 == 0o640


def test_token_for_a_new_client_is_added(tmp_path, monkeypatch):
    path = filled_example(tmp_path, monkeypatch)
    new = set_client_token(path, "ci-bot")
    assert load(path).http.clients == {"ci-bot": new, "agent": "a" * 43}


@pytest.mark.parametrize("name", ["", "a b", 'x" = 1 #', "../x"])
def test_token_rejects_odd_client_names(tmp_path, monkeypatch, name):
    path = filled_example(tmp_path, monkeypatch)
    with pytest.raises(ConfigError, match="client name"):
        set_client_token(path, name)
