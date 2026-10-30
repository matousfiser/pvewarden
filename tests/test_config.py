import tomllib
from pathlib import Path

import pytest

from pvewarden.config import TOKEN_SECRET_ENV, ConfigError, load, parse

ROOT = Path(__file__).parent.parent


def minimal(**extra):
    return {"ssh": {"key": "/k"}, "static_guests": [{"vmid": 1, "name": "a", "address": "192.0.2.1"}], **extra}


def test_minimal_static_config_defaults():
    cfg = parse(minimal())
    assert cfg.proxmox is None
    assert cfg.ssh.user == "pvewarden"
    assert cfg.policy.tag_update == "pvewarden-update"
    assert cfg.policy.tag_reboot == "pvewarden-reboot"
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
