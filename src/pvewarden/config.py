"""Configuration file loading and validation."""

import ipaddress
import os
import re
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/pvewarden/config.toml")
TOKEN_SECRET_ENV = "PVEWARDEN_PROXMOX_TOKEN_SECRET"
PLACEHOLDER = "CHANGE_ME"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ProxmoxConfig:
    host: str
    token_id: str
    token_secret: str
    port: int = 8006
    verify_tls: bool | str = True  # True, False or path to a CA bundle


@dataclass(frozen=True)
class SSHConfig:
    key: Path
    user: str = "pvewarden"
    subnets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    parallel: int = 5
    connect_timeout: int = 10


CONFIRM_MODES = ("required", "if-supported", "off")


@dataclass(frozen=True)
class PolicyConfig:
    tag_update: str = "pvewarden-update"
    tag_reboot: str = "pvewarden-reboot"
    # rollback, snapshot deletion, updates without a snapshot: "required" = the user must confirm in
    # the MCP client (refused if the client cannot ask), "if-supported" = ask when the client can,
    # "off" = never ask
    confirm_destructive: str = "required"


@dataclass(frozen=True)
class HTTPConfig:
    listen: str
    port: int = 8765
    clients: dict[str, str] = field(default_factory=dict)
    # extra names clients may use in the Host header (e.g. a DNS name matching the TLS certificate)
    hostnames: tuple[str, ...] = ()
    tls_cert: Path | None = None
    tls_key: Path | None = None
    # the CA clients should trust (public); served without a token at /ca.pem so a client can
    # fetch it and check its fingerprint instead of copying files around
    tls_ca: Path | None = None

    @property
    def scheme(self) -> str:
        return "https" if self.tls_cert else "http"


@dataclass(frozen=True)
class StaticGuest:
    vmid: int
    name: str
    address: str
    type: str = "qemu"
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    state_dir: Path
    ssh: SSHConfig
    policy: PolicyConfig = PolicyConfig()
    proxmox: ProxmoxConfig | None = None
    http: HTTPConfig | None = None
    addresses: dict[int, str] = field(default_factory=dict)
    static_guests: tuple[StaticGuest, ...] = ()


def _section(data: dict, name: str, allowed: set[str], required: set[str] = frozenset()) -> dict:
    section = data.get(name, {})
    if not isinstance(section, dict):
        raise ConfigError(f"[{name}] must be a table")
    unknown = set(section) - allowed
    if unknown:
        raise ConfigError(f"[{name}]: unknown keys {sorted(unknown)}")
    missing = required - set(section)
    if missing:
        raise ConfigError(f"[{name}]: missing keys {sorted(missing)}")
    return section


def parse(data: dict) -> Config:
    top = {"state_dir", "proxmox", "ssh", "policy", "http", "addresses", "static_guests"}
    unknown = set(data) - top
    if unknown:
        raise ConfigError(f"unknown top-level keys {sorted(unknown)}")

    proxmox = None
    if "proxmox" in data:
        p = _section(data, "proxmox", {"host", "port", "token_id", "token_secret", "verify_tls"}, {"host", "token_id"})
        secret = os.environ.get(TOKEN_SECRET_ENV) or p.get("token_secret", "")
        if not secret or secret == PLACEHOLDER:
            raise ConfigError(f"[proxmox] token_secret is not set (config or ${TOKEN_SECRET_ENV})")
        proxmox = ProxmoxConfig(
            host=p["host"],
            token_id=p["token_id"],
            token_secret=secret,
            port=int(p.get("port", 8006)),
            verify_tls=p.get("verify_tls", True),
        )

    s = _section(data, "ssh", {"key", "user", "subnets", "parallel", "connect_timeout"}, {"key"})
    try:
        subnets = tuple(ipaddress.ip_network(n) for n in s.get("subnets", []))
    except ValueError as e:
        raise ConfigError(f"[ssh] subnets: {e}") from e
    ssh = SSHConfig(
        key=Path(s["key"]).expanduser(),
        user=s.get("user", "pvewarden"),
        subnets=subnets,
        parallel=int(s.get("parallel", 5)),
        connect_timeout=int(s.get("connect_timeout", 10)),
    )

    pol = _section(data, "policy", {"tag_update", "tag_reboot", "confirm_destructive"})
    policy = PolicyConfig(**pol)
    if policy.confirm_destructive not in CONFIRM_MODES:
        raise ConfigError(f"[policy] confirm_destructive must be one of {', '.join(CONFIRM_MODES)}")

    http = None
    if "http" in data:
        h = _section(
            data, "http", {"listen", "port", "clients", "hostnames", "tls_cert", "tls_key", "tls_ca"}, {"listen"}
        )
        clients = h.get("clients", {})
        weak = [name for name, token in clients.items() if len(token) < 32 or token == PLACEHOLDER]
        if weak:
            raise ConfigError(f"[http.clients] tokens must be at least 32 characters: {weak}")
        if ("tls_cert" in h) != ("tls_key" in h):
            raise ConfigError("[http] set both tls_cert and tls_key, or neither")
        if "tls_ca" in h and "tls_cert" not in h:
            raise ConfigError("[http] tls_ca needs tls_cert and tls_key")
        http = HTTPConfig(
            listen=h["listen"],
            port=int(h.get("port", 8765)),
            clients=dict(clients),
            hostnames=tuple(h.get("hostnames", [])),
            tls_cert=Path(h["tls_cert"]) if "tls_cert" in h else None,
            tls_key=Path(h["tls_key"]) if "tls_key" in h else None,
            tls_ca=Path(h["tls_ca"]) if "tls_ca" in h else None,
        )

    addresses = {int(k): v for k, v in data.get("addresses", {}).items()}

    static = []
    for g in data.get("static_guests", []):
        unknown = set(g) - {"vmid", "name", "address", "type", "tags"}
        if unknown:
            raise ConfigError(f"[[static_guests]]: unknown keys {sorted(unknown)}")
        static.append(
            StaticGuest(
                vmid=int(g["vmid"]),
                name=g["name"],
                address=g["address"],
                type=g.get("type", "qemu"),
                tags=tuple(g.get("tags", [])),
            )
        )

    if proxmox is None and not static:
        raise ConfigError("configure [proxmox] or, for testing without Proxmox, [[static_guests]]")

    return Config(
        state_dir=Path(data.get("state_dir", "/var/lib/pvewarden")).expanduser(),
        ssh=ssh,
        policy=policy,
        proxmox=proxmox,
        http=http,
        addresses=addresses,
        static_guests=tuple(static),
    )


def load(path: Path | str) -> Config:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e
    return parse(data)


CLIENT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def set_client_token(path: Path | str, name: str) -> str:
    """Give HTTP client `name` a new random token in [http.clients], in place. Returns the token.

    The old token stops working once the server restarts. Comments and layout are kept: only the
    client's line is replaced (or added at the top of the section).
    """
    if not CLIENT_NAME.match(name):
        raise ConfigError(f"client name may contain letters, digits, '-' and '_': {name!r}")
    path = Path(path)
    text = path.read_text()
    section = re.search(r"(?ms)^\[http\.clients\][ \t]*\n(.*?)(?=^\[|\Z)", text)
    if section is None:
        raise ConfigError(f"{path}: no [http.clients] section")
    token = secrets.token_urlsafe(32)
    line = f'{name} = "{token}"'
    body = section.group(1)
    existing = re.compile(rf"^{re.escape(name)}[ \t]*=.*$", re.M)
    body = existing.sub(line, body, count=1) if existing.search(body) else f"{line}\n{body}"
    text = text[: section.start(1)] + body + text[section.end(1) :]
    parse(tomllib.loads(text))  # never write a config the server would reject
    path.write_text(text)  # same file: owner and mode stay
    return token
