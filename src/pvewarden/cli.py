import argparse
import logging
import os
import sys

from pvewarden import __version__
from pvewarden.config import DEFAULT_CONFIG_PATH, ConfigError, load, set_client_token
from pvewarden.errors import WardenError
from pvewarden.keys import KeyStoreError


def serve(args: argparse.Namespace) -> None:
    from pvewarden.app import App
    from pvewarden.tools import create_server

    cfg = load(args.config)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # no per-request API noise
    app = App(cfg)
    server = create_server(app)
    if not args.http:
        server.run()
        return

    import uvicorn

    from pvewarden.http import build_app

    if cfg.http is None:
        raise ConfigError("--http needs an [http] section in the config")
    uvicorn.run(
        build_app(server, cfg.http, app.audit),
        host=cfg.http.listen,
        port=cfg.http.port,
        ssl_certfile=cfg.http.tls_cert,
        ssl_keyfile=cfg.http.tls_key,
        # MCP clients keep a stream open for as long as they run; without a limit a graceful
        # shutdown waits for them forever and systemd kills the service only after 90 s
        timeout_graceful_shutdown=5,
    )


def check_config(args: argparse.Namespace) -> None:
    cfg = load(args.config)
    mode = "proxmox" if cfg.proxmox else f"static inventory ({len(cfg.static_guests)} guests)"
    http = f"http on {cfg.http.listen}:{cfg.http.port}, {len(cfg.http.clients)} client(s)" if cfg.http else "no http"
    print(f"config OK: {mode}, {http}")


def doctor(args: argparse.Namespace) -> None:
    import asyncio

    from pvewarden.app import App
    from pvewarden.doctor import ok, render, run_checks

    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg = load(args.config)
    results = [ok("Config", str(args.config)), *asyncio.run(run_checks(App(cfg)))]
    print(render(results, verbose=args.verbose))
    if any(r.status == "fail" for r in results):
        sys.exit(1)


def token(args: argparse.Namespace) -> None:
    new = set_client_token(args.config, args.name)
    print(new)
    print(
        f"new token for HTTP client {args.name!r} written to {args.config}; the old one stops working once "
        "the server restarts (systemctl restart pvewarden)",
        file=sys.stderr,
    )


def key(args: argparse.Namespace) -> None:
    """Per-guest SSH keys; pvewarden-enroll calls these steps in order: new, verify, activate."""
    from pvewarden.keys import KeyStore

    cfg = load(args.config)
    store = KeyStore(cfg.state_dir / "keys")
    if args.action == "list":
        for vmid in store.vmids():
            print(vmid)
        return
    if args.vmid is None:
        sys.exit(f"pvewarden key {args.action}: a VMID is needed")
    if args.action == "new":
        print(store.new(args.vmid))
    elif args.action == "verify":
        sys.exit(verify_new_key(cfg, args.vmid))
    elif args.action == "activate":
        store.activate(args.vmid)
        print(f"guest {args.vmid}: new key active", file=sys.stderr)
    elif args.action == "remove":
        store.remove(args.vmid)


def pending(args: argparse.Namespace) -> None:
    """Updates that fence their guest. 'clear' is for a human who has checked the guest."""
    import json

    from pvewarden.audit import AuditLog
    from pvewarden.fence import Fence

    cfg = load(args.config)
    fence = Fence(cfg.state_dir)
    if args.action == "list":
        for vmid in fence.vmids():
            p = fence.pending(vmid) or {}
            print(vmid, p.get("state"), p.get("reason", ""), json.dumps({k: p.get(k) for k in ("snapshot", "log")}))
        return
    if args.vmid is None:
        sys.exit("pvewarden pending clear: a VMID is needed")
    with fence.lock(args.vmid):  # not while the server is working on this guest
        removed = fence.clear(args.vmid)
    if removed is None:
        print(f"guest {args.vmid}: nothing pending", file=sys.stderr)
        return
    AuditLog(cfg.state_dir / "audit.jsonl").write("pending_cleared_by_admin", vmid=args.vmid, pending=removed)
    print(f"guest {args.vmid}: cleared (was {removed.get('state')}); pvewarden may change it again", file=sys.stderr)


def verify_new_key(cfg, vmid: int) -> int:
    """Log in to the guest with the key being enrolled. 0 = the guest accepts it."""
    import asyncio

    from pvewarden.app import App
    from pvewarden.errors import WardenError

    logging.getLogger("httpx").setLevel(logging.WARNING)

    async def check() -> int:
        app = App(cfg)
        try:
            g = await app.guest(vmid)
            rc, out = await app.run(g, "status", new_key=True, timeout=60)
        except WardenError as e:
            print(f"guest {vmid}: {e}", file=sys.stderr)
            return 1
        if rc != 0:
            print(f"guest {vmid}: the new key was not accepted: {out.strip()[-300:]}", file=sys.stderr)
            return 1
        return 0

    return asyncio.run(check())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pvewarden", description="Agent-safe patching of Proxmox VE guests over MCP")
    parser.add_argument("--version", action="version", version=f"pvewarden {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        default=os.environ.get("PVEWARDEN_CONFIG", DEFAULT_CONFIG_PATH),
        help=f"config file (default: $PVEWARDEN_CONFIG or {DEFAULT_CONFIG_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("serve", help="run the MCP server (stdio by default)")
    p.add_argument("--http", action="store_true", help="serve streamable HTTP as configured in [http]")
    p.set_defaults(func=serve)
    p = sub.add_parser("check-config", help="validate the config file and exit")
    p.set_defaults(func=check_config)
    p = sub.add_parser("doctor", help="check Proxmox access, token privileges and SSH to every guest")
    p.add_argument("-v", "--verbose", action="store_true", help="also show what each check saw (API data, SSH output)")
    p.set_defaults(func=doctor)
    p = sub.add_parser("token", help="give an HTTP client a new random token (rotation) and print it")
    p.add_argument("name", nargs="?", default="agent", help="client name in [http.clients] (default: agent)")
    p.set_defaults(func=token)
    p = sub.add_parser("key", help="per-guest SSH keys (used by pvewarden-enroll)")
    p.add_argument("action", choices=["new", "verify", "activate", "remove", "list"])
    p.add_argument("vmid", type=int, nargs="?")
    p.set_defaults(func=key)
    p = sub.add_parser("pending", help="updates that block their guest; clear one after checking the guest")
    p.add_argument("action", choices=["list", "clear"])
    p.add_argument("vmid", type=int, nargs="?")
    p.set_defaults(func=pending)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ConfigError as e:
        sys.exit(f"pvewarden: config error: {e}")
    except (KeyStoreError, WardenError) as e:
        sys.exit(f"pvewarden: {e}")
