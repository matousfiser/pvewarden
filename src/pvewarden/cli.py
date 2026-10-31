import argparse
import logging
import os
import sys

from pvewarden import __version__
from pvewarden.config import DEFAULT_CONFIG_PATH, ConfigError, load, set_client_token


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

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ConfigError as e:
        sys.exit(f"pvewarden: config error: {e}")
