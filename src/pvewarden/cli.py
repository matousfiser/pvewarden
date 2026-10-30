import argparse
import logging
import os
import sys

from pvewarden import __version__
from pvewarden.config import DEFAULT_CONFIG_PATH, ConfigError, load


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
    uvicorn.run(build_app(server, cfg.http, app.audit), host=cfg.http.listen, port=cfg.http.port)


def check_config(args: argparse.Namespace) -> None:
    cfg = load(args.config)
    mode = "proxmox" if cfg.proxmox else f"static inventory ({len(cfg.static_guests)} guests)"
    http = f"http on {cfg.http.listen}:{cfg.http.port}, {len(cfg.http.clients)} client(s)" if cfg.http else "no http"
    print(f"config OK: {mode}, {http}")


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

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ConfigError as e:
        sys.exit(f"pvewarden: config error: {e}")
