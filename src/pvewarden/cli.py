import argparse

from pvewarden import __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pvewarden", description="Agent-safe patching of Proxmox VE guests over MCP"
    )
    parser.add_argument("--version", action="version", version=f"pvewarden {__version__}")
    parser.parse_args()
    parser.print_help()
