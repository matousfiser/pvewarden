# pvewarden

**Agent-safe patching of Proxmox VE guests over MCP.**

pvewarden lets an AI agent (Claude Code or any other MCP client) keep your Proxmox VMs and containers up to date:
check pending updates, snapshot, install, reboot and verify services. The agent never gets a shell or root.
It can only call a small set of tools, and what it may do is enforced by Proxmox and by the server, not by the prompt.

> **Status:** early development (v0.1.0.dev). Not ready for use yet.

## License

[Apache-2.0](LICENSE)
