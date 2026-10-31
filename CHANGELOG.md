# Changelog

## Unreleased

- `pvewarden-setup`: the install summary, `connect` and `token` output are laid out in clear
  sections that fit 80 columns. Long commands start at the left edge, so they wrap cleanly and copy
  well. Colors appear on a terminal, never with `NO_COLOR` or when the output is redirected.

## 0.1.0 (2026-10-31)

First public release.

**Server and tools**
- MCP server over streamable HTTP with one bearer token per agent, or over stdio.
- Tools:
  - reading: `list_guests`, `check_updates`, `check_services`, `list_snapshots`,
  - updating: `snapshot_guest`, `apply_updates`, `update_result`, `reboot_guest`,
  - snapshots: `rollback_snapshot`, `delete_snapshot`, `delete_old_snapshots`.
- Policy from Proxmox: only guests in the `pvewarden` pool; updates need tag `pvewarden-update`,
  reboots need `pvewarden-reboot`.
- Updates only from the distribution's official archives (Debian, Ubuntu incl. ESM). Third-party
  repositories and held packages are reported, never installed.
- A snapshot before every update, and none when nothing is pending. Snapshot descriptions name the
  agent.
- The user confirms rollback, snapshot deletion and updates without a snapshot in a dialog in the
  MCP client (MCP elicitation, `[policy] confirm_destructive`).
- Guests that Proxmox has locked (backup, migration) are left alone. `check_updates` reports locks
  and running backups.
- Updates run detached on the guest. A dropped connection or a timeout does not interrupt dpkg;
  `update_result` picks the result up later.
- Services are compared before and after an update; newly failed units are reported.
- Audit log of every call, with the agent's name. Full apt output is kept for every update.
- `pvewarden doctor` checks the config, the Proxmox API, the token's privileges (too few and too
  many) and SSH to every guest.

**Setup (`pvewarden-setup`, on the Proxmox host)**
- TUI wizard: pool, minimal role and token, an unprivileged Debian container for the server,
  enrolling guests (LXC and VMs), connection summary.
- HTTPS certificate signed by the Proxmox cluster CA. Clients fetch the CA from `/ca.pem` with a
  fingerprint-checked command.
- Commands: `install`, `enroll`, `connect`, `token`, `renew-cert`, `upgrade`, `uninstall`;
  `--dry-run` and an unattended mode (`--yes` with `PVEWARDEN_*` variables).
- The guests' own automatic updates: keep (default), off or on, chosen per enroll.

**Tested with** Proxmox VE 9.1 and Debian 12/13 and Ubuntu 22.04/24.04/26.04 guests, as containers
and VMs. Claude Code is the MCP client.
