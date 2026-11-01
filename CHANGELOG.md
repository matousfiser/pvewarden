# Changelog

## Unreleased

**Security**
- Every guest has its own SSH key, made on the server when the guest is enrolled. Before, guests
  shared one key and the server connected to whatever address a guest reported, so a compromised
  guest with the update tag could report another guest's address and have updates run there
  without a snapshot and without that guest's tags. Now the server picks the key by VMID and the
  other guest refuses it. Guest host keys are remembered per VMID too.
- Enrolling switches a guest to its new key in checked steps and never leaves it half switched: if a
  step fails, the server refuses the guest until it is enrolled again. Re-enrolling rotates the key.
- **Upgrading:** `pvewarden-setup upgrade` enrolls the guests again and then removes the old shared
  key. Guests that are not enrolled again are refused ("has no pvewarden key of its own yet").
- A shared `[ssh] key` is still possible, but only for guests whose address is fixed in the config.
- New `pvewarden key new|verify|activate|remove|list` for manual installs.

**One change per guest at a time**
- Every change to a guest (snapshot, update, waiting for an update, reboot, rollback, snapshot
  deletion) holds a lock for that guest; a second one is refused at once. Before, two updates of one
  guest called at the same time took two snapshots, and the second removed the first one's record of
  the running update, which unblocked reboot and rollback while dpkg ran.
- A running update is recorded before anything changes, with a random run id, and outlives a server
  restart. Only its own run removes it. The guest names each run, and `update_result` lifts the
  block only when the result is provably from that run, or when provably nothing ran
  (`never_started`). When pvewarden cannot tell (e.g. the update process vanished during dpkg), the
  guest stays blocked and a human clears it after checking: `pvewarden pending list|clear <vmid>`.
- A lost SSH connection during an update no longer counts as a failed update: the guest stays
  blocked and `update_result` picks it up.

**Audit log**
- Every tool call gets an id and two records: `tool_call` (agent, IP, arguments) before it runs and
  `tool_result` (`ok`, `error` with the reason, or `asked_user`, and the duration) after. Records
  written in between carry the same id. Before, errors and refusals had no outcome record.
- A tool that changes something does not run if its `tool_call` record cannot be written.
- Refused requests are summarised per address and minute (`http_denied_summary` with a count)
  instead of one line each, so a flood of them cannot fill the disk.
- The HTTP layer no longer reads every request body into memory for the audit log.

## 0.1.1 (2026-11-01)

- `pvewarden-setup`: the install summary, `connect` and `token` output are laid out in clear
  sections that fit 80 columns. Long commands start at the left edge, so they wrap cleanly and copy
  well. Colors appear on a terminal, never with `NO_COLOR` or when the output is redirected.
- The connection steps and the `token` output describe any MCP client first; Claude Code is one
  example.

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
