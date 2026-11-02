# Changelog

## Unreleased

From a code review; no new features.

- **Upgrading needs 0.1.3 or newer.** The code that migrated installs from 0.1.0 to 0.1.2 is gone
  (shared guest SSH key, unrecorded ownership of the pool, role and user, the old enroll.conf, the
  pip-installed server, guest clients without `services`). To upgrade an older install: uninstall
  and install again.
- Fix: the install refused an agent name with spaces or dots only after the container existed (the
  config could not hold it). It is now checked when it is asked, like `pvewarden-setup token` does.
- Fix: the install left `umask 077` in effect after writing the server config, so the host's files
  written after it (enroll.conf, /opt/pvewarden) were readable by root only.
- `pvewarden-setup renew-cert` turns HTTPS on with the new `pvewarden config enable-tls` in the
  container, which validates the config before writing it, instead of sed. The certificate is now
  in place before the config names it.
- The upgrade's question about enrolling the guests again says what it does today: it updates the
  guest client (each guest gets a fresh key; permissions and automatic updates stay).
- Docs are tool-neutral: docs/wireguard.md became docs/vpn.md, a guide for any VPN with WireGuard
  as one example; docs/clients.md describes proxies that add credentials in general. The service
  no longer orders itself after `wg-quick@wg0`: it retries every 10 s until its address exists,
  whatever the VPN.
- Smaller code: shared helpers in pvewarden-setup (installing the server code, restarting the
  service, the MCP address, the install check) and in the server (snapshot confirmations, the
  update check, HTTP responses).

## 0.1.5 (2026-11-02)

Clearer install, from the first production install:

- The root password of the server container is described as what it is: console and `pct enter`
  only. Debian refuses root passwords over SSH; the wizard now says so and points to SSH keys.
- Reaching the server through a VPN: the wizard explains the two addresses (LAN for the guests, VPN
  for the agents). A VPN address that is not up yet at the end of the install is the next step, not
  a failure: the summary says what to do, and the server starts by itself within 10 s once the
  address exists. New guide: docs/wireguard.md (also in Czech).
- `pvewarden-setup renew-cert` switches an install made with plain HTTP to HTTPS on the same address
  (certificate signed by the Proxmox CA; tokens stay). With a VPN address, the wizard now defaults
  to HTTPS too: some MCP clients refuse a remote server over plain HTTP.
- Enrolling: VMs whose QEMU guest agent does not answer are no longer offered (and skipped with
  `--yes`); the wizard lists them with the steps to add the agent, including the power cycle.
- New `pvewarden-setup doctor [-v]`: the server's self-check from the host, without `runuser` and
  full paths. "run as root" now says `sudo -i`.
- Automatic updates: the wizard says what on and off mean; doctor lists the guests where they are
  on as one `[INFO]` line with how to turn them off, instead of a note on every guest.
- Docs: checking the downloaded script is optional (pvewarden-setup checks what it downloads);
  the upgrade steps no longer require it.

## 0.1.4 (2026-11-02)

- Fix: `pvewarden-setup upgrade` installed the version recorded in `/etc/pvewarden/setup.conf`
  (the one installed last) instead of its own. 0.1.3 therefore switched to the newest setup, which
  installed the old version again; the downgrade blamed on an old script in 0.1.3 had this cause.
- **Upgrading:** from 0.1.3, `pvewarden-setup upgrade` switches to 0.1.4's setup by itself. From
  0.1.2 or older, download the current `pvewarden-setup` first (docs/install.md).

## 0.1.3 (2026-11-02)

- `pvewarden-setup upgrade` first switches to the newest release's `pvewarden-setup` (checksum
  checked) and lets it do the upgrade. Before, the installed script installed its own version, so
  an old script could downgrade the server: 0.1.0's setup put 0.1.0 back over 0.1.2.
- The upgrade refuses to install an older version than the server runs, before changing anything
  (`--allow-downgrade` to do it anyway).
- **Upgrading from 0.1.2 or older:** download the current `pvewarden-setup` first (docs/install.md).

## 0.1.2 (2026-11-01)

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
- Writes of that record are fsynced together with its directory (and the directory's creation), so
  on file systems that honour fsync it survives a power loss.
- Enrolling a guest takes its lock in each step, and a new key is refused while an update's result
  is unknown.

**Audit log**
- A call that is cancelled (client gone, server stopping) still gets its `tool_result` record
  (`cancelled`).
- Every tool call gets an id and two records: `tool_call` (agent, IP, arguments) before it runs and
  `tool_result` (`ok`, `error` with the reason, or `asked_user`, and the duration) after. Records
  written in between carry the same id. Before, errors and refusals had no outcome record.
- A tool that changes something does not run if its `tool_call` record cannot be written.
- Refused requests are summarised per address and minute (`http_denied_summary` with a count)
  instead of one line each, so a flood of them cannot fill the disk.
- The HTTP layer no longer reads every request body into memory for the audit log.

**Limits**
- Requests larger than 1 MiB are refused (413), also when they are streamed.
- More than 16 MiB of output from one guest command is refused; the run log stays as small. Output
  is read in blocks, so one endless line from a guest cannot break reading.
- The server rotates its audit log weekly (a year kept, `logrotate`) and removes run logs older than
  180 days (`systemd-tmpfiles`).

**Supply chain**
- `requirements.lock` pins every dependency with SHA-256 hashes. The server installs them with
  `--require-hashes --only-binary=:all:`: no unpinned build tools, no pip upgrade from the network.
  pvewarden itself is copied from the checked source instead of being built.
- Release files get a signed build provenance attestation
  (`gh attestation verify <file> -R matousfiser/pvewarden`).

**Rollback**
- After every rollback pvewarden waits until the guest answers again and reports its state, also
  when the guest kept running (before, only when it had to start it).
- The security model documents what a snapshot is (disk only, crash-consistent; file system
  consistent with the guest agent's freeze) and what that means for databases.
- Open, accepted as lower priority for now: snapshots are recognised as pvewarden's by their name
  prefix alone (rollback and deletion still need the user's confirmation). Planned for a later release.

**Installer**
- A pool, role or user with pvewarden's names that the installer did not create is no longer taken
  over silently: the install stops before any change, or takes them over only when you say so
  (dialog, or `PVEWARDEN_ADOPT_EXISTING=yes`). Before, it rewrote an existing `Warden` role's
  privileges and `uninstall` deleted such objects. `uninstall` now deletes only what the installer
  created or took over (`/etc/pvewarden/owned.conf`); upgrades record the objects of older installs.
- Upgrading an install from before 0.1.2 no longer records the pool, role and user as created by
  pvewarden: older installers may have taken over existing ones. The upgrade asks (default no;
  `PVEWARDEN_ADOPT_EXISTING=yes` with `--yes`). `uninstall` always removes pvewarden's API token,
  also from a user it leaves in place, and prints how to remove what it left.
- When a step fails, `pvewarden-setup` says so instead of stopping without a word.
- When a guest refuses the server's new key because the server's address changed (DHCP),
  `pvewarden-enroll` says so; docs/troubleshooting.md has the steps to move to a new address.

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
