# Troubleshooting

## First: `doctor`

In the server container (`pct enter <ctid>` on the host):

```
runuser -u pvewarden -- pvewarden doctor        # add -v to see what each check saw
```

It checks the config, the Proxmox API and the token's privileges (too few *and* too many). Then it
connects over SSH to every guest in the pool. Every failure comes with a hint. `pvewarden-setup`
runs the same check at the end of the install.

## Logs

All paths are in the server container.

| What | Where |
|---|---|
| Server log, errors | `journalctl -u pvewarden` |
| Every tool call and its outcome | `/var/lib/pvewarden/audit.jsonl` |
| Full apt output of each update | `/var/lib/pvewarden/runs/<time>_<vmid>_<name>_<mode>.log` |
| Snapshots, rollbacks, reboots | Proxmox UI → node → Task History (user `pvewarden@pve`) |
| The last update, on the guest itself | `/var/lib/pvewarden/upgrade.log` |

## Connecting the agent

**`DEPTH_ZERO_SELF_SIGNED_CERT` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `self-signed certificate in
certificate chain`:** the client does not trust the server's certificate.
- Run the trust command from `pvewarden-setup connect`.
- Open a **new** terminal and restart the agent: `NODE_EXTRA_CA_CERTS` is read only at start.
- Check that the variable points to the file the command saved. An old file from a previous install
  will not work.

**`401 unauthorized`:** wrong or old token. Tokens change with `pvewarden-setup token`; update the
client (`claude mcp remove pvewarden`, then add it again).

**`421 Misdirected Request` / `Invalid Host header`:** the URL uses a name or address the server does
not know. Use the address from the summary, or add the name to `[http] hostnames`.

**Connection refused or timeout:**
- Is the service running? Check `systemctl status pvewarden` in the container.
- Did the container's address change? The server listens on the address it had at install time. If
  DHCP gave it a new one, check `ip -4 addr` in the container, then either restore the old address
  (DHCP reservation) or set `[http] listen` to the new one, run `pvewarden-setup renew-cert` and
  restart.
- Firewall: the agent must reach TCP 8765.

## Guests

**A guest is missing from `list_guests`:** it is not in the `pvewarden` pool. Enroll it with
`pvewarden-setup enroll`, or add it to the pool in the Proxmox UI.

**"missing the Proxmox tag 'pvewarden-update'":** working as intended. Add the tag in the Proxmox
UI if agents should update that guest.

**"the last pvewarden update needs a human":** pvewarden cannot tell what happened to an update,
for example the guest was rebooted while dpkg ran. It blocks every change to that guest until you
have looked. In the guest, check with `dpkg --audit` (fix with `dpkg --configure -a`) and look at
`/var/lib/pvewarden/upgrade.log`. Then, in the server container:
`runuser -u pvewarden -- pvewarden pending clear <vmid>`. `pvewarden pending list` shows what is
blocked and why.

**"another pvewarden operation on guest … is in progress":** pvewarden makes one change per guest at
a time. Wait for the other one (often an update) to finish.

**"has no pvewarden key of its own yet":** the guest was enrolled before 0.1.2, or enrolling it
stopped halfway. Enroll it again: `pvewarden-enroll <vmid>`.

**SSH "Permission denied":** the guest's client is missing, it accepts the key only from another
address (`from=` in `~pvewarden/.ssh/authorized_keys`, e.g. after the server's address changed), or
it has a different key than the server. Re-enroll the guest.

**"the guest's host key changed":** expected after reinstalling the guest. In the server container:
`ssh-keygen -R pvewarden-vmid-<vmid> -f /var/lib/pvewarden/known_hosts`

**A VM has no address / "does not resolve":** `qemu-guest-agent` is not running in the VM, or the
*QEMU Guest Agent* option is off in Proxmox. Alternatively, set the address in `[addresses]`.

**The wrong address of a guest is used** (e.g. a Docker bridge): set `[ssh] subnets` to your guest
network.

**"runs an outdated pvewarden client":** re-enroll the guest (`pvewarden-enroll --all` refreshes all).

## Updates

**"is being backed up by Proxmox right now (lock 'backup')":** wait for the backup to finish. Then
ask the agent again. Better: don't patch during your backup schedule. Even when a guest is not
locked itself, a running backup job makes updates on that node slow (`check_updates` shows
`backup_running`).

**"locked in Proxmox (lock 'snapshot' / 'rollback' / ...)":** an earlier operation was interrupted.
Check the task log. If nothing is running, clear the lock on the host with `pct unlock <vmid>` or
`qm unlock <vmid>`.

**Snapshot fails ("snapshot feature is not available"):** the guest's disk is on storage without
snapshots (plain LVM, raw files). Move the disk to ZFS, LVM-thin, Ceph or qcow2. pvewarden does not
skip the snapshot on its own; with your confirmation, an update without one is possible.

**`still_running`:** the update took longer than pvewarden waits (30 minutes) and goes on in the
guest. The agent calls `update_result` to wait for it. Until then, no other update, reboot or
rollback of that guest is accepted.

**`nothing_to_install` but `check_updates` lists packages:** those packages are third-party, held,
or (for `mode=security`) not security updates. Nothing pvewarden would install is pending.

**apt errors in the result:** read the full log in `runs/`. Common causes are a broken mirror,
`dpkg` interrupted earlier (fix it with `dpkg --configure -a` on the guest), or no disk space.

**Updates nobody asked for:** `check_updates` shows `auto_updates: true` for guests that install
updates by themselves every day (unattended-upgrades). Those updates are made without a snapshot.
Turn them off with `pvewarden-enroll --auto-updates off <vmid>`, or keep them on knowingly.

## Confirmation dialogs

**"this MCP client cannot ask the user (no elicitation support)":** your client does not show
pvewarden's confirmation dialogs. Do the action in the Proxmox UI, use a client that supports MCP
elicitation (Claude Code does), or relax `[policy] confirm_destructive` (see
[configuration.md](configuration.md#policy)).

**"the user did not confirm this action":** you declined, or closed the dialog. Nothing was changed.
