# pvewarden

**Agent-safe patching of Proxmox VE guests over MCP.**

pvewarden lets an AI agent keep your Proxmox VMs and containers up to date. It works with Claude Code
or any other MCP client. The agent checks pending updates, takes a snapshot, installs, reboots and
verifies services. It never gets a shell or root. It can only call a small set of tools, and Proxmox
and the server decide what it may do, not the prompt.

> **Status:** v0.1, the first release. Tested on Proxmox VE 9 with Debian 12/13 and Ubuntu
> 22.04/24.04/26.04 guests, containers and VMs. Feedback and issues are welcome.

[Česky](docs/cs/README.md)

```
You:    What updates are pending?
Agent:  ct101 (Debian 13): 4 security updates. vm110 (Debian 13): nothing pending.
        ct100 (Ubuntu 24.04): 12 updates, 3 of them security; docker-ce 29.1 → 29.2 comes from a
        third-party repository, so pvewarden only reports it.
You:    Install the security updates.
Agent:  ct101: snapshot pvewarden_20261031_145241, 4 packages installed, services OK, no reboot needed.
        ct100: the guest is being backed up by Proxmox right now. Nothing was changed; I'll try
        again when the backup is done.
```

## Why it is safe to hand to an agent

| Risk | What pvewarden does |
|---|---|
| The agent touches guests it should not | It only sees guests in the `pvewarden` pool. Updates need the Proxmox tag `pvewarden-update` and reboots need `pvewarden-reboot`. Only you set the tags. |
| The agent gets a shell | On guests, the server's SSH key is bound to a forced command that accepts a handful of fixed command words (`check`, `status`, `upgrade-security`, …). No shell, no port forwarding. |
| A compromised guest reaches others | Every guest has its own SSH key and accepts only that one. Whatever address a guest reports, the server cannot be sent to another guest. |
| A stolen token unlocks Proxmox | The Proxmox API token has a role limited to the pool. It can see guests, take snapshots, roll back and power-manage them. It cannot create, delete, reconfigure or reach the host. |
| A bad update breaks a guest | A snapshot comes first, automatically. If the snapshot fails, nothing is installed. |
| The agent "solves" a problem its own way | Rollback, snapshot deletion and updates without a snapshot need *your* click in a dialog that the agent cannot answer (MCP elicitation). |
| An update pulls in something unexpected | Only the distribution's official archives are used. Third-party repositories (Docker, PHP, …) and held packages are reported, never installed. No release upgrades. |
| A backup or a dropped connection interrupts an update | Updates wait while Proxmox locks the guest, e.g. during a backup. They run detached on the guest, so a dropped connection does not stop dpkg halfway. |
| Nobody knows what happened | Every call is written to an audit log with the client's name. Every update keeps its full apt output. |

Details: [docs/security.md](docs/security.md).

## Requirements

- Proxmox VE 8 or 9. You run the installer as root on a node.
- Guests: Debian 12/13 or Ubuntu 22.04+, as LXC containers or VMs.
  - VMs need `qemu-guest-agent` running, so pvewarden can find their address and enroll them.
- An MCP client that supports streamable HTTP. Claude Code works. For the confirmation dialogs the
  client must support MCP elicitation. Without it, rollback and the other confirmed actions are
  refused; see [configuration](docs/configuration.md#policy).
- Network: the agent's computer must reach the pvewarden container on TCP 8765. The container
  must reach the guests over SSH.

## Install

On a Proxmox node, as root:

```
curl -fsSLO https://github.com/matousfiser/pvewarden/releases/latest/download/pvewarden-setup
less pvewarden-setup        # it is a readable shell script, worth a look before running it as root
bash pvewarden-setup
```

`pvewarden-setup` checks the checksum of everything it downloads. To check the script itself, compare
`sha256sum pvewarden-setup` with `SHA256SUMS` on the [release page](https://github.com/matousfiser/pvewarden/releases/latest).

The wizard asks a few questions and then:

1. creates a pool, a minimal role and an API token limited to that pool,
2. creates a small Debian container that runs the server (512 MB RAM),
3. issues the server's HTTPS certificate, signed by your Proxmox CA,
4. offers to **enroll guests**. Enrolling installs a restricted `pvewarden` user on each guest,
   adds it to the pool and sets the tags you pick.
5. ends with a summary: the MCP address, a one-time token and a paste-ready command for your computer.

Nothing runs on the Proxmox host afterwards. Step by step, plus manual install, upgrade and removal:
[docs/install.md](docs/install.md).

## Connect your agent

The install summary prints everything you need. `pvewarden-setup connect` prints it again, without
the token. For Claude Code it comes down to:

1. Trust the server's certificate once with the printed command. It downloads the CA, checks its
   fingerprint and sets `NODE_EXTRA_CA_CERTS`.
2. Add the server:
   ```
   claude mcp add --scope user --transport http pvewarden https://<server>:8765/mcp --header "Authorization: Bearer <token>"
   ```
3. Restart Claude Code and ask: *"What updates are pending?"*

Other clients, agents in containers and HTTP behind a VPN: [docs/clients.md](docs/clients.md).

## Tools

| Tool | What it does | Needs |
|---|---|---|
| `list_guests` | Guests in the pool, their status, tags and permissions | – |
| `check_updates` | Pending updates per guest: security or not, official or third-party, reboot needed, automatic updates on, Proxmox locks | – |
| `check_services` | systemd state and failed units | – |
| `list_snapshots` | Snapshots of a guest; marks the ones pvewarden took | – |
| `snapshot_guest` | Take a snapshot | `pvewarden-update` |
| `apply_updates` | Snapshot, install (`security` or `all`), compare services before and after | `pvewarden-update`; your confirmation for `snapshot=false` |
| `update_result` | Wait for an update that is still running and return its result | `pvewarden-update` |
| `reboot_guest` | Reboot through Proxmox and wait until the guest answers | `pvewarden-reboot` |
| `rollback_snapshot` | Roll back to a pvewarden snapshot and start the guest | `pvewarden-update` + your confirmation |
| `delete_snapshot` | Delete one pvewarden snapshot | `pvewarden-update` + your confirmation |
| `delete_old_snapshots` | Delete pvewarden snapshots older than N days | `pvewarden-update` + your confirmation |

pvewarden only rolls back or deletes snapshots it took itself (`pvewarden_*`).

## What changes on a guest

Enrolling a guest:

- adds a system user `pvewarden` with one SSH key, made for this guest only. The key accepts only
  connections from the server's address and only the forced command `/usr/local/sbin/pvewarden-gate`.
- adds `/usr/local/sbin/pvewarden-guest` and `/etc/sudoers.d/pvewarden`, which allow exactly five
  commands as root.
- installs `unattended-upgrades` and `sudo` if they are missing. pvewarden uses `unattended-upgrade`
  to install only from official archives.
- **automatic updates:** pvewarden does not change your setting unless you choose to. Installing
  `unattended-upgrades` turns on daily automatic updates on Debian, which then happen without a
  pvewarden snapshot. The enroll dialog therefore asks: *keep* (default), *off* or *on*. *off* and
  *on* are written to `/etc/apt/apt.conf.d/52pvewarden-auto-upgrades`. `check_updates` always
  reports the current state.
- keeps the last update's log in `/var/lib/pvewarden`.

`pvewarden-enroll --uninstall <vmid>` removes all of it. It leaves `unattended-upgrades` and `sudo`
installed, since other things may use them.

## Known limitations (v0.1)

- **Fixed server address.** The server listens on the address its container had at install time.
  Give the container a static IP or a DHCP reservation. After a change, reinstall or edit `listen` in
  the config and run `pvewarden-setup renew-cert`.
- **Avoid backup windows.** pvewarden waits while a guest is being backed up, but updates on a node
  that is busy with a backup job are slow. Don't patch during your backup schedule.
- **No browser clients.** Requests carrying an `Origin` header are refused (DNS-rebinding protection).
  Desktop and CLI agents are not affected.
- **Debian and Ubuntu guests only.** Other distributions are refused, not guessed at.
- **One guest per call.** `apply_updates` handles one guest at a time; the agent loops over them.
- **Interactive use.** pvewarden has no scheduler. An agent patches when you ask it to.

## Documentation

- [Install, upgrade, remove](docs/install.md)
- [Connecting MCP clients](docs/clients.md)
- [Configuration](docs/configuration.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

[Apache-2.0](LICENSE)
