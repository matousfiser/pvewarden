# Security model

pvewarden gives an AI agent a narrow, well-defined way to patch your guests. This page says what the
agent can and cannot do, what protects each part, and what remains your responsibility.

## Components and trust

```
 agent (MCP client) ──HTTPS + token──▶ pvewarden server (LXC) ──API token──▶ Proxmox API
                                              │
                                              └──SSH key, forced command──▶ guests
```

| Part | Holds | Can |
|---|---|---|
| Agent | an MCP token | call pvewarden's tools, nothing else |
| pvewarden server | MCP tokens, Proxmox API token, SSH private key | everything below, on behalf of agents |
| Proxmox API token | role `Warden` on pool `pvewarden` | see pool guests, snapshot, roll back, start/stop/reboot, read VM addresses |
| SSH key on guests | user `pvewarden` | run a handful of fixed commands, some via sudo |
| `pvewarden-setup` | root on the host, only while it runs | create the above; nothing stays running on the host |

The server is the valuable target. Keep its container on a management network and don't run other
services in it.

## What an agent can do

Everything goes through the tools listed in the [README](../README.md#tools). On top of that:

- **Only guests in the pool.** The Proxmox token cannot see anything else. Guests outside the pool
  do not exist for pvewarden.
- **Tags decide.** Without `pvewarden-update` a guest is read-only. Without `pvewarden-reboot` it is
  never rebooted. Agents cannot set tags: the token lacks `VM.Config.Options`.
- **You confirm the irreversible.** Rollback, snapshot deletion and updates without a snapshot need
  a click in a dialog in your MCP client (`[policy] confirm_destructive`). The dialog goes to the
  user, not to the model. A confused or prompt-injected agent cannot answer it.
- **Only official packages.** Updates come from the distribution's own archives (Debian, Debian
  security, Ubuntu, Ubuntu security/ESM), whatever else the guest has configured. pvewarden
  enforces this by running `unattended-upgrade` with its own origin list. Third-party repositories
  and held packages are only reported. Release upgrades are not possible.
- **Snapshots first.** `apply_updates` refuses to run if the snapshot fails. Snapshots are named
  `pvewarden_*`, and pvewarden only rolls back or deletes its own.
- **Proxmox locks are respected.** A guest being backed up or migrated is left alone.

## What an agent cannot do

- run arbitrary commands on guests or on the host, open a shell or forward ports,
- create, delete, clone, migrate or reconfigure guests, or touch storage, network or users,
- change tags, the pool or pvewarden's own configuration,
- install from third-party repositories or upgrade to a new distribution release,
- roll back to or delete snapshots that pvewarden did not take.

## Guests: the forced command

Each guest's `~pvewarden/.ssh/authorized_keys` has exactly one line:

```
restrict,from="<server address>",command="/usr/local/sbin/pvewarden-gate" ssh-ed25519 ...
```

- `restrict` disables port, agent and X11 forwarding and the PTY.
- `from=` accepts the key only from the server's address.
- `pvewarden-gate` compares the requested command with a fixed list: `check`, `status`, `services`,
  `upgrade-security`, `upgrade-all`, `upgrade-follow`. Anything else is refused, including
  arguments and shell syntax. `services` runs as the unprivileged user. The others run via sudo as
  `/usr/local/sbin/pvewarden-guest <command>`, and `/etc/sudoers.d/pvewarden` allows exactly those
  five commands.
- The scripts are owned by root and not writable by `pvewarden`.

Updates run detached from the SSH session (a transient systemd unit), so a dropped connection or a
timeout cannot interrupt dpkg halfway.

## Tokens and network

- **MCP tokens** are random, at least 32 characters, one per agent, and compared in constant time.
  Each tool call is written to the audit log with the agent's name and IP. Rotate with
  `pvewarden-setup token <name>`. Treat a token like a password: it allows everything the tags allow.
- **Transport:** HTTPS with a certificate signed by your Proxmox CA, or plain HTTP inside a VPN you
  trust. Requests are refused if their `Host` header is not the server's address or a configured
  name. They are also refused if they carry a browser `Origin` header. Both protect against DNS
  rebinding.
- **Proxmox API token:** stored only in the server's config. It never passes through the agent or
  through `pvewarden-setup`'s output. Its certificate is pinned to the Proxmox CA.
- **SSH key:** generated in the server container. Only the public half is copied to guests.
- **Setup** never prints the Proxmox token. It shows the agent token once, at the end. The HTTPS
  private key is created in the container and never leaves it; only a signing request goes to the
  host.

## Audit trail

- `state_dir/audit.jsonl`: one JSON line per event. It records tool calls (agent, IP, arguments),
  refused requests, snapshots (with the agent's name), updates (snapshot, exit code, reboot needed,
  newly failed services), reboots, rollbacks and deletions.
- `state_dir/runs/`: the complete apt output of every update.
- Proxmox's own task log shows every snapshot, rollback and reboot as user `pvewarden@pve`.
- Snapshot descriptions name the agent, e.g. `before security updates (client: claude)`.

## Your responsibility

- **Who holds a token.** Anyone with a token acts as that agent.
- **What you tag.** Give `pvewarden-update` to guests where a snapshot is an acceptable safety net.
  For a database server, a rollback also discards data written since the snapshot.
- **The server container.** Keep it updated (`apt upgrade` in it) and restrict who can reach port 8765.
- **The agent's own permissions.** pvewarden limits what the agent can do *through pvewarden*. If
  the same agent also has a shell on your machine or other MCP servers, those are separate.

## Reporting a vulnerability

Please report security issues privately via GitHub's *Report a vulnerability* (Security tab), not in
public issues.
