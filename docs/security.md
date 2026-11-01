# Security model

pvewarden gives an AI agent a narrow, well-defined way to patch your guests. This page says what the
agent can and cannot do, what protects each part, and what remains your responsibility.

## Components and trust

```
 agent (MCP client) ──HTTPS + token──▶ pvewarden server (LXC) ──API token──▶ Proxmox API
                                              │
                                              └──one SSH key per guest, forced command──▶ guests
```

| Part | Holds | Can |
|---|---|---|
| Agent | an MCP token | call pvewarden's tools, nothing else |
| pvewarden server | MCP tokens, Proxmox API token, one SSH private key per guest | everything below, on behalf of agents |
| Proxmox API token | role `Warden` on pool `pvewarden` | see pool guests, snapshot, roll back, start/stop/reboot, read VM addresses |
| a guest's SSH key | user `pvewarden` on that guest only | run a handful of fixed commands, some via sudo |
| `pvewarden-setup` | root on the host, only while it runs | create the above; nothing stays running on the host |

The server is the valuable target. Keep its container on a management network and don't run other
services in it.

## Threat model

pvewarden is built to hold when one of these happens:

- **The agent is confused, wrong or prompt-injected.** It can only call the tools, the tags limit
  what they do, and the irreversible steps need your click.
- **An MCP token leaks.** The holder can do what the tags allow, nothing more, and is logged.
- **An enrolled guest is compromised** (root on it). It cannot use pvewarden to reach other guests:
  each guest accepts only its own key, so whatever address it reports, the server's connection on
  its behalf cannot log in anywhere else. It can lie about its own updates and services.

Not in scope: someone with root on the Proxmox host or in the server container (they hold the
keys), and anyone who can reach port 8765 and holds a token. Keep port 8765 on a network you trust
(management network, VPN).

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

## Guests: own key, forced command

Each guest has its own SSH key pair, made in the server container when the guest is enrolled. The
guest's `~pvewarden/.ssh/authorized_keys` has exactly one line, with that guest's public key:

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

The server picks the key by VMID, not by address. A VM's address comes from the guest agent and a
container's from its own network settings, so a guest could report another guest's address; with
its own key, the login there fails. Guest host keys are also remembered per VMID
(`HostKeyAlias=pvewarden-vmid-<vmid>`), as a second check.

Enrolling switches a guest to a new key in checked steps: the new key is added next to the old one,
the server logs in with it, then only the new key is left in the guest, and only then does the server
use it. If enrolling stops in between, the server refuses the guest until it is enrolled again; it
never falls back to another key. Enrolling again is also how to rotate a guest's key.

Updates run detached from the SSH session (a transient systemd unit), so a dropped connection or a
timeout cannot interrupt dpkg halfway.

## One change per guest

Every change to a guest holds a lock for that guest, so two changes never interleave. A running
update is also recorded on disk before anything changes (`state_dir/pending`). That record outlives
a server restart and blocks reboot, rollback, snapshots and further updates of the guest until the
update's result is known. The guest names each update run, and the block is lifted only when the
result is provably from that run or provably nothing ran. If pvewarden cannot tell, the guest stays
blocked until a human has checked it (`pvewarden pending clear`); the agent cannot lift it.

## Tokens and network

- **MCP tokens** are random, at least 32 characters, one per agent, and compared in constant time.
  Each tool call and its outcome is written to the audit log with the agent's name and IP. Rotate with
  `pvewarden-setup token <name>`. Treat a token like a password: it allows everything the tags allow.
- **Transport:** HTTPS with a certificate signed by your Proxmox CA, or plain HTTP inside a VPN you
  trust. Requests are refused if their `Host` header is not the server's address or a configured
  name. They are also refused if they carry a browser `Origin` header. Both protect against DNS
  rebinding.
- **Proxmox API token:** stored only in the server's config. It never passes through the agent or
  through `pvewarden-setup`'s output. Its certificate is pinned to the Proxmox CA.
- **SSH keys:** one per guest, generated in the server container (`state_dir/keys`). Only the public
  half is copied to that guest.
- **Setup** never prints the Proxmox token. It shows the agent token once, at the end. The HTTPS
  private key is created in the container and never leaves it; only a signing request goes to the
  host.

## Snapshots and rollback

What a pvewarden snapshot is, so you know what a rollback brings back:

- **Disk only, no RAM.** pvewarden asks Proxmox for a plain snapshot (no `vmstate`). Rolling back
  to it is like the guest losing power at that moment and booting again: the file systems are
  consistent (journaling), applications get what they had flushed to disk.
- **VMs with the guest agent:** if the VM's *QEMU Guest Agent* option has *freeze/thaw* on (the
  Proxmox default), Proxmox freezes the file systems for the snapshot. That makes it consistent at
  the file system level, still not at the application level.
- **Databases:** a crash-consistent copy is what their recovery is built for, but a rollback also
  throws away everything written since the snapshot. Tag database guests with care, or dump the
  database before you let an agent update them.
- **Storage:** what a snapshot costs and whether it is possible at all depends on the storage
  (ZFS, LVM-thin, Ceph, qcow2 yes; plain LVM or raw on directory storage no). If Proxmox cannot
  snapshot a guest, `apply_updates` refuses to update it.
- **After a rollback** Proxmox leaves the guest stopped; pvewarden starts it and reports only once
  the guest answers over SSH again, with its kernel and pending reboot state. It does this check
  after every rollback.

## Known open points

- **Which snapshots are pvewarden's** is decided by the name prefix `pvewarden_`. A snapshot someone
  else names that way can be rolled back to or deleted by an agent with the update tag. Not closed;
  accepted as lower priority because rollback and deletion require your confirmation in the client,
  which the agent cannot give. Planned for 0.1.3: a record of the snapshots pvewarden took.
- **A shared `[ssh] key`** is still accepted for guests whose address you fix in `[addresses]` (or
  static guests). There the address comes from you, not from a guest, so a guest cannot redirect
  it, but one key opens all of those guests. Prefer `pvewarden key new` per guest.
- **The installer does not check the provenance attestation**, only the checksum, and both come
  from the same GitHub release. A Proxmox host has no `gh`. Check it yourself before installing
  (see Supply chain) if a compromised release page is in your threat model.
- **Enrolling is several steps** (`pvewarden-enroll`). Each step on the server takes the guest's
  lock and a new key is refused while an update's result is unknown, but the whole enrollment is
  not one locked operation. A change the agent starts between two steps works with either key.
- **Audit records are not redacted.** Tool arguments are VMIDs, modes and snapshot names; guest
  output goes to the run logs, which are readable only by the service user.
- **Tested combinations.** Containers and VMs on Proxmox VE 9 with directory/LVM-thin storage and the
  guest agent. Other storage and older versions should behave the same but are less tested.

## Supply chain

- Releases are built by a GitHub Actions workflow after the full test suite, from the tagged commit.
  Actions are pinned to commit hashes. Each release has SHA-256 checksums and a signed build
  provenance (`gh attestation verify <file> -R matousfiser/pvewarden`).
- `pvewarden-setup` checks the checksum of the source it downloads.
- The server installs its Python dependencies only as wheels whose SHA-256 is in
  `requirements.lock`; nothing is built and pip is not upgraded from the network. pvewarden itself
  is plain Python, copied from the checked source.
- The checksum and the files come from the same GitHub release. The provenance attestation is the
  check that does not depend on the release page alone.

## Audit trail

- `state_dir/audit.jsonl`: one JSON line per event. Every tool call gets an id, a `tool_call` record
  before it runs (agent, IP, arguments) and a `tool_result` record after it (`ok`, `error` with the
  reason, `asked_user`, or `cancelled` when the client went away or the server stopped, plus the
  duration). What the call did in between carries the same id:
  snapshots, updates (snapshot, exit code, reboot needed, newly failed services), reboots,
  rollbacks, deletions. A tool that changes something does not run if its `tool_call` record cannot
  be written.
- Refused requests (no or wrong token) are summarised: the first one from an address is written at
  once, the rest of that minute as one `http_denied_summary` line with a count.
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
