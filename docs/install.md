# Install, upgrade, remove

Everything is done by one script, `pvewarden-setup`, run as root on a Proxmox VE node. Without
arguments it shows a menu. With a command it goes straight to that task:

| Command | What it does |
|---|---|
| `install` | Set up Proxmox access, create the server container, enroll guests |
| `enroll` | Add guests (or change what agents may do on them) |
| `connect` | Show again how to connect an agent (without the token) |
| `token [name]` | Give an agent a new token; the old one stops working at once |
| `renew-cert` | New HTTPS certificate, e.g. after the server's address changed |
| `upgrade` | Update the server and the host tools to this script's version |
| `uninstall` | Remove pvewarden from guests, Proxmox and this host |

Options: `--dry-run` shows what would be done and changes nothing. `--yes` answers every question
with its default (see [Unattended install](#unattended-install)). `--source DIR|TARBALL` installs a
local copy instead of downloading the release.

## Before you start

- **Proxmox VE 8 or 9.** In a cluster, run the script on one node; the container lives there.
- **A fixed address for the server.** Agents connect to it and the certificate is issued for it.
  Choose a static IP in the wizard or reserve the DHCP address in your router.
- **Guests:** Debian 12/13 or Ubuntu 22.04 and newer, running, with network access to their package
  mirrors. VMs need `qemu-guest-agent` installed and the *QEMU Guest Agent* option enabled in
  Proxmox. pvewarden uses it to install its client and to find the VM's address.
- **Storage:** pvewarden takes snapshots of guests before updates, so guest disks must be on storage
  that supports snapshots (ZFS, LVM-thin, Ceph RBD, qcow2 files). Snapshots of guests on plain LVM or
  raw files fail, and updates of those guests are refused.

## Install

```
curl -fsSLO https://github.com/matousfiser/pvewarden/releases/latest/download/pvewarden-setup
less pvewarden-setup
bash pvewarden-setup install
```

The questions, in order:

1. **Container settings.** *Default* uses a Debian container with 1 core, 512 MB RAM, 4 GB disk, the
   next free ID and the first bridge. *Advanced* lets you set ID, hostname, storage, size, bridge
   and VLAN.
2. **Network.** An IPv4 address with prefix (e.g. `192.168.1.50/24`) and gateway, or `dhcp`. Then,
   optionally, IPv6, DNS servers and search domain; empty means the same as the host.
3. **Root password** for the container. Empty means no password; you can still use `pct enter`.
4. **SSH keys** for root in the container: from your GitHub or GitLab account (the public keys at
   `github.com/<user>.keys`), pasted, from a file or a URL, or none. The wizard shows the fingerprints
   of every key it adds, so you can compare them with your own.
5. **How agents reach the server.**
   - *HTTPS on the container's address* (recommended). The certificate is signed by your Proxmox
     cluster's CA. Clients trust that CA once with a command from the summary.
   - *My own address*, e.g. a WireGuard IP you configure in the container yourself. You can choose
     plain HTTP here, which is fine inside an encrypted VPN.
6. **Name of the first agent.** It appears in the audit log and in snapshot descriptions.
7. **Review.** The wizard lists everything it is about to create. Nothing happens before you confirm.

Then it:

- creates the Proxmox pool `pvewarden`, the role `Warden`, the API-only user `pvewarden@pve` and its
  token. The token is granted only on the pool and goes straight into the server's config; it is
  never shown. Role privileges: `VM.Audit`, `VM.Snapshot`, `VM.Snapshot.Rollback`, `VM.PowerMgmt`,
  plus `VM.GuestAgent.Audit` on PVE 9 or `VM.Monitor` on PVE 8 (to read VM addresses).
- creates the container (unprivileged, starts at boot) and installs the server in it.
- issues the HTTPS certificate. Its private key is created in the container and never leaves it.
- installs `pvewarden-enroll` on the host and asks whether to **enroll guests** now (see below).
- starts the server, runs its self-check (`pvewarden doctor`) and prints the summary.

The summary contains the MCP address, the agent's token and the commands to connect an agent. **The
token is shown only once.** If you lose it, `pvewarden-setup token` makes a new one. See
[clients.md](clients.md) for connecting.

## Enroll guests

`pvewarden-setup enroll` (or the question at the end of the install) shows a checklist of guests.
Then it asks:

- **What agents may do** on them:
  - *read only:* no tags,
  - *install updates:* tag `pvewarden-update`,
  - *install updates and reboot:* tags `pvewarden-update` and `pvewarden-reboot`.
- **Automatic updates**, which are the guest's own daily unattended-upgrades:
  - *keep* (default) leaves each guest's setting alone,
  - *off* means only pvewarden installs updates, always with a snapshot,
  - *on* means guests also update themselves daily.

Enrolling adds the guest to the pool, merges the tags and installs the client. It is safe to run
again: re-enrolling refreshes the client, for example after an upgrade of pvewarden. What the client
changes on a guest is listed in the [README](../README.md#what-changes-on-a-guest).

The same from the command line:

```
pvewarden-enroll --pool --tags pvewarden-update,pvewarden-reboot 101 102 110
pvewarden-enroll --all                  # refresh the client on every guest in the pool
pvewarden-enroll --uninstall 102        # remove the client from a guest
```

**Changing permissions later:** edit the tags in the Proxmox UI (guest → Summary → tags). Removing
`pvewarden-update` makes a guest read-only for agents. Removing a guest from the `pvewarden` pool
hides it from pvewarden entirely.

## Upgrade

Download the new `pvewarden-setup` and run:

```
bash pvewarden-setup upgrade
```

This updates the server in its container and the tools on the host. The configuration, tokens, guest
keys, audit log and certificate are kept. It then offers to enroll every guest again
(`pvewarden-enroll --all`), which updates their client. Say yes unless you know the guest client did
not change. Guests keep their automatic-updates setting.

**From 0.1.1 or older:** guests used to share one SSH key; since 0.1.2 each has its own. Enrolling
again switches them, and the server refuses a guest until it is switched. Once every guest has its
own key, the upgrade removes the old shared key from the server.

## Uninstall

```
bash pvewarden-setup uninstall
```

It removes, in this order:

1. the client from every guest in the pool,
2. the token, user, role and pool in Proxmox, but only those that `pvewarden-setup` created (or that
   you told it to take over). Guests stay; only their pool membership goes.
3. the tools on the host.

Guest tags are left in place. The container (with the audit log) is destroyed only if you confirm
that separately. Snapshots pvewarden took are not deleted; remove them in the Proxmox UI if you like.

## Unattended install

With `--yes`, every question takes its default or the value of an environment variable named
`PVEWARDEN_<QUESTION>`:

```
PVEWARDEN_IP=192.168.1.50/24 PVEWARDEN_GW=192.168.1.1 \
PVEWARDEN_SSH_KEYS=gh:octocat PVEWARDEN_ENROLL="101 102" PVEWARDEN_LEVEL=update \
  bash pvewarden-setup install --yes
```

Useful variables include `CTID`, `IP`, `GW`, `ROOT_PASSWORD`, `SSH_KEYS` (`gh:<user>`, `gl:<user>`,
or a URL), `ACCESS` (`https` or `custom`), `LISTEN`, `USE_TLS`, `AGENT_NAME`, `ENROLL` (VMIDs),
`LEVEL` (`readonly`, `update`, `reboot`) and `AUTO_UPDATES` (`keep`, `off`, `on`). Try it with
`--dry-run` first.

If Proxmox already has a pool `pvewarden`, a role `Warden` or a user `pvewarden@pve` that the
installer did not create, it stops before changing anything. Interactively it asks whether to take
them over; unattended, `PVEWARDEN_ADOPT_EXISTING=yes` does. Taking over sets the role's privileges
(every user with that role gets exactly these) and lets `uninstall` delete the objects.

## Manual install

If you would rather not use the wizard, for example to run the server outside Proxmox, these are
the pieces. The wizard does exactly this.

**1. Proxmox access** (on a node, as root):

```
pveum pool add pvewarden --comment "guests pvewarden may manage"
pveum role add Warden --privs VM.Audit,VM.Snapshot,VM.Snapshot.Rollback,VM.PowerMgmt,VM.GuestAgent.Audit
pveum user add pvewarden@pve --comment "pvewarden (API only, no login)"
pveum acl modify /pool/pvewarden --users pvewarden@pve --roles Warden
pveum user token add pvewarden@pve server --privsep 0
```

On PVE 8 use `VM.Monitor` instead of `VM.GuestAgent.Audit`. Keep the token secret for step 2.

**2. Server** (Debian or Ubuntu with Python 3.11+, from a checkout of this repository):

```
deploy/install-server.sh <listen-address>
```

It installs the server into `/opt/pvewarden`, creates the service user, and writes
`/etc/pvewarden/config.toml` with a fresh agent token. Fill in the `[proxmox]` section (see
[configuration.md](configuration.md)), then check and start:

```
runuser -u pvewarden -- pvewarden doctor
systemctl start pvewarden
```

**3. Guests:** add the guest to the `pvewarden` pool and set its tags in the Proxmox UI. Each guest
gets its own key. On the server, make it:

```
runuser -u pvewarden -- pvewarden key new <vmid>
```

Copy the `guest/` directory to the guest and run, as root, with the printed public key:

```
guest/install.sh "<public key>" <server address as the guest sees it>
```

Back on the server, check the key works, then make it active:

```
runuser -u pvewarden -- pvewarden key verify <vmid>
runuser -u pvewarden -- pvewarden key activate <vmid>
```

`pvewarden-enroll` does the same from a Proxmox node. To use it with a server outside Proxmox, set
`SERVER_CMD` in `/etc/pvewarden/enroll.conf` to a command that runs `pvewarden` on the server, e.g.
`SERVER_CMD="ssh root@warden runuser -u pvewarden -- pvewarden"`, plus `FROM=<server address>`.
