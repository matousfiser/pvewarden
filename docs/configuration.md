# Configuration

The server reads `/etc/pvewarden/config.toml` in its container, or the file named by
`$PVEWARDEN_CONFIG` or `--config`. `pvewarden-setup` writes it for you. You only edit it to change
the defaults below. The file holds secrets: keep it `root:pvewarden 0640`.

After a change, check and restart (in the container):

```
pvewarden check-config
runuser -u pvewarden -- pvewarden doctor
systemctl restart pvewarden
```

Unknown keys are an error, not silently ignored, so a typo shows up in `check-config`. The annotated
example is [config.example.toml](../config.example.toml).

## Top level

| Key | Default | |
|---|---|---|
| `state_dir` | `/var/lib/pvewarden` | Audit log (`audit.jsonl`), full apt output of every update (`runs/`), the guests' SSH keys (`keys/<vmid>`), SSH `known_hosts`, updates still running (`pending/`) |

## `[proxmox]`

| Key | Default | |
|---|---|---|
| `host` | – (required) | Proxmox API host. It must match a name in the Proxmox certificate. |
| `port` | `8006` | |
| `token_id` | – (required) | e.g. `pvewarden@pve!server` |
| `token_secret` | – | Or set `$PVEWARDEN_PROXMOX_TOKEN_SECRET` instead. |
| `verify_tls` | `true` | `true` uses the system CAs. A path pins a CA file, e.g. a copy of `/etc/pve/pve-root-ca.pem` (what setup does). `false` turns checking off; don't. |

Without `[proxmox]` you must list `[[static_guests]]` (see below).

## `[ssh]`

How the server reaches guests.

| Key | Default | |
|---|---|---|
| `key` | – | A shared key, **only** for guests whose address is fixed in `[addresses]` or `static_guests`. Other guests always use their own key from `state_dir/keys`, made when they are enrolled. |
| `user` | `pvewarden` | |
| `subnets` | `[]` | Guests often report several addresses (Docker bridges, VPNs). pvewarden uses the first one inside these networks. Empty: the first non-loopback IPv4. |
| `parallel` | `5` | At most this many SSH sessions at once, e.g. during `check_updates` on all guests |
| `connect_timeout` | `10` | Seconds |

## `[policy]`

| Key | Default | |
|---|---|---|
| `tag_update` | `pvewarden-update` | Proxmox tag that allows updates, snapshots, rollback and snapshot deletion |
| `tag_reboot` | `pvewarden-reboot` | Proxmox tag that allows reboots |
| `confirm_destructive` | `required` | See below |

`confirm_destructive` controls three actions: rollback, snapshot deletion and updates without a
snapshot. For these, pvewarden asks **you** in a dialog in the MCP client (MCP elicitation). The
agent cannot answer that dialog.

- `required`: ask. If the client cannot show dialogs, refuse.
- `if-supported`: ask when the client can show dialogs, otherwise go ahead.
- `off`: never ask. The tags still apply.

Keep `required` unless your client lacks elicitation support and you accept that an agent can then
roll back on its own.

If you change the tag names, change them on the guests too; `pvewarden-setup` and
`pvewarden-enroll` use the default names.

## `[http]`

| Key | Default | |
|---|---|---|
| `listen` | – (required) | Address to listen on. Keep it on a management network or VPN. |
| `port` | `8765` | |
| `hostnames` | `[]` | Other names clients use in the URL. Requests with any other `Host` header are refused (DNS-rebinding protection). |
| `tls_cert`, `tls_key` | – | HTTPS. Both or neither. |
| `tls_ca` | – | The CA that signed `tls_cert`. Served without a token at `/ca.pem`, so clients can fetch it and check its fingerprint. |

### `[http.clients]`

One line per agent: `name = "token"`. Tokens must be at least 32 characters. The name appears in
the audit log and in the descriptions of snapshots that agent caused.

```
[http.clients]
claude-laptop = "..."
nanoclaw = "..."
```

To add or rotate one, use `pvewarden-setup token <name>` on the host or `pvewarden token <name>` in
the container. Both write a new random token and print it once; then restart the service.

## `[addresses]`

Fixed addresses for guests whose address pvewarden cannot discover, e.g. a VM without a guest
agent:

```
[addresses]
108 = "192.0.2.45"
```

## `[[static_guests]]` (testing without Proxmox)

Without `[proxmox]`, guests are listed by hand. Snapshots, reboots and rollbacks are then
unavailable, and `apply_updates` needs `snapshot=false`.

```
[[static_guests]]
vmid = 1
name = "test"
address = "192.0.2.50"
type = "lxc"
tags = ["pvewarden-update"]
```
