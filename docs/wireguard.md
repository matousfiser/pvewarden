# Reaching the server through WireGuard

Use this when your agents are not on the Proxmox LAN but reach it through a WireGuard VPN, and you
want the server to be visible only inside the VPN.

## Two addresses

The server container then has two addresses:

| Address | Example | Used for |
|---|---|---|
| LAN address (`eth0`) | `10.100.0.200` | The server connects from it to the guests over SSH. Guests accept the server only from this address (`from=` in their `authorized_keys`). |
| VPN address (`wg0`) | `10.200.0.200` | The server listens only here (port 8765). Agents connect to it. |

The guests do not need to be in the VPN. The agents do not need to reach the LAN.

## In the wizard

1. **Network:** the container's LAN address, e.g. `10.100.0.200/24`, and the LAN gateway.
2. **How agents reach the server:** *Through a VPN inside the container*.
3. **The container's address in the VPN:** e.g. `10.200.0.200`.
4. **HTTPS on that address too?** *No* is fine. WireGuard ends in the container itself, so the
   traffic is encrypted all the way from the agent to the server.

The address does not exist in the container yet, so at the end the wizard says
"pvewarden is installed; it starts once 10.200.0.200 exists". That is expected. **Keep the agent
token it shows:** it is shown only once.

## Bring up WireGuard in the container

**1. A peer on your WireGuard server** with the container's VPN address as a `/32`
(e.g. `10.200.0.200/32`). Download its client config. Many WireGuard UIs only rewrite the config file
when you apply a change, so reload the running interface on the WireGuard server too
(`wg syncconf wg0 <(wg-quick strip wg0)`, as root).

**2. The kernel module on the Proxmox host.** An unprivileged container cannot load it, so load it
on the host once and at every boot (as root):

```
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf
```

**3. The client in the container.** On the Proxmox host as root (`103` is the container ID):

```
pct enter 103
apt-get update && apt-get install -y wireguard-tools
nano /etc/wireguard/wg0.conf        # paste the client config
chmod 600 /etc/wireguard/wg0.conf
```

Change two lines in the config before you start it:

- **Delete the `DNS = ...` line.** The container has no `resolvconf`, so `wg-quick` would fail.
- **`AllowedIPs` = only the VPN network**, e.g. `AllowedIPs = 10.200.0.0/24`. The default
  `0.0.0.0/0` would send all traffic into the VPN and cut the container off from the guests.

Then:

```
systemctl enable --now wg-quick@wg0
wg show                              # "latest handshake: ... seconds ago"
exit
```

**4. Check.** The server starts by itself within 10 seconds once the address exists, and after a
reboot it starts after `wg-quick@wg0`. On the Proxmox host:

```
pvewarden-setup doctor
```

The `HTTP` line shows `http://10.200.0.200:8765/mcp`. Connect your agents to that address
(`pvewarden-setup connect` shows how).

## Troubleshooting

- **`wg-quick` says `Unknown device type`:** the module is not loaded on the host (step 2).
- **`resolvconf: command not found`:** the `DNS =` line is still in the config.
- **No handshake:** the peer is not active on the WireGuard server yet (reload it there), or UDP
  to the WireGuard server is blocked.
- **doctor warns "Listen address ... is not an address of this machine":** `wg0` is not up, or its
  address differs from the one in the wizard. Compare `ip -o addr show` in the container with
  `listen` in `/etc/pvewarden/config.toml`.
