# Reaching the server through a VPN

Use this when your agents are not on the Proxmox LAN but reach it through a VPN, and you want the
server to be visible only inside the VPN. Any VPN works that gives the server container its own
address: the VPN client runs inside the container.

## Two addresses

The server container then has two addresses:

| Address | Example | Used for |
|---|---|---|
| LAN address (`eth0`) | `10.100.0.200` | The server connects from it to the guests over SSH. Guests accept the server only from this address (`from=` in their `authorized_keys`). |
| VPN address | `10.200.0.200` | The server listens only here (port 8765). Agents connect to it. |

The guests do not need to be in the VPN. The agents do not need to reach the LAN.

## In the wizard

1. **Network:** the container's LAN address, e.g. `10.100.0.200/24`, and the LAN gateway.
2. **How agents reach the server:** *Through a VPN inside the container*.
3. **The container's address in the VPN:** e.g. `10.200.0.200`.
4. **HTTPS on that address too?** *Yes* (the default). Some MCP clients refuse a remote server over
   plain HTTP whatever the network. With *No*, you can switch later: `pvewarden-setup renew-cert`.

The address does not exist in the container yet, so at the end the wizard says
"pvewarden is installed; it starts once 10.200.0.200 exists". That is expected. **Keep the agent
token it shows:** it is shown only once.

## Bring up the VPN in the container

Install and configure your VPN's client in the container (`pct enter <ctid>` on the Proxmox host)
so that it has the VPN address you gave the wizard and starts at boot. Three things matter for
every VPN:

- **Route only the VPN network through the VPN.** A client that sends all traffic into the VPN
  (a default route, `0.0.0.0/0`) cuts the container off from the guests on the LAN.
- **No DNS changes from the VPN client** unless the container can apply them. The Debian template
  has no `resolvconf`, and some clients fail without it.
- **An unprivileged container cannot load kernel modules or create TUN devices by itself.** A VPN
  that needs a kernel module (WireGuard, for example) needs it loaded on the Proxmox host. A VPN
  that needs `/dev/net/tun` (OpenVPN, Tailscale and others) needs the device passed into the
  container (Proxmox UI: container -> Resources -> Add -> Device Passthrough, `/dev/net/tun`).

Example with WireGuard, as root:

```
# on the Proxmox host: the kernel module, now and at every boot
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf

# in the container
pct enter <ctid>
apt-get update && apt-get install -y wireguard-tools
nano /etc/wireguard/wg0.conf        # the peer config from your WireGuard server
chmod 600 /etc/wireguard/wg0.conf   # without a DNS = line; AllowedIPs = the VPN network only
systemctl enable --now wg-quick@wg0
exit
```

## Check

The server starts by itself within 10 seconds once the address exists, and it keeps retrying
after a reboot until the VPN is up. On the Proxmox host:

```
pvewarden-setup doctor
```

The `HTTP` line shows `https://10.200.0.200:8765/mcp`. Connect your agents to that address
(`pvewarden-setup connect` shows how, including trusting the Proxmox CA once).

**An install with plain HTTP** (`http://...`): `pvewarden-setup renew-cert` switches it to HTTPS on
the same address. Tokens stay; agents change the address to `https://` and trust the Proxmox CA.

## Troubleshooting

- **doctor warns "Listen address ... is not an address of this machine":** the VPN is not up in
  the container, or its address differs from the one in the wizard. Compare `ip -o addr show` in
  the container with `listen` in `/etc/pvewarden/config.toml`.
- **The VPN is up but agents get no answer:** check that the VPN lets the agent's address reach
  the container's VPN address on TCP port 8765, and that the agent uses `https://` when the
  server has a certificate.
