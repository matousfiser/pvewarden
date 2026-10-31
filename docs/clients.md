# Connecting MCP clients

pvewarden is a remote MCP server (streamable HTTP). A client needs three things:

1. the **endpoint**, e.g. `https://192.0.2.50:8765/mcp`,
2. a **token**, sent as `Authorization: Bearer <token>`,
3. with HTTPS, **trust in the server's certificate**.

`pvewarden-setup` prints all three at the end of the install. `pvewarden-setup connect` prints
them again, without the token. A new token, for example for a second agent, comes from
`pvewarden-setup token`. Each agent should have its own
token: the audit log records which one acted.

## The certificate

By default the server's certificate is signed by your Proxmox cluster's own CA,
`/etc/pve/pve-root-ca.pem`. That is the CA behind the Proxmox web UI. Trust that CA once on
each computer. After that, reinstalls and new certificates need nothing new on the client.
That includes the certificate `pvewarden-setup renew-cert` issues after the server's address
changed. The certificate's private key is created in the server container and never leaves
it. The CA key stays on the Proxmox host.

The server offers the CA without a token at `https://<server>:8765/ca.pem`. The summary
`pvewarden-setup` prints contains a paste-ready command for PowerShell and for Linux/macOS. The
command:

1. downloads `/ca.pem`,
2. checks its SHA-256 against the fingerprint written into the command, and deletes the file
   if it does not match,
3. sets `NODE_EXTRA_CA_CERTS` to it. If that variable already points to some other file, the
   command changes nothing and tells you to add the CA to that file instead.

The download skips certificate validation (`curl -k`), since nothing is trusted yet. The
fingerprint check makes that safe: a certificate swapped on the way does not match. SSH's
first-connection check works the same way, except that here nobody has to compare the
fingerprint by eye.

The CA is a public certificate, not a secret. You can copy it anywhere, for example into a
container image. On the Proxmox host it is `/etc/pve/pve-root-ca.pem`.

Installs from before this change, or hosts without the CA key, use a self-signed certificate.
`pvewarden-setup renew-cert` switches them to the Proxmox CA.

## Claude Code

1. Make Node trust the CA: run the command from the install summary or from
   `pvewarden-setup connect`, then open a new terminal. To do it by hand, save the CA as a file
   and set `NODE_EXTRA_CA_CERTS` to its path.

2. Add the server. Use one line; it works in every shell:

   ```
   claude mcp add --scope user --transport http pvewarden https://192.0.2.50:8765/mcp --header "Authorization: Bearer <token>"
   ```

3. Restart `claude` and check `/mcp`.

`DEPTH_ZERO_SELF_SIGNED_CERT` or `UNABLE_TO_VERIFY_LEAF_SIGNATURE` means Node does not trust the
certificate. Either `NODE_EXTRA_CA_CERTS` is not set in the terminal `claude` runs in, or it points
to an old file. Node reads it only at start: restart `claude` after changing it.

## Other MCP clients

Most clients take a JSON entry like this:

```json
{
  "mcpServers": {
    "pvewarden": {
      "type": "http",
      "url": "https://192.0.2.50:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

How a client trusts a CA depends on its runtime:

| Runtime | How to trust `pve-root-ca.pem` |
|---|---|
| Node.js (Claude Code, Claude Agent SDK, most JS agents) | `NODE_EXTRA_CA_CERTS=/path/pve-root-ca.pem` |
| Python (httpx, requests) | `SSL_CERT_FILE=/path/bundle.pem`, a bundle with the system CAs plus `pve-root-ca.pem` (see the note) |
| Anything using the system trust store | Debian/Ubuntu: copy it to `/usr/local/share/ca-certificates/pve-root-ca.crt`, run `update-ca-certificates` |

**Python 3.13 and newer:** these versions check certificates strictly by default, and they reject
the Proxmox CA because it lacks a key-usage extension: `CA cert does not include key usage
extension`. pvewarden's own server code relaxes that one check for the pinned Proxmox CA. A
Python MCP client has to do the same. If it cannot, use plain HTTP inside a VPN, or a reverse
proxy (both below).

## Agents that run in containers (NanoClaw and similar)

When the agent runs in a container, the CA and the variable must be inside that container:

1. Mount the CA read-only, or bake it into the image. It is not a secret.
2. Set the trust variable for the agent's runtime, e.g. `NODE_EXTRA_CA_CERTS`.
3. Pass the token like any other secret of that agent, never in the image.
4. Make sure the container can reach the endpoint. The server only accepts traffic on the
   address it listens on, and the agent's container network must route there.

If changing the agent's container is impractical, two alternatives need no certificate on the
client:

- **Plain HTTP inside a network you trust.** At install, choose "My own address" and no HTTPS. A
  WireGuard tunnel is the usual choice: it already encrypts and authenticates the traffic, so TLS
  on top adds nothing.
- **A reverse proxy with a publicly trusted certificate.** For example Caddy or Traefik with a
  Let's Encrypt certificate (DNS challenge) for a name in your own domain, forwarding to
  pvewarden. Clients then need no extra trust at all.

## The token

- It is shown once. The server stores it in `/etc/pvewarden/config.toml` in its container.
- `pvewarden-setup token [name]` replaces it. The old token stops working immediately.
- Treat it like a password: it allows everything the agent may do under pvewarden's policy.
  Pvewarden's tags and its confirmation dialogs still limit what any token holder can do.
