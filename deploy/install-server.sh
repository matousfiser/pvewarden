#!/bin/bash
# Install or update the pvewarden server on a Debian/Ubuntu machine (typically a dedicated LXC).
# Run as root from a checkout of the repository:
#   deploy/install-server.sh <listen-address>
# Re-running updates code and dependencies; existing config, SSH key and tokens are kept.
set -euo pipefail
LISTEN="${1:?usage: install-server.sh <listen-address>}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/pvewarden
ETC=/etc/pvewarden
STATE=/var/lib/pvewarden
SVC_USER=pvewarden

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv openssh-client openssl ca-certificates

id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o root -g root -m 0755 "$APP"
install -d -o root -g "$SVC_USER" -m 0750 "$ETC"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$STATE"

# code: root-owned venv, read-only for the service; dependencies pinned by requirements.lock
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$SRC/requirements.lock"
"$APP/venv/bin/pip" install -q --no-deps --force-reinstall "$SRC"
ln -sf "$APP/venv/bin/pvewarden" /usr/local/bin/pvewarden

# SSH key for guests: generated here and never leaves this machine
if [ ! -f "$ETC/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "pvewarden@$(hostname)" -f "$ETC/id_ed25519"
  chown root:"$SVC_USER" "$ETC/id_ed25519" "$ETC/id_ed25519.pub"
  chmod 0640 "$ETC/id_ed25519"
fi

# config with a fresh HTTP token; the Proxmox part is filled in by hand (or by the installer)
FRESH=0
if [ ! -f "$ETC/config.toml" ]; then
  FRESH=1
  TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  sed -e "s|^listen = .*|listen = \"$LISTEN\"|" \
      -e "s|^agent = .*|agent = \"$TOKEN\"|" \
      "$SRC/config.example.toml" > "$ETC/config.toml"
  chown root:"$SVC_USER" "$ETC/config.toml"
  chmod 0640 "$ETC/config.toml"
fi

install -o root -g root -m 0644 "$SRC/deploy/pvewarden.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pvewarden >/dev/null

echo
echo "Installed $("$APP/venv/bin/pvewarden" --version)."
[ "$FRESH" = 1 ] && echo "Next: edit $ETC/config.toml ([proxmox]), then check: runuser -u $SVC_USER -- pvewarden doctor"
echo
echo "Guest public key (for pvewarden-enroll / guest/install.sh):"
cat "$ETC/id_ed25519.pub"
