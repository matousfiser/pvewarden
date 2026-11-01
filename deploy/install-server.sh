#!/bin/bash
# Install or update the pvewarden server on a Debian/Ubuntu machine (typically a dedicated LXC).
# Run as root from a checkout of the repository:
#   deploy/install-server.sh <listen-address>
# Re-running updates code and dependencies; existing config, guest keys and tokens are kept.
set -euo pipefail
LISTEN="${1:?usage: install-server.sh <listen-address>}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/pvewarden
ETC=/etc/pvewarden
STATE=/var/lib/pvewarden
SVC_USER=pvewarden

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

echo "    apt: installing python3-venv, openssh-client, openssl, logrotate"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv openssh-client openssl ca-certificates logrotate

id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o root -g root -m 0755 "$APP"
install -d -o root -g "$SVC_USER" -m 0750 "$ETC"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$STATE"

# code: root-owned venv, read-only for the service. Dependencies: only wheels whose SHA-256 is in
# requirements.lock (nothing is built, so no unpinned build tools are fetched either).
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
echo "    pip: installing the pinned, hash-checked dependencies (the slowest step)"
"$APP/venv/bin/pip" install -q --disable-pip-version-check --require-hashes --only-binary=:all: \
  -r "$SRC/requirements.lock"
# pvewarden itself is plain Python from the (checksum-verified) source: copied, not built
"$APP/venv/bin/pip" uninstall -q -y pvewarden 2>/dev/null || true # 0.1.1 and older installed it with pip
rm -rf "${APP:?}/lib.new"
install -d -o root -g root -m 0755 "$APP/lib.new"
cp -r "$SRC/src/pvewarden" "$APP/lib.new/"
find "$APP/lib.new" -name __pycache__ -prune -exec rm -rf {} +
rm -rf "${APP:?}/lib" && mv "$APP/lib.new" "$APP/lib"
site=$("$APP/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
echo "$APP/lib" > "$site/pvewarden.pth"
cat > "$APP/venv/bin/pvewarden" <<EOF
#!$APP/venv/bin/python
from pvewarden.cli import main
main()
EOF
chmod 0755 "$APP/venv/bin/pvewarden"
"$APP/venv/bin/python" -m compileall -q "$APP/lib" >/dev/null || true
ln -sf "$APP/venv/bin/pvewarden" /usr/local/bin/pvewarden

# SSH keys for guests: one per guest, made in $STATE/keys when it is enrolled; they never leave
# this machine
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$STATE/keys"

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
# the audit log is rotated weekly, run logs older than 180 days are removed
install -o root -g root -m 0644 "$SRC/deploy/pvewarden.logrotate" /etc/logrotate.d/pvewarden
install -o root -g root -m 0644 "$SRC/deploy/pvewarden.tmpfiles" /usr/lib/tmpfiles.d/pvewarden.conf
systemctl daemon-reload
systemctl enable pvewarden >/dev/null

echo
echo "Installed $("$APP/venv/bin/pvewarden" --version)."
if [ "$FRESH" = 1 ]; then
  echo "Next: edit $ETC/config.toml ([proxmox]), then check: runuser -u $SVC_USER -- pvewarden doctor"
fi
