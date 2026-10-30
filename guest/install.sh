#!/bin/bash
# Install or remove the pvewarden guest client. Run as root on the guest:
#   install.sh "<server public key>" <server address>    install or refresh (idempotent)
#   install.sh --uninstall                               remove user, scripts and sudoers rule
# Usually run for you by pvewarden-enroll on the Proxmox host.
set -euo pipefail
USER_NAME=pvewarden
SBIN=/usr/local/sbin
SUDOERS=/etc/sudoers.d/pvewarden

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  id "$USER_NAME" >/dev/null 2>&1 && userdel -r "$USER_NAME" 2>/dev/null || true
  rm -f "$SBIN/pvewarden-guest" "$SBIN/pvewarden-gate" "$SUDOERS"
  echo "pvewarden client removed"
  exit 0
fi

PUBKEY="${1:?usage: install.sh \"<server public key>\" <server address> | --uninstall}"
FROM="${2:?usage: install.sh \"<server public key>\" <server address> | --uninstall}"
DIR="$(cd "$(dirname "$0")" && pwd)"

case "$PUBKEY" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
  *) echo "not an SSH public key: $PUBKEY" >&2; exit 1 ;;
esac

. /etc/os-release
case "$ID" in
  ubuntu) ;;
  *) echo "unsupported distribution: $ID (supported: ubuntu)" >&2; exit 3 ;;
esac

# check/upgrade need unattended-upgrades and python3-apt (pulled in by it)
if ! command -v unattended-upgrade >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades
fi

id "$USER_NAME" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$USER_NAME"
usermod -p '*' "$USER_NAME"  # no password login, but not "locked" (sshd would refuse the key)

install -o root -g root -m 0755 "$DIR/pvewarden-guest" "$SBIN/pvewarden-guest"
install -o root -g root -m 0755 "$DIR/pvewarden-gate" "$SBIN/pvewarden-gate"

tmp=$(mktemp)
cat > "$tmp" <<EOF
# pvewarden: the only commands the pvewarden user may run as root
$USER_NAME ALL=(root) NOPASSWD: $SBIN/pvewarden-guest check, $SBIN/pvewarden-guest status, $SBIN/pvewarden-guest upgrade-security, $SBIN/pvewarden-guest upgrade-all
EOF
visudo -cqf "$tmp"
install -o root -g root -m 0440 "$tmp" "$SUDOERS"
rm -f "$tmp"

home=$(getent passwd "$USER_NAME" | cut -d: -f6)
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$home/.ssh"
echo "restrict,from=\"$FROM\",command=\"$SBIN/pvewarden-gate\" $PUBKEY" > "$home/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
echo "pvewarden client installed (key accepted from $FROM)"
