#!/bin/bash
# Install or remove the pvewarden guest client. Run as root on the guest:
#   install.sh [--dry-run] "<server public key>" <server address>   install or refresh (idempotent)
#   install.sh [--dry-run] --uninstall                              remove user, scripts and sudoers rule
# --dry-run prints what would change and changes nothing.
# Usually run for you by pvewarden-enroll on the Proxmox host.
set -euo pipefail
# pct exec passes the host locale, which the guest may not have: apt and perl then warn on every call
export LC_ALL=C.UTF-8
USER_NAME=pvewarden
SBIN=/usr/local/sbin
SUDOERS=/etc/sudoers.d/pvewarden
USAGE='usage: install.sh [--dry-run] "<server public key>" <server address> | [--dry-run] --uninstall'

DRY_RUN=0 UNINSTALL=0 ARGS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

# say WHAT: describe a change; in dry-run mode that is all that happens
say() { if [ "$DRY_RUN" = 1 ]; then echo "would: $*"; else echo "$*"; fi; }
real() { [ "$DRY_RUN" = 0 ]; }

[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

if [ "$UNINSTALL" = 1 ]; then
  say "remove user $USER_NAME and its home directory"
  say "remove $SBIN/pvewarden-guest, $SBIN/pvewarden-gate, $SUDOERS"
  if real; then
    if id "$USER_NAME" >/dev/null 2>&1; then userdel -r "$USER_NAME" 2>/dev/null || true; fi
    rm -f "$SBIN/pvewarden-guest" "$SBIN/pvewarden-gate" "$SUDOERS"
    echo "pvewarden client removed"
  fi
  exit 0
fi

[ ${#ARGS[@]} = 2 ] || { echo "$USAGE" >&2; exit 2; }
PUBKEY="${ARGS[0]}"
FROM="${ARGS[1]}"
DIR="$(cd "$(dirname "$0")" && pwd)"

case "$PUBKEY" in
  ssh-ed25519\ * | ssh-rsa\ * | ecdsa-sha2-*) ;;
  *) echo "not an SSH public key: $PUBKEY" >&2; exit 1 ;;
esac

# shellcheck source=/dev/null
. /etc/os-release
case "$ID" in
  ubuntu | debian) ;;
  *) echo "unsupported distribution: $ID (supported: ubuntu, debian)" >&2; exit 3 ;;
esac

SUDO_RULE="$USER_NAME ALL=(root) NOPASSWD: $SBIN/pvewarden-guest check, $SBIN/pvewarden-guest status, $SBIN/pvewarden-guest upgrade-security, $SBIN/pvewarden-guest upgrade-all"
KEY_LINE="restrict,from=\"$FROM\",command=\"$SBIN/pvewarden-gate\" $PUBKEY"

# check/upgrade need unattended-upgrades and python3-apt (pulled in by it)
if ! command -v unattended-upgrade >/dev/null; then
  say "apt-get install unattended-upgrades"
  if real; then
    if ! { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades; }; then
      echo "cannot install unattended-upgrades: does this guest have network and DNS? try 'apt-get update' in it" >&2
      exit 4
    fi
  fi
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then
  say "create user $USER_NAME (no password, SSH key login only)"
  real && useradd --create-home --shell /bin/bash "$USER_NAME"
fi
# '*' = no password, but not "locked": sshd refuses key logins for locked accounts
real && usermod -p '*' "$USER_NAME"

say "install $SBIN/pvewarden-guest and $SBIN/pvewarden-gate (root:root 0755)"
if real; then
  install -o root -g root -m 0755 "$DIR/pvewarden-guest" "$SBIN/pvewarden-guest"
  install -o root -g root -m 0755 "$DIR/pvewarden-gate" "$SBIN/pvewarden-gate"
fi

say "write $SUDOERS: $SUDO_RULE"
if real; then
  tmp=$(mktemp)
  printf '# pvewarden: the only commands the pvewarden user may run as root\n%s\n' "$SUDO_RULE" > "$tmp"
  visudo -cqf "$tmp"
  install -o root -g root -m 0440 "$tmp" "$SUDOERS"
  rm -f "$tmp"
fi

say "write ~$USER_NAME/.ssh/authorized_keys (replacing it): $KEY_LINE"
if real; then
  home=$(getent passwd "$USER_NAME" | cut -d: -f6)
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$home/.ssh"
  echo "$KEY_LINE" > "$home/.ssh/authorized_keys"
  chown "$USER_NAME:$USER_NAME" "$home/.ssh/authorized_keys"
  chmod 0600 "$home/.ssh/authorized_keys"
  echo "pvewarden client installed (key accepted from $FROM)"
fi
