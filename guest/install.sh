#!/bin/bash
# Install or remove the pvewarden guest client. Run as root on the guest:
#   install.sh [--dry-run] [--auto-updates=keep|off|on] "<server public key>" <server address>
#                                         install or refresh (idempotent)
#   install.sh [--dry-run] --uninstall    remove user, scripts, sudoers rule and the auto-updates override
# --dry-run prints what would change and changes nothing.
# --keep-keys: add the key next to the keys already there (enrolling a new key: it is tested before
#   the old ones go). --keys-only: only replace authorized_keys with this one key (the last enroll
#   step); nothing else is installed.
# --auto-updates: the guest's own daily unattended-upgrades run (it installs updates without a
#   pvewarden snapshot). keep (default) leaves the guest's setting alone; off/on write an override
#   to $AUTO_CONF, which --uninstall removes again.
# Usually run for you by pvewarden-enroll on the Proxmox host.
set -euo pipefail
# pct exec passes the host locale, which the guest may not have: apt and perl then warn on every call
export LC_ALL=C.UTF-8
USER_NAME=pvewarden
SBIN=/usr/local/sbin
SUDOERS=/etc/sudoers.d/pvewarden
AUTO_CONF=/etc/apt/apt.conf.d/52pvewarden-auto-upgrades
USAGE='usage: install.sh [--dry-run] [--auto-updates=keep|off|on] [--keep-keys|--keys-only] "<server public key>" <server address>
       install.sh [--dry-run] --uninstall'

DRY_RUN=0 UNINSTALL=0 AUTO=keep KEYS=replace ARGS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --keep-keys) KEYS=keep ;;
    --keys-only) KEYS=only ;;
    --auto-updates=keep | --auto-updates=off | --auto-updates=on) AUTO=${a#*=} ;;
    --auto-updates*) echo "$USAGE" >&2; exit 2 ;;
    *) ARGS+=("$a") ;;
  esac
done

# say WHAT: describe a change; in dry-run mode that is all that happens
say() { if [ "$DRY_RUN" = 1 ]; then echo "would: $*"; else echo "$*"; fi; }
real() { [ "$DRY_RUN" = 0 ]; }

# on/off: does the guest's daily unattended-upgrades run install updates by itself?
auto_updates_state() {
  local v=0
  if ! command -v unattended-upgrade >/dev/null || ! command -v apt-config >/dev/null; then
    echo off
    return
  fi
  eval "$(apt-config shell v APT::Periodic::Unattended-Upgrade)"
  case "$v" in "" | 0) echo off ;; *) echo on ;; esac
}

[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

if [ "$UNINSTALL" = 1 ]; then
  say "remove user $USER_NAME and its home directory"
  say "remove $SBIN/pvewarden-guest, $SBIN/pvewarden-gate, $SUDOERS, /var/lib/pvewarden (last update's log)"
  [ -f "$AUTO_CONF" ] && say "remove $AUTO_CONF (automatic updates go back to the guest's own setting)"
  if real; then
    if id "$USER_NAME" >/dev/null 2>&1; then userdel -r "$USER_NAME" 2>/dev/null || true; fi
    rm -f "$SBIN/pvewarden-guest" "$SBIN/pvewarden-gate" "$SUDOERS" "$AUTO_CONF"
    rm -rf /var/lib/pvewarden
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

KEY_LINE="restrict,from=\"$FROM\",command=\"$SBIN/pvewarden-gate\" $PUBKEY"

# write_keys: authorized_keys = this key alone, or (--keep-keys) added to the keys already there
write_keys() {
  local home tmp blob
  home=$(getent passwd "$USER_NAME" | cut -d: -f6)
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$home/.ssh"
  tmp=$(mktemp "$home/.ssh/.authorized_keys.XXXXXX")
  if [ "$KEYS" = keep ] && [ -f "$home/.ssh/authorized_keys" ]; then
    blob=$(echo "$PUBKEY" | awk '{print $2}')
    grep -vF -- "$blob" "$home/.ssh/authorized_keys" >> "$tmp" || true
  fi
  echo "$KEY_LINE" >> "$tmp"
  chown "$USER_NAME:$USER_NAME" "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$home/.ssh/authorized_keys" # atomic: sshd never sees a half-written file
}

if [ "$KEYS" = only ]; then
  id "$USER_NAME" >/dev/null 2>&1 || { echo "the pvewarden client is not installed here" >&2; exit 5; }
  say "replace ~$USER_NAME/.ssh/authorized_keys with only: $KEY_LINE"
  real && write_keys && echo "pvewarden key replaced (only the new key is accepted now)"
  exit 0
fi

SUDO_RULE="$USER_NAME ALL=(root) NOPASSWD: $SBIN/pvewarden-guest check, $SBIN/pvewarden-guest status, $SBIN/pvewarden-guest upgrade-security, $SBIN/pvewarden-guest upgrade-all, $SBIN/pvewarden-guest upgrade-follow"
# check/upgrade need unattended-upgrades (it pulls in python3-apt); minimal images often lack sudo.
# No recommends: they would pull in e.g. systemd-resolved, which takes over /etc/resolv.conf.
missing=() INSTALLED_UU=0
command -v unattended-upgrade >/dev/null || { missing+=(unattended-upgrades); INSTALLED_UU=1; }
command -v visudo >/dev/null || missing+=(sudo)
if [ ${#missing[@]} -gt 0 ]; then
  say "apt-get install ${missing[*]} (can take a minute)"
  if real; then
    if ! { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}"; }; then
      echo "cannot install ${missing[*]}: does this guest have network and DNS? try 'apt-get update' in it" >&2
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
  visudo -cqf "$tmp" >/dev/null # some versions print "parsed OK" despite -q
  install -o root -g root -m 0440 "$tmp" "$SUDOERS"
  rm -f "$tmp"
fi

if [ "$KEYS" = keep ]; then
  say "add to ~$USER_NAME/.ssh/authorized_keys (keeping the keys already there): $KEY_LINE"
else
  say "write ~$USER_NAME/.ssh/authorized_keys (replacing it): $KEY_LINE"
fi
if real; then
  write_keys
  echo "pvewarden client installed (key accepted from $FROM)"
fi

case "$AUTO" in
  off | on)
    say "write $AUTO_CONF: automatic updates $AUTO"
    if real; then
      v=$([ "$AUTO" = on ] && echo 1 || echo 0)
      printf '// written by pvewarden (install.sh --auto-updates=%s); delete this file to undo\n' "$AUTO" > "$AUTO_CONF"
      printf 'APT::Periodic::Update-Package-Lists "%s";\nAPT::Periodic::Unattended-Upgrade "%s";\n' "$v" "$v" >> "$AUTO_CONF"
    fi
    ;;
esac
if real; then
  state=$(auto_updates_state)
  if [ "$state" = on ]; then
    echo "automatic updates: ON - unattended-upgrades installs updates every day by itself, without a pvewarden snapshot"
    if [ "$INSTALLED_UU" = 1 ] && [ "$AUTO" = keep ]; then
      echo "  (the distribution turned this on when unattended-upgrades was installed just now)"
    fi
    if [ "$AUTO" = off ]; then
      echo "  WARNING: still on although --auto-updates=off: another apt.conf.d file overrides $AUTO_CONF"
    fi
  else
    echo "automatic updates: off - only pvewarden installs updates (with snapshots)"
  fi
fi
