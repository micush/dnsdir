#!/usr/bin/env bash
# AnyTime NTP Director uninstaller.
#
#   sudo ntpdir-uninstall [--purge] [--remove-group] [-y] [--dry-run]
#
# Removes the service, binary and support files installed by install.sh.
# Your configuration and certificates (in /var/lib/ntpdir) are
# kept unless --purge is given. Works without the manifest (falls back to the
# default layout).

set -euo pipefail

SHARE=/usr/local/share/ntpdir
MANIFEST=$SHARE/install.manifest
BIN=/usr/local/sbin/ntpdir
BIN_DIR=/usr/local/sbin
UNIT_NAME=ntpdir.service
UNIT=/etc/systemd/system/$UNIT_NAME
PAM_FILE=/etc/pam.d/ntpdir
NM_FILE=/etc/NetworkManager/conf.d/90-ntpdir-unmanaged.conf
GROUP=ntpdir
LEGACY_CONF_DIR=/etc/liras   # where releases before v15 kept the config
STATE_DIR=/var/lib/ntpdir
CONF_DIR=$STATE_DIR
SYSTEMCTL=${NTPDIR_SYSTEMCTL:-systemctl}
PAM_CREATED=""; NM_CREATED=""; GROUP_CREATED=""; PAM_SHA256=""; CHRONY_CONF=""
CHRONY_BEGIN='# >>> ntpdir (managed block, removed by ntpdir-uninstall) >>>'
CHRONY_END='# <<< ntpdir <<<'
CHRONY_OFF='#ntpdir-off# '

PURGE=0; RM_GROUP=0; ASSUME_YES=0; DRY=0
if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; N=$'\033[0m'; else B=; R=; Y=; G=; N=; fi
step() { printf '%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { if [ "$DRY" = 1 ]; then printf '    [dry-run] %s\n' "$*"; return 0; fi; "$@"; }

usage() {
  cat <<EOT
AnyTime NTP Director uninstaller

Usage: sudo ntpdir-uninstall [options]

  --purge         also remove $CONF_DIR/ntpdir.conf, the GUI certificate/key,
                  /etc/pam.d/ntpdir even if you edited it, and the '$GROUP' group
  --remove-group  remove the '$GROUP' group (default: only if the installer
                  created it, and only with --purge)
  -y, --yes       don't ask for confirmation
  --dry-run       show what would be removed, change nothing
  -h, --help      this help
EOT
}

while [ $# -gt 0 ]; do
  case $1 in
    --purge) PURGE=1; shift;;
    --remove-group) RM_GROUP=1; shift;;
    -y|--yes) ASSUME_YES=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; die "unknown option: $1";;
  esac
done

if [ "$(id -u)" -ne 0 ] && [ "$DRY" = 0 ]; then
  have sudo || die "must be run as root"
  exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
fi

# Read the manifest as data, never by sourcing it.
mval() { sed -n "s/^$1=//p" "$MANIFEST" 2>/dev/null | head -n1; }
if [ -f "$MANIFEST" ]; then
  PAM_CREATED=$(mval PAM_CREATED); NM_CREATED=$(mval NM_CREATED)
  GROUP_CREATED=$(mval GROUP_CREATED); PAM_SHA256=$(mval PAM_SHA256); CHRONY_CONF=$(mval CHRONY_CONF)
else
  warn "no install manifest at $MANIFEST — using the default layout; the group and PAM file will be left alone unless --purge"
fi

HAVE_SYSTEMD=0
if have "$SYSTEMCTL" && { [ -d /run/systemd/system ] || [ -n "${NTPDIR_FORCE_SYSTEMD:-}" ]; }; then HAVE_SYSTEMD=1; fi

[ -e "$BIN" ] || [ -d "$SHARE" ] || [ -e "$UNIT" ] || { echo "AnyTime does not appear to be installed."; exit 0; }

step "This will remove AnyTime"
info "service $UNIT_NAME, $BIN, $SHARE, $BIN_DIR/ntpdir-uninstall"
info "leftover ntpdir<group>.<slot> network interfaces and the control socket"
if [ "$PURGE" = 1 ]; then
  info "PURGE: $CONF_DIR/ntpdir.conf, GUI certificate/key, $STATE_DIR (config history, cluster identity, update data), $PAM_FILE, group $GROUP"
else
  info "kept: $CONF_DIR/ntpdir.conf, GUI certificate and $STATE_DIR (use --purge to remove)"
fi
if [ "$ASSUME_YES" = 0 ] && [ "$DRY" = 0 ]; then
  [ -t 0 ] || die "not a terminal; re-run with --yes to confirm"
  read -r -p "    Continue? [y/N] " a || exit 1
  [[ $a =~ ^[Yy] ]] || { echo "aborted"; exit 1; }
fi

step "Stopping service"
if [ "$HAVE_SYSTEMD" = 1 ]; then
  run "$SYSTEMCTL" stop "$UNIT_NAME" 2>/dev/null || true
  run "$SYSTEMCTL" disable "$UNIT_NAME" >/dev/null 2>&1 || true
  run rm -f "$UNIT"
  run "$SYSTEMCTL" daemon-reload || true
  run "$SYSTEMCTL" reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
elif [ -e "$UNIT" ]; then
  run rm -f "$UNIT"
fi
# a daemon started by hand
if [ "$DRY" = 0 ] && have pgrep && pgrep -x ntpdir >/dev/null 2>&1; then
  warn "a ntpdir process is still running (not started by systemd); stopping it"
  pkill -x ntpdir || true; sleep 1
fi

step "Removing virtual interfaces"
if have ip; then
  for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^ntpdir[0-9]+\.[0-9]+$' || true); do
    run ip link delete "$l" 2>/dev/null && info "removed $l" || true
  done
fi
run rm -f /run/ntpdir/ntpdir.sock /run/liras/ntpdir.sock
if [ "$DRY" = 0 ]; then rmdir /run/ntpdir /run/liras 2>/dev/null || true; fi

step "Removing files"
run rm -f "$BIN" "$BIN.new" "$BIN_DIR/ntpdir-uninstall"
if [ "$DRY" = 1 ]; then info "[dry-run] remove the files in $SHARE and the directory"; else
  # remove only what we put there (plus the rollback copy), then the dir if empty
  rm -f "$SHARE"/{ntpdir.conf.example,README.md,CHANGELOG.md,LICENSE,VERSION,ntpdir.prev,install.manifest}
  rm -rf "$SHARE/go" "$SHARE/go.new"   # the toolchain install.sh downloaded for updates
  # (the running script lives in $SHARE; bash has it open, deleting is safe)
  rm -f "$SHARE/uninstall.sh"
  rmdir "$SHARE" 2>/dev/null || warn "$SHARE not empty; left in place"
fi

# NetworkManager drop-in
if [ -f "$NM_FILE" ] && { [ "$NM_CREATED" = 1 ] || [ "$PURGE" = 1 ] || [ -z "$NM_CREATED" ]; }; then
  run rm -f "$NM_FILE"; info "removed $NM_FILE"
  if [ "$HAVE_SYSTEMD" = 1 ]; then run "$SYSTEMCTL" reload NetworkManager >/dev/null 2>&1 || true; fi
fi

# chrony: take our block (port 0) out of its config; chrony itself stays installed (it is the system clock)
if [ -z "$CHRONY_CONF" ]; then
  for c in "${NTPDIR_CHRONY_CONF:-}" /etc/chrony/chrony.conf /etc/chrony.conf; do
    [ -n "$c" ] && [ -f "$c" ] && grep -qxF "$CHRONY_BEGIN" "$c" && { CHRONY_CONF=$c; break; }
  done
fi
if [ -n "$CHRONY_CONF" ] && [ -f "$CHRONY_CONF" ] && grep -qxF "$CHRONY_BEGIN" "$CHRONY_CONF"; then
  if [ "$DRY" = 1 ]; then info "[dry-run] remove the ntpdir block from $CHRONY_CONF"; else
    cmode=$(stat -c %a "$CHRONY_CONF" 2>/dev/null || echo 644)
    ctmp=$(mktemp "$CHRONY_CONF.XXXXXX.tmp")
    awk -v b="$CHRONY_BEGIN" -v e="$CHRONY_END" -v m="$CHRONY_OFF" '$0==b{skip=1} !skip{ if (index($0,m)==1) print substr($0,length(m)+1); else print } $0==e{skip=0}' "$CHRONY_CONF" >"$ctmp"
    chmod "$cmode" "$ctmp"; mv -f "$ctmp" "$CHRONY_CONF"
    for cf in "$(dirname "$CHRONY_CONF")"/sources.d/*.sources.ntpdir-off; do
      [ -f "$cf" ] && mv -f "$cf" "${cf%.ntpdir-off}"
    done
    if [ "$PURGE" = 1 ]; then rm -rf "${NTPDIR_CHRONY_SOURCEDIR:-/etc/chrony/ntpdir.sources.d}" "${NTPDIR_CHRONY_CONFDIR:-/etc/chrony/ntpdir.conf.d}" "${NTPDIR_CHRONY_AUTHDIR:-/etc/chrony/ntpdir.auth.d}"; fi
    info "removed the ntpdir block from $CHRONY_CONF and put chrony's own servers back (chrony itself is left installed)"
    if [ "$HAVE_SYSTEMD" = 1 ]; then
      for cu in chrony.service chronyd.service; do
        "$SYSTEMCTL" is-active --quiet "$cu" 2>/dev/null && { run "$SYSTEMCTL" restart "$cu" >/dev/null 2>&1 || true; break; }
      done
    fi
  fi
fi

# chrony's container drop-in (chrony -x), when the installer wrote one
for cu in chrony.service chronyd.service; do
  df="${NTPDIR_CHRONY_DROPIN_DIR:-/etc/systemd/system/$cu.d}/ntpdir.conf"
  if [ -f "$df" ] && grep -q '^# Written by ntpdir' "$df"; then
    run rm -f "$df"; rmdir "$(dirname "$df")" 2>/dev/null || true
    [ "$HAVE_SYSTEMD" = 1 ] && run "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
    info "removed the chrony container drop-in $df"
  fi
done

# snmpd: when ntpdir was running it (Configure ▸ SNMP), switch it off and put back the snmpd.conf it replaced.  snmpd stays installed.
SNMP_CONF="${NTPDIR_SNMP_CONF:-/etc/snmp/snmpd.conf}"
if [ -f "$SNMP_CONF" ] && grep -q '^# Managed by ntpdir (Configure' "$SNMP_CONF"; then
  if [ "$HAVE_SYSTEMD" = 1 ]; then run "$SYSTEMCTL" disable --now snmpd >/dev/null 2>&1 || true; fi
  if [ -f "$SNMP_CONF.ntpdir-orig" ]; then
    run mv -f "$SNMP_CONF.ntpdir-orig" "$SNMP_CONF"; info "put back the original $SNMP_CONF and switched snmpd off (snmpd itself is left installed)"
  else
    run rm -f "$SNMP_CONF"; info "removed $SNMP_CONF written by ntpdir and switched snmpd off (snmpd itself is left installed)"
  fi
fi

# PAM service
if [ -f "$PAM_FILE" ]; then
  if [ "$PURGE" = 1 ]; then
    run rm -f "$PAM_FILE"; info "removed $PAM_FILE"
  elif [ "$PAM_CREATED" = 1 ] && [ -n "$PAM_SHA256" ] && [ "$(sha256sum "$PAM_FILE" | awk '{print $1}')" = "$PAM_SHA256" ]; then
    run rm -f "$PAM_FILE"; info "removed $PAM_FILE (unchanged since install)"
  else
    info "kept $PAM_FILE (not created by the installer, or edited since)"
  fi
fi

# config and certificate
if [ "$PURGE" = 1 ]; then
  run rm -f "$CONF_DIR/ntpdir.conf" "$CONF_DIR/ntpdir.conf".* "$CONF_DIR"/ntpdir-web.crt "$CONF_DIR"/ntpdir-web.key "$CONF_DIR"/ntpdir.crt "$CONF_DIR"/ntpdir.key
  # leftovers of an install from before v15
  run rm -f "$LEGACY_CONF_DIR"/ntpdir.conf "$LEGACY_CONF_DIR"/ntpdir.conf.* "$LEGACY_CONF_DIR"/ntpdir-web.crt* "$LEGACY_CONF_DIR"/ntpdir-web.key* "$LEGACY_CONF_DIR"/ntpdir.crt "$LEGACY_CONF_DIR"/ntpdir.key
  if [ "$DRY" = 0 ]; then rmdir "$LEGACY_CONF_DIR" 2>/dev/null || true; fi
  info "removed configuration and certificate"
fi

# state (history, cluster identity and secret, installed certificate, update data)
if [ "$PURGE" = 1 ] && [ -d "$STATE_DIR" ]; then
  run rm -rf "$STATE_DIR"; info "removed $STATE_DIR"
fi

# group
if [ "$RM_GROUP" = 1 ] || { [ "$PURGE" = 1 ] && [ "$GROUP_CREATED" = 1 ]; }; then
  if getent group "$GROUP" >/dev/null 2>&1; then
    run groupdel "$GROUP" && info "removed group $GROUP" || warn "could not remove group $GROUP"
  fi
elif getent group "$GROUP" >/dev/null 2>&1; then
  info "kept group $GROUP (use --remove-group to delete it)"
fi

step "AnyTime removed"
[ -f "$CONF_DIR/ntpdir.conf" ] && info "your config is still at $CONF_DIR/ntpdir.conf"
[ -f "$LEGACY_CONF_DIR/ntpdir.conf" ] && info "your config is still at $LEGACY_CONF_DIR/ntpdir.conf"
exit 0
