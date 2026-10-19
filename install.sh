#!/usr/bin/env bash
# AnyTime NTP Director installer / upgrader.
#
# Builds AnyTime from the source tree this script sits in and installs it as a
# systemd service. Supports Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch and
# Manjaro (and derivatives that declare them in ID_LIKE).  If AnyTime is already
# installed it is upgraded in place: config, certificate, group membership and
# PAM service file are kept, the previous binary is saved, and the upgrade is
# rolled back automatically if the new version fails to start.
#
#   sudo ./install.sh [options]        see --help
#
# Test hooks (not for normal use): NTPDIR_OS_RELEASE, NTPDIR_SYSTEMCTL,
# NTPDIR_FORCE_SYSTEMD, NTPDIR_ASSUME_MISSING, NTPDIR_FORCE_GO_DOWNLOAD,
# NTPDIR_GO_BASE_URL, NTPDIR_SETTLE, NTPDIR_CHRONY_CONF, NTPDIR_CHRONY_SOURCEDIR, NTPDIR_CHRONY_CONFDIR.

set -euo pipefail
umask 022

# ── fixed layout (the daemon's own defaults) ─────────────────────────────────
BIN_DIR=/usr/local/sbin
BIN=$BIN_DIR/ntpdir
SHARE=/usr/local/share/ntpdir
MANIFEST=$SHARE/install.manifest
LEGACY_CONF_DIR=/etc/liras   # where releases before v15 kept the config
UNIT_NAME=ntpdir.service
UNIT=/etc/systemd/system/$UNIT_NAME
PAM_FILE=/etc/pam.d/ntpdir
NM_FILE=/etc/NetworkManager/conf.d/90-ntpdir-unmanaged.conf
GROUP=ntpdir
CHRONY_BEGIN='# >>> ntpdir (managed block, removed by ntpdir-uninstall) >>>'
CHRONY_END='# <<< ntpdir <<<'
GUI_PORT=12380
CLUSTER_PORT=12381
STATE_DIR=/var/lib/ntpdir
CONF_DIR=$STATE_DIR   # the config lives with everything else ntpdir keeps

GO_MIN=1.24
GO_VERSION=1.24.7
GO_BASE=${NTPDIR_GO_BASE_URL:-https://go.dev/dl}
SYSTEMCTL=${NTPDIR_SYSTEMCTL:-systemctl}
OS_RELEASE=${NTPDIR_OS_RELEASE:-/etc/os-release}
SETTLE=${NTPDIR_SETTLE:-3}

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ── output ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; N=$'\033[0m'; else B=; R=; Y=; G=; N=; fi
step() { printf '%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
AnyTime NTP Director installer

Usage: sudo ./install.sh [options]

  --add-user NAME   add NAME to the '$GROUP' group so they can log in to the
                    web GUI (repeatable). The user running the installer
                    (the one behind sudo) is always added.
  --no-start        install and enable the service but do not start/restart it
  --force           reinstall even if this version is already installed, and
                    allow a downgrade
  --skip-deps       don't install build prerequisites (you provide gcc, the PAM
                    development headers, iproute2, FRR and Go >= $GO_MIN)
  --go PATH         use this 'go' binary instead of searching / downloading
  --no-keep-go      remove a downloaded Go toolchain after the build. By default
                    it is kept in $SHARE/go because the daemon rebuilds
                    itself with it when you apply an update from the GUI/CLI.
  -y, --yes         don't ask questions
  --dry-run         show what would be done, change nothing
  -h, --help        this help

Supported: Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch, Manjaro.
EOF
}

# ── arguments ────────────────────────────────────────────────────────────────
ADD_USERS=(); KEEP_GO=1; NO_START=0; FORCE=0; SKIP_DEPS=0; ASSUME_YES=0; DRY=0; OPT_GO=""
while [ $# -gt 0 ]; do
  case $1 in
    --add-user)    [ $# -ge 2 ] || die "--add-user needs a user name"; ADD_USERS+=("$2"); shift 2;;
    --add-user=*)  ADD_USERS+=("${1#*=}"); shift;;
    --no-start)    NO_START=1; shift;;
    --no-keep-go)  KEEP_GO=0; shift;;
    --force)       FORCE=1; shift;;
    --skip-deps)   SKIP_DEPS=1; shift;;
    --go)          [ $# -ge 2 ] || die "--go needs a path"; OPT_GO=$2; shift 2;;
    --go=*)        OPT_GO=${1#*=}; shift;;
    -y|--yes)      ASSUME_YES=1; shift;;
    --dry-run)     DRY=1; shift;;
    -h|--help)     usage; exit 0;;
    *)             usage >&2; die "unknown option: $1";;
  esac
done

# ── helpers ──────────────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

# run a state-changing command (printed, not executed, under --dry-run)
run() {
  if [ "$DRY" = 1 ]; then printf '    [dry-run] %s\n' "$*"; return 0; fi
  "$@"
}

confirm() { # confirm "question" -> 0 if yes; never prompts without a terminal
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 1
  local a; read -r -p "    $1 [y/N] " a || return 1
  [[ $a =~ ^[Yy] ]]
}

# write_file PATH MODE  (content on stdin); only touches the file if it changed.
# Echoes "created", "updated" or "unchanged".
write_file() {
  local path=$1 mode=$2 tmp
  tmp=$(mktemp "$path.XXXXXX.tmp" 2>/dev/null || mktemp)
  cat >"$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"; echo unchanged; return 0
  fi
  local what=created; [ -f "$path" ] && what=updated
  if [ "$DRY" = 1 ]; then rm -f "$tmp"; echo "$what"; return 0; fi
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path"
  echo "$what"
}

sha() { sha256sum "$1" | awk '{print $1}'; }

# Treat a tool/header as missing when the test hook says so.
assumed_missing() { [[ ",${NTPDIR_ASSUME_MISSING:-}," == *",$1,"* ]]; }

# ── root ─────────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ] && [ "$DRY" = 0 ]; then
  if have sudo; then
    info "re-running with sudo…"
    exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
  fi
  die "must be run as root (sudo ./install.sh)"
fi

[ -f "$SRC/source/go.mod" ] && [ -f "$SRC/source/VERSION" ] && [ -f "$SRC/source/main.go" ] ||
  die "run this script from the top of the AnyTime tree (source/go.mod, source/VERSION and source/main.go not found next to it)"
NEW_VER=$(tr -d '[:space:]' <"$SRC/source/VERSION")
[[ $NEW_VER =~ ^[0-9]+$ ]] || die "bad VERSION file: '$NEW_VER'"

# ── distro ───────────────────────────────────────────────────────────────────
detect_family() {
  [ -r "$OS_RELEASE" ] || die "cannot read $OS_RELEASE — unsupported system"
  local id like name
  # shellcheck disable=SC1090
  eval "$(. "$OS_RELEASE"; printf 'id=%q like=%q name=%q' "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-${ID:-linux}}")"
  OS_NAME=$name
  local tok
  for tok in $id $like; do
    case $tok in
      ubuntu|debian|linuxmint|pop|raspbian|kali|elementary|zorin|neon) FAMILY=debian; return;;
      fedora)                                                           FAMILY=fedora; return;;
      rhel|centos|rocky|almalinux|ol)                                   FAMILY=rhel;   return;;
      arch|manjaro|endeavouros|garuda|cachyos)                          FAMILY=arch;   return;;
    esac
  done
  die "unsupported distribution '$name' (ID=$id ID_LIKE=$like). Supported: Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch, Manjaro."
}
detect_family
case $FAMILY in
  debian) PM=apt;;
  fedora|rhel) if have dnf; then PM=dnf; elif have yum; then PM=yum; else die "neither dnf nor yum found"; fi;;
  arch)   PM=pacman;;
esac

if { [ -d /run/systemd/system ] && have "$SYSTEMCTL"; } || [ -n "${NTPDIR_FORCE_SYSTEMD:-}" ]; then
  HAVE_SYSTEMD=1
else
  HAVE_SYSTEMD=0
fi

step "AnyTime v$NEW_VER on $OS_NAME ($FAMILY family, package manager: $PM)"
[ "$DRY" = 1 ] && info "dry run: nothing will be changed"

# ── existing installation? ───────────────────────────────────────────────────
OLD_VER=""; MODE=fresh
if [ -x "$BIN" ]; then
  OLD_VER=$("$BIN" --version 2>/dev/null | sed -n 's/^ntpdir v\([0-9][0-9]*\).*/\1/p' | head -1 || true)
  OLD_VER=${OLD_VER:-0}   # present but too old to report a version
fi
if [ -n "$OLD_VER" ]; then
  if [ "$OLD_VER" -lt "$NEW_VER" ]; then
    MODE=upgrade; info "installed: v$OLD_VER → upgrading to v$NEW_VER"
  elif [ "$OLD_VER" -eq "$NEW_VER" ] && [ "$FORCE" = 0 ]; then
    info "AnyTime v$OLD_VER is already installed and up to date (use --force to reinstall/repair)."
    exit 0
  elif [ "$OLD_VER" -gt "$NEW_VER" ] && [ "$FORCE" = 0 ]; then
    die "installed v$OLD_VER is newer than this source (v$NEW_VER); use --force to downgrade"
  else
    MODE=reinstall; info "installed: v$OLD_VER — reinstalling v$NEW_VER (--force)"
  fi
else
  info "no existing installation found: fresh install"
fi
OTHER=$(command -v ntpdir 2>/dev/null || true)
if [ -n "$OTHER" ] && [ "$OTHER" != "$BIN" ]; then
  warn "another ntpdir exists at $OTHER and may shadow $BIN in PATH"
fi

# values remembered from a previous install (so upgrades keep them)
GROUP_CREATED=0; PAM_CREATED=0; NM_CREATED=0
if [ -f "$MANIFEST" ]; then
  # shellcheck disable=SC1090
  GROUP_CREATED=$( . "$MANIFEST"; echo "${GROUP_CREATED:-0}" )
  # shellcheck disable=SC1090
  PAM_CREATED=$( . "$MANIFEST"; echo "${PAM_CREATED:-0}" )
  # shellcheck disable=SC1090
  NM_CREATED=$( . "$MANIFEST"; echo "${NM_CREATED:-0}" )
fi

WAS_ACTIVE=0
if [ "$HAVE_SYSTEMD" = 1 ]; then
  "$SYSTEMCTL" is-active  --quiet "$UNIT_NAME" 2>/dev/null && WAS_ACTIVE=1  || true
fi

# ── build prerequisites ──────────────────────────────────────────────────────
TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT
TMP=$(mktemp -d /var/tmp/ntpdir-build.XXXXXX)

pkg_install() {
  [ $# -gt 0 ] || return 0
  case $PM in
    apt)
      run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@";;
    dnf|yum)
      if ! run "$PM" install -y "$@"; then
        warn "install failed; the PAM headers can live in a disabled repo (CRB/PowerTools/CodeReady). Trying to enable it…"
        enable_crb
        run "$PM" install -y "$@"
      fi;;
    pacman)
      run pacman -S --needed --noconfirm "$@" ||
        die "pacman could not install: $* — if the package database is stale run 'pacman -Syu' first, then re-run this script";;
  esac
}

enable_crb() {
  local r
  if have dnf; then
    run dnf install -y dnf-plugins-core >/dev/null 2>&1 || true
    for r in crb powertools; do
      if run dnf config-manager --set-enabled "$r" >/dev/null 2>&1; then info "enabled repo $r"; return 0; fi
    done
  fi
  if have subscription-manager; then
    local rel arch; rel=$(rpm -E %rhel 2>/dev/null || echo 9); arch=$(uname -m)
    run subscription-manager repos --enable "codeready-builder-for-rhel-${rel}-${arch}-rpms" >/dev/null 2>&1 || true
  fi
  return 0
}

install_deps() {
  local pkgs=()
  if assumed_missing gcc || ! { have gcc || have cc; }; then
    case $FAMILY in debian) pkgs+=(gcc libc6-dev);; *) pkgs+=(gcc);; esac
  elif [ "$FAMILY" = debian ] && [ ! -f /usr/include/stdio.h ]; then
    pkgs+=(libc6-dev)
  fi
  if assumed_missing pam || [ ! -f /usr/include/security/pam_appl.h ]; then
    case $FAMILY in
      debian) pkgs+=(libpam0g-dev);;
      fedora|rhel) pkgs+=(pam-devel);;
      arch) pkgs+=(pam);;
    esac
  fi
  if assumed_missing ip || ! have ip; then
    case $FAMILY in debian|arch) pkgs+=(iproute2);; *) pkgs+=(iproute);; esac
  fi
  if assumed_missing tar || ! have tar; then pkgs+=(tar gzip); fi
  if [ "$NEED_DOWNLOAD" = 1 ] && ! { have curl || have wget; }; then
    pkgs+=(curl ca-certificates)
  fi
  if [ ${#pkgs[@]} -eq 0 ]; then info "build prerequisites already present"; return 0; fi
  info "installing: ${pkgs[*]}"
  pkg_install "${pkgs[@]}"
  if [ "$DRY" = 0 ]; then
    { have gcc || have cc; }                        || die "no C compiler after installing prerequisites"
    [ -f /usr/include/security/pam_appl.h ]         || die "PAM development headers still missing (package for $FAMILY: see README)"
    have ip                                         || die "'ip' (iproute2) still missing"
  fi
}

# chrony is what answers NTP clients (on every address of this node, including a gateway's shared address) and
# keeps this node's own clock.  ntpdir tests the configured upstream servers and writes the healthy ones into
# a source directory chrony watches (sourcedir) and the client settings into a conf directory (confdir), so
# chrony 4.0 or newer is required.  The installer adds a marked block to chrony's config that the uninstaller
# removes again, and switches off the servers chrony shipped with (the distribution's pool lines and
# sources.d files), each marked so uninstall puts them back: until servers are defined in ntpdir this node has
# no time source.
have_chronyd() { ! assumed_missing chrony && { have chronyd || [ -x /usr/sbin/chronyd ]; }; }
install_chrony() {
  if have_chronyd; then info "chrony already present"; return 0; fi
  info "installing chrony (it answers NTP clients and keeps this node's clock)"
  pkg_install chrony
  if [ "$DRY" = 0 ]; then have_chronyd || die "chrony still missing after installing it"; fi
}

chrony_conf_path() {
  if [ -n "${NTPDIR_CHRONY_CONF:-}" ]; then echo "$NTPDIR_CHRONY_CONF"; return; fi
  if [ "$FAMILY" = debian ]; then echo /etc/chrony/chrony.conf; else echo /etc/chrony.conf; fi
}
chrony_unit() { if [ "$FAMILY" = debian ]; then echo chrony.service; else echo chronyd.service; fi; }
chrony_sourcedir() { echo "${NTPDIR_CHRONY_SOURCEDIR:-/etc/chrony/ntpdir.sources.d}"; }
chrony_confdir() { echo "${NTPDIR_CHRONY_CONFDIR:-/etc/chrony/ntpdir.conf.d}"; }
CHRONY_OFF='#ntpdir-off# '

# chrony_version prints "major.minor" of the installed chronyd ("" when it cannot be told)
chrony_version() {
  local c v
  c=$(command -v chronyd 2>/dev/null || true); [ -n "$c" ] || { [ -x /usr/sbin/chronyd ] && c=/usr/sbin/chronyd; }
  [ -n "$c" ] || return 0
  v=$("$c" --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1)
  echo "$v"
}

# can_set_clock: true when this machine may set the system clock (CAP_SYS_TIME, bit 25).  A container usually may not, and
# systemd then skips chrony's unit ("start condition unmet"), so nothing answers NTP.  NTPDIR_NO_SYS_TIME=1/0 forces the answer.
can_set_clock() {
  case "${NTPDIR_NO_SYS_TIME:-}" in 1) return 1;; 0) return 0;; esac
  local f cap
  for f in /proc/self/status /proc/1/status; do
    cap=$(awk '/^CapEff:|^CapBnd:/{print $2}' "$f" 2>/dev/null)
    for cap in $cap; do [ $(( (0x$cap >> 25) & 1 )) = 1 ] || return 1; done
  done
  return 0
}
# unit_skipped: systemd decided not to start the chrony unit because a start condition failed (what a container does)
unit_skipped() {
  [ "$HAVE_SYSTEMD" = 1 ] || return 1
  case "${NTPDIR_UNIT_SKIPPED:-}" in 1) return 0;; 0) return 1;; esac
  [ "$("$SYSTEMCTL" show -p ConditionResult --value "$(chrony_unit)" 2>/dev/null)" = no ]
}
chrony_dropin_dir() { echo "${NTPDIR_CHRONY_DROPIN_DIR:-/etc/systemd/system/$(chrony_unit).d}"; }
# chrony without clock control (-x): it still tracks its sources and answers clients; the clock comes from the host
configure_chrony_container() {
  can_set_clock && ! unit_skipped && return 0
  local d f opts bin; d=$(chrony_dropin_dir); f="$d/ntpdir.conf"
  bin=$(command -v chronyd 2>/dev/null || echo /usr/sbin/chronyd)
  if [ "$FAMILY" = debian ]; then opts='$DAEMON_OPTS'; else opts='$OPTIONS'; fi
  warn "this machine cannot set the system clock (a container?): chrony runs with -x, so its time comes from the host; keep the host synchronised"
  if [ "$DRY" = 1 ]; then info "[dry-run] write $f (chronyd -x)"; return 0; fi
  mkdir -p "$d"
  printf '%s\n' "# Written by ntpdir: chrony cannot set the clock here, so it runs with -x." "[Unit]" "ConditionCapability=" "ConditionVirtualization=" "[Service]" "ExecStart=" "ExecStart=!$bin -x $opts" >"$f"
  [ "$HAVE_SYSTEMD" = 1 ] && run "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
  CHRONY_DROPIN=1
}

configure_chrony() {
  CHRONY_CONF=$(chrony_conf_path); CHRONY_BLOCK=0
  if ! have_chronyd && [ "$DRY" = 0 ]; then
    warn "chrony is not installed (--skip-deps?); this node cannot answer NTP clients. Install chrony 4.0 or newer and re-run the installer."
    return 0
  fi
  local ver major
  ver=$(chrony_version)
  major=${ver%%.*}
  if [ -n "$major" ] && [ "$major" -lt 4 ] 2>/dev/null; then
    die "chrony $ver is too old: ntpdir needs chrony 4.0 or newer (sourcedir). Upgrade chrony and run the installer again."
  fi
  local sd cdir body
  sd=$(chrony_sourcedir); cdir=$(chrony_confdir)
  body="# ntpdir writes the healthy upstream servers to $sd/ntpdir.sources"$'\n'
  body+="# and the client settings (port, allow, ratelimit) to $cdir/ntpdir.conf"$'\n'
  body+="sourcedir $sd"$'\n'"confdir $cdir"
  if [ ! -f "$CHRONY_CONF" ]; then
    if [ "$DRY" = 1 ]; then info "[dry-run] would add the ntpdir block to $CHRONY_CONF: ${body//$'\n'/ | }"; CHRONY_BLOCK=1; return 0; fi
    warn "$CHRONY_CONF not found; chrony was not configured"
    return 0
  fi
  if [ "$DRY" = 0 ]; then
    mkdir -p "$sd" "$cdir"; chmod 0755 "$sd" "$cdir"
  fi
  # the servers chrony came with are switched off (marked, so uninstall restores them)
  local mode new res off=0 f
  mode=$(stat -c %a "$CHRONY_CONF" 2>/dev/null || echo 644)
  new=$(awk -v b="$CHRONY_BEGIN" -v e="$CHRONY_END" -v m="$CHRONY_OFF" '
    $0==b{skip=1} !skip{ if ($0 ~ /^[[:space:]]*(pool|server|peer)[[:space:]]/) print m $0; else print } $0==e{skip=0}' "$CHRONY_CONF")
  [ "$(printf '%s\n' "$new" | grep -c "^$CHRONY_OFF")" -gt "$(grep -c "^$CHRONY_OFF" "$CHRONY_CONF" || true)" ] && off=1
  new=$(printf '%s\n%s\n%s\n%s\n' "$new" "$CHRONY_BEGIN" "$body" "$CHRONY_END")
  res=$(printf '%s\n' "$new" | write_file "$CHRONY_CONF" "$mode")
  CHRONY_BLOCK=1
  # distribution source files (Ubuntu: /etc/chrony/sources.d/*.sources) are moved aside the same way
  for f in "$(dirname "$CHRONY_CONF")"/sources.d/*.sources; do
    [ -f "$f" ] || continue
    if [ "$DRY" = 1 ]; then info "[dry-run] would switch off $f"; else mv -f "$f" "$f.ntpdir-off"; fi
    off=1; res=updated
  done
  info "chrony: $CHRONY_CONF $res (sourcedir $sd, confdir $cdir)"
  [ "$off" = 1 ] && warn "chrony's own servers were switched off; define NTP servers in ntpdir (Topology or Configure ▸ NTP) or this node has no time source"
  CHRONY_DROPIN=0; configure_chrony_container
  if [ "$HAVE_SYSTEMD" = 1 ]; then
    run "$SYSTEMCTL" enable "$(chrony_unit)" >/dev/null 2>&1 || warn "could not enable $(chrony_unit)"
    if [ "$res" != unchanged ] || [ "$CHRONY_DROPIN" = 1 ] || ! "$SYSTEMCTL" is-active --quiet "$(chrony_unit)" 2>/dev/null; then
      run "$SYSTEMCTL" restart "$(chrony_unit)" || warn "could not (re)start $(chrony_unit)"
    fi
    if [ "$CHRONY_DROPIN" = 0 ] && [ "$DRY" = 0 ] && unit_skipped; then
      configure_chrony_container && run "$SYSTEMCTL" restart "$(chrony_unit)" || warn "could not (re)start $(chrony_unit)"
    fi
  fi
}

# FRR is what the BGP page configures (anycast addresses announced to routers).
# It is installed here so the page works at once, but ntpdir does not touch FRR
# until a local AS number is set, so an install on a host that never uses BGP is
# unchanged.  A failure to install it is only a warning: everything else works.
install_frr() {
  if ! assumed_missing frr && { have vtysh || [ -x /usr/lib/frr/bgpd ]; }; then
    info "FRR already present"
  else
    info "installing FRR (used by the BGP page; idle until a local AS is set there)"
    if [ "$FAMILY" = rhel ] && [ "$DRY" = 0 ] && have dnf; then
      # on the RHEL family FRR comes from EPEL
      dnf list --available frr >/dev/null 2>&1 || run dnf install -y epel-release >/dev/null 2>&1 || true
    elif [ "$FAMILY" = rhel ]; then
      info "(the RHEL family gets FRR from EPEL: epel-release is installed first when frr is not available)"
    fi
    if ! (pkg_install frr); then
      warn "FRR could not be installed. Everything else works; install the 'frr' package yourself before using Configure → BGP."
      return 0
    fi
    [ "$DRY" = 1 ] || have vtysh || warn "FRR installed but 'vtysh' is not on the PATH"
  fi
  # FRR's reload (how ntpdir applies a changed BGP setting without dropping the sessions)
  # needs frr-reload.py, which Debian ships in a separate package;
  # on the RPM distributions and Arch it is part of frr.  Without it ntpdir has to restart FRR for every change.
  if [ "$FAMILY" = debian ] && { assumed_missing frr-reload || { [ ! -e /usr/lib/frr/frr-reload.py ] && [ ! -e /usr/libexec/frr/frr-reload.py ]; }; }; then
    info "installing frr-pythontools (lets FRR reload a changed config without dropping BGP sessions)"
    (pkg_install frr-pythontools) || warn "frr-pythontools could not be installed; AnyTime will restart FRR (briefly dropping BGP sessions) when the BGP setting changes."
  fi
  return 0
}

# nmap runs the "Scan" of a client on the Statistics page.  Only that feature needs it, so a failure is a warning.
install_nmap() {
  if ! assumed_missing nmap && have nmap; then
    info "nmap already present"
    return 0
  fi
  info "installing nmap (Statistics ▸ right-click a client ▸ Scan)"
  (pkg_install nmap) || warn "nmap could not be installed. Everything else works; install the 'nmap' package yourself before using Scan."
  return 0
}

# snmpd answers SNMP while a community string is set (Configure ▸ SNMP); ntpdir writes /etc/snmp/snmpd.conf and switches the
# service on and off by itself.  A package that starts snmpd as soon as it is installed (Debian) must not leave it running with its
# own default configuration, so a freshly installed snmpd is switched off here: with no community string SNMP is off.
# Only that feature needs it, so a failure is a warning.
have_snmpd() { ! assumed_missing snmpd && { have snmpd || [ -x /usr/sbin/snmpd ]; }; }
install_snmpd() {
  local pkg=snmpd
  case $FAMILY in fedora|rhel|arch) pkg=net-snmp;; esac
  if have_snmpd; then
    info "snmpd already present"
    return 0
  fi
  info "installing $pkg (Configure ▸ SNMP; stays off until a community string is set)"
  if ! (pkg_install "$pkg"); then
    warn "snmpd could not be installed. Everything else works; install the '$pkg' package yourself before using Configure ▸ SNMP."
    return 0
  fi
  if [ "$HAVE_SYSTEMD" = 1 ]; then run "$SYSTEMCTL" disable --now snmpd >/dev/null 2>&1 || true; fi
  return 0
}

# ping and mtr run the "Ping" and "Traceroute" of a client on the Statistics page.  Only those need them, so a failure is a warning.
install_nettools() {
  local want=() ping_pkg=iputils-ping
  case $PM in dnf|yum|pacman) ping_pkg=iputils;; esac
  if assumed_missing ping || ! have ping; then want+=("$ping_pkg"); fi
  if assumed_missing mtr || ! have mtr; then want+=(mtr); fi
  if [ ${#want[@]} -eq 0 ]; then
    info "ping and mtr already present"
    return 0
  fi
  info "installing ${want[*]} (Statistics ▸ right-click a client ▸ Ping, Traceroute)"
  (pkg_install "${want[@]}") || warn "${want[*]} could not be installed. Everything else works; install them yourself before using Ping and Traceroute."
  return 0
}

# ── Go toolchain (>= $GO_MIN) ────────────────────────────────────────────────
go_ok() {
  local bin=$1 v
  [ -x "$bin" ] || return 1
  v=$("$bin" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  [[ $v =~ ^[0-9]+\.[0-9]+ ]] || return 1
  [ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" = "$GO_MIN" ]
}

find_go() {
  local c
  if [ -n "$OPT_GO" ]; then
    go_ok "$OPT_GO" || die "$OPT_GO is not a Go >= $GO_MIN"
    GO=$OPT_GO; return 0
  fi
  [ -n "${NTPDIR_FORCE_GO_DOWNLOAD:-}" ] && return 1
  for c in "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go /usr/lib/go/bin/go /usr/lib/golang/bin/go /snap/bin/go /usr/lib/go-*/bin/go "$SHARE/go/bin/go"; do
    [ -n "$c" ] && go_ok "$c" && { GO=$c; return 0; }
  done
  return 1
}

fetch() { # fetch URL DEST
  if have curl; then curl -fsSL --retry 3 -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}

download_go() {
  local arch file
  case $(uname -m) in
    x86_64|amd64)   arch=amd64;;
    aarch64|arm64)  arch=arm64;;
    armv7l|armv6l)  arch=armv6l;;
    i?86)           arch=386;;
    riscv64)        arch=riscv64;;
    *) die "no Go toolchain for $(uname -m); install Go >= $GO_MIN yourself and re-run with --go /path/to/go";;
  esac
  file=go${GO_VERSION}.linux-${arch}.tar.gz
  info "no Go >= $GO_MIN on this system; fetching the official go$GO_VERSION toolchain (kept in $SHARE/go for in-place updates unless --no-keep-go)"
  have curl || have wget || die "need curl or wget to download Go (or pass --go PATH)"
  if [ "$DRY" = 1 ]; then info "[dry-run] download $GO_BASE/$file and verify its sha256"; GO=$TMP/goroot/go/bin/go; return 0; fi
  fetch "$GO_BASE/$file" "$TMP/$file"        || die "could not download $GO_BASE/$file"
  fetch "$GO_BASE/$file.sha256" "$TMP/$file.sha256" || die "could not download the checksum $GO_BASE/$file.sha256"
  local want got
  want=$(awk '{print $1; exit}' "$TMP/$file.sha256"); got=$(sha "$TMP/$file")
  [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $file (wanted '$want', got '$got') — refusing to use it"
  mkdir -p "$TMP/goroot"
  tar -xzf "$TMP/$file" -C "$TMP/goroot"
  GO=$TMP/goroot/go/bin/go
  go_ok "$GO" || die "downloaded toolchain does not run on this system"
}

# Prefer the distribution's own Go package when it is recent enough; the
# official tarball (below) is the fallback for distros that ship an older Go.
pkg_version_ok() { # pkg_version_ok VERSION-STRING -> 0 if >= GO_MIN
  local v=${1#*:}; v=${v%%[~+-]*}
  [[ $v =~ ^[0-9]+\.[0-9]+ ]] && [ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" = "$GO_MIN" ]
}
try_distro_go() {
  local p cand
  [ -z "${NTPDIR_FORCE_GO_DOWNLOAD:-}" ] || return 1
  case $FAMILY in
    debian) set -- golang-1.25-go golang-1.24-go golang-go;;
    fedora|rhel) set -- golang;;
    arch) set -- go;;
    *) return 1;;
  esac
  for p in "$@"; do
    if [ "$FAMILY" = debian ] && [ "$DRY" = 0 ]; then
      cand=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}')
      { [ -n "$cand" ] && [ "$cand" != "(none)" ] && pkg_version_ok "$cand"; } || continue
    fi
    info "installing Go from the distribution package: $p"
    if (pkg_install "$p") && { [ "$DRY" = 1 ] || find_go; }; then return 0; fi
    info "package $p did not give a usable Go >= $GO_MIN"
  done
  return 1
}

GO=""; NEED_DOWNLOAD=0
if [ "$SKIP_DEPS" = 0 ] || [ -z "$OPT_GO" ]; then
  find_go >/dev/null 2>&1 || NEED_DOWNLOAD=1
fi
step "Build prerequisites"
if [ "$SKIP_DEPS" = 1 ]; then
  info "skipped (--skip-deps)"
  { have gcc || have cc; } || die "--skip-deps given but no C compiler found"
  [ -f /usr/include/security/pam_appl.h ] || die "--skip-deps given but PAM headers (security/pam_appl.h) are missing"
else
  install_deps
  install_chrony
  install_frr
  install_nmap
  install_nettools
  install_snmpd
fi
step "Go toolchain"
if find_go; then info "using $GO ($("$GO" version | awk '{print $3}'))"
elif [ "$SKIP_DEPS" = 0 ] && [ -z "$OPT_GO" ] && try_distro_go && [ "$DRY" = 0 ]; then
  find_go; info "using $GO ($("$GO" version | awk '{print $3}'))"
else
  [ "$DRY" = 1 ] && [ "$SKIP_DEPS" = 0 ] && [ -z "$OPT_GO" ] && [ -z "${NTPDIR_FORCE_GO_DOWNLOAD:-}" ] && info "[dry-run] (if the package gives no Go >= $GO_MIN, the official toolchain is downloaded instead)"
  download_go
fi

# ── build (before touching the installed system) ─────────────────────────────
step "Building AnyTime v$NEW_VER (with PAM)"
NEWBIN=$TMP/ntpdir
if [ "$DRY" = 1 ]; then
  info "[dry-run] CGO_ENABLED=1 $GO build -trimpath -o ntpdir ."
else
  ( cd "$SRC/source" &&
    GOTOOLCHAIN=local CGO_ENABLED=1 GOCACHE="$TMP/gocache" GOPATH="$TMP/gopath" GOFLAGS=-mod=mod \
    "$GO" build -trimpath -ldflags='-s -w' -o "$NEWBIN" . ) ||
    die "build failed — the installed version (if any) was not touched"
  grep -aq 'libpam\.so' "$NEWBIN" || die "built binary has no PAM support (cgo disabled?) — web GUI logins would not work"
  [ "$("$NEWBIN" --version)" = "ntpdir v$NEW_VER" ] || die "built binary reports '$("$NEWBIN" --version)', expected 'ntpdir v$NEW_VER'"
  info "built $(du -h "$NEWBIN" | cut -f1) binary, PAM linked"
fi

# ── install files ────────────────────────────────────────────────────────────
step "Installing files"
run mkdir -p "$BIN_DIR" "$SHARE"
run install -d -m 0700 "$STATE_DIR"   # config, history, cluster identity, certificates, update data

# an install from before v15 kept its config in /etc/liras: move it over (never
# overwrite a config that is already here; each old file is removed once its copy
# is in place, and /etc/liras goes when it is empty)
if [ -f "$LEGACY_CONF_DIR/ntpdir.conf" ] && [ ! -f "$CONF_DIR/ntpdir.conf" ]; then
  if [ "$DRY" = 1 ]; then
    info "[dry-run] move $LEGACY_CONF_DIR/ntpdir.conf (and ntpdir-web.crt/.key) to $CONF_DIR"
  else
    for f in ntpdir.conf ntpdir-web.crt ntpdir-web.key; do
      if [ -f "$LEGACY_CONF_DIR/$f" ] && [ ! -e "$CONF_DIR/$f" ]; then
        cp -p "$LEGACY_CONF_DIR/$f" "$CONF_DIR/$f" && chmod 0600 "$CONF_DIR/$f" &&
          cmp -s "$LEGACY_CONF_DIR/$f" "$CONF_DIR/$f" && rm -f "$LEGACY_CONF_DIR/$f"
      fi
    done
    rmdir "$LEGACY_CONF_DIR" 2>/dev/null || true
    info "moved your configuration from $LEGACY_CONF_DIR to $CONF_DIR"
  fi
fi
run rm -f /run/liras/ntpdir.sock   # control socket of an older release

# keep the previous binary for rollback, then replace atomically
HAD_BIN=0
if [ -x "$BIN" ]; then
  HAD_BIN=1
  run cp -p "$BIN" "$SHARE/ntpdir.prev"
  info "previous binary saved to $SHARE/ntpdir.prev"
fi
run install -m 0755 "$NEWBIN" "$BIN.new"
run mv -f "$BIN.new" "$BIN"
info "installed $BIN"

# keep a downloaded Go: in-place updates (GUI/CLI) compile with it
GO_KEPT=0
if [ "${GO#"$TMP"/}" != "$GO" ]; then
  if [ "$KEEP_GO" = 1 ]; then
    if [ "$DRY" = 1 ]; then info "[dry-run] keep the downloaded Go in $SHARE/go"; else
      rm -rf "$SHARE/go.new" && mv "$TMP/goroot/go" "$SHARE/go.new" && rm -rf "$SHARE/go" && mv "$SHARE/go.new" "$SHARE/go"
      GO_KEPT=1; info "kept the Go toolchain in $SHARE/go (used when applying updates; --no-keep-go to skip)"
    fi
  else
    info "downloaded Go not kept (--no-keep-go): applying updates from the GUI/CLI needs a Go >= $GO_MIN on this node"
  fi
elif [ "$GO" = "$SHARE/go/bin/go" ]; then
  GO_KEPT=1
fi

# docs, examples, and the uninstaller (so removal works without the source tree)
run install -m 0644 "$SRC/source/ntpdir.conf.example" "$SHARE/ntpdir.conf.example"
for f in README.md CHANGELOG.md LICENSE; do
  src="$SRC/docs/$f"; [ "$f" = CHANGELOG.md ] || src="$SRC/$f"
  [ -f "$src" ] && run install -m 0644 "$src" "$SHARE/$f"
done
run install -m 0644 "$SRC/source/VERSION" "$SHARE/VERSION"
if [ -f "$SRC/uninstall.sh" ]; then
  run install -m 0755 "$SRC/uninstall.sh" "$SHARE/uninstall.sh"
  run ln -sf "$SHARE/uninstall.sh" "$BIN_DIR/ntpdir-uninstall"
fi

# group
step "Group '$GROUP' (members may log in to the web GUI)"
if getent group "$GROUP" >/dev/null 2>&1; then
  info "group exists"
else
  run groupadd --system "$GROUP"
  GROUP_CREATED=1
  info "created group $GROUP"
fi

for u in ${ADD_USERS[@]+"${ADD_USERS[@]}"}; do
  if id -u "$u" >/dev/null 2>&1; then
    run usermod -aG "$GROUP" "$u"; info "added $u to $GROUP"
  else
    warn "no such user '$u' — not added"
  fi
done

# PAM service
step "PAM service $PAM_FILE"
case $FAMILY in
  debian)
    PAM_STACK=common-auth
    PAM_BODY='# /etc/pam.d/ntpdir — installed by ntpdir install.sh
# Password check for the ntpdir web GUI. Group membership is enforced by ntpdir.
@include common-auth
@include common-account';;
  fedora|rhel)
    PAM_STACK=system-auth
    PAM_BODY='#%PAM-1.0
# /etc/pam.d/ntpdir — installed by ntpdir install.sh
# Password check for the ntpdir web GUI. Group membership is enforced by ntpdir.
auth       substack     system-auth
account    include      system-auth';;
  arch)
    PAM_STACK=system-auth
    PAM_BODY='#%PAM-1.0
# /etc/pam.d/ntpdir — installed by ntpdir install.sh
# Password check for the ntpdir web GUI. Group membership is enforced by ntpdir.
auth       include      system-auth
account    include      system-auth';;
esac
if [ -f "$PAM_FILE" ]; then
  if [ "$PAM_CREATED" = 1 ] && [ "$(printf '%s\n' "$PAM_BODY" | sha256sum | awk '{print $1}')" != "$(sha "$PAM_FILE")" ]; then
    info "exists and has been customised — left untouched"
  else
    info "exists — left untouched"
  fi
else
  printf '%s\n' "$PAM_BODY" | write_file "$PAM_FILE" 0644 >/dev/null
  PAM_CREATED=1
  info "created (includes the system $PAM_STACK stack)"
fi
[ "$DRY" = 1 ] || [ -f "/etc/pam.d/$PAM_STACK" ] ||
  warn "/etc/pam.d/$PAM_STACK not found — web logins will fail until $PAM_FILE points at a valid stack"

# NetworkManager: keep it away from the virtual MAC interfaces
if [ -d /etc/NetworkManager ] && { [ "$HAVE_SYSTEMD" = 0 ] || "$SYSTEMCTL" is-active --quiet NetworkManager 2>/dev/null || [ -d /etc/NetworkManager/conf.d ]; }; then
  mkdir -p /etc/NetworkManager/conf.d 2>/dev/null || true
  res=$(printf '%s\n' '# installed by ntpdir: the gateway creates macvlan interfaces named ntpdir<group>.<slot>;' \
                      '# NetworkManager must not try to configure them.' \
                      '[keyfile]' 'unmanaged-devices=interface-name:ntpdir*' | write_file "$NM_FILE" 0644)
  if [ "$res" != unchanged ]; then
    NM_CREATED=1; info "NetworkManager: marked ntpdir* interfaces unmanaged ($res)"
    [ "$HAVE_SYSTEMD" = 1 ] && run "$SYSTEMCTL" reload NetworkManager >/dev/null 2>&1 || true
  fi
fi

# chrony: answers NTP clients; ntpdir feeds it sources and client settings
step "chrony"
configure_chrony

# SELinux labels (RHEL family)
if have restorecon; then run restorecon -F "$BIN" "$PAM_FILE" "$SHARE" >/dev/null 2>&1 || true; fi

# ── systemd unit ─────────────────────────────────────────────────────────────
UNIT_BODY="[Unit]
Description=ntpdir - NTP Distributed Gateway
Documentation=file://$SHARE/README.md
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$BIN --config $CONF_DIR/ntpdir.conf
Restart=always
RestartSec=2
TimeoutStopSec=15
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"

ROLLED_BACK=0
if [ "$HAVE_SYSTEMD" = 1 ]; then
  step "systemd service"
  res=$(printf '%s\n' "$UNIT_BODY" | write_file "$UNIT" 0644)
  info "unit $UNIT: $res"
  run "$SYSTEMCTL" daemon-reload
  run "$SYSTEMCTL" enable "$UNIT_NAME" >/dev/null 2>&1 || warn "could not enable $UNIT_NAME"

  start_wanted=1
  [ "$NO_START" = 1 ] && start_wanted=0
  # an upgrade keeps the service in the state it was found in
  if [ "$MODE" != fresh ] && [ "$WAS_ACTIVE" = 0 ]; then start_wanted=0; fi

  if [ "$start_wanted" = 1 ]; then
    if [ "$WAS_ACTIVE" = 1 ]; then run "$SYSTEMCTL" restart "$UNIT_NAME" || true; else run "$SYSTEMCTL" start "$UNIT_NAME" || true; fi   # a unit that fails to start is caught by the is-active check below
    if [ "$DRY" = 0 ]; then
      sleep "$SETTLE"
      if ! "$SYSTEMCTL" is-active --quiet "$UNIT_NAME"; then
        errmsg="ntpdir v$NEW_VER failed to start"
        if [ "$HAD_BIN" = 1 ] && [ -x "$SHARE/ntpdir.prev" ]; then
          warn "$errmsg — rolling back to the previous binary"
          cp -p "$SHARE/ntpdir.prev" "$BIN.new" && mv -f "$BIN.new" "$BIN"
          [ "${OLD_VER:-0}" != 0 ] && echo "$OLD_VER" >"$SHARE/VERSION"
          "$SYSTEMCTL" restart "$UNIT_NAME" || true
          sleep "$SETTLE"
          ROLLED_BACK=1
          if "$SYSTEMCTL" is-active --quiet "$UNIT_NAME"; then
            die "$errmsg; the previous version was restored and is running. See: journalctl -u ntpdir -n 50"
          fi
          die "$errmsg and the restored previous version is not running either. See: journalctl -u ntpdir -n 50"
        fi
        die "$errmsg. See: journalctl -u ntpdir -n 50"
      fi
      info "service is running"
    fi
  else
    info "service not (re)started"
  fi
else
  step "systemd"
  warn "systemd is not running here — unit file not installed. Start it yourself: $BIN --config $CONF_DIR/ntpdir.conf"
fi

# ── manifest ─────────────────────────────────────────────────────────────────
if [ "$DRY" = 0 ]; then
  {
    echo "VERSION=$NEW_VER"
    echo "INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "FAMILY=$FAMILY"
    echo "BIN=$BIN"
    echo "SHARE=$SHARE"
    echo "UNIT=$UNIT"
    echo "PAM_FILE=$PAM_FILE"
    echo "PAM_CREATED=$PAM_CREATED"
    echo "PAM_SHA256=$([ -f "$PAM_FILE" ] && sha "$PAM_FILE" || echo)"
    echo "NM_FILE=$NM_FILE"
    echo "NM_CREATED=$NM_CREATED"
    echo "GROUP=$GROUP"
    echo "GROUP_CREATED=$GROUP_CREATED"
    echo "CONF_DIR=$CONF_DIR"
    echo "STATE_DIR=$STATE_DIR"
    echo "CHRONY_CONF=$CHRONY_CONF"
    echo "CHRONY_BLOCK=$CHRONY_BLOCK"
    echo "GO_KEPT=$GO_KEPT"
  } >"$MANIFEST"
  chmod 0644 "$MANIFEST"
fi

# ── summary ──────────────────────────────────────────────────────────────────
step "Done: AnyTime v$NEW_VER ($MODE)"
HOST=$(hostname -f 2>/dev/null || hostname)
if [ ! -f "$CONF_DIR/ntpdir.conf" ]; then
  info "no config yet ($CONF_DIR/ntpdir.conf): the daemon runs with no gateway groups until you create one."
  info "  - in the web GUI: https://$HOST:$GUI_PORT  → Configuration"
  info "  - or by hand: cp $SHARE/ntpdir.conf.example $CONF_DIR/ntpdir.conf && chmod 600 $CONF_DIR/ntpdir.conf  (edits apply live)"
fi
# The user who ran the installer (the one behind sudo, or root itself) can log in to the GUI.
INVOKER="${SUDO_USER:-${DOAS_USER:-}}"
[ -n "$INVOKER" ] || INVOKER="$(id -un)"
if id -u "$INVOKER" >/dev/null 2>&1 && ! id -nG "$INVOKER" | tr ' ' '\n' | grep -qx "$GROUP"; then
  run usermod -aG "$GROUP" "$INVOKER"; info "added $INVOKER to $GROUP (can log in to the GUI)"
fi
if [ -z "$(getent group "$GROUP" | cut -d: -f4)" ] && [ "$DRY" != 1 ]; then
  info "'$GROUP' has no members yet, so nobody can log in to the GUI. Add someone:  usermod -aG $GROUP <user>"
fi
info "web GUI: https://$HOST:$GUI_PORT (self-signed certificate until you set web.cert_file/key_file)"
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
  info "firewalld is active; open what you need, e.g.: firewall-cmd --permanent --add-port=$GUI_PORT/tcp --add-port=$CLUSTER_PORT/tcp --add-service=ntp && firewall-cmd --reload"
elif have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
  info "ufw is active; open what you need, e.g.: ufw allow $GUI_PORT/tcp && ufw allow $CLUSTER_PORT/tcp && ufw allow 123/udp && ufw allow 12382/udp"
else
  info "ports used: GUI tcp/$GUI_PORT, cluster tcp/$CLUSTER_PORT (only if clustering is on), NTP (chrony) udp/123, gateway protocol udp/12382 (open them if a firewall is active)"
fi
info "status: ntpdir --show-gateways | ntpdir --show-ntp     logs: journalctl -u ntpdir -f"
info "uninstall: sudo ntpdir-uninstall   (add --purge to remove config and certificate too)"
[ "$ROLLED_BACK" = 1 ] && warn "rolled back"
exit 0
