#!/usr/bin/env bash
# connections/singleSetup.sh
# Create a TAP (tap-<name>) and a bridge (br-<name>), put TAP in promisc, enslave to bridge.
# Quiet by default; pass -v to print what it’s doing (in any position).
set -Eeuo pipefail
IFS=$'\n\t'

usage(){ echo "Usage: $0 <name> [-v]  ( -v can appear before or after <name> )"; exit 1; }

# -------- Flexible arg parsing: allow -v anywhere --------
VERBOSE="${DDOSIM_SCRIPT_VERBOSE:-0}"
NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v) VERBOSE=1; shift ;;
    --) shift; break ;;
    -*) shift ;;                    # ignore other flags for now
    *)  if [[ -z "$NAME" ]]; then NAME="$1"; fi; shift ;;
  esac
done
[[ -n "$NAME" ]] || usage

# sudo helper (prompt when needed)
SUDO=""
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then SUDO="sudo"; fi

TAP="tap-$NAME"
BR="br-$NAME"

log() { if [[ "$VERBOSE" -eq 1 ]]; then echo "[singleSetup] $*"; fi; }
err() { echo "[singleSetup] ERROR: $*" >&2; }

trap 'err "command failed at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}"; exit 1' ERR

# -------- Preconditions --------
command -v ip >/dev/null || { err "'ip' not found (install iproute2)"; exit 2; }

# Ensure /dev/net/tun exists (common on minimal setups)
if [[ ! -e /dev/net/tun ]]; then
  $SUDO modprobe tun || true
  if [[ ! -e /dev/net/tun ]]; then
    $SUDO mkdir -p /dev/net
    $SUDO mknod /dev/net/tun c 10 200 || true
    $SUDO chmod 0666 /dev/net/tun || true
    log "created /dev/net/tun node"
  fi
fi

# -------- 1) TAP: create if missing; up + promisc (idempotent) --------
if ! ip link show "$TAP" &>/dev/null; then
  $SUDO ip tuntap add dev "$TAP" mode tap
  log "created $TAP"
fi
$SUDO ip link set dev "$TAP" promisc on || true
$SUDO ip link set dev "$TAP" up || true

# -------- 2) Bridge: create if missing; up (idempotent) --------
if ! ip link show "$BR" &>/dev/null; then
  $SUDO ip link add name "$BR" type bridge
  log "created $BR"
fi
$SUDO ip link set dev "$BR" up || true

# -------- 3) Enslave TAP to bridge (detach from any previous master first) --------
current_master=""
if [[ -L "/sys/class/net/${TAP}/master" ]]; then
  current_master="$(basename "$(readlink -f "/sys/class/net/${TAP}/master")" 2>/dev/null || true)"
fi

if [[ "$current_master" != "$BR" ]]; then
  $SUDO ip link set dev "$TAP" nomaster || true
  $SUDO ip link set dev "$TAP" master "$BR"
  log "enslaved $TAP -> $BR"
else
  log "$TAP already enslaved to $BR"
fi

exit 0
