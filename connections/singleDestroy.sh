#!/usr/bin/env bash
# Idempotent teardown for a node's TAP/bridge and veth pair.
# Quiet by default; use -v or set DDOSIM_SCRIPT_VERBOSE=1 for logs.

set -Eeuo pipefail
IFS=$'\n\t'

usage(){ echo "Usage: $0 <name> [-v] [--unload-brnf]"; exit 1; }

VERBOSE="${DDOSIM_SCRIPT_VERBOSE:-0}"
UNLOAD_BRNF=0
NAME=""

# Accept -v anywhere; optional --unload-brnf to remove br_netfilter
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v) VERBOSE=1; shift ;;
    --unload-brnf) UNLOAD_BRNF=1; shift ;;
    --) shift; break ;;
    -*) shift ;;                                # ignore other flags
    *)  if [[ -z "$NAME" ]]; then NAME="$1"; fi; shift ;;
  esac
done
[[ -n "$NAME" ]] || usage

SUDO=""; [[ ${EUID:-$(id -u)} -ne 0 ]] && SUDO="sudo"

TAP="tap-$NAME"
BR="br-$NAME"
SI="si-$NAME"
SE="se-$NAME"

# SAFE logger: never returns non-zero
log() {
  if [ "${VERBOSE}" = "1" ]; then
    echo "[singleDestroy] $*"
  fi
  return 0
}
err(){ echo "[singleDestroy] ERROR: $*" >&2; }
trap 'err "command failed at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}"; exit 1' ERR

link_exists(){ ip link show "$1" &>/dev/null; }

# --- veth pair: delete either end if present (deleting one removes its peer) ---
if link_exists "$SI"; then
  $SUDO ip link set "$SI" nomaster || true
  $SUDO ip link set "$SI" down || true
  $SUDO ip link delete "$SI" || true
  log "deleted $SI (and peer if present)"
elif link_exists "$SE"; then
  $SUDO ip link set "$SE" down || true
  $SUDO ip link delete "$SE" || true
  log "deleted $SE (and peer if present)"
else
  log "no veth pair ($SI/$SE) found"
fi

# --- TAP: detach from bridge (if any), down, delete ---
if link_exists "$TAP"; then
  $SUDO ip link set "$TAP" nomaster || true
  $SUDO ip link set "$TAP" down || true
  $SUDO ip link delete "$TAP" || true
  log "deleted $TAP"
else
  log "no $TAP found"
fi

# --- Bridge: down, delete ---
if link_exists "$BR"; then
  $SUDO ip link set "$BR" down || true
  $SUDO ip link delete "$BR" || true
  log "deleted $BR"
else
  log "no $BR found"
fi

# --- br_netfilter unloading (opt-in only) ---
if [[ "$UNLOAD_BRNF" -eq 1 ]]; then
  $SUDO modprobe -r br_netfilter || true
  log "unloaded br_netfilter"
fi

exit 0