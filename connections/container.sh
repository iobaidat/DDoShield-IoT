#!/usr/bin/env bash
# Wire a --net=none Docker container into host bridge br-<name> via a veth pair.
# Keeps original addressing logic; adds readiness waits and idempotent cleanup.
# Quiet by default; use -v for logs.

set -uo pipefail
IFS=$'\n\t'

usage(){ echo "Usage: $0 <container-name> <index> [-v]"; exit 1; }

VERBOSE="${DDOSIM_SCRIPT_VERBOSE:-0}"
NAME=""
INDEX=""

# Parse args (allow -v anywhere)
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v) VERBOSE=1; shift ;;
    --) shift; break ;;
    -*) shift ;;  # ignore other flags
    *)  if [[ -z "$NAME"   ]]; then NAME="$1";
        elif [[ -z "$INDEX" ]]; then INDEX="$1";
        fi
        shift ;;
  esac
done
[[ -n "$NAME" && -n "$INDEX" ]] || usage
[[ "$INDEX" =~ ^[0-9]+$ ]] || { echo "[container] ERROR: index must be an integer" >&2; exit 2; }

log(){ if [[ "$VERBOSE" -eq 1 ]]; then echo "[container] $*"; fi; }
err(){ echo "[container] ERROR: $*" >&2; }

# sudo helper (prompt when needed)
SUDO=""; [[ ${EUID:-$(id -u)} -ne 0 ]] && SUDO="sudo"

# Tools
command -v docker >/dev/null || { err "'docker' not found"; exit 2; }
command -v ip     >/dev/null || { err "'ip' not found (install iproute2)"; exit 2; }

SIDE_A="si-$NAME"
SIDE_B="se-$NAME"
BRIDGE="br-$NAME"

# --- Robustly obtain a ready PID + netns (wait up to ~5s) ---
PID=""
for _ in $(seq 1 50); do
  PID="$(docker inspect --format '{{ .State.Pid }}' "$NAME" 2>/dev/null || echo 0)"
  # running container should have a positive PID and a netns under /proc
  if [[ "$PID" =~ ^[0-9]+$ ]] && [[ "$PID" -gt 0 ]] && $SUDO test -e "/proc/$PID/ns/net"; then
    break
  fi
  sleep 0.1
done

if ! [[ "$PID" =~ ^[0-9]+$ ]] || [[ "$PID" -le 0 ]] || ! $SUDO test -e "/proc/$PID/ns/net"; then
  err "Network namespace not ready for '$NAME'. Missing /proc/<pid>/ns/net after wait."
  exit 3
fi
log "using PID=$PID"

# Ensure /var/run/netns symlink exists for ip(8) tooling
$SUDO mkdir -p /var/run/netns
# replace if stale / already present
$SUDO ln -sf "/proc/$PID/ns/net" "/var/run/netns/$PID"

# Ensure the bridge exists and is up
if ! ip link show "$BRIDGE" &>/dev/null; then
  err "Bridge '$BRIDGE' not found. Did you run singleSetup.sh $NAME?"
  exit 2
fi
$SUDO ip link set "$BRIDGE" up || true

# --- Keep your original addressing/mac logic (no behavior change) ---
INDEX_VAL=$INDEX

# IPv4
let OCTET1=(INDEX_VAL%255)
let SEGMENT0=(INDEX_VAL/255)
let SEGMENT1=(SEGMENT0/255)
let OCTET2=(SEGMENT0%256)
let OCTET3=(SEGMENT1%256)

# IPv6
let HEXTET_1=(INDEX_VAL%0xffff)
HEXTET1=$(printf %x $(echo $HEXTET_1))
let SEGMENT2=(INDEX_VAL/0xffff)
let HEXTET_2=(SEGMENT2%0x10000)
HEXTET2=$(printf %x $(echo $HEXTET_2))
let SEGMENT3=(SEGMENT2/0xffff)
let HEXTET_3=(SEGMENT3%0x10000)
HEXTET3=$(printf %x $(echo $HEXTET_3))

# Random MAC address (matches your original approach)
hexchars="0123456789ABCDEF"
end=$( for i in {1..8}; do echo -n ${hexchars:$(( RANDOM % 16 )):1}; done | sed -e 's/\(..\)/:\1/g' )
MAC_ADDR="12:34$end"

# --- Idempotent cleanup: remove stale veth ends if present ---
for IFACE in "$SIDE_A" "$SIDE_B"; do
  if ip link show "$IFACE" &>/dev/null; then
    $SUDO ip link del "$IFACE" || true
    log "deleted stale $IFACE"
  fi
done

# --- Create veth, enslave host side, move peer to container ns ---
$SUDO ip link add "$SIDE_A" type veth peer name "$SIDE_B"

$SUDO ip link set dev "$SIDE_A" master "$BRIDGE"
$SUDO ip link set "$SIDE_A" up

$SUDO ip link set "$SIDE_B" netns "$PID"
$SUDO ip netns exec "$PID" ip link set dev "$SIDE_B" name eth0
$SUDO ip netns exec "$PID" ip link set eth0 address "$MAC_ADDR"
$SUDO ip netns exec "$PID" ip link set eth0 up

$SUDO ip netns exec "$PID" ip addr add 10.$OCTET3.$OCTET2.$OCTET1/8 dev eth0
$SUDO ip netns exec "$PID" ip -6 addr add fd00::$HEXTET3:$HEXTET2:$HEXTET1/64 dev eth0 || true

log "wired $NAME -> $BRIDGE (PID=$PID) IPv4=10.$OCTET3.$OCTET2.$OCTET1/8 IPv6=fd00::$HEXTET3:$HEXTET2:$HEXTET1/64 MAC=$MAC_ADDR"
exit 0
