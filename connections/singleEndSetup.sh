#!/usr/bin/env bash
# Quiet, idempotent end-setup for bridge netfilter sysctls.
# - Loads br_netfilter if available.
# - Disables bridge netfilter (iptables/ip6tables/arptables).
# - Quiet by default; pass -v or set DDOSIM_SCRIPT_VERBOSE=1 for logs.

set -Eeuo pipefail
IFS=$'\n\t'

# Verbosity: -v flag or env var
VERBOSE="${DDOSIM_SCRIPT_VERBOSE:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v) VERBOSE=1; shift ;;
    --) shift; break ;;
    *)  shift ;;
  esac
done

# SAFE logger: never triggers ERR on false conditions
log() {
  if [ "${VERBOSE}" = "1" ]; then
    echo "[singleEndSetup] $*"
  fi
}
err() { echo "[singleEndSetup] ERROR: $*" >&2; }
trap 'err "command failed at ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}"; exit 1' ERR

# If run without sudo, allow prompting (main.py usually calls with sudo).
SUDO=""; if [[ ${EUID:-$(id -u)} -ne 0 ]]; then SUDO="sudo"; fi

# 1) Load br_netfilter if present (don’t fail if missing)
$SUDO modprobe br_netfilter 2>/dev/null || true
log "br_netfilter checked"

# 2) Disable bridge netfilter paths quietly (prefer sysctl, fallback to /proc)
set_sysctl() {
  local key="$1" val="$2"
  if command -v sysctl >/dev/null; then
    $SUDO sysctl -qw "$key=$val" || true
  fi
}
set_sysctl net.bridge.bridge-nf-call-iptables   0
set_sysctl net.bridge.bridge-nf-call-ip6tables  0
set_sysctl net.bridge.bridge-nf-call-arptables  0

for f in /proc/sys/net/bridge/bridge-nf-call-{iptables,ip6tables,arptables}; do
  if [[ -e "$f" ]]; then echo 0 | $SUDO tee "$f" >/dev/null || true; fi
done

log "bridge netfilter sysctls set to 0"
exit 0
