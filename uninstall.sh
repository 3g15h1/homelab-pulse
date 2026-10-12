#!/usr/bin/env bash
# Remove Homelab Pulse. Run as root on the Proxmox host:  bash uninstall.sh [--vmid N] [--yes]
# Destroys the container tagged "homelab-pulse" (or --vmid) and its API token; the pulse@pve user
# is deleted too once no other Pulse install uses it.
set -euo pipefail
VMID="" YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID=$2; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    *) echo "usage: uninstall.sh [--vmid N] [--yes]" >&2; exit 2 ;;
  esac
done
if [ -z "$VMID" ]; then
  for id in $(pct list | awk 'NR>1 {print $1}'); do
    if pct config "$id" | grep -qE '^tags:.*\bhomelab-pulse\b'; then VMID=$id; break; fi
  done
fi
if [ "$YES" != 1 ]; then
  echo "This will destroy CT ${VMID:-<none found>} and its pulse@pve API token."
  read -r -p "Type 'yes' to continue: " answer
  [ "$answer" = yes ] || { echo "Aborted."; exit 1; }
fi
if [ -n "$VMID" ]; then
  pct stop "$VMID" 2>/dev/null || true
  pct destroy "$VMID"
fi
if [ -n "$VMID" ]; then pveum user token remove pulse@pve "ct$VMID" 2>/dev/null || true; fi
left=$(pveum user token list pulse@pve --output-format json 2>/dev/null |
  python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
if [ "$left" = 0 ]; then pveum user delete pulse@pve 2>/dev/null || true; else
  echo "Kept pulse@pve: $left other token(s) still use it (pveum user token list pulse@pve)."; fi
echo "Homelab Pulse removed."
