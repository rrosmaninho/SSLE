#!/usr/bin/env bash
# Toggle internet egress for the Incus lab network.
# Use "on" before attack experiments (DDoS, C2, DNS hijack), "off" after.
# LAN access from the lab is ALWAYS blocked regardless of this toggle.
# Lockdown does not survive a reboot / guard reload (it resets to "off").
set -euo pipefail

case "${1:-status}" in
  on)
    nft flush chain inet ssle_guard egress
    nft add rule inet ssle_guard egress counter drop
    echo "Lab internet egress: BLOCKED"
    ;;
  off)
    nft flush chain inet ssle_guard egress
    echo "Lab internet egress: allowed"
    ;;
  status)
    if nft list chain inet ssle_guard egress | grep -q drop; then
      echo "Lab internet egress: BLOCKED"
    else
      echo "Lab internet egress: allowed"
    fi
    ;;
  *)
    echo "usage: $0 on|off|status" >&2; exit 2 ;;
esac
