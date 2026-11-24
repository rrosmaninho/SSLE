#!/usr/bin/env bash
# Deploy the SIEM layer:
#   - custom decoders, rules and active-response config on the Wazuh manager
#   - the wazuh-agent on every service container, enrolled and configured
#
#   bash deploy/incus/deploy-siem.sh             # rules + agents
#   bash deploy/incus/deploy-siem.sh --rules     # rules/config only (fast iteration)
#   bash deploy/incus/deploy-siem.sh --agents    # agents only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MGR=wazuh
AGENTS="registry storage ingestion analytics sensors-aveiro-rack2-node1 sensors-coimbra-rack1-node1"

DO_RULES=1; DO_AGENTS=1
case "${1:-}" in
  --rules)  DO_AGENTS=0 ;;
  --agents) DO_RULES=0 ;;
esac

MGR_IP=$(incus list "$MGR" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
[[ -n "$MGR_IP" ]] || { echo "Wazuh manager has no IP" >&2; exit 1; }
echo "Wazuh manager: $MGR_IP"

# Append a fragment to ossec.conf only once, marked so re-runs replace it.
append_once() {  # $1=container  $2=marker  $3=local file
  local ct="$1" marker="$2" file="$3"
  incus file push -q "$file" "$ct/tmp/fragment.conf"
  incus exec "$ct" -- bash -c "
    conf=/var/ossec/etc/ossec.conf
    # Remove a previously inserted block (between the markers) if present.
    if grep -q '$marker BEGIN' \$conf; then
      sed -i '/$marker BEGIN/,/$marker END/d' \$conf
    fi
    { echo '<!-- $marker BEGIN -->'; cat /tmp/fragment.conf; echo '<!-- $marker END -->'; } >> \$conf
    rm -f /tmp/fragment.conf
  "
}

if [[ $DO_RULES -eq 1 ]]; then
  echo "==> Manager: decoders, rules, active response"
  incus file push -q "$ROOT/modules/siem/decoders/ssle_decoders.xml" \
    "$MGR/var/ossec/etc/decoders/ssle_decoders.xml"
  incus file push -q "$ROOT/modules/siem/rules/ssle_rules.xml" \
    "$MGR/var/ossec/etc/rules/ssle_rules.xml"
  incus file push -q "$ROOT/modules/siem/active-response/ssle-isolate.sh" \
    "$MGR/var/ossec/active-response/bin/ssle-isolate"

  incus exec "$MGR" -- bash -c '
    chown root:wazuh /var/ossec/etc/decoders/ssle_decoders.xml /var/ossec/etc/rules/ssle_rules.xml
    chmod 660 /var/ossec/etc/decoders/ssle_decoders.xml /var/ossec/etc/rules/ssle_rules.xml
    chown root:wazuh /var/ossec/active-response/bin/ssle-isolate
    chmod 750 /var/ossec/active-response/bin/ssle-isolate
  '

  append_once "$MGR" "SSLE-MANAGER-CONFIG" "$ROOT/modules/siem/manager/ssle-manager.conf"

  echo "==> Validating manager configuration"
  # wazuh-analysisd -t parses decoders, rules and ossec.conf without starting.
  # Catching an error here avoids restarting into a dead manager.
  if ! incus exec "$MGR" -- /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -viE '^$|Started|INFO' | head -10; then :; fi
  if incus exec "$MGR" -- /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    echo "  ruleset and configuration valid"
  else
    echo "  CONFIGURATION INVALID - not restarting the manager" >&2
    incus exec "$MGR" -- /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -10 >&2
    exit 1
  fi
  incus exec "$MGR" -- systemctl restart wazuh-manager
  echo "  waiting for manager..."
  for _ in $(seq 1 60); do
    incus exec "$MGR" -- /var/ossec/bin/wazuh-control status 2>/dev/null |
      grep -q 'wazuh-analysisd is running' && break
    sleep 2
  done
  incus exec "$MGR" -- /var/ossec/bin/wazuh-control status | grep -c running | xargs -I{} echo "  {} manager processes running"
fi

if [[ $DO_AGENTS -eq 1 ]]; then
  echo "==> Agents"
  for ct in $AGENTS; do
    printf '  %-30s ' "$ct"

    if incus exec "$ct" -- test -d /var/ossec 2>/dev/null; then
      echo -n "already installed; reconfiguring... "
    else
      echo -n "installing... "
      incus exec "$ct" -- env DEBIAN_FRONTEND=noninteractive bash -c "
        set -e
        apt-get update -q >/dev/null
        apt-get install -y -q --no-install-recommends gnupg curl ca-certificates >/dev/null
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
          gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
          > /etc/apt/sources.list.d/wazuh.list
        apt-get update -q >/dev/null
        WAZUH_MANAGER='$MGR_IP' apt-get install -y -q wazuh-agent >/dev/null
        apt-get clean; rm -rf /var/lib/apt/lists/*
      " >/dev/null 2>&1
    fi

    # Manager address (idempotent: set even on reconfigure).
    incus exec "$ct" -- bash -c "
      sed -i 's|<address>[^<]*</address>|<address>$MGR_IP</address>|' /var/ossec/etc/ossec.conf
    "

    # Outbound-connection reporter used by the C2 rules.
    incus file push -q "$ROOT/modules/siem/agent/ssle-netwatch.sh" "$ct/var/ossec/wodles/ssle-netwatch"
    incus exec "$ct" -- bash -c 'chmod 750 /var/ossec/wodles/ssle-netwatch; chown root:wazuh /var/ossec/wodles/ssle-netwatch'

    # Active-response script (runs here when the manager triggers it).
    incus file push -q "$ROOT/modules/siem/active-response/ssle-isolate.sh" \
      "$ct/var/ossec/active-response/bin/ssle-isolate"
    incus exec "$ct" -- bash -c '
      chmod 750 /var/ossec/active-response/bin/ssle-isolate
      chown root:wazuh /var/ossec/active-response/bin/ssle-isolate
      mkdir -p /var/log/ssle
      # nftables is needed by the active response to block a C2 address.
      command -v nft >/dev/null 2>&1 || (apt-get update -q >/dev/null 2>&1 && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends nftables >/dev/null 2>&1) || true
    '

    # systemd timer that runs ssle-netwatch every 15s and appends the result
    # to a log the agent tails. Reliable agent-side command execution via
    # Wazuh itself proved flaky, so the connection reporter is driven here and
    # delivered as a plain log file instead.
    incus exec "$ct" -- bash -c 'cat > /etc/systemd/system/ssle-netwatch.service <<EOF
[Unit]
Description=SSLE netwatch outbound-connection reporter
[Service]
Type=oneshot
# Keep only the last 400 lines so the log cannot grow without bound.
ExecStart=/bin/bash -c "/var/ossec/wodles/ssle-netwatch >> /var/log/ssle/netwatch.log 2>&1; tail -n 400 /var/log/ssle/netwatch.log > /var/log/ssle/netwatch.log.tmp && mv /var/log/ssle/netwatch.log.tmp /var/log/ssle/netwatch.log"
EOF
cat > /etc/systemd/system/ssle-netwatch.timer <<EOF
[Unit]
Description=Run SSLE netwatch every 15s
[Timer]
OnBootSec=15
OnUnitActiveSec=15
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF
mkdir -p /var/log/ssle; touch /var/log/ssle/netwatch.log
chown ssle:ssle /var/log/ssle 2>/dev/null || true
systemctl daemon-reload; systemctl enable --now ssle-netwatch.timer >/dev/null 2>&1'

    append_once "$ct" "SSLE-AGENT-CONFIG" "$ROOT/modules/siem/agent/ssle-agent.conf"

    incus exec "$ct" -- bash -c 'systemctl daemon-reload; systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent'
    echo "ok"
  done

  echo "==> Waiting for agents to enrol"
  for _ in $(seq 1 45); do
    n=$(incus exec "$MGR" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active' || true)
    [[ "${n:-0}" -ge 6 ]] && break
    sleep 2
  done
  incus exec "$MGR" -- /var/ossec/bin/agent_control -l 2>/dev/null | sed 's/^/  /'
fi

echo
echo "Wazuh dashboard: https://$MGR_IP (self-signed cert)"
echo "Tunnel from your workstation:"
echo "  ssh -L 8443:$MGR_IP:443 rrosmaninho@10.20.4.114   then https://localhost:8443"
echo "Credentials were written by the installer to /root/wazuh-install-files.tar inside the container."
