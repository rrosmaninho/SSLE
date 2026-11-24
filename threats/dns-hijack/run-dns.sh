#!/usr/bin/env bash
# Threat 3 - DNS hijacking / phishing: full experiment cycle.
#
#   baseline -> hijack (rogue resolver + clone) -> defend (protective resolver)
#   -> detect -> respond -> post-mortem
#
# Three roles, all on the isolated lab network:
#   dns-attacker  rogue dnsmasq (resolves the bank name to the clone) + the
#                 phishing clone site that captures credentials
#   dns-victim    a user that resolves names and visits the resulting site
#   dns-defender  the protective resolver that scores a domain before
#                 answering, sinkholes the phishing name, and logs each
#                 decision for the SIEM (Wazuh agent tails the resolver log)
#
# Everything stays inside 10.255.255.0/24. A rogue DNS/DHCP service must never
# reach the home network; the lab bridge has no uplink and nftables blocks the
# LAN, so the rogue resolver cannot serve anything outside the VM.
#
#   bash threats/dns-hijack/run-dns.sh            # full cycle
#   bash threats/dns-hijack/run-dns.sh --cleanup  # remove the three containers
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/threats/dns-hijack"
EV="$ROOT/evidence/dns-$(date +%Y%m%d-%H%M%S)"
ATTACKER=dns-attacker
VICTIM=dns-victim
DEFENDER=dns-defender
WAZUH=wazuh
CLONE_PORT=80

ip_of() { incus list "$1" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+'; }
log() { echo "$@" | tee -a "$EV/summary.txt"; }

cleanup() {
  echo "==> Cleanup"
  for c in "$ATTACKER" "$VICTIM" "$DEFENDER"; do
    incus delete -f "$c" >/dev/null 2>&1 && echo "  removed $c"
  done
  echo "  done"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }

mkdir -p "$EV"
echo "=== DNS hijacking / phishing experiment  $(date -Is)" | tee "$EV/summary.txt"

wait_ip() { for _ in $(seq 1 60); do incus list "$1" -c4 -f csv | grep -qE '10\.255\.255\.' && return 0; sleep 1; done; return 1; }

# -- Setup ----------------------------------------------------------------
echo "==> Setup: three containers"
for c in "$ATTACKER" "$VICTIM" "$DEFENDER"; do
  incus info "$c" >/dev/null 2>&1 || incus launch ssle-base "$c" >/dev/null
done
for c in "$ATTACKER" "$VICTIM" "$DEFENDER"; do wait_ip "$c"; done
ATT_IP=$(ip_of "$ATTACKER"); VIC_IP=$(ip_of "$VICTIM"); DEF_IP=$(ip_of "$DEFENDER")
# Victim needs dig + curl up front (installing them lazily mid-run raced with
# other apt activity and failed).
incus exec "$VICTIM" -- bash -c 'command -v dig >/dev/null && command -v curl >/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends dnsutils curl >/dev/null 2>&1); command -v dig >/dev/null && echo "  victim tools ready" || echo "  WARN: victim missing dig/curl"'

log "  attacker (rogue resolver + clone): $ATT_IP"
log "  victim:                           $VIC_IP"
log "  defender (protective resolver):   $DEF_IP"

echo "==> Provision the attacker (rogue dnsmasq + clone site)"
incus exec "$ATTACKER" -- bash -c 'command -v dnsmasq >/dev/null && command -v python3 >/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null; apt-get install -y -q --no-install-recommends dnsmasq python3 >/dev/null; apt-get clean)'
incus exec "$ATTACKER" -- systemctl disable --now dnsmasq 2>/dev/null || true
sed "s/__CLONE_IP__/$ATT_IP/" "$HERE/dnsmasq-rogue.conf" | incus file push -q - "$ATTACKER/etc/dnsmasq.d/rogue.conf"
incus file push -q "$HERE/clone-site.py" "$ATTACKER/root/clone-site.py"

echo "==> Provision the defender (protective resolver + Wazuh agent)"
incus exec "$DEFENDER" -- bash -c 'command -v python3 >/dev/null && python3 -c "import dnslib" 2>/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null; apt-get install -y -q --no-install-recommends python3 python3-dnslib >/dev/null; apt-get clean)'
incus exec "$DEFENDER" -- mkdir -p /opt/ssle-dns /var/log/ssle
incus exec "$DEFENDER" -- touch /var/log/ssle/dns-resolver.log
incus file push -q "$HERE/protective-resolver.py" "$DEFENDER/opt/ssle-dns/protective-resolver.py"
incus file push -q "$HERE/reputation.json" "$DEFENDER/opt/ssle-dns/reputation.json"
incus exec "$DEFENDER" -- bash -c 'cat > /etc/systemd/system/ssle-resolver.service <<EOF
[Unit]
Description=SSLE protective DNS resolver
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/ssle-dns/protective-resolver.py /opt/ssle-dns/reputation.json 0.0.0.0 /var/log/ssle/dns-resolver.log
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now ssle-resolver 2>/dev/null; systemctl restart ssle-resolver'

# Wazuh agent on the defender, tailing the resolver decision log.
MGR_IP=$(ip_of "$WAZUH")
if ! incus exec "$DEFENDER" -- test -d /var/ossec 2>/dev/null; then
  echo "  installing Wazuh agent on the defender..."
  incus exec "$DEFENDER" -- env DEBIAN_FRONTEND=noninteractive bash -c "
    apt-get install -y -q --no-install-recommends gnupg curl >/dev/null 2>&1
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
    apt-get update -q >/dev/null; WAZUH_MANAGER='$MGR_IP' apt-get install -y -q wazuh-agent >/dev/null 2>&1
    apt-get clean" >/dev/null 2>&1
fi
incus exec "$DEFENDER" -- bash -c "
  sed -i 's|<address>[^<]*</address>|<address>$MGR_IP</address>|' /var/ossec/etc/ossec.conf
  grep -v dns-resolver.log /var/ossec/etc/ossec.conf > /tmp/o.conf && mv /tmp/o.conf /var/ossec/etc/ossec.conf
  sed -i 's#</ossec_config>#  <localfile><log_format>syslog</log_format><location>/var/log/ssle/dns-resolver.log</location></localfile>\n</ossec_config>#' /var/ossec/etc/ossec.conf
  # Also install iptables for the campaign firewall-drop response.
  command -v iptables >/dev/null || (DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends iptables >/dev/null 2>&1)
  systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent"
echo "  waiting for the defender's agent to enrol..."
for _ in $(seq 1 30); do
  incus exec "$WAZUH" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -q "$DEFENDER" && break; sleep 2
done
echo "  letting logcollector settle on the resolver log..."
sleep 8

# Helper: run a DNS query from the victim against a given resolver.
dig_at() { incus exec "$VICTIM" -- bash -c "command -v dig >/dev/null || (DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends dnsutils >/dev/null 2>&1); dig +short +time=3 +tries=1 @$1 $2 A 2>/dev/null | head -1"; }

echo
echo "==> PHASE 1 - Baseline: victim uses the protective resolver" | tee -a "$EV/summary.txt"
incus exec "$DEFENDER" -- systemctl restart ssle-resolver; sleep 2
ANS=$(dig_at "$DEF_IP" bank-legit.example)
log "  dig bank-legit.example @protective -> ${ANS:-(no answer)}  (legitimate, resolves normally)"

echo
echo "==> PHASE 2 - Attack: DNS hijack + phishing clone" | tee -a "$EV/summary.txt"
incus exec "$ATTACKER" -- systemctl restart dnsmasq 2>/dev/null || incus exec "$ATTACKER" -- bash -c 'systemctl start dnsmasq'
incus exec "$ATTACKER" -- bash -c 'systemctl is-active dnsmasq' >/dev/null && log "  rogue dnsmasq running on $ATT_IP"
# Start the clone site.
incus exec "$ATTACKER" -- systemctl stop ssle-clone 2>/dev/null; incus exec "$ATTACKER" -- systemctl reset-failed ssle-clone 2>/dev/null || true
incus exec "$ATTACKER" -- systemd-run --unit=ssle-clone --quiet python3 /root/clone-site.py 0.0.0.0 "$CLONE_PORT"
sleep 2
HJ=$(dig_at "$ATT_IP" bank-lab.example)
log "  victim points resolv.conf at the rogue resolver and looks up the bank:"
log "    dig bank-lab.example @rogue -> ${HJ:-(no answer)}  (hijacked to the clone at $ATT_IP)"
# Victim visits the hijacked site and submits credentials.
incus exec "$VICTIM" -- bash -c "command -v curl >/dev/null || (DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends curl >/dev/null 2>&1)"
PAGE=$(incus exec "$VICTIM" -- curl -s --max-time 5 "http://$HJ/" | grep -o '<title>[^<]*' | head -1)
log "    victim fetches the site -> ${PAGE#<title>}"
incus exec "$VICTIM" -- curl -s --max-time 5 -d 'username=joao.silva&password=Sup3rSecret!' "http://$HJ/login" >/dev/null
sleep 1
CAP=$(incus exec "$ATTACKER" -- tail -1 /root/captured-credentials.log 2>/dev/null)
log "    CREDENTIALS CAPTURED at the attacker: ${CAP}"

echo
echo "==> PHASE 3 - Defense: victim switches to the protective resolver" | tee -a "$EV/summary.txt"
SINK=$(dig_at "$DEF_IP" bank-lab.example)
log "  dig bank-lab.example @protective -> ${SINK:-(sinkholed)}  (0.0.0.0 = SINKHOLED, not the clone)"
WARN=$(dig_at "$DEF_IP" secure-bank-login.example)
log "  dig secure-bank-login.example @protective -> ${WARN:-(NXDOMAIN)}  (lookalike, WARN)"

echo
echo "==> PHASE 4 - Campaign + response (repeated phishing lookups)" | tee -a "$EV/summary.txt"
echo "  victim is repeatedly steered to phishing domains (e.g. a compromised host)..."
for i in $(seq 1 8); do dig_at "$DEF_IP" bank-lab.example >/dev/null; sleep 0.3; done
log "  8 sinkholed lookups generated from $VIC_IP"

echo
echo "==> PHASE 5 - Detection (Wazuh rules on the resolver decision log)" | tee -a "$EV/summary.txt"
echo "  waiting for Wazuh alerts (up to 60s)..."
for _ in $(seq 1 12); do
  SK=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"100302\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null')
  [[ "${SK:-0}" -gt 0 ]] && break; sleep 5
done
WN=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"100301\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null')
SK=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"100302\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null')
CM=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"100303\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null')
log "  Wazuh WARN (100301):     ${WN:-0}"
log "  Wazuh SINKHOLE (100302): ${SK:-0}"
log "  Wazuh campaign (100303): ${CM:-0}"
incus exec "$WAZUH" -- bash -c 'grep -h "\"id\":\"100302\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -1' |
  python3 -c 'import json,sys
try:
    a=json.loads(sys.stdin.read()); d=a.get("data",{})
    print("    e.g. %s" % a["rule"]["description"])
except Exception: pass' | tee -a "$EV/summary.txt"

echo
echo "==> PHASE 6 - Post-mortem" | tee -a "$EV/summary.txt"
{
  echo "The hijack works by controlling the resolver the victim uses: pointed at"
  echo "the rogue resolver, the bank name resolves to the clone and credentials"
  echo "are captured. The defence is a protective resolver that scores the domain"
  echo "BEFORE answering (risk = category + reports + domain age + DNSSEC + IP"
  echo "reputation) and sinkholes the phishing name in the data path, so the"
  echo "victim never reaches the clone. The SIEM turns each resolver decision into"
  echo "an event: WARN, SINKHOLE, and a campaign alert on repeated hits."
  echo "Honest limits: reputation is evidence about the PAST, so a brand-new"
  echo "domain with no history scores low (ADTree counter-defence C1); and the"
  echo "defence only holds where the protective resolver is the one actually in"
  echo "use - if the attacker controls resolv.conf, it can bypass it (C2 / gap"
  echo "D3.5, pinned resolver configuration)."
} | tee -a "$EV/summary.txt"

# Save the resolver decision log as evidence.
incus exec "$DEFENDER" -- cat /var/log/ssle/dns-resolver.log > "$EV/dns-resolver.log" 2>/dev/null
incus exec "$ATTACKER" -- cat /root/captured-credentials.log > "$EV/captured-credentials.log" 2>/dev/null

echo
echo "Evidence under: ${EV#$ROOT/}/"
echo "Run 'bash threats/dns-hijack/run-dns.sh --cleanup' to remove the three containers."
