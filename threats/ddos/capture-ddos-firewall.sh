#!/usr/bin/env bash
# DDoS reactive response: show the Wazuh firewall-drop neutralising the flood.
#
# Agent ON, limiter OFF, target CPU-throttled. A sustained flood trips rule
# 100102 (> req/60s per source) -> firewall-drop blocks the source IPs on
# ingestion -> the attacker's ingest rate collapses. Records the ingest rate
# and the number of block rules over time. Cleanup trap restores the lab.
#
#   bash threats/ddos/capture-ddos-firewall.sh
#   bash threats/ddos/capture-ddos-firewall.sh --cleanup
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/ddos-firewall-$(date +%Y%m%d-%H%M%S)"
TARGET=ingestion; MON=monitoring; WAZUH=wazuh; IMG=ssle-loadclient
CLIENTS="fw-client-1 fw-client-2"
DUR="${DUR:-80}"

MGR_Q(){ incus exec "$MON" -- curl -s --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query; }
scalar(){ python3 -c 'import json,sys,math
r=json.load(sys.stdin); res=r.get("data",{}).get("result",[])
v=res[0]["value"][1] if res else ""
try:
    f=float(v); print("" if (math.isnan(f) or math.isinf(f)) else round(f,2))
except: print("")'; }
ip_of(){ incus list "$1" -c4 -f csv 2>/dev/null | grep -oE '10\.255\.255\.[0-9]+' | head -1; }
# Instantaneous ingest rate from the target's own counter, sampled directly
# (not Prometheus rate(), whose 30s window smears the block into a slow decay).
TIP=""
recv_total(){ incus exec "$MON" -- curl -s "http://$TIP:5001/metrics" 2>/dev/null | awk '/^ssle_ingestion_received_total /{print $2}'; }
PREV_C=""; PREV_T=""
sample(){ local phase=$1 now c rps
  now=$(date +%s); c=$(recv_total); c=${c:-0}
  if [[ -n "$PREV_C" && -n "$PREV_T" && $now -gt ${PREV_T:-0} ]]; then
    rps=$(python3 -c "print(round(($c-$PREV_C)/($now-$PREV_T),2))" 2>/dev/null)
  else rps=0; fi
  PREV_C=$c; PREV_T=$now
  echo "$((now-start)),$phase,${rps:-0},$c,$(blocks)" >> "$EV/firewall.csv"
}
blocks(){ incus exec "$TARGET" -- bash -c 'iptables -L INPUT -n 2>/dev/null | grep -icE "DROP|REJECT" || true' 2>/dev/null; }

restore(){
  incus config unset "$TARGET" limits.cpu.allowance 2>/dev/null || true
  incus config unset "$TARGET" limits.memory 2>/dev/null || true
  incus exec "$TARGET" -- bash -c 'sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env 2>/dev/null; iptables -F 2>/dev/null; true' || true
  incus exec "$TARGET" -- systemctl restart ssle-ingestion 2>/dev/null || true
  incus exec "$TARGET" -- systemctl restart wazuh-agent 2>/dev/null || true
  incus exec storage -- sqlite3 /var/lib/ssle/storage.db "DELETE FROM readings WHERE sensor LIKE 'loadtest-%'" 2>/dev/null || true
}
cleanup(){ echo "==> cleanup"; for c in $CLIENTS; do incus delete -f "$c" >/dev/null 2>&1; done; restore; echo "  lab restored"; }
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }
trap cleanup EXIT INT TERM

mkdir -p "$EV"; LOG="$EV/firewall.log"; exec > >(tee -a "$LOG") 2>&1
echo "=== DDoS firewall-drop  $(date -Is)"

echo "==> throttle + limiter OFF + agent ON + reset AR state"
incus config set "$TARGET" limits.cpu.allowance=10ms/100ms
incus config set "$TARGET" limits.memory=256MiB
incus exec "$TARGET" -- bash -c 'iptables -F 2>/dev/null; sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env; echo "RATE_LIMIT_RPS=1000000" >> /etc/ssle/env'
incus exec "$TARGET" -- systemctl restart ssle-ingestion
incus exec "$TARGET" -- systemctl restart wazuh-agent
for _ in $(seq 1 20); do incus exec "$TARGET" -- bash -c 'tail -5 /var/ossec/logs/ossec.log 2>/dev/null | grep -q "Connected to the server"' && break; sleep 2; done
sleep 5

echo "==> flood clients"
for c in $CLIENTS; do incus info "$c" >/dev/null 2>&1 || incus launch "$IMG" "$c" >/dev/null; done
for c in $CLIENTS; do
  for _ in $(seq 1 60); do [[ -n "$(ip_of "$c")" ]] && break; sleep 1; done
  incus file push -q "$ROOT/threats/ddos/body.json" "$c/root/body.json"
done
TIP="$(ip_of "$TARGET")"
URL="http://$TIP:5001/ingest"

echo "t_s,phase,ingest_rps,recv,blocks" > "$EV/firewall.csv"
start=$(date +%s)
PREV_C=$(recv_total); PREV_C=${PREV_C:-0}; PREV_T=$(date +%s)   # seed the delta
while [[ $(( $(date +%s)-start )) -lt 15 ]]; do   # ~15 s baseline before the flood
  sample baseline; sleep 2
done
echo "==> start flood (${DUR}s); firewall-drop should land mid-run"
FP=""
for c in $CLIENTS; do incus exec "$c" -- ab -t "$DUR" -c 10 -s 60 -p /root/body.json -T application/json "$URL" >/dev/null 2>&1 & FP="$FP $!"; done
astart=$(date +%s)
while [[ $(( $(date +%s)-astart )) -lt $DUR ]]; do
  sample attack
done
wait $FP 2>/dev/null || true
echo "==> done. blocks at end: $(blocks). Evidence: ${EV#$ROOT/}/"
