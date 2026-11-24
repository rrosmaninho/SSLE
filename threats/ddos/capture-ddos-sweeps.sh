#!/usr/bin/env bash
# DDoS capacity + attacker-count sweeps (focused figure set).
#
#   capacity sweep : fixed FIXED_ATTACKERS flooders, target CPU in CAPS% ->
#                    legit-user p95 (the prober), undefended vs defended.
#   attacker sweep : fixed ATTACK_CAP% CPU, flooders in ATTACKERS ->
#                    junk rows delivered to storage, undefended vs defended.
#
# The agent is stopped in both modes, so these figures ISOLATE the per-identity
# rate limiter (the Wazuh firewall-drop is a separate story). All traffic stays
# on the isolated lab net; a cleanup trap restores the lab even on failure.
#
#   bash threats/ddos/capture-ddos-sweeps.sh [capacity|attacker|both]   (default both)
#   bash threats/ddos/capture-ddos-sweeps.sh --cleanup
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/ddos-sweeps-$(date +%Y%m%d-%H%M%S)"
TARGET=ingestion; MON=monitoring; PROBER=ddos-prober
IMG=ssle-loadclient
FLOOD_ID='loadtest-ddos.node9.rack9.dc-probe.pt-centro.pt'

CAPS="${CAPS:-10 15 25 50 75 100}"
ATTACKERS="${ATTACKERS:-1 2 4 8 16 32}"
ATTACK_CAP="${ATTACK_CAP:-15}"
FIXED_ATTACKERS="${FIXED_ATTACKERS:-4}"
PHASE="${1:-both}"; [[ "$PHASE" == --* ]] || true

MAXN="$FIXED_ATTACKERS"; for n in $ATTACKERS; do (( n > MAXN )) && MAXN=$n; done
CLIENTS=""; for i in $(seq 1 "$MAXN"); do CLIENTS="$CLIENTS ddos-cap-$i"; done

MGR_Q(){ incus exec "$MON" -- curl -s --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query; }
scalar(){ python3 -c 'import json,sys,math
r=json.load(sys.stdin); res=r.get("data",{}).get("result",[])
v=res[0]["value"][1] if res else ""
try:
    f=float(v); print("" if (math.isnan(f) or math.isinf(f)) else f)
except: print("")'; }
ip_of(){ incus list "$1" -c4 -f csv 2>/dev/null | grep -oE '10\.255\.255\.[0-9]+' | head -1; }
server_p95(){ local s; s=$(MGR_Q 'histogram_quantile(0.95, sum by (le) (rate(ssle_ingestion_latency_seconds_bucket[30s])))' | scalar); [[ -n "$s" ]] && python3 -c "print(round($s*1000,2))" || echo ""; }
flood_rows(){ incus exec storage -- sqlite3 /var/lib/ssle/storage.db "SELECT count(*) FROM readings WHERE sensor='$FLOOD_ID'" 2>/dev/null; }
# p95 (ms) of the legit prober over an epoch range [a,b].
user_p95_range(){ incus exec "$PROBER" -- awk -v a="$1" -v b="$2" '$1>=a && $1<=b{print $2}' /root/prober.log 2>/dev/null \
  | python3 -c 'import sys
v=sorted(float(x) for x in sys.stdin if x.strip())
print(round(v[int(0.95*(len(v)-1))],2) if v else "")'; }
prober_start(){ incus exec "$PROBER" -- bash -c ": > /root/prober.log; setsid nohup python3 /root/prober.py \"$URL\" /root/body-legit.json 5 /root/prober.log </dev/null >/dev/null 2>&1 &"; }
prober_stop(){ incus exec "$PROBER" -- pkill -f prober.py 2>/dev/null || true; }
drain(){ echo "    draining 36s"; sleep 36; }

restore(){
  incus config unset "$TARGET" limits.cpu.allowance 2>/dev/null || true
  incus config unset "$TARGET" limits.memory 2>/dev/null || true
  incus exec "$TARGET" -- bash -c 'sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env 2>/dev/null; iptables -F 2>/dev/null; true' || true
  incus exec "$TARGET" -- systemctl restart ssle-ingestion 2>/dev/null || true
  incus exec "$TARGET" -- systemctl start wazuh-agent 2>/dev/null || true
  incus exec storage -- sqlite3 /var/lib/ssle/storage.db "DELETE FROM readings WHERE sensor LIKE 'loadtest-%'" 2>/dev/null || true
}
cleanup(){
  echo "==> Cleanup / restore"
  for c in $CLIENTS $PROBER; do incus delete -f "$c" >/dev/null 2>&1; done
  restore; echo "  lab restored"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }
trap cleanup EXIT INT TERM

mkdir -p "$EV"; LOG="$EV/sweeps.log"; exec > >(tee -a "$LOG") 2>&1
echo "=== DDoS sweeps  $(date -Is)  PHASE=$PHASE  CAPS=[$CAPS]  ATTACKERS=[$ATTACKERS]"

# Build a load-client image with ApacheBench baked in (fast many-client launch).
if ! incus image info "$IMG" >/dev/null 2>&1; then
  echo "==> Building $IMG image (ab preinstalled)"
  incus delete -f lc-build >/dev/null 2>&1 || true
  incus launch ssle-base lc-build >/dev/null
  for _ in $(seq 1 60); do [[ -n "$(ip_of lc-build)" ]] && break; sleep 1; done
  incus exec lc-build -- bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends apache2-utils >/dev/null 2>&1'
  incus exec lc-build -- bash -c 'command -v ab >/dev/null' || { echo "  ERROR: ab not installed in build container"; exit 1; }
  incus stop lc-build >/dev/null
  incus publish lc-build --alias "$IMG" >/dev/null && echo "  published $IMG"
  incus delete -f lc-build >/dev/null
fi

# Launch flood clients ONE AT A TIME (launch -> wait RUNNING+IP -> next). A
# simultaneous burst of launches overruns the VM's container-start ceiling
# (~75): the surplus come up STOPPED and the run silently loses flooders.
echo "==> Launch $MAXN flood clients from $IMG (sequential) + push payload"
for c in $CLIENTS; do
  incus info "$c" >/dev/null 2>&1 || incus launch "$IMG" "$c" >/dev/null 2>&1
  for _ in $(seq 1 60); do [[ "$(incus list "$c" -c s -f csv 2>/dev/null)" == RUNNING && -n "$(ip_of "$c")" ]] && break; sleep 1; done
  [[ "$(incus list "$c" -c s -f csv 2>/dev/null)" == RUNNING ]] || { echo "  ERROR: $c did not reach RUNNING (container-start ceiling? lower the attacker count)"; exit 1; }
  incus file push -q "$ROOT/threats/ddos/body.json" "$c/root/body.json"
done
echo "==> Provision legit-user prober (ssle-prober image: python3 baked in)"
# Always recreate fresh: a stale STOPPED prober from an interrupted run would be
# found by `incus info` and skipped, leaving the prober un-launched and every
# user_p95 empty (a bug that silently killed the capacity sweep).
incus delete -f "$PROBER" >/dev/null 2>&1 || true
incus launch ssle-prober "$PROBER" >/dev/null 2>&1
for _ in $(seq 1 60); do [[ "$(incus list "$PROBER" -c s -f csv 2>/dev/null)" == RUNNING && -n "$(ip_of "$PROBER")" ]] && break; sleep 1; done
# Correct check: python3 is a real binary; `command` is a shell builtin and
# cannot be exec'd directly by `incus exec`.
incus exec "$PROBER" -- python3 --version >/dev/null 2>&1 || { echo "  ERROR: python3 missing in prober (rebuild the ssle-prober image)"; exit 1; }
incus file push -q "$ROOT/threats/ddos/body-legit.json" "$PROBER/root/body-legit.json"
incus file push -q "$ROOT/threats/ddos/prober.py" "$PROBER/root/prober.py"
URL="http://$(ip_of "$TARGET"):5001/ingest"
incus config set "$TARGET" limits.memory=256MiB

# off = limiter disabled; on = default limiter. Agent stopped in both (constant CPU, no block).
set_mode(){
  incus exec "$TARGET" -- bash -c 'iptables -F 2>/dev/null; systemctl stop wazuh-agent 2>/dev/null; sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env; true'
  [[ "$1" == off ]] && incus exec "$TARGET" -- bash -c 'echo "RATE_LIMIT_RPS=1000000" >> /etc/ssle/env'
  incus exec "$TARGET" -- systemctl restart ssle-ingestion; sleep 3
}
flood_start(){ FLOOD_PIDS=""; local i=0 c
  for c in $CLIENTS; do i=$((i+1)); [[ $i -gt $1 ]] && break
    incus exec "$c" -- ab -t "$2" -c 10 -s 60 -p /root/body.json -T application/json "$URL" >/dev/null 2>&1 &
    FLOOD_PIDS="$FLOOD_PIDS $!"
  done; }

capacity_sweep(){
  local csv="$EV/capacity-sweep.csv" cap mode a b up sp
  echo "capacity_pct,mode,user_p95_ms,server_p95_ms" > "$csv"
  echo "==> CAPACITY sweep (fixed $FIXED_ATTACKERS attackers; CPU in [$CAPS]%)"
  for cap in $CAPS; do
    incus config set "$TARGET" limits.cpu.allowance="${cap}ms/100ms"
    for mode in off on; do
      set_mode "$mode"; drain; prober_start; sleep 12
      a=$(( $(date +%s)+5 )); flood_start "$FIXED_ATTACKERS" 34
      sp=0; local st=$(date +%s)
      while [[ $(( $(date +%s)-st )) -lt 32 ]]; do local s; s=$(server_p95); [[ -n "$s" ]] && sp=$(python3 -c "print(max($sp,$s))"); sleep 3; done
      b=$(date +%s); wait $FLOOD_PIDS 2>/dev/null; prober_stop
      up=$(user_p95_range "$a" "$b")
      echo "$cap,$mode,${up:-},$sp" >> "$csv"; echo "  cap=${cap}% $mode  user_p95=${up} ms  server_p95=${sp} ms"
    done
  done
}

attacker_sweep(){
  local csv="$EV/attacker-sweep.csv" n mode c0 c1
  echo "attackers,mode,junk_rows,server_p95_ms" > "$csv"
  echo "==> ATTACKER sweep (fixed ${ATTACK_CAP}% CPU; attackers in [$ATTACKERS])"
  incus config set "$TARGET" limits.cpu.allowance="${ATTACK_CAP}ms/100ms"
  for n in $ATTACKERS; do
    for mode in off on; do
      set_mode "$mode"; drain
      incus exec storage -- sqlite3 /var/lib/ssle/storage.db "DELETE FROM readings WHERE sensor='$FLOOD_ID'" 2>/dev/null
      c0=$(flood_rows); c0=${c0:-0}
      flood_start "$n" 20
      local sp=0 st=$(date +%s)
      while [[ $(( $(date +%s)-st )) -lt 20 ]]; do local s; s=$(server_p95); [[ -n "$s" ]] && sp=$(python3 -c "print(max($sp,$s))"); sleep 3; done
      wait $FLOOD_PIDS 2>/dev/null
      c1=$(flood_rows); c1=${c1:-0}
      echo "$n,$mode,$((c1-c0)),$sp" >> "$csv"; echo "  attackers=$n $mode  junk=$((c1-c0)) rows  server_p95=${sp} ms"
    done
  done
}

[[ "$PHASE" == capacity || "$PHASE" == both ]] && capacity_sweep
[[ "$PHASE" == attacker || "$PHASE" == both ]] && attacker_sweep
echo "==> Sweeps complete. Evidence: ${EV#$ROOT/}/"
