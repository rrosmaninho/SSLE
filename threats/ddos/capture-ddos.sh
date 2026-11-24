#!/usr/bin/env bash
# DDoS capture harness — produces real data for the report figures:
#   (1) time-series of server-side p95 / ingest-rate / CPU-throttle across the
#       attack, for BOTH defence-off and defence-on (the counterfactual).
#   (2) attacker-count sweep (1/2/4/8 flooding clients): peak p95 per count,
#       defence-off vs defence-on.
#
# All traffic stays on the isolated lab net; the target is CPU-throttled so a
# bounded flood is visible. A cleanup trap restores the lab (limits unset,
# iptables flushed, default rate limiter, wazuh-agent running, clients removed)
# even if the run fails.
#
#   bash threats/ddos/capture-ddos.sh          # full capture (~15-20 min)
#   bash threats/ddos/capture-ddos.sh --quick  # short smoke test (DUR=20, sweep 1,2)
#   bash threats/ddos/capture-ddos.sh --cleanup
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/ddos-capture-$(date +%Y%m%d-%H%M%S)"
TARGET=ingestion; MON=monitoring; WAZUH=wazuh; PROBER=ddos-prober

DUR="${DUR:-75}"; SWEEP="${SWEEP-1 2 4 8}"   # overridable by env
THROTTLE="${THROTTLE:-25ms/100ms}"           # target CPU cap (looser than 10% for stable latency)
[[ "${1:-}" == "--quick" ]] && { DUR=20; SWEEP="1 2"; }
# Provision only as many clients as the largest sweep point (min 2 for the time-series).
MAXC=2; for n in $SWEEP; do (( n > MAXC )) && MAXC=$n; done
CLIENTS=""; for i in $(seq 1 "$MAXC"); do CLIENTS="$CLIENTS ddos-cap-$i"; done

MGR_Q(){ incus exec "$MON" -- curl -s --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query; }
scalar(){ python3 -c 'import json,sys,math
r=json.load(sys.stdin); res=r.get("data",{}).get("result",[])
v=res[0]["value"][1] if res else ""
try:
    f=float(v); print("" if (math.isnan(f) or math.isinf(f)) else f)
except: print("")'; }
drain(){ echo "  draining 36s (clearing the metric window)"; sleep 36; }
ip_of(){ incus list "$1" -c4 -f csv 2>/dev/null | grep -oE '10\.255\.255\.[0-9]+' | head -1; }
p95_ms(){ local s; s=$(MGR_Q 'histogram_quantile(0.95, sum by (le) (rate(ssle_ingestion_latency_seconds_bucket[30s])))' | scalar); [[ -n "$s" ]] && python3 -c "print(round($s*1000,2))" || echo ""; }
rate_now(){ MGR_Q 'sum(rate(ssle_ingestion_received_total[30s]))' | scalar; }
throttled(){ incus exec "$TARGET" -- awk '/^nr_throttled/{print $2}' /sys/fs/cgroup/cpu.stat 2>/dev/null; }
# Legit-user prober: client-side p95 (ms) over the last ~8s of its own requests.
user_p95(){
  incus exec "$PROBER" -- awk -v cut=$(( $(date +%s)-12 )) '$1>=cut{print $2}' /root/prober.log 2>/dev/null \
    | python3 -c 'import sys
v=sorted(float(x) for x in sys.stdin if x.strip())
print(round(v[int(0.95*(len(v)-1))],2) if v else "")'
}
prober_start(){ incus exec "$PROBER" -- bash -c ": > /root/prober.log; setsid nohup python3 /root/prober.py \"$URL\" /root/body-legit.json 5 /root/prober.log </dev/null >/dev/null 2>&1 &"; }
prober_stop(){ incus exec "$PROBER" -- pkill -f prober.py 2>/dev/null || true; }

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
  for c in $CLIENTS $PROBER; do incus delete -f "$c" >/dev/null 2>&1 && echo "  removed $c"; done
  restore; echo "  lab restored"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }
trap cleanup EXIT INT TERM

mkdir -p "$EV"
LOG="$EV/capture.log"; exec > >(tee -a "$LOG") 2>&1
echo "=== DDoS capture  $(date -Is)  DUR=$DUR SWEEP=[$SWEEP]"

echo "==> Snapshot target (pre-capture)"
incus snapshot delete "$TARGET" pre-capture >/dev/null 2>&1 || true
incus snapshot create "$TARGET" pre-capture && echo "  $TARGET/pre-capture"

echo "==> Provision $MAXC client containers (ab)"
for c in $CLIENTS; do incus info "$c" >/dev/null 2>&1 || incus launch ssle-base "$c" >/dev/null; done
for c in $CLIENTS; do
  for _ in $(seq 1 60); do [[ -n "$(ip_of "$c")" ]] && break; sleep 1; done
  incus exec "$c" -- bash -c 'command -v ab >/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends apache2-utils >/dev/null 2>&1)'
  incus file push -q "$ROOT/threats/ddos/body.json" "$c/root/body.json"
done
echo "==> Provision the legit-user prober (python3)"
incus info "$PROBER" >/dev/null 2>&1 || incus launch ssle-base "$PROBER" >/dev/null
for _ in $(seq 1 60); do [[ -n "$(ip_of "$PROBER")" ]] && break; sleep 1; done
incus exec "$PROBER" -- bash -c 'command -v python3 >/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends python3 >/dev/null 2>&1)'
incus file push -q "$ROOT/threats/ddos/body-legit.json" "$PROBER/root/body-legit.json"
incus file push -q "$ROOT/threats/ddos/prober.py" "$PROBER/root/prober.py"
URL="http://$(ip_of "$TARGET"):5001/ingest"
echo "  target URL $URL"

echo "==> Throttle target to CPU allowance $THROTTLE / 256 MiB (makes a bounded flood visible)"
incus config set "$TARGET" limits.cpu.allowance="$THROTTLE"
incus config set "$TARGET" limits.memory=256MiB
incus exec "$TARGET" -- systemctl restart ssle-ingestion; sleep 3

# Put the target into a defence mode.  off = limiter disabled + agent stopped
# (no firewall-drop) ; on = default limiter + agent running (block fires).
set_mode(){ # $1 = off|on — this figure ISOLATES the per-identity rate limiter.
  # Agent is stopped in BOTH modes (constant CPU, no firewall-drop cutting the
  # flood); the only difference is the limiter. The Wazuh firewall-drop response
  # is demonstrated separately.
  incus exec "$TARGET" -- bash -c 'iptables -F 2>/dev/null; systemctl stop wazuh-agent 2>/dev/null; sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env; true'
  [[ "$1" == off ]] && incus exec "$TARGET" -- bash -c 'echo "RATE_LIMIT_RPS=1000000" >> /etc/ssle/env'
  incus exec "$TARGET" -- systemctl restart ssle-ingestion; sleep 3
}

flood_start(){ # $1 = n clients, $2 = duration ; returns PIDs via global FLOOD_PIDS
  FLOOD_PIDS=""; local i=0
  for c in $CLIENTS; do
    i=$((i+1)); [[ $i -gt $1 ]] && break
    incus exec "$c" -- ab -t "$2" -c 10 -s 60 -p /root/body.json -T application/json "$URL" >/dev/null 2>&1 &
    FLOOD_PIDS="$FLOOD_PIDS $!"
  done
}

# -------- (1) TIME-SERIES, both modes --------
timeseries(){ # $1 = off|on
  local mode="$1" csv="$EV/timeseries-$1.csv" BASELINE=15
  echo "==> Time-series  mode=$mode  (prober + baseline ${BASELINE}s + attack ${DUR}s, 2 clients)"
  set_mode "$mode"; drain
  echo "t_s,phase,user_p95_ms,server_p95_ms,ingest_rps,throttle_delta" > "$csv"
  local base; base=$(throttled); base=${base:-0}
  prober_start; sleep 12  # let the legit prober fill its window before sampling
  local start; start=$(date +%s); local el up sp r th
  # Phase A: pre-flood baseline (prober only) — both runs start at the same place.
  while :; do
    el=$(( $(date +%s)-start )); [[ $el -ge $BASELINE ]] && break
    up=$(user_p95); sp=$(p95_ms); r=$(rate_now); th=$(throttled)
    echo "$el,baseline,${up:-},${sp:-},${r:-},$(( ${th:-0}-base ))" >> "$csv"; sleep 3
  done
  # Phase B: attack (flood uses the loadtest identity; prober keeps its own).
  flood_start 2 "$DUR"; local astart; astart=$(date +%s)
  while :; do
    [[ $(( $(date +%s)-astart )) -ge $DUR ]] && break
    el=$(( $(date +%s)-start )); up=$(user_p95); sp=$(p95_ms); r=$(rate_now); th=$(throttled)
    echo "$el,attack,${up:-},${sp:-},${r:-},$(( ${th:-0}-base ))" >> "$csv"; sleep 3
  done
  wait $FLOOD_PIDS 2>/dev/null || true
  prober_stop
  echo "  wrote $csv ($(($(wc -l <"$csv")-1)) samples)"
}

# -------- (2) ATTACKER-COUNT SWEEP, both modes --------
sweep(){ # $1 = off|on
  local mode="$1" csv="$EV/sweep-$1.csv" n peak p
  echo "==> Sweep  mode=$mode  counts=[$SWEEP]"
  [[ -f "$csv" ]] || echo "clients,peak_p95_ms" > "$csv"
  for n in $SWEEP; do
    set_mode "$mode"; drain     # fresh state per point (clears block, AR dedup, metric window)
    flood_start "$n" 40
    peak=0; local start; start=$(date +%s)
    while [[ $(( $(date +%s)-start )) -lt 36 ]]; do
      p=$(p95_ms); [[ -n "$p" ]] && peak=$(python3 -c "print(max($peak,$p))"); sleep 2
    done
    wait $FLOOD_PIDS 2>/dev/null || true
    echo "$n,$peak" >> "$csv"; echo "  clients=$n  peak p95=${peak} ms"
  done
}

timeseries off
timeseries on
if [[ -n "${SWEEP// }" ]]; then sweep off; sweep on; fi

echo "==> Capture complete.  Evidence: ${EV#$ROOT/}/"
echo "   timeseries-off.csv timeseries-on.csv sweep-off.csv sweep-on.csv"
# trap cleanup runs on exit
