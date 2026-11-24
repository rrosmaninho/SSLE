#!/usr/bin/env bash
# Threat 1 - Distributed Denial of Service: full experiment cycle.
#
#   baseline -> constrain target -> paired attack -> detect -> respond -> post-mortem
#
# Follows the methodology of the DoS guide (Guide 5): a single-client baseline
# compared against a paired-client run, the same endpoint and body in every
# run, a CPU/memory-constrained target, and the guide's worksheet fields
# (throughput, median, p95, failed/non-2xx, target CPU). It differs from the
# guide's literal "ab -n 40" only in volume: a C++ service shows nothing at 40
# requests and the Wazuh frequency rules need ~120-300 requests to trip. The
# workload stays bounded and safe - a fixed request count, modest concurrency,
# a target capped at 1 CPU / 256 MiB, on the isolated lab network, with a
# snapshot taken first.
#
#   bash threats/ddos/run-ddos.sh            # full cycle (~4 min)
#   bash threats/ddos/run-ddos.sh --cleanup  # just tear down clients + restore
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/ddos-$(date +%Y%m%d-%H%M%S)"
TARGET=ingestion
CLIENTS="load-client-a load-client-b"
MON=monitoring
WAZUH=wazuh

MGR_Q() { incus exec "$MON" -- curl -s --data-urlencode "query=$1" \
            http://127.0.0.1:9090/api/v1/query; }
scalar() { python3 -c 'import json,sys
r=json.load(sys.stdin); res=r.get("data",{}).get("result",[])
print(res[0]["value"][1] if res else "")'; }

target_ip() { incus list "$TARGET" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+'; }

# --------------------------------------------------------------------------
cleanup() {
  echo "==> Cleanup"
  for c in $CLIENTS; do incus delete -f "$c" >/dev/null 2>&1 && echo "  removed $c"; done
  echo "  restoring target resource limits"
  incus config unset "$TARGET" limits.cpu.allowance 2>/dev/null || true
  incus config unset "$TARGET" limits.cpu 2>/dev/null || true
  incus config unset "$TARGET" limits.memory 2>/dev/null || true
  incus exec "$TARGET" -- systemctl restart ssle-ingestion 2>/dev/null || true
  # Remove any active-response block left on the target.
  incus exec "$TARGET" -- bash -c 'iptables -F 2>/dev/null; nft flush table inet ssle_ar 2>/dev/null' || true
  # Remove the load-test rows so they do not pollute analytics.
  incus exec storage -- bash -c "sqlite3 /var/lib/ssle/storage.db \"DELETE FROM readings WHERE sensor LIKE 'loadtest-%'\"" 2>/dev/null \
    && echo "  cleaned load-test rows from storage"
  echo "  done"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }

mkdir -p "$EV"
echo "=== DDoS experiment  $(date -Is)" | tee "$EV/summary.txt"
echo "Target: $TARGET ($(target_ip))" | tee -a "$EV/summary.txt"

# --------------------------------------------------------------------------
# Start from a known-unconstrained target: a throttle left over from a prior
# run would contaminate the phase-1 baseline.
echo "==> Reset any leftover resource limits on the target"
incus config unset "$TARGET" limits.cpu.allowance 2>/dev/null || true
incus config unset "$TARGET" limits.cpu 2>/dev/null || true
incus config unset "$TARGET" limits.memory 2>/dev/null || true
incus exec "$TARGET" -- systemctl restart ssle-ingestion 2>/dev/null || true
sleep 2

echo "==> Safety: snapshot the target before the experiment"
incus snapshot delete "$TARGET" pre-ddos >/dev/null 2>&1 || true
incus snapshot create "$TARGET" pre-ddos && echo "  snapshot $TARGET/pre-ddos"

# Clear any leftover block and Wazuh's active-response dedup state, so the
# firewall-drop fires fresh. Wazuh keeps a list of currently-blocked keys and
# aborts a duplicate block within the AR timeout window (600s); a manual
# iptables flush alone does not clear that list, so a re-run would detect but
# not re-block. Restarting the target agent clears its AR state.
echo "==> Reset active-response state on the target"
incus exec "$TARGET" -- bash -c 'iptables -F 2>/dev/null; nft flush table inet ssle_ar 2>/dev/null; true'
incus exec "$TARGET" -- systemctl restart wazuh-agent 2>/dev/null || true
echo "  waiting for the agent to reconnect..."
for _ in $(seq 1 20); do
  incus exec "$TARGET" -- tail -5 /var/ossec/logs/ossec.log 2>/dev/null | grep -q "Connected to the server" && break
  sleep 2
done
sleep 5

echo "==> Setup: two load-client containers (the emulated botnet sources)"
for c in $CLIENTS; do
  if ! incus info "$c" >/dev/null 2>&1; then
    incus launch ssle-base "$c" >/dev/null
  fi
done
for c in $CLIENTS; do
  for _ in $(seq 1 60); do
    incus list "$c" -c4 -f csv | grep -qE '10\.255\.255\.' && break; sleep 1
  done
  incus exec "$c" -- bash -c 'command -v ab >/dev/null 2>&1 || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends apache2-utils >/dev/null 2>&1)'
  incus file push -q "$ROOT/threats/ddos/body.json" "$c/root/body.json"
done
CA_IP=$(incus list load-client-a -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
CB_IP=$(incus list load-client-b -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
echo "  load-client-a = $CA_IP" | tee -a "$EV/summary.txt"
echo "  load-client-b = $CB_IP" | tee -a "$EV/summary.txt"

URL="http://$(target_ip):5001/ingest"

# Run ApacheBench on a client; args: container, n, c, outfile
run_ab() {
  local c="$1" n="$2" conc="$3" out="$4"
  incus exec "$c" -- ab -n "$n" -c "$conc" -s 10 -p /root/body.json \
    -T application/json "$URL" > "$out" 2>&1
}

# Parse the guide's worksheet fields from an ab output file. ab only prints
# the percentile summary when it finishes; under a hard throttle or once the
# active-response block drops its packets, it aborts instead - which is itself
# an availability observation, so that case is reported rather than hidden.
parse_ab() {  # $1=file $2=scenario-label
  python3 - "$1" "$2" <<'PY'
import re, sys
f, label = sys.argv[1], sys.argv[2]
t = open(f).read()
def g(pat, d=None):
    m = re.search(pat, t); return m.group(1) if m else d
comp = g(r"Complete requests:\s+(\d+)")
if comp is not None:   # ab finished: full worksheet row
    def gg(p, d="?"):
        m = re.search(p, t); return m.group(1) if m else d
    print("%-22s | reqs %-6s | rps %-8s | median %-5s ms | p95 %-6s ms | failed %-4s | non-2xx %s"
          % (label, comp, gg(r"Requests per second:\s+([\d.]+)"), gg(r"\s+50%\s+(\d+)"),
             gg(r"\s+95%\s+(\d+)"), gg(r"Failed requests:\s+(\d+)"),
             gg(r"Non-2xx responses:\s+(\d+)", "0")))
else:                  # ab aborted - report how far it got and why
    partial = g(r"Total of (\d+) requests completed", "0")
    if "pollset_poll" in t or "timeout" in t:
        reason = "ABORTED: target saturated (socket timeout)"
    elif "Connection refused" in t or "reset" in t:
        reason = "ABORTED: connection refused/reset (blocked)"
    else:
        reason = "ABORTED"
    print("%-22s | %s after %s requests" % (label, reason, partial))
PY
}

# Snapshot the target's cgroup v2 CPU accounting: cumulative CPU time and the
# throttling counters a CPU quota produces. The delta of nr_throttled /
# throttled_usec across the attack is direct evidence the container hit its
# CPU limit under load (far cleaner than estimating a percentage).
cpu_stat() {  # prints: usage_usec nr_throttled throttled_usec
  incus exec "$TARGET" -- awk '
    /^usage_usec/{u=$2} /^nr_throttled/{n=$2} /^throttled_usec/{t=$2}
    END{print u, n, t}' /sys/fs/cgroup/cpu.stat
}

echo
echo "==> PHASE 1 - Baseline (single client, target UNCONSTRAINED)" | tee -a "$EV/summary.txt"
run_ab load-client-a 300 1 "$EV/ab-baseline.txt"
parse_ab "$EV/ab-baseline.txt" "baseline 1-client" | tee -a "$EV/summary.txt"

echo
echo "==> PHASE 2 - Constrain the target (hard CPU throttle: 10% of one core)" | tee -a "$EV/summary.txt"
# A 10%/core quota (10ms run per 100ms period) plus a tight memory limit. The
# unconstrained C++ service shrugs off a bounded load, so without a real
# throttle there is nothing to detect; 10% makes the same bounded workload
# saturate the target, which is the point of the exercise.
incus config set "$TARGET" limits.cpu.allowance=10ms/100ms
incus config set "$TARGET" limits.memory=256MiB
sleep 2
incus exec "$TARGET" -- systemctl restart ssle-ingestion
sleep 3
echo "  target throttled to 10% CPU; small single-client baseline" | tee -a "$EV/summary.txt"
# Small count and a generous timeout so a single client still completes
# against the throttled target, giving a clean p95 to compare with phase 1.
incus exec load-client-a -- ab -n 80 -c 1 -s 60 -p /root/body.json \
  -T application/json "$URL" > "$EV/ab-baseline-constrained.txt" 2>&1
parse_ab "$EV/ab-baseline-constrained.txt" "baseline throttled" | tee -a "$EV/summary.txt"

echo
echo "==> PHASE 3 - Paired attack (both clients at once, time-bounded 20s)" | tee -a "$EV/summary.txt"
read -r U0 N0 T0 < <(cpu_stat)
START=$(date +%s)
# -t 20 bounds each client to 20 wall-seconds (and 50000 requests); -s 3 so a
# connection dropped by the active-response block fails in 3s rather than
# hanging. The block is expected to land mid-run and cut the clients off.
incus exec load-client-a -- ab -t 20 -c 10 -s 3 -p /root/body.json -T application/json "$URL" > "$EV/ab-attack-a.txt" 2>&1 &
PA=$!
incus exec load-client-b -- ab -t 20 -c 10 -s 3 -p /root/body.json -T application/json "$URL" > "$EV/ab-attack-b.txt" 2>&1 &
PB=$!
wait $PA $PB
read -r U1 N1 T1 < <(cpu_stat)
parse_ab "$EV/ab-attack-a.txt" "attack client-a" | tee -a "$EV/summary.txt"
parse_ab "$EV/ab-attack-b.txt" "attack client-b" | tee -a "$EV/summary.txt"
awk -v n0="$N0" -v n1="$N1" -v t0="$T0" -v t1="$T1" 'BEGIN{
  printf "  target CPU throttling under load: %d throttle events, %.1f ms spent throttled\n",
         n1-n0, (t1-t0)/1000}' | tee -a "$EV/summary.txt"

echo
echo "==> PHASE 4 - Detection" | tee -a "$EV/summary.txt"
sleep 5
# Server-side p95 from the Prometheus histogram.
SRV_P95=$(MGR_Q 'histogram_quantile(0.95, sum by (le) (rate(ssle_ingestion_latency_seconds_bucket[1m])))' | scalar)
SRV_RATE=$(MGR_Q 'sum(rate(ssle_ingestion_received_total[1m]))' | scalar)
echo "  Prometheus server-side p95: ${SRV_P95}s, ingest rate: ${SRV_RATE} req/s" | tee -a "$EV/summary.txt"
# Is the latency alert firing?
ALERT=$(incus exec "$MON" -- curl -s http://127.0.0.1:9093/api/v2/alerts | python3 -c '
import json,sys
a=[x for x in json.load(sys.stdin) if x["labels"]["alertname"]=="IngestionLatencyHigh"]
print("firing" if a and a[0]["status"]["state"]=="active" else "not firing")' 2>/dev/null)
echo "  Prometheus IngestionLatencyHigh alert: ${ALERT:-unknown}" | tee -a "$EV/summary.txt"
# Wazuh DoS alerts.
echo "  waiting for Wazuh DoS alerts (up to 60s)..."
WZ=""
for _ in $(seq 1 12); do
  WZ=$(incus exec "$WAZUH" -- bash -c "grep -hoE '\"id\":\"10010[0-9]\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | sort | uniq -c" 2>/dev/null)
  echo "$WZ" | grep -qE '100101|100102' && break
  sleep 5
done
echo "  Wazuh DoS rule hits:" | tee -a "$EV/summary.txt"
echo "$WZ" | sed 's/^/    /' | tee -a "$EV/summary.txt"

echo
echo "==> PHASE 5 - Response (Wazuh active-response firewall-drop)" | tee -a "$EV/summary.txt"
echo "  checking for a firewall-drop block on the target..."
BLOCK=""
for _ in $(seq 1 12); do
  BLOCK=$(incus exec "$TARGET" -- bash -c 'iptables -L INPUT -n 2>/dev/null | grep -iE "DROP|REJECT" | head' 2>/dev/null)
  [[ -n "$BLOCK" ]] && break
  sleep 5
done
if [[ -n "$BLOCK" ]]; then
  echo "  ACTIVE RESPONSE FIRED - blocked source(s) on $TARGET:" | tee -a "$EV/summary.txt"
  echo "$BLOCK" | sed 's/^/    /' | tee -a "$EV/summary.txt"
else
  echo "  no firewall-drop observed (see post-mortem note)" | tee -a "$EV/summary.txt"
fi
incus exec "$WAZUH" -- bash -c 'grep -i "active-response\|firewall-drop" /var/ossec/logs/active-responses.log 2>/dev/null | tail -5' \
  > "$EV/active-responses.log" 2>/dev/null || true

echo
echo "==> PHASE 6 - Post-mortem" | tee -a "$EV/summary.txt"
{
  echo "Interpretation:"
  echo " - Compare p95 and throughput: baseline vs constrained vs paired attack."
  echo " - Throughput alone does not prove loss of availability; the evidence is"
  echo "   the combination of raised p95, saturated target CPU, and any non-2xx /"
  echo "   failed requests appearing only under the paired load."
  echo " - Detection correlates two independent signals: Prometheus p95 (server"
  echo "   latency) and the Wazuh frequency rule (request volume per source)."
  echo " - Response: firewall-drop on the sustained-flood rule (100102), wired to"
  echo "   the severe case so a brief legitimate spike does not auto-block a client."
  echo " - Snapshot $TARGET/pre-ddos allows a clean revert."
} | tee -a "$EV/summary.txt"

echo
echo "Evidence saved under: ${EV#$ROOT/}/"
echo "Run 'bash threats/ddos/run-ddos.sh --cleanup' to remove clients and restore limits."
