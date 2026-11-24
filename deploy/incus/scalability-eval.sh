#!/usr/bin/env bash
# Scalability evaluation: measure the architecture at several sensor counts.
#
# For each size the script sets SENSOR_COUNT on the two sensor nodes, waits
# for every sensor to register and the pipeline to reach steady state, then
# records throughput, latency, resource use and per-service memory. Results
# go to evidence/scalability-<ts>/results.csv and a summary table.
#
# The per-service RSS columns are the point of the memory measurements: the
# registry keeps all discovery state in memory and is a single instance, so
# its growth with sensor count is the headline bottleneck discussed in the
# report.
#
#   bash deploy/incus/scalability-eval.sh                 # sizes 10 50 100
#   bash deploy/incus/scalability-eval.sh 10 50 100 200   # custom sizes
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/scalability-$(date +%Y%m%d-%H%M%S)"
MON=monitoring
NODES=(sensors-aveiro-rack2-node1 sensors-coimbra-rack1-node1)
SIZES=("$@"); [[ ${#SIZES[@]} -eq 0 ]] && SIZES=(10 50 100)
SETTLE=45      # seconds to reach steady state before measuring
WINDOW=30      # measurement window

mkdir -p "$EV"
CSV="$EV/results.csv"
echo "sensors,registered,register_s,ingest_rps,p95_ms,storage_rps,vm_cpu_pct,vm_mem_used_mb,registry_rss_mb,storage_rss_mb,ingestion_rss_mb" > "$CSV"

q() { incus exec "$MON" -- curl -s --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query |
  python3 -c 'import json,sys
r=json.load(sys.stdin); res=r.get("data",{}).get("result",[])
print(res[0]["value"][1] if res else "")'; }

# Resident memory (MB) of the main process in a container.
rss_mb() { incus exec "$1" -- bash -c "ps -o rss= -C $2 2>/dev/null | awk '{s+=\$1} END{printf \"%.1f\", s/1024}'"; }

reg_total() { incus exec registry -- curl -s http://127.0.0.1:5050/metrics 2>/dev/null |
  awk '/^ssle_registry_total/{print $2}'; }
reg_healthy_sensors() { incus exec registry -- curl -s http://127.0.0.1:5050/services 2>/dev/null |
  python3 -c 'import json,sys
d=json.load(sys.stdin)
print(sum(1 for v in d.values() if v["kind"]=="sensor" and v["healthy"]))'; }

set_size() {   # total sensors across the two nodes
  local total="$1" per=$(( ($1 + ${#NODES[@]} - 1) / ${#NODES[@]} ))
  for n in "${NODES[@]}"; do
    incus exec "$n" -- bash -c "sed -i 's/^SENSOR_COUNT=.*/SENSOR_COUNT=$per/' /etc/ssle/env || echo 'SENSOR_COUNT=$per' >> /etc/ssle/env"
    incus exec "$n" -- systemctl restart ssle-sensor
  done
  echo "$(( per * ${#NODES[@]} ))"
}

echo "=== Scalability evaluation  $(date -Is)" | tee "$EV/summary.txt"
echo "Sizes: ${SIZES[*]}   settle ${SETTLE}s, window ${WINDOW}s" | tee -a "$EV/summary.txt"
printf '%-8s %-11s %-10s %-10s %-8s %-11s %-8s %-10s %-12s %-11s %-13s\n' \
  sensors registered reg_time ingest_rps p95_ms storage_rps vm_cpu% vm_mem_MB registry_RSS storage_RSS ingestion_RSS | tee -a "$EV/summary.txt"

for size in "${SIZES[@]}"; do
  actual=$(set_size "$size")
  # Time until all sensors have registered and are healthy.
  start=$(date +%s); reg_time=""
  for _ in $(seq 1 120); do
    h=$(reg_healthy_sensors)
    if [[ "${h:-0}" -ge "$actual" ]]; then reg_time=$(( $(date +%s) - start )); break; fi
    sleep 1
  done
  [[ -z "$reg_time" ]] && reg_time=">120"

  sleep "$SETTLE"   # steady state

  ingest_rps=$(q 'sum(rate(ssle_ingestion_received_total['"$WINDOW"'s]))')
  p95=$(q 'histogram_quantile(0.95, sum by (le) (rate(ssle_ingestion_latency_seconds_bucket['"$WINDOW"'s])))')
  storage_rps=$(q 'sum(rate(ssle_storage_readings_total['"$WINDOW"'s]))')
  vm_cpu=$(q '100 - (avg(rate(node_cpu_seconds_total{mode="idle",job="monitoring-node"}['"$WINDOW"'s])) * 100)')
  vm_mem=$(q '(node_memory_MemTotal_bytes{job="monitoring-node"} - node_memory_MemAvailable_bytes{job="monitoring-node"}) / 1048576')
  registered=$(( $(reg_total) - 3 ))
  reg_rss=$(rss_mb registry ssle-registry)
  sto_rss=$(rss_mb storage ssle-storage)
  ing_rss=$(rss_mb ingestion ssle-ingestion)

  p95_ms=$(python3 -c "print('%.1f' % (float('${p95:-0}' or 0)*1000))")
  fmt() { python3 -c "print('%.1f' % float('${1:-0}' or 0))"; }
  row="$actual,$registered,$reg_time,$(fmt "$ingest_rps"),$p95_ms,$(fmt "$storage_rps"),$(fmt "$vm_cpu"),$(fmt "$vm_mem"),${reg_rss:-?},${sto_rss:-?},${ing_rss:-?}"
  echo "$row" >> "$CSV"
  printf '%-8s %-11s %-10s %-10s %-8s %-11s %-8s %-10s %-12s %-11s %-13s\n' \
    "$actual" "$registered" "${reg_time}s" "$(fmt "$ingest_rps")" "$p95_ms" "$(fmt "$storage_rps")" \
    "$(fmt "$vm_cpu")" "$(fmt "$vm_mem")" "${reg_rss}" "${sto_rss}" "${ing_rss}" | tee -a "$EV/summary.txt"
done

echo | tee -a "$EV/summary.txt"
echo "CSV: ${CSV#$ROOT/}" | tee -a "$EV/summary.txt"
echo "Reset to 5 sensors/node with: bash deploy/incus/scalability-eval.sh 10" | tee -a "$EV/summary.txt"
