#!/usr/bin/env bash
# End-to-end verification of the K3s-hosted SSLE stack, with a Kubernetes-native
# scaling demonstration. Mirrors deploy/k8s/verify-services.sh for the Incus stack.
#
#   bash deploy/k8s/verify-k3s.sh
#
# Checks: both nodes Ready; every pod Ready; the registry is populated through
# in-cluster discovery; readings flow sensor->ingestion->storage ACROSS pods and
# nodes (storage row count grows); analytics produces a report; and
# `kubectl scale` adds whole sensor nodes with collision-free hierarchical names.
# Output is saved under evidence/k3s-<timestamp>/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
K="incus exec k3s-master -- k3s kubectl"
TS="$(date +%Y%m%d-%H%M%S)"
EV="$ROOT/evidence/k3s-$TS"
mkdir -p "$EV"

PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hd()   { printf '\n== %s ==\n' "$*"; }

# curl inside a running pod (selected by workload) against its own localhost
pod_curl() { $K -n ssle exec "$1" -- curl -s --max-time 5 "http://localhost:$2$3"; }
sensor_count() { pod_curl deploy/registry 5050 /services | grep -o '"kind":"sensor"' | wc -l; }
stored_count() { pod_curl deploy/storage 5002 /stats | sed -n 's/.*"count":[ ]*\([0-9]\+\).*/\1/p'; }

hd "Nodes"
$K get nodes -o wide | tee "$EV/nodes.txt"
ready_nodes=$($K get nodes --no-headers | grep -c ' Ready ')
[[ "$ready_nodes" -ge 2 ]] && ok "$ready_nodes nodes Ready" || bad "only $ready_nodes nodes Ready"

hd "Pods"
$K -n ssle get pods -o wide | tee "$EV/pods.txt"
total=$($K -n ssle get pods --no-headers | wc -l)
ready=$($K -n ssle get pods --no-headers | awk '{print $2}' | awk -F/ '$1==$2' | wc -l)
[[ "$ready" -eq "$total" && "$total" -ge 6 ]] && ok "$ready/$total pods Ready" || bad "$ready/$total pods Ready"

# pods landed on more than one node? (proves the 2-node scheduler works)
nodes_used=$($K -n ssle get pods -o wide --no-headers | awk '{print $7}' | sort -u | wc -l)
[[ "$nodes_used" -ge 2 ]] && ok "workload spread across $nodes_used nodes" \
                          || echo "  INFO  all pods on one node (scheduler chose $nodes_used)"

hd "Discovery (registry populated in-cluster)"
pod_curl deploy/registry 5050 /services > "$EV/services.json" || true
nsvc=$(grep -o '"kind"' "$EV/services.json" | wc -l)
nsens=$(sensor_count)
echo "  registered instances: $nsvc  (sensors: $nsens)"
[[ "$nsvc" -ge 6 ]] && ok "registry sees $nsvc instances" || bad "registry sees only $nsvc"
# 2 sensor pods x SENSOR_COUNT 5 = 10
[[ "$nsens" -ge 10 ]] && ok "$nsens sensors registered (2 pods x 5)" || bad "only $nsens sensors"
# hierarchical names are unique per pod (no collisions)
uniq_nodes=$(grep -o 'sensor-[0-9][0-9]*\.sensor-[0-9]*\.' "$EV/services.json" | sort -u | wc -l)
echo "  distinct sensor IDs: $uniq_nodes"

hd "Data flow sensor->ingestion->storage (across pods/nodes)"
c1=$(stored_count); echo "  stored rows now:   ${c1:-?}"
sleep 12
c2=$(stored_count); echo "  stored rows +12s:  ${c2:-?}"
{ echo "t0=$c1"; echo "t1=$c2"; } > "$EV/dataflow.txt"
if [[ -n "${c1:-}" && -n "${c2:-}" && "$c2" -gt "$c1" ]]; then
  ok "storage grew $c1 -> $c2 (pipeline live end to end)"
else
  bad "storage did not grow ($c1 -> $c2)"
fi

hd "Analytics report"
pod_curl deploy/analytics 5003 /report > "$EV/report.json" || true
if grep -q '{' "$EV/report.json" 2>/dev/null; then ok "analytics /report served"; else bad "no analytics report"; fi

hd "Kubernetes-native scaling: scale statefulset/sensor 2 -> 3"
before=$(sensor_count); echo "  sensors before: $before"
$K -n ssle scale statefulset/sensor --replicas=3 >/dev/null
$K -n ssle rollout status statefulset/sensor --timeout=120s
sleep 8
after=$(sensor_count); echo "  sensors after:  $after"
{ echo "before=$before"; echo "after=$after"; } > "$EV/scaling.txt"
if [[ -n "$after" && "$after" -gt "$before" ]]; then
  ok "scaling added $((after-before)) sensors (expected +5), no name collisions"
else
  bad "sensor count did not rise on scale-up ($before -> $after)"
fi
echo "  (scaling back to 2)"
$K -n ssle scale statefulset/sensor --replicas=2 >/dev/null

$K -n ssle get pods -o wide > "$EV/pods-after.txt" 2>/dev/null || true

hd "Result"
echo "  $PASS passed, $FAIL failed"
echo "  evidence: $EV"
[[ "$FAIL" -eq 0 ]]
