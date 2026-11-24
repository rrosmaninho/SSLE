#!/usr/bin/env bash
# Phase 2 check: base architecture works and behaves as designed.
#   bash deploy/incus/verify-services.sh          # quick checks (~30 s)
#   bash deploy/incus/verify-services.sh --full   # + registry restart and failure detection (~2 min)
# Saves a copy of the output under evidence/ for the report.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/verify-services-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

FULL=0; [[ "${1:-}" == "--full" ]] && FULL=1
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }
check() { local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }

SERVICES="registry storage ingestion analytics"
SENSOR_NODES="sensors-aveiro-rack2-node1 sensors-coimbra-rack1-node1"
SENSORS_PER_NODE=5
EXPECTED=$(( 3 + 2 * SENSORS_PER_NODE ))   # storage+ingestion+analytics + sensors

reg() { incus exec registry -- curl -sf "http://127.0.0.1:5050$1"; }

# Registry summary as "total healthy stale" from /services JSON.
reg_counts() {
  reg /services | python3 -c '
import json, sys
d = json.load(sys.stdin)
h = sum(1 for v in d.values() if v["healthy"])
print(len(d), h, len(d) - h)'
}

stored() { incus exec storage -- curl -sf http://127.0.0.1:5002/stats |
           python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])'; }

echo "==> Containers and services"
for ct in $SERVICES $SENSOR_NODES; do
  check "$ct: service active" incus exec "$ct" -- bash -c 'systemctl is-active --quiet ssle-*.service'
done
for ct in $SERVICES $SENSOR_NODES; do
  u=$(incus exec "$ct" -- bash -c 'ps -eo user=,comm= | awk "/ssle-/ {print \$1}" | sort -u' 2>/dev/null)
  [[ "$u" == "ssle" ]] && ok "$ct: runs as unprivileged user 'ssle'" || bad "$ct: runs as '$u' (expected ssle)"
done

echo "==> Registry and naming"
read -r total healthy stale < <(reg_counts)
[[ "$total" -eq "$EXPECTED" ]] && ok "registry has $total instances (expected $EXPECTED)" \
                               || bad "registry has $total instances (expected $EXPECTED)"
[[ "$stale" -eq 0 ]] && ok "all $healthy instances healthy" || bad "$stale stale instances"

bad_names=$(reg /services | python3 -c '
import json, re, sys
pat = re.compile(r"^[a-z]+-\d{2}\.node\d+\.rack\d+\.dc-[a-z]+\.pt-centro\.pt$")
print(" ".join(n for n in json.load(sys.stdin) if not pat.match(n)))')
[[ -z "$bad_names" ]] && ok "all names follow <kind>-NN.node.rack.dc.region" \
                      || bad "names not matching scheme: $bad_names"

echo "  registry contents:"
reg /services | python3 -c '
import json, sys
d = json.load(sys.stdin)
for n, v in sorted(d.items(), key=lambda x: (x[1]["kind"], x[0])):
    print("    %-10s %-6s %-52s %s" % (v["kind"], "ok" if v["healthy"] else "STALE", n, v["url"]))'

echo "==> Discovery (no hardcoded addresses)"
for kind in storage ingestion analytics; do
  ip=$(incus list "$kind" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
  url=$(reg "/discover/$kind" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')
  [[ "$url" == "http://$ip:"* ]] && ok "discover($kind) -> $url" || bad "discover($kind) -> '$url' (container IP $ip)"
done
check "unknown kind returns 404" bash -c '! incus exec registry -- curl -sf http://127.0.0.1:5050/discover/nope'
check "sensor node resolves registry.incus" incus exec sensors-aveiro-rack2-node1 -- getent hosts registry.incus

echo "==> Data flow: sensors -> ingestion -> storage -> analytics"
c1=$(stored); sleep 12; c2=$(stored)
[[ "$c2" -gt "$c1" ]] && ok "storage grew $c1 -> $c2 in 12 s ($(( (c2-c1) )) readings)" \
                      || bad "storage did not grow ($c1 -> $c2)"
a=$(incus exec analytics -- curl -sf http://127.0.0.1:5003/report |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["count"], d["avg"])')
read -r acount aavg <<<"$a"
[[ "${acount:-0}" -gt 0 ]] && ok "analytics sees $acount readings, avg ${aavg}C" || bad "analytics has no data"

echo "==> Prometheus endpoints"
for pair in registry:5050:ssle_registry_total storage:5002:ssle_storage_rows \
            ingestion:5001:ssle_ingestion_received_total analytics:5003:ssle_analytics_readings \
            sensors-aveiro-rack2-node1:9101:ssle_sensor_count sensors-coimbra-rack1-node1:9101:ssle_sensor_count; do
  IFS=: read -r ct port metric <<<"$pair"
  check "$ct:$port/metrics exposes $metric" \
    bash -c "incus exec $ct -- curl -sf http://127.0.0.1:$port/metrics | grep -q '^$metric'"
done

if [[ $FULL -eq 1 ]]; then
  echo "==> Self-healing: restart registry (in-memory state is lost)"
  incus exec registry -- systemctl restart ssle-registry.service
  sleep 2
  read -r t0 _ _ < <(reg_counts)
  echo "  right after restart: $t0 instances"
  sleep 15
  read -r t1 h1 _ < <(reg_counts)
  [[ "$t1" -eq "$EXPECTED" && "$h1" -eq "$EXPECTED" ]] \
    && ok "all $EXPECTED instances re-registered within 15 s" \
    || bad "only $t1 instances back ($h1 healthy) after 15 s"

  echo "==> Failure detection: stop ingestion, expect STALE and removal from discovery"
  incus exec ingestion -- systemctl stop ssle-ingestion.service
  sleep 40      # TTL is 30 s
  st=$(reg /services | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(" ".join("healthy" if v["healthy"] else "stale" for v in d.values() if v["kind"] == "ingestion"))')
  [[ "$st" == "stale" ]] && ok "ingestion marked stale after TTL" || bad "ingestion state: '$st'"
  check "discover(ingestion) returns 404 while it is down" \
    bash -c '! incus exec registry -- curl -sf http://127.0.0.1:5050/discover/ingestion'
  f=$(incus exec sensors-aveiro-rack2-node1 -- curl -sf http://127.0.0.1:9101/metrics |
      awk '/^ssle_sensor_failed_total/ {s+=$2} END {print s+0}')
  [[ "$f" -gt 0 ]] && ok "sensors record failed sends ($f) during the outage" || bad "no failed sends recorded"

  echo "==> Recovery"
  incus exec ingestion -- systemctl start ssle-ingestion.service
  sleep 15
  c1=$(stored); sleep 10; c2=$(stored)
  [[ "$c2" -gt "$c1" ]] && ok "data flowing again after ingestion restart ($c1 -> $c2)" \
                        || bad "data not flowing after restart ($c1 -> $c2)"
fi

echo
echo "Result: $pass passed, $fail failed   (saved to ${OUT#$ROOT/})"
[[ $fail -eq 0 ]]
