#!/usr/bin/env bash
# Phase 3 check: monitoring, alerting and root-cause correlation.
#   bash deploy/incus/verify-monitoring.sh          # quick checks (~1 min)
#   bash deploy/incus/verify-monitoring.sh --full   # + live fault injection (~5 min)
#
# --full stops the ingestion service, waits for the alert cascade, and proves
# that Alertmanager inhibits the SYMPTOM alerts while the CAUSE is firing.
# Output is saved under evidence/ for the report.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/verify-monitoring-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

FULL=0; [[ "${1:-}" == "--full" ]] && FULL=1
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

PROM="incus exec monitoring -- curl -s"
prom_query() {  # $1 = PromQL, prints scalar value of first result or empty
  $PROM --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query |
    python3 -c 'import json,sys
r=json.load(sys.stdin)
res=r.get("data",{}).get("result",[])
print(res[0]["value"][1] if res else "")'
}
prom_count() { # number of result series
  $PROM --data-urlencode "query=$1" http://127.0.0.1:9090/api/v1/query |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("data",{}).get("result",[])))'
}
alert_state() { # $1 = alertname -> "firing"/"pending"/"" from Alertmanager
  incus exec monitoring -- curl -s http://127.0.0.1:9093/api/v2/alerts |
    python3 -c "import json,sys
a=[x for x in json.load(sys.stdin) if x['labels']['alertname']=='$1']
print(a[0]['status']['state'] if a else '')"
}
alert_inhibited() { # $1 = alertname -> "yes"/"no"/""
  incus exec monitoring -- curl -s http://127.0.0.1:9093/api/v2/alerts |
    python3 -c "import json,sys
a=[x for x in json.load(sys.stdin) if x['labels']['alertname']=='$1']
print(('yes' if a[0]['status'].get('inhibitedBy') else 'no') if a else '')"
}
show_alerts() {
  incus exec monitoring -- curl -s http://127.0.0.1:9093/api/v2/alerts |
    python3 -c 'import json,sys
al=json.load(sys.stdin)
if not al: print("    (none)")
for x in sorted(al, key=lambda y: y["labels"]["alertname"]):
    st = "INHIBITED" if x["status"].get("inhibitedBy") else x["status"]["state"]
    lbl = x["labels"]
    loc = " ".join("%s=%s" % (k, lbl[k]) for k in ("kind","node","rack","dc") if k in lbl)
    print("    %-10s %-34s %s" % (st, lbl["alertname"], loc))'
}

echo "==> Services"
for svc in prometheus prometheus-alertmanager; do
  incus exec monitoring -- systemctl is-active --quiet $svc && ok "$svc active" || bad "$svc active"
done
incus exec monitoring -- promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1 \
  && ok "prometheus config valid" || bad "prometheus config valid"
incus exec monitoring -- amtool check-config /etc/prometheus/alertmanager.yml >/dev/null 2>&1 \
  && ok "alertmanager config valid" || bad "alertmanager config valid"

echo "==> Target discovery (from the registry, not a static list)"
targets=$($PROM "http://127.0.0.1:9090/api/v1/targets?state=active" |
  python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["activeTargets"]))')
down=$($PROM "http://127.0.0.1:9090/api/v1/targets?state=active" |
  python3 -c 'import json,sys; print(sum(1 for t in json.load(sys.stdin)["data"]["activeTargets"] if t["health"]!="up"))')
[[ "$targets" -ge 13 ]] && ok "$targets active targets discovered" || bad "only $targets active targets"
[[ "$down" -eq 0 ]] && ok "all targets healthy" || bad "$down targets unhealthy"

sd=$(incus exec registry -- curl -s http://127.0.0.1:5050/sd |
     python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
[[ "$sd" -ge 5 ]] && ok "registry /sd advertises $sd targets" || bad "registry /sd returned $sd"

# A sensor node hosts 5 logical sensors behind one metrics port; discovery
# must not scrape it 5 times.
dupes=$(incus exec registry -- curl -s http://127.0.0.1:5050/sd |
  python3 -c 'import json,sys
d=json.load(sys.stdin); t=[x["targets"][0] for x in d]; print(len(t)-len(set(t)))')
[[ "$dupes" -eq 0 ]] && ok "no duplicate scrape targets (sensor nodes deduplicated)" \
                     || bad "$dupes duplicate targets"

echo "==> Application metrics"
for m in ssle_registry_total ssle_storage_rows ssle_ingestion_received_total \
         ssle_analytics_readings ssle_sensor_sent_total node_cpu_seconds_total; do
  n=$(prom_count "$m")
  [[ "${n:-0}" -gt 0 ]] && ok "$m present ($n series)" || bad "$m missing"
done

echo "==> Per-location monitoring (the bonus: monitor by location)"
dcs=$(prom_count 'sum by (dc) (ssle_sensor_sent_total)')
[[ "${dcs:-0}" -ge 2 ]] && ok "readings aggregate across $dcs datacenters" \
                        || bad "expected >=2 datacenters, got $dcs"
racks=$(prom_count 'sum by (dc,rack) (ssle_registry_services{state="healthy"})')
[[ "${racks:-0}" -ge 2 ]] && ok "fleet health split across $racks dc/rack buckets" \
                          || bad "fleet health collapsed into $racks bucket (label collision?)"

echo "==> Alert rules"
rules=$($PROM http://127.0.0.1:9090/api/v1/rules |
  python3 -c 'import json,sys; print(sum(len(g["rules"]) for g in json.load(sys.stdin)["data"]["groups"]))')
[[ "${rules:-0}" -ge 14 ]] && ok "$rules alert rules loaded" || bad "only $rules rules loaded"
inhibits=$(incus exec monitoring -- amtool check-config /etc/prometheus/alertmanager.yml |
           grep -oE '[0-9]+ inhibit rules' | grep -oE '^[0-9]+')
[[ "${inhibits:-0}" -ge 6 ]] && ok "$inhibits inhibition rules for root-cause correlation" \
                             || bad "only ${inhibits:-0} inhibition rules"

echo "==> Baseline (recorded for the DDoS comparison later)"
p95=$(prom_query 'histogram_quantile(0.95, sum by (le) (rate(ssle_ingestion_latency_seconds_bucket[5m])))')
rate=$(prom_query 'sum(rate(ssle_ingestion_received_total[5m]))')
cpu=$(prom_query '100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)')
printf '  ingestion p95 latency : %s s\n  ingestion request rate: %s req/s\n  VM CPU used           : %s %%\n' \
       "${p95:-n/a}" "${rate:-n/a}" "${cpu:-n/a}"
[[ -n "$p95" ]] && ok "p95 latency baseline measurable" || bad "p95 latency not measurable"

if [[ $FULL -eq 1 ]]; then
  echo
  echo "==> Fault injection: stop ingestion and watch the cascade"
  echo "    (this is the FCAPS workflow: detect -> isolate -> correlate)"
  incus exec ingestion -- systemctl stop ssle-ingestion.service
  echo "    ingestion stopped; waiting for alerts to fire (up to 3 min)..."

  deadline=$(( $(date +%s) + 200 ))
  until [[ "$(alert_state ServiceDown)" == "active" ]] || [[ $(date +%s) -gt $deadline ]]; do
    sleep 5
  done

  [[ "$(alert_state ServiceDown)" == "active" ]] \
    && ok "CAUSE detected: ServiceDown fired for the stopped service" \
    || bad "ServiceDown did not fire within 3 min"

  # Give the symptom alerts time to appear and be evaluated for inhibition.
  echo "    waiting for symptom alerts..."
  deadline=$(( $(date +%s) + 120 ))
  until [[ -n "$(alert_state SensorsCannotReachIngestion)" ]] || [[ $(date +%s) -gt $deadline ]]; do
    sleep 5
  done

  echo "    Alertmanager state:"
  show_alerts

  sym=$(alert_state SensorsCannotReachIngestion)
  if [[ -n "$sym" ]]; then
    ok "SYMPTOM detected: SensorsCannotReachIngestion also fired"
    [[ "$(alert_inhibited SensorsCannotReachIngestion)" == "yes" ]] \
      && ok "CORRELATION: symptom is INHIBITED by the cause (not shown to operator)" \
      || bad "symptom was NOT inhibited - correlation rule did not match"
  else
    bad "SensorsCannotReachIngestion never fired (expected as a symptom)"
  fi

  [[ "$(alert_inhibited ServiceDown)" == "no" ]] \
    && ok "the cause itself is not inhibited (operator still sees it)" \
    || bad "the cause was inhibited - that would hide the real fault"

  echo "==> Recovery"
  incus exec ingestion -- systemctl start ssle-ingestion.service
  echo "    ingestion restarted; waiting for alerts to resolve..."
  deadline=$(( $(date +%s) + 180 ))
  until [[ "$(alert_state ServiceDown)" == "" ]] || [[ $(date +%s) -gt $deadline ]]; do
    sleep 5
  done
  [[ "$(alert_state ServiceDown)" == "" ]] && ok "alerts resolved after recovery" \
                                           || bad "ServiceDown still firing after recovery"
  echo "    Alertmanager state after recovery:"
  show_alerts
fi

echo
echo "Result: $pass passed, $fail failed   (saved to ${OUT#$ROOT/})"
[[ $fail -eq 0 ]]
