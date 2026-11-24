#!/usr/bin/env bash
# DoS mitigation exercise (DoS guide): measure the system under the same
# bounded flood BEFORE and AFTER the per-identity rate-limiting control, and
# compare what each lets through.
#
# The flood posts a fixed body - i.e. a single sensor identity - which is what
# a reflected/replayed DoS looks like. Without the control every request is
# served and its junk reading is stored; with the control the identity's token
# bucket empties and the excess is shed with HTTP 429 before reaching storage.
#
#   bash threats/ddos/mitigation-compare.sh            # run the comparison
#   bash threats/ddos/mitigation-compare.sh --cleanup  # remove the load client
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/ddos-mitigation-$(date +%Y%m%d-%H%M%S)"
CLIENT=ddos-mit-client
TARGET=ingestion
N=3000; C=10          # bounded flood: 3000 requests, concurrency 10

ip_of() { incus list "$1" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+'; }

cleanup() {
  echo "==> Cleanup"
  incus delete -f "$CLIENT" >/dev/null 2>&1 && echo "  removed $CLIENT"
  incus exec "$TARGET" -- bash -c 'sed -i "/^RATE_LIMIT_RPS=/d" /etc/ssle/env' 2>/dev/null || true
  incus exec "$TARGET" -- systemctl restart ssle-ingestion 2>/dev/null || true
  incus exec storage -- sqlite3 /var/lib/ssle/storage.db "DELETE FROM readings WHERE sensor LIKE 'loadtest-%'" 2>/dev/null
  echo "  restored default rate limit, cleaned load-test rows"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }

mkdir -p "$EV"
echo "=== DoS mitigation comparison  $(date -Is)" | tee "$EV/summary.txt"

# Load client with ApacheBench.
incus info "$CLIENT" >/dev/null 2>&1 || incus launch ssle-base "$CLIENT" >/dev/null
for _ in $(seq 1 60); do incus list "$CLIENT" -c4 -f csv | grep -qE '10\.255\.255\.' && break; sleep 1; done
incus exec "$CLIENT" -- bash -c 'command -v python3 >/dev/null || (export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends python3 >/dev/null 2>&1)'
incus file push -q "$ROOT/threats/ddos/body.json" "$CLIENT/root/body.json"
incus file push -q "$ROOT/threats/ddos/flooder.py" "$CLIENT/root/flooder.py"
URL="http://$(ip_of "$TARGET"):5001/ingest"

set_limit() {   # $1 = RATE_LIMIT_RPS value
  incus exec "$TARGET" -- bash -c "sed -i '/^RATE_LIMIT_RPS=/d' /etc/ssle/env; echo 'RATE_LIMIT_RPS=$1' >> /etc/ssle/env"
  incus exec "$TARGET" -- systemctl restart ssle-ingestion
  sleep 3
}

storage_count() { incus exec storage -- curl -s http://127.0.0.1:5002/stats |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])'; }

# A bounded flood from the client that counts response codes directly. ab
# stalls under a storm of concurrent 429s, so the flood is C parallel workers
# each issuing N/C sequential POSTs of the one-identity body, tallying codes.
flood() {  # prints "<201count> <429count> <elapsed_s>"
  # One Python process with WORKERS threads (stdlib urllib) - fast and
  # reliable where process-per-request (curl/ab) is slow or stalls on 429s.
  local out
  out=$(incus exec "$CLIENT" -- python3 /root/flooder.py "$URL" "$N" "$C" /root/body.json)
  # flooder prints "201 429 other elapsed"; collapse to "201 429 elapsed".
  awk '{print $1, $2, $4}' <<<"$out"
}
measure() {   # $1 = label, $2 = RATE_LIMIT_RPS
  set_limit "$2"
  incus exec storage -- sqlite3 /var/lib/ssle/storage.db "DELETE FROM readings WHERE sensor LIKE 'loadtest-%'" 2>/dev/null
  local before after res served shed elapsed
  before=$(storage_count)
  res=$(flood)
  after=$(storage_count)
  read -r served shed elapsed <<<"$res"
  python3 - "$1" "$served" "$shed" "$((after-before))" "$elapsed" <<'PY'
import sys
label, served, shed, stored, elapsed = sys.argv[1:6]
total = int(served) + int(shed)
tput = total / float(elapsed) if float(elapsed) > 0 else 0
print("%-16s | sent %-5s | served(201) %-6s | shed(429) %-6s | junk stored %-6s | %.0f req/s"
      % (label, total, served, shed, stored, tput))
PY
}

echo "Bounded flood: $N requests, concurrency $C, single sensor identity." | tee -a "$EV/summary.txt"
echo | tee -a "$EV/summary.txt"
echo "BEFORE: rate limiting effectively disabled (RATE_LIMIT_RPS very high)" | tee -a "$EV/summary.txt"
measure before 1000000 | tee -a "$EV/summary.txt"
echo | tee -a "$EV/summary.txt"
echo "AFTER:  per-identity rate limiting at the default 5 req/s, burst 10" | tee -a "$EV/summary.txt"
measure after 5 | tee -a "$EV/summary.txt"

echo | tee -a "$EV/summary.txt"
cat <<EOF | tee -a "$EV/summary.txt"
Reading the table:
 - "junk stored" is the attacker's impact on the data store. The control cuts
   it to roughly the burst size: the flood is shed at the service before it
   reaches storage, so the database is protected.
 - The control is PROACTIVE (it acts on the first request, in the data path)
   and complements the REACTIVE SIEM firewall-drop (which blocks the source
   after the sustained-flood rule fires).
 - What it does NOT stop: an attacker who rotates through many distinct
   identities gets one burst each. That flood is instead visible as a surge of
   unknown/implausible sensor identities (the anomaly rules) and as a growing
   bucket count; per-identity limiting raises the attacker's cost rather than
   closing the attack entirely.
EOF
set_limit 5   # leave the default in place
echo
echo "Evidence under: ${EV#$ROOT/}/   (run with --cleanup to remove the client)"
