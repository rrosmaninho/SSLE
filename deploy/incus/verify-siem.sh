#!/usr/bin/env bash
# Phase 5 check: Wazuh SIEM, custom rules and action-responses.
#   bash deploy/incus/verify-siem.sh          # rule + agent checks (~1 min)
#   bash deploy/incus/verify-siem.sh --full   # + live end-to-end alert via an agent
#
# Rules are exercised with wazuh-logtest, which runs a log line through the
# real decoder and rule tree, so a PASS means the deployed ruleset matched -
# not that a file merely exists. Output is saved under evidence/.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/verify-siem-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

FULL=0; [[ "${1:-}" == "--full" ]] && FULL=1
MGR=wazuh
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

# Run one log line through the live ruleset; assert rule id and level.
# $1 = description, $2 = expected rule id, $3 = expected level, $4 = log line
expect_rule() {
  local desc="$1" want_id="$2" want_lvl="$3" line="$4"
  local out id lvl
  # wazuh-logtest writes its whole report to stderr, so 2>&1 is required.
  out=$(printf '%s\n' "$line" | incus exec "$MGR" -- /var/ossec/bin/wazuh-logtest 2>&1)
  id=$(grep -oP "^\tid: '\K[0-9]+" <<<"$out" | tail -1)
  lvl=$(grep -oP "^\tlevel: '\K[0-9]+" <<<"$out" | tail -1)
  if [[ "$id" == "$want_id" && "$lvl" == "$want_lvl" ]]; then
    ok "$desc -> rule $id level $lvl"
  else
    bad "$desc -> got rule '${id:-none}' level '${lvl:-none}', expected $want_id/$want_lvl"
  fi
}

echo "==> Wazuh manager"
for svc in wazuh-manager wazuh-indexer filebeat wazuh-dashboard; do
  incus exec "$MGR" -- systemctl is-active --quiet $svc && ok "$svc active" || bad "$svc active"
done
procs=$(incus exec "$MGR" -- /var/ossec/bin/wazuh-control status 2>/dev/null | grep -c running)
[[ "${procs:-0}" -ge 10 ]] && ok "$procs manager processes running" || bad "only ${procs:-0} processes running"

echo "==> Agents enrolled"
agents=$(incus exec "$MGR" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -cE 'ID: 0[0-9]+.*(Active|Pending)')
active=$(incus exec "$MGR" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active')
[[ "${agents:-0}" -ge 7 ]] && ok "$agents agents registered (6 services + manager)" \
                           || bad "only ${agents:-0} agents registered"
[[ "${active:-0}" -ge 6 ]] && ok "$active agents active" || bad "only ${active:-0} agents active"
incus exec "$MGR" -- /var/ossec/bin/agent_control -l 2>/dev/null | grep -E 'ID: 0' | sed 's/^/    /'

echo "==> Custom ruleset loaded"
incus exec "$MGR" -- test -f /var/ossec/etc/rules/ssle_rules.xml && ok "ssle_rules.xml installed" || bad "rules missing"
incus exec "$MGR" -- test -f /var/ossec/etc/decoders/ssle_decoders.xml && ok "ssle_decoders.xml installed" || bad "decoders missing"
nrules=$(grep -c '<rule id="1004\?[0-9]*"' "$ROOT/modules/siem/rules/ssle_rules.xml")
ok "$nrules custom rules defined"

echo
echo "==> THREAT 1 - DoS detection (log lines through the live ruleset)"
# Both sightings are level 2 (not 0): Wazuh's if_matched_sid frequency counter
# ignores level-0 rules, so the sighting has to be level>0 (with no_log) to feed
# the frequency rules 100101/100102/100103. See the rule comments.
expect_rule "ingestion request (sighting, no alert)" 100100 2 \
  '10.255.255.6 - - [21/Nov/2026:06:10:11 +0000] "POST /ingest HTTP/1.1" 201 21'
expect_rule "ingestion 5xx (sighting, no alert)" 100104 2 \
  '10.255.255.6 - - [21/Nov/2026:06:10:11 +0000] "POST /ingest HTTP/1.1" 503 48'

# Frequency/correlation rules cannot be exercised with wazuh-logtest: it
# evaluates events one at a time and does not keep the cross-event state
# that frequency/timeframe needs. Here we confirm the correlated rules are
# loaded and correctly formed; they are exercised for real against live
# traffic in the DDoS phase (threats/ddos/run-ddos.sh).
for r in 100101 100102 100103; do
  if incus exec "$MGR" -- grep -q "rule id=\"$r\"" /var/ossec/etc/rules/ssle_rules.xml; then
    freq=$(grep -oP "rule id=\"$r\" level=\"[0-9]+\" frequency=\"\K[0-9]+" "$ROOT/modules/siem/rules/ssle_rules.xml")
    ok "correlation rule $r loaded (frequency ${freq:-?}) - exercised live in the DDoS phase"
  else
    bad "correlation rule $r not loaded"
  fi
done

echo
echo "==> THREAT 2 - C2 detection"
expect_rule "reverse shell to :4444" 100213 14 \
  'ssle-netwatch: UNEXPECTED 10.255.255.44:44312 -> 10.255.255.99:4444 (ssle-ingestion)'
expect_rule "unexpected outbound connection" 100212 12 \
  'ssle-netwatch: UNEXPECTED 10.255.255.44:44312 -> 10.255.255.99:8443 (ssle-ingestion)'
expect_rule "expected architecture traffic (no alert)" 100210 0 \
  'ssle-netwatch: OK 10.255.255.44:51200 -> 10.255.255.32:5002 (ssle-ingestion)'

echo
echo "==> THREAT 3 - DNS hijacking detection"
expect_rule "sinkholed hijack attempt" 100302 12 \
  '2026-11-21T06:10:11Z ssle-resolver action=SINKHOLE domain=bank-lab.example risk=82 client=10.255.255.40 reason=young-domain'
expect_rule "suspicious domain warning" 100301 5 \
  '2026-11-21T06:10:11Z ssle-resolver action=WARN domain=odd-site.example risk=55 client=10.255.255.40 reason=young-domain'
expect_rule "DNS leaving the lab resolver" 100304 12 \
  'ssle-netwatch: UNEXPECTED 10.255.255.44:35000 -> 8.8.8.8:53 (ssle-resolver)'

echo
echo "==> Architecture integrity"
expect_rule "service deregistration" 100400 10 \
  '10.255.255.185 - - [21/Nov/2026:06:10:11 +0000] "DELETE /unregister HTTP/1.1" 200 44'

echo
echo "==> Action-responses configured (spec: 3 incident types, each with a response)"
for pair in 100102:firewall-drop:DoS 100213:ssle-isolate:C2 100303:firewall-drop:DNS; do
  IFS=: read -r rule cmd label <<<"$pair"
  if incus exec "$MGR" -- bash -c "grep -A4 '<command>$cmd</command>' /var/ossec/etc/ossec.conf | grep -q '<rules_id>$rule</rules_id>'"; then
    ok "$label: rule $rule triggers '$cmd'"
  else
    bad "$label: no active-response wiring rule $rule to '$cmd'"
  fi
done
incus exec "$MGR" -- test -x /var/ossec/active-response/bin/ssle-isolate \
  && ok "ssle-isolate response script installed on manager" || bad "ssle-isolate missing on manager"
for ct in ingestion registry; do
  incus exec "$ct" -- test -x /var/ossec/active-response/bin/ssle-isolate \
    && ok "ssle-isolate installed on agent $ct" || bad "ssle-isolate missing on agent $ct"
  incus exec "$ct" -- test -x /var/ossec/wodles/ssle-netwatch \
    && ok "ssle-netwatch installed on agent $ct" || bad "ssle-netwatch missing on agent $ct"
done

echo
echo "==> Agent collection configured"
for ct in ingestion registry; do
  incus exec "$ct" -- grep -q '/var/log/ssle/\*-access.log' /var/ossec/etc/ossec.conf \
    && ok "$ct collects service access logs" || bad "$ct not collecting access logs"
  incus exec "$ct" -- grep -q '<directories check_all="yes" realtime="yes" report_changes="yes">/opt/ssle</directories>' /var/ossec/etc/ossec.conf \
    && ok "$ct has realtime FIM on /opt/ssle" || bad "$ct missing FIM on /opt/ssle"
done

if [[ $FULL -eq 1 ]]; then
  echo
  echo "==> End-to-end: generate a real event on an agent and look for the alert"
  # The netwatch script output is collected by the agent; write a line into
  # a log the agent already watches and confirm it reaches the manager.
  marker="10.255.255.$(( RANDOM % 200 + 20 ))"
  # Build the line on the HOST so the timestamp is expanded here; passing a
  # $(date) through nested quoting into the container left it literal and the
  # decoder then rejected the entry.
  ts=$(date -u '+%d/%b/%Y:%H:%M:%S')
  logline="$marker - - [$ts +0000] \"DELETE /unregister HTTP/1.1\" 200 44"
  # Append to the access log the agent already watches, in the Common Log
  # Format the services emit. A deregistration request raises rule 100400.
  printf '%s\n' "$logline" |
    incus exec ingestion -- tee -a /var/log/ssle/ingestion-access.log >/dev/null
  echo "    wrote a deregistration event from $marker; waiting for the alert..."
  found=0
  deadline=$(( $(date +%s) + 90 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if incus exec "$MGR" -- grep -q "$marker" /var/ossec/logs/alerts/alerts.json 2>/dev/null; then
      found=1; break
    fi
    sleep 5
  done
  if [[ $found -eq 1 ]]; then
    ok "event travelled agent -> manager -> alerts.json"
    incus exec "$MGR" -- bash -c "grep '$marker' /var/ossec/logs/alerts/alerts.json | tail -1" |
      python3 -c 'import json,sys
a=json.loads(sys.stdin.read())
print("    rule %s (level %s): %s" % (a["rule"]["id"], a["rule"]["level"], a["rule"]["description"]))
print("    agent: %s" % a.get("agent",{}).get("name"))' 2>/dev/null || true
  else
    bad "event did not reach alerts.json within 90s"
  fi
fi

echo
echo "Result: $pass passed, $fail failed   (saved to ${OUT#$ROOT/})"
[[ $fail -eq 0 ]]
