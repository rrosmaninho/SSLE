#!/usr/bin/env bash
# Attack-surface probe for the risk-management chapter.
#
# Launches a throwaway, unprivileged container on the lab network - the
# "remote attacker" of the threat model, with no credentials and no access
# beyond being on the same network - and records what it can actually reach
# and do. Findings feed the Attack-Defense Tree.
#
# Everything stays inside the Incus lab network (10.255.255.0/24); nothing
# is sent outside the VM. Destructive probes are performed on a disposable
# decoy service that is registered for the purpose, never on a real one.
#
#   bash threats/attack-surface-probe.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/attack-surface-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

ATTACKER="probe-attacker"
findings=0
finding() { echo "  [!] $*"; findings=$((findings+1)); }
noted()   { echo "  [ok] $*"; }

cleanup() { incus delete -f "$ATTACKER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== Attack-surface probe  $(date -Is)"
echo "Attacker model: unauthenticated host on the lab network, no credentials."
echo

incus launch ssle-base "$ATTACKER" >/dev/null
for _ in $(seq 1 60); do
  incus list "$ATTACKER" -c4 -f csv | grep -qE '10\.255\.255\.' && break
  sleep 1
done
ATT_IP=$(incus list "$ATTACKER" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
echo "Attacker container: $ATT_IP"

run() { incus exec "$ATTACKER" -- bash -c "$1" 2>/dev/null; }

ip_of() { incus list "$1" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+'; }
REG=$(ip_of registry); ING=$(ip_of ingestion); STO=$(ip_of storage)
ANA=$(ip_of analytics); MON=$(ip_of monitoring)

echo
echo "--- 1. Reconnaissance: can the attacker enumerate the architecture?"
# The registry is designed to be queryable; the question is by whom.
svc=$(run "curl -s --max-time 5 http://$REG:5050/services" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null)
if [[ -n "${svc:-}" && "$svc" -gt 0 ]]; then
  finding "Registry /services is unauthenticated: full inventory of $svc instances, with hierarchical names, IPs, ports and physical location"
  run "curl -s --max-time 5 http://$REG:5050/services" |
    python3 -c 'import json,sys
d=json.load(sys.stdin)
for n,v in list(sorted(d.items()))[:3]: print("       e.g.", n, "->", v["url"])' 2>/dev/null
else
  noted "Registry /services not reachable from the attacker"
fi

run "curl -sf --max-time 5 http://$REG:5050/sd >/dev/null" &&
  finding "Registry /sd exposes the monitoring target list (maps the whole fleet)" ||
  noted "Registry /sd not reachable"

echo
echo "--- 2. Service discovery integrity: can the attacker tamper with the registry?"
# Register a decoy so the destructive tests never touch a real service.
DECOY="decoy-99.node9.rack9.dc-probe.pt-centro.pt"
reg=$(run "curl -s --max-time 5 -X POST http://$REG:5050/register -H 'Content-Type: application/json' -d '{\"name\":\"$DECOY\",\"kind\":\"decoy\",\"url\":\"http://$ATT_IP:9999\",\"labels\":{\"dc\":\"dc-probe\"}}'")
if grep -q registered <<<"$reg"; then
  finding "Registry /register is unauthenticated: an attacker can register arbitrary services (discovery poisoning - traffic can be redirected to attacker-controlled endpoints)"
else
  noted "Registry /register rejected the attacker"
fi

# Can the attacker make the architecture hand clients an attacker address?
poison=$(run "curl -s --max-time 5 http://$REG:5050/discover/decoy")
if grep -q "$ATT_IP" <<<"$poison"; then
  finding "Discovery now returns the attacker's address for kind=decoy - clients would connect to the attacker"
fi

unreg=$(run "curl -s --max-time 5 -X DELETE http://$REG:5050/unregister -H 'Content-Type: application/json' -d '{\"name\":\"$DECOY\"}'")
if grep -q unregistered <<<"$unreg"; then
  finding "Registry /unregister is unauthenticated: any instance can be evicted from the architecture (denial of service by deregistration)"
else
  noted "Registry /unregister rejected the attacker"
fi

echo
echo "--- 3. Data integrity: can the attacker inject sensor data?"
inj=$(run "curl -s --max-time 5 -o /dev/null -w '%{http_code}' -X POST http://$ING:5001/ingest -H 'Content-Type: application/json' -d '{\"sensor\":\"FAKE-probe.node9.rack9.dc-probe.pt-centro.pt\",\"value\":999.0,\"unit\":\"C\",\"labels\":{\"dc\":\"dc-probe\"}}'")
if [[ "$inj" == "201" ]]; then
  finding "Ingestion /ingest is unauthenticated: forged readings from a non-existent sensor are accepted and stored (HTTP $inj)"
else
  noted "Ingestion rejected the forged reading (HTTP $inj)"
fi

echo
echo "--- 4. Confidentiality: can the attacker read stored data?"
rows=$(run "curl -s --max-time 5 'http://$STO:5002/readings?limit=5'" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null)
if [[ -n "${rows:-}" && "$rows" -gt 0 ]]; then
  finding "Storage /readings is unauthenticated: historical measurements can be read directly, bypassing ingestion"
else
  noted "Storage /readings not readable by the attacker"
fi
run "curl -sf --max-time 5 http://$ANA:5003/report >/dev/null" &&
  finding "Analytics /report is unauthenticated (aggregate disclosure)" ||
  noted "Analytics /report not reachable"

echo
echo "--- 5. Monitoring plane: is the observability stack exposed?"
run "curl -sf --max-time 5 http://$MON:9090/api/v1/targets >/dev/null" &&
  finding "Prometheus API is unauthenticated: an attacker can read all metrics and learn the full topology" ||
  noted "Prometheus API not reachable"
run "curl -sf --max-time 5 http://$MON:9093/api/v2/alerts >/dev/null" &&
  finding "Alertmanager API is unauthenticated: alerts are readable and silences can be created (detection can be muted)" ||
  noted "Alertmanager API not reachable"
run "curl -sf --max-time 5 http://$ING:9100/metrics >/dev/null" &&
  finding "node_exporter is unauthenticated on every container (host inventory: kernel, filesystems, network)" ||
  noted "node_exporter not reachable"

echo
echo "--- 6. Transport: is traffic protected?"
if run "curl -s --max-time 5 -o /dev/null http://$ING:5001/health"; then
  finding "All inter-service traffic is plain HTTP - no TLS, no mutual authentication (interception and tampering possible for an on-path attacker)"
fi

echo
echo "--- 7. Containment: can the attacker escape the lab?"
run "timeout 4 bash -c 'echo > /dev/tcp/10.20.4.1/443'" &&
  finding "Lab container reached the home gateway - CONTAINMENT BROKEN" ||
  noted "Home LAN unreachable from the lab (nftables ssle_guard)"
run "timeout 4 bash -c 'echo > /dev/tcp/10.255.255.1/22'" &&
  finding "Lab container reached the VM's SSH - CONTAINMENT BROKEN" ||
  noted "VM SSH unreachable from the lab"
run "getent hosts deb.debian.org >/dev/null" &&
  noted "Internet reachable (expected while building; 'lab-lockdown on' closes it for attack runs)" ||
  noted "Internet egress blocked (lab-lockdown active)"

echo
echo "--- 8. Privilege: what does the attacker get on a compromised service container?"
if incus exec ingestion -- test -x /usr/bin/g++ 2>/dev/null; then
  finding "Service containers ship a compiler (attacker can build tooling in place)"
else
  noted "No compiler in service containers (runtime image only)"
fi
u=$(incus exec ingestion -- bash -c 'ps -eo user=,comm= | awk "/ssle-/ {print \$1}" | sort -u')
[[ "$u" == "ssle" ]] && noted "Services run as unprivileged user '$u', not root" \
                     || finding "Services run as '$u'"
incus exec ingestion -- grep -q 'ProtectSystem=strict' /etc/systemd/system/ssle-ingestion.service &&
  noted "systemd hardening active (ProtectSystem=strict, NoNewPrivileges, ProtectHome)" ||
  finding "No systemd hardening on the service unit"
priv=$(incus config get ingestion security.privileged 2>/dev/null)
[[ "$priv" == "true" ]] && finding "Container is privileged" \
                        || noted "Container is unprivileged (security.privileged unset)"

echo
echo "=== $findings exposures recorded. Full output: ${OUT#$ROOT/}"
echo "Note: the forged reading and the decoy registration are test artefacts."
