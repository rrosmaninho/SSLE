#!/bin/bash
# Wazuh active response for THREAT 2 (APT / C2).
#
# Runs on the agent where the alert fired. Three actions, in order of how
# reversible they are:
#
#   1. Block the C2 address (nftables), cutting the channel.
#   2. Deregister this service from the Service Registry, so the
#      architecture stops routing work to a host believed compromised.
#      This is containment at the application layer: the service is
#      isolated from the system without killing it, which preserves the
#      host for forensics.
#   3. Record everything to a local log for the post-mortem.
#
# Wazuh 4.x passes the alert as JSON on stdin and the command ("add" or
# "delete") inside it. "delete" undoes the block when the AR times out.
#
# Installed to /var/ossec/active-response/bin/ssle-isolate on each agent.

LOG=/var/ossec/logs/active-responses.log
EVIDENCE=/var/log/ssle/incident-response.log
mkdir -p "$(dirname "$EVIDENCE")" 2>/dev/null

read -r INPUT
COMMAND=$(echo "$INPUT" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
RULE=$(echo "$INPUT"  | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p' | head -1)
# The C2 address: the alert's destination, not its source.
DSTIP=$(echo "$INPUT" | sed -n 's/.*"dstip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
DSTPORT=$(echo "$INPUT" | sed -n 's/.*"dstport"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

ts() { date -Is; }
note() {
  echo "$(ts) ssle-isolate: $*" >> "$LOG"
  echo "$(ts) ssle-isolate: $*" >> "$EVIDENCE"
}

if [ -z "$DSTIP" ]; then
  note "no destination address in alert (rule $RULE); nothing to block"
  exit 0
fi

# ---- 1. Block the C2 channel -------------------------------------------
TABLE=ssle_ar
ensure_table() {
  nft list table inet $TABLE >/dev/null 2>&1 || {
    nft add table inet $TABLE
    nft add chain inet $TABLE output '{ type filter hook output priority 0; }'
  }
}

case "$COMMAND" in
  add)
    if command -v nft >/dev/null 2>&1; then
      ensure_table
      nft add rule inet $TABLE output ip daddr "$DSTIP" counter drop 2>/dev/null &&
        note "BLOCKED C2 address $DSTIP:$DSTPORT (rule $RULE)" ||
        note "failed to block $DSTIP"
    else
      note "nft not available; cannot block $DSTIP"
    fi
    ;;
  delete)
    if command -v nft >/dev/null 2>&1; then
      handle=$(nft -a list table inet $TABLE 2>/dev/null |
               awk -v ip="$DSTIP" '$0 ~ ip {print $NF}' | head -1)
      [ -n "$handle" ] && nft delete rule inet $TABLE output handle "$handle" 2>/dev/null &&
        note "unblocked $DSTIP (AR expired)"
    fi
    exit 0
    ;;
esac

# ---- 2. Deregister this service from the architecture ------------------
# Reading the service's own identity file rather than guessing it.
if [ -r /etc/ssle/env ]; then
  # shellcheck disable=SC1091
  . /etc/ssle/env
  if [ -n "${SERVICE_NAME:-}" ] && [ -n "${REGISTRY_URL:-}" ]; then
    resp=$(curl -s --max-time 5 -X DELETE "$REGISTRY_URL/unregister" \
             -H 'Content-Type: application/json' \
             --data-binary "{\"name\":\"$SERVICE_NAME\"}" 2>&1)
    case "$resp" in
      *unregistered*)
        note "ISOLATED: deregistered $SERVICE_NAME from the registry; discovery will stop returning it" ;;
      *)
        note "deregistration of $SERVICE_NAME failed or already removed: $resp" ;;
    esac
  else
    note "no SERVICE_NAME/REGISTRY_URL in /etc/ssle/env; skipped deregistration"
  fi
else
  note "no /etc/ssle/env on this host; skipped deregistration"
fi

# ---- 3. Forensic snapshot for the post-mortem --------------------------
{
  echo "--- incident snapshot $(ts) (rule $RULE, C2 $DSTIP:$DSTPORT)"
  echo "[connections]"; ss -tunap 2>/dev/null | head -40
  echo "[processes]";   ps -eo pid,ppid,user,etime,cmd --sort=start_time 2>/dev/null | tail -25
  echo "[recent files in /opt/ssle]"; ls -la --time-style=full-iso /opt/ssle 2>/dev/null
  echo "[cron]"; ls -la /etc/cron.d /var/spool/cron/crontabs 2>/dev/null
  echo "--- end snapshot"
} >> "$EVIDENCE" 2>&1

note "incident snapshot written to $EVIDENCE"
exit 0
