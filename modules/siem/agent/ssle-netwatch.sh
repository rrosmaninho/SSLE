#!/bin/bash
# Outbound-connection reporter for the C2 detection (threat 2).
#
# Wazuh's command monitoring runs this periodically on each agent. It prints
# one line per established OUTBOUND TCP connection, classified as OK (a
# destination this architecture legitimately uses) or UNEXPECTED:
#
#   ssle-netwatch: OK 10.255.255.44:512 -> 10.255.255.32:5002 (ssle-ingestion)
#   ssle-netwatch: UNEXPECTED 10.255.255.44:44312 -> 10.255.255.99:4444 (ssle-ingestion)
#
# The classification is done here rather than in a Wazuh rule because
# "destination is not in the known set" is a negation over a list, which the
# rule language expresses poorly (dstport is a static field and OS_Regex has
# no grouped negation). Doing it at the source also keeps the known-good
# topology in one place and lets the rules stay simple and readable.
#
# Only connections this host INITIATED are reported: inbound connections to
# the service's own listening port are normal traffic and would drown the
# signal. A C2 channel is by definition outbound, which is what makes this
# cheap to watch.

# Ports this architecture legitimately connects out to:
#   5050 registry | 5002 storage | 5001 ingestion | 5003 analytics
#   9101 sensor metrics | 9100 node_exporter | 9090 Prometheus | 9093 Alertmanager
#   53 DNS (lab resolver only) | 1514/1515 Wazuh agent | 80/443 package repos
ARCH_PORTS="5050 5002 5001 5003 9101 9100 9090 9093 53 1514 1515 80 443"
LAB_NET="10.255.255."

is_arch_port() {
  for p in $ARCH_PORTS; do [ "$1" = "$p" ] && return 0; done
  return 1
}

# Local listening ports: a connection whose LOCAL side is one of them is
# inbound, not an egress channel.
listening=$(ss -tlnH 2>/dev/null | awk '{split($4,a,":"); print a[length(a)]}' | sort -u)

ss -tnpH state established 2>/dev/null | while read -r line; do
  local_addr=$(echo "$line"  | awk '{print $3}')
  remote_addr=$(echo "$line" | awk '{print $4}')
  proc=$(echo "$line" | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p')

  local_port=${local_addr##*:}
  remote_ip=${remote_addr%:*}
  remote_port=${remote_addr##*:}

  # Skip inbound connections.
  echo "$listening" | grep -qx "$local_port" && continue
  # Skip loopback and IPv6 link-local noise.
  case "$local_addr" in 127.0.0.1:*|\[*) continue ;; esac
  case "$remote_addr" in 127.0.0.1:*|\[*) continue ;; esac

  state=UNEXPECTED
  if is_arch_port "$remote_port"; then
    # DNS is only legitimate towards the lab's own resolver; a query leaving
    # the lab means the protective resolver was bypassed.
    if [ "$remote_port" = "53" ]; then
      case "$remote_ip" in "$LAB_NET"*) state=OK ;; *) state=UNEXPECTED ;; esac
    else
      state=OK
    fi
  fi

  echo "ssle-netwatch: $state $local_addr -> $remote_addr (${proc:-unknown})"
done
