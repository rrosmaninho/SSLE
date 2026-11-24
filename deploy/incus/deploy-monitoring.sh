#!/usr/bin/env bash
# Deploy the monitoring layer:
#   - a `monitoring` container running Prometheus + Alertmanager
#   - prometheus-node-exporter on every service container (CPU/memory/disk)
#
# Prometheus discovers application targets from the registry (/sd), so this
# script does not need to know how many sensors exist.
#
#   bash deploy/incus/deploy-monitoring.sh              # deploy / update config
#   bash deploy/incus/deploy-monitoring.sh --recreate   # rebuild the container
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CT=monitoring
IMAGE=ssle-base
SERVICE_CTS="registry storage ingestion analytics sensors-aveiro-rack2-node1 sensors-coimbra-rack1-node1"

[[ "${1:-}" == "--recreate" ]] && incus delete -f "$CT" >/dev/null 2>&1 || true

wait_ip() {
  for _ in $(seq 1 60); do
    incus list "$1" -c4 -f csv | grep -qE '10\.255\.255\.' && return 0
    sleep 1
  done
  echo "  !! $1 got no IP" >&2; return 1
}

echo "==> Node exporters on service containers"
for ct in $SERVICE_CTS; do
  if incus exec "$ct" -- test -x /usr/bin/prometheus-node-exporter 2>/dev/null; then
    printf '  %-30s already installed\n' "$ct"
  else
    printf '  %-30s installing...\n' "$ct"
    incus exec "$ct" -- env DEBIAN_FRONTEND=noninteractive bash -c '
      apt-get update -q >/dev/null
      apt-get install -y -q --no-install-recommends prometheus-node-exporter >/dev/null
      apt-get clean; rm -rf /var/lib/apt/lists/*
      systemctl enable --now prometheus-node-exporter >/dev/null 2>&1
    '
  fi
  incus exec "$ct" -- systemctl is-active --quiet prometheus-node-exporter ||
    incus exec "$ct" -- systemctl restart prometheus-node-exporter
done

echo "==> Monitoring container"
if ! incus info "$CT" >/dev/null 2>&1; then
  incus launch "$IMAGE" "$CT" >/dev/null
  wait_ip "$CT"
  incus exec "$CT" -- env DEBIAN_FRONTEND=noninteractive bash -c '
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends \
      prometheus prometheus-alertmanager prometheus-node-exporter >/dev/null
    apt-get clean; rm -rf /var/lib/apt/lists/*
  '
else
  [[ "$(incus list "$CT" -cs -f csv)" == "RUNNING" ]] || incus start "$CT"
  wait_ip "$CT"
fi

REGISTRY_IP=$(incus list registry -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
[[ -n "$REGISTRY_IP" ]] || { echo "registry has no IP" >&2; exit 1; }
echo "  registry at $REGISTRY_IP"

echo "==> Pushing configuration"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed "s/REGISTRY_HOST/$REGISTRY_IP/g" "$ROOT/modules/monitoring/prometheus.yml" > "$tmp/prometheus.yml"

incus exec "$CT" -- mkdir -p /etc/prometheus/rules
incus file push -q "$tmp/prometheus.yml" "$CT/etc/prometheus/prometheus.yml"
incus file push -q "$ROOT/modules/monitoring/rules/ssle-alerts.yml" "$CT/etc/prometheus/rules/ssle-alerts.yml"
incus file push -q "$ROOT/modules/monitoring/alertmanager.yml" "$CT/etc/prometheus/alertmanager.yml"

# Debian's prometheus unit reads flags from /etc/default/prometheus.
incus file push -q /dev/stdin "$CT/etc/default/prometheus" <<'EOF'
ARGS="--web.listen-address=0.0.0.0:9090 --storage.tsdb.retention.time=15d --web.enable-lifecycle"
EOF
incus file push -q /dev/stdin "$CT/etc/default/prometheus-alertmanager" <<'EOF'
ARGS="--web.listen-address=0.0.0.0:9093 --cluster.listen-address="
EOF

echo "==> Validating configuration"
incus exec "$CT" -- promtool check config /etc/prometheus/prometheus.yml
incus exec "$CT" -- amtool check-config /etc/prometheus/alertmanager.yml

echo "==> Restarting"
incus exec "$CT" -- bash -c '
  sed -i "s|^ARGS=.*|ARGS=\"--config.file=/etc/prometheus/alertmanager.yml --storage.path=/var/lib/prometheus/alertmanager --web.listen-address=0.0.0.0:9093 --cluster.listen-address=\"|" /etc/default/prometheus-alertmanager
  systemctl enable --now prometheus-node-exporter >/dev/null 2>&1
  systemctl restart prometheus-alertmanager
  systemctl restart prometheus
'
sleep 5
incus exec "$CT" -- systemctl is-active prometheus prometheus-alertmanager

MON_IP=$(incus list "$CT" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+')
cat <<EOF

Monitoring is up.
  Prometheus    http://$MON_IP:9090
  Alertmanager  http://$MON_IP:9093

These are on the isolated lab network. Reach them from your workstation with
an SSH tunnel (do not publish ports to the LAN):
  ssh -L 9090:$MON_IP:9090 -L 9093:$MON_IP:9093 rrosmaninho@10.20.4.114
then open http://localhost:9090 and http://localhost:9093
EOF
