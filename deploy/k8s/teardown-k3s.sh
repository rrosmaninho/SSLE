#!/usr/bin/env bash
# Tear down the K3s track. The Incus telemetry stack (the graded primary) and
# the ssle- images are untouched.
#
#   bash deploy/k8s/teardown-k3s.sh          # delete k3s-master, k3s-node1, docker
#   bash deploy/k8s/teardown-k3s.sh --stop    # just stop them (keep for re-runs)
set -euo pipefail

CTS=(k3s-master k3s-node1 docker)

if [[ "${1:-}" == "--stop" ]]; then
  for c in "${CTS[@]}"; do incus stop "$c" 2>/dev/null && echo "stopped $c" || true; done
  exit 0
fi

for c in "${CTS[@]}"; do
  incus delete -f "$c" 2>/dev/null && echo "deleted $c" || echo "$c not present"
done
echo "Done. The 'k3s' profile and the Incus stack remain."
