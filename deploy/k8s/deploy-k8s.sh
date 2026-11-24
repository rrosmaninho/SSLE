#!/usr/bin/env bash
# Deploy the SSLE stack onto the K3s cluster from k8s/*.yaml.
#
#   bash deploy/k8s/deploy-k8s.sh            # apply + wait for rollout
#   bash deploy/k8s/deploy-k8s.sh --delete   # remove the ssle namespace
#
# kubectl runs on k3s-master as `k3s kubectl`; manifests are copied there and
# applied. Images must already be imported (deploy/k8s/build-images.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
K="incus exec k3s-master -- k3s kubectl"

if [[ "${1:-}" == "--delete" ]]; then
  $K delete namespace ssle --ignore-not-found
  exit 0
fi

echo "== Copy manifests to k3s-master =="
incus exec k3s-master -- rm -rf /root/k8s
incus exec k3s-master -- mkdir -p /root/k8s
for f in "$ROOT"/deploy/k8s/*.yaml; do
  incus file push -q "$f" "k3s-master/root/k8s/$(basename "$f")"
done

echo "== Apply =="
$K apply -f /root/k8s/

echo "== Wait for rollout =="
for d in registry storage ingestion analytics; do
  $K -n ssle rollout status deploy/$d --timeout=120s
done
$K -n ssle rollout status statefulset/sensor --timeout=120s

echo
$K -n ssle get pods -o wide
echo
echo "Verify end-to-end:  bash deploy/k8s/verify-k3s.sh"
