#!/usr/bin/env bash
# Package the five services as Docker images (Guide 2 §5) and load them into the
# K3s cluster — fully offline, no external registry.
#
#   bash deploy/k8s/build-images.sh
#
# Flow:
#   1. build ssle/<kind>:v1 inside the `docker` Incus container (never on the VM
#      root — Guide 2 warning), from the pre-compiled binaries in build/bin/;
#   2. `docker save` all five into one layer-deduplicated tar;
#   3. import that tar into each K3s node's containerd (k8s.io namespace) with
#      `k3s ctr images import`, so pods run them with imagePullPolicy IfNotPresent
#      and never reach out to Docker Hub.
#
# This is the "sovereignty / offline" path named in Guide 2 §5 — appropriate for
# the isolated lab, and it keeps working with `lab-lockdown on`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/bin"
SERVICES=(registry storage ingestion analytics sensor)
TAG=v1
TAR=/root/ssle-images.tar
NODES=(k3s-master k3s-node1)

say() { printf '\n== %s ==\n' "$*"; }

for s in "${SERVICES[@]}"; do
  [[ -x "$BIN/ssle-$s" ]] || { echo "!! Missing $BIN/ssle-$s — run deploy/k8s/build-services.sh first" >&2; exit 1; }
done
incus info docker >/dev/null 2>&1 || { echo "!! 'docker' container missing — run setup-cluster.sh" >&2; exit 1; }
incus exec docker -- test -x /usr/bin/docker || { echo "!! docker not installed in the docker container" >&2; exit 1; }

say "1/4  Stage build context into the docker container"
incus exec docker -- rm -rf /root/ssle-build
incus exec docker -- mkdir -p /root/ssle-build
incus file push -qr "$BIN" docker/root/ssle-build/        # -> /root/ssle-build/bin
for s in "${SERVICES[@]}"; do                              # each module's own Dockerfile
  incus file push -q "$ROOT/modules/$s/Dockerfile" "docker/root/ssle-build/Dockerfile.$s"
done

say "2/4  Build images inside the docker container"
incus exec docker -- bash -c "
  set -e
  cd /root/ssle-build
  for s in ${SERVICES[*]}; do
    echo \"  building ssle/\$s:$TAG\"
    docker build -q -f Dockerfile.\$s --build-arg BIN=bin/ssle-\$s -t ssle/\$s:$TAG . >/dev/null
  done
  docker images ssle/'*'
"

say "3/4  Export images to a single tar"
incus exec docker -- bash -c "docker save $(printf 'ssle/%s:'"$TAG"' ' "${SERVICES[@]}") -o $TAR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
incus file pull -q "docker$TAR" "$TMP/ssle-images.tar"
echo "  tar size: $(du -h "$TMP/ssle-images.tar" | cut -f1)"

say "4/4  Import into each K3s node's containerd (k8s.io namespace)"
for n in "${NODES[@]}"; do
  echo "  -> $n"
  incus file push -q "$TMP/ssle-images.tar" "$n$TAR"
  incus exec "$n" -- k3s ctr images import "$TAR" | sed 's/^/     /'
  incus exec "$n" -- rm -f "$TAR"
done
incus exec docker -- rm -f "$TAR"

echo
echo "Images loaded on both nodes. Next: bash deploy/k8s/deploy-k8s.sh"
