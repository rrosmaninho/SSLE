#!/usr/bin/env bash
# Stand up the K3s cluster for the PaaS-packaging track (Guide 2 §3.2–3.4).
#
#   bash deploy/k8s/setup-cluster.sh            # create master + node1 + docker
#   bash deploy/k8s/setup-cluster.sh --recreate # destroy and recreate them
#
# Creates three privileged Incus containers on the `k3s` profile, all on the
# isolated lab network (10.255.255.0/24):
#   k3s-master  — K3s server (control-plane)
#   k3s-node1   — K3s agent (worker)
#   docker      — Docker engine for building images (Guide 2 §3.4); Docker is
#                 installed HERE, never on the VM root (Incus + Docker clash).
#
# Needs lab internet egress (get.k3s.io, Docker apt repo, Docker Hub base image),
# i.e. `lab-lockdown off` — this is setup, not an attack experiment. Nothing is
# published to the home LAN; containment (ssle-guard) stays enforced.
set -euo pipefail

PROFILE=k3s
IMAGE=images:debian/trixie
RECREATE=0
[[ "${1:-}" == "--recreate" ]] && RECREATE=1

say() { printf '\n== %s ==\n' "$*"; }

need_profile() {
  incus profile show "$PROFILE" >/dev/null 2>&1 || {
    echo "!! Incus profile '$PROFILE' missing — run deploy/k8s/platform/setup-platform.sh first" >&2
    exit 1
  }
}

egress_ok() {
  timeout 25 incus exec k3s-master -- bash -c \
    'curl -sfI https://get.k3s.io -o /dev/null --max-time 15' 2>/dev/null
}

launch() {
  local ct="$1"
  if [[ $RECREATE -eq 1 ]]; then incus delete -f "$ct" >/dev/null 2>&1 || true; fi
  if incus info "$ct" >/dev/null 2>&1; then
    echo "  $ct already exists"
    [[ "$(incus list "$ct" -cs -f csv)" == "RUNNING" ]] || incus start "$ct"
  else
    echo "  launching $ct ($IMAGE, profile $PROFILE)"
    incus launch "$IMAGE" "$ct" --profile "$PROFILE" >/dev/null
  fi
  # wait for a lab IP + working DNS before any apt/curl
  for _ in $(seq 1 60); do
    incus list "$ct" -c4 -f csv | grep -qE '10\.255\.255\.' && \
      incus exec "$ct" -- getent hosts deb.debian.org >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "!! $ct did not get network/DNS" >&2; return 1
}

apt_install() {
  local ct="$1"; shift
  incus exec "$ct" -- env DEBIAN_FRONTEND=noninteractive bash -c \
    "apt-get update -q && apt-get install -y -q --no-install-recommends $*"
}

need_profile

say "1/5  Launch k3s-master"
launch k3s-master
if ! egress_ok; then
  echo "!! No internet egress from the lab (get.k3s.io unreachable)." >&2
  echo "   Run 'sudo lab-lockdown off' and retry — K3s install needs egress." >&2
  exit 1
fi

say "2/5  Install K3s server on k3s-master"
if ! incus exec k3s-master -- test -x /usr/local/bin/k3s; then
  apt_install k3s-master curl ca-certificates
  incus exec k3s-master -- bash -c 'curl -sfL https://get.k3s.io | sh -'
fi
# wait for the control-plane to report Ready
for _ in $(seq 1 60); do
  incus exec k3s-master -- k3s kubectl get nodes 2>/dev/null | grep -q ' Ready ' && break
  sleep 2
done
incus exec k3s-master -- k3s kubectl get nodes

TOKEN="$(incus exec k3s-master -- cat /var/lib/rancher/k3s/server/node-token)"
[[ -n "$TOKEN" ]] || { echo "!! could not read node-token" >&2; exit 1; }

say "3/5  Launch k3s-node1 and join it to the cluster"
launch k3s-node1
if ! incus exec k3s-node1 -- test -x /usr/local/bin/k3s; then
  apt_install k3s-node1 curl ca-certificates
  incus exec k3s-node1 -- bash -c \
    "curl -sfL https://get.k3s.io | K3S_URL=https://k3s-master.incus:6443 K3S_TOKEN=$TOKEN sh -"
fi

say "4/5  Launch docker build container (Guide 2 §3.4)"
launch docker
if ! incus exec docker -- test -x /usr/bin/docker; then
  incus exec docker -- bash -c '
    set -e
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -y -q --no-install-recommends docker-ce docker-ce-cli containerd.io
  ' || { apt_install docker curl ca-certificates; echo "  (retry docker repo step if this failed)"; }
fi

say "5/5  Cluster status"
# let node1 register
for _ in $(seq 1 60); do
  [[ "$(incus exec k3s-master -- k3s kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ')" -ge 2 ]] && break
  sleep 2
done
incus exec k3s-master -- k3s kubectl get nodes -o wide
echo
echo "K3s version: $(incus exec k3s-master -- k3s --version 2>/dev/null | head -1)"
incus exec docker -- docker --version 2>/dev/null || true
echo
echo "Next: bash deploy/k8s/build-images.sh && bash deploy/k8s/deploy-k8s.sh"
