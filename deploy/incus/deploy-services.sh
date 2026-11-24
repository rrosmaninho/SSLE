#!/usr/bin/env bash
# Deploy (or update) the SSLE base architecture into Incus containers.
#
#   bash deploy/incus/deploy-services.sh              # deploy all / push binaries + restart
#   bash deploy/incus/deploy-services.sh --recreate   # destroy and recreate containers
#   bash deploy/incus/deploy-services.sh storage      # only the listed containers
#
# Expects compiled binaries in build/bin (deploy/incus/build-services.sh) and the
# ssle-base runtime image (deploy/incus/build-base-image.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/bin"
IMAGE="ssle-base"
REGION="pt-centro.pt"
REGISTRY_URL="http://registry.incus:5050"

# container | kind | binary | port | node | rack | dc | extra env (k=v,k=v)
TOPOLOGY="
registry                   |registry |ssle-registry |5050|node1|rack1|dc-aveiro |
storage                    |storage  |ssle-storage  |5002|node1|rack1|dc-aveiro |
ingestion                  |ingestion|ssle-ingestion|5001|node2|rack1|dc-aveiro |
analytics                  |analytics|ssle-analytics|5003|node2|rack1|dc-aveiro |
sensors-aveiro-rack2-node1 |sensor   |ssle-sensor   |9101|node1|rack2|dc-aveiro |SENSOR_COUNT=5
sensors-coimbra-rack1-node1|sensor   |ssle-sensor   |9101|node1|rack1|dc-coimbra|SENSOR_COUNT=5
"

RECREATE=0
ONLY=()
for a in "$@"; do
  case "$a" in
    --recreate) RECREATE=1 ;;
    *) ONLY+=("$a") ;;
  esac
done

for b in ssle-registry ssle-storage ssle-ingestion ssle-analytics ssle-sensor; do
  [[ -x "$BIN/$b" ]] || { echo "Missing $BIN/$b - run deploy/incus/build-services.sh first" >&2; exit 1; }
done

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }

wait_ip() {
  for _ in $(seq 1 60); do
    incus list "$1" -c4 -f csv | grep -qE '10\.255\.255\.' && return 0
    sleep 1
  done
  echo "  !! $1 got no IP" >&2; return 1
}

deploy_one() {
  local ct="$1" kind="$2" binary="$3" port="$4" node="$5" rack="$6" dc="$7" extra="$8"
  local name="${kind}-01.${node}.${rack}.${dc}.${REGION}"
  echo "==> $ct  ($name)"

  if [[ $RECREATE -eq 1 ]]; then incus delete -f "$ct" >/dev/null 2>&1 || true; fi
  if ! incus info "$ct" >/dev/null 2>&1; then
    incus launch "$IMAGE" "$ct" >/dev/null
  elif [[ "$(incus list "$ct" -cs -f csv)" != "RUNNING" ]]; then
    incus start "$ct"
  fi
  wait_ip "$ct"

  # Binary. A running executable cannot be written to (ETXTBSY), so push
  # alongside and rename over it: the running process keeps the old inode
  # until its restart below picks up the new one.
  incus exec "$ct" -- mkdir -p /opt/ssle /etc/ssle /var/lib/ssle /var/log/ssle
  incus file push -q "$BIN/$binary" "$ct/opt/ssle/$binary.new"
  incus exec "$ct" -- bash -c "chmod 755 /opt/ssle/$binary.new && mv -f /opt/ssle/$binary.new /opt/ssle/$binary"

  # Identity + location, read by the service at start-up
  local envf; envf=$(mktemp)
  {
    echo "SERVICE_KIND=$kind"
    echo "SERVICE_NAME=$name"
    echo "SERVICE_PORT=$port"
    echo "REGISTRY_URL=$REGISTRY_URL"
    echo "REGION=$REGION"
    echo "DC=$dc"
    echo "RACK=$rack"
    echo "NODE=$node"
    if [[ -n "$extra" ]]; then tr ',' '\n' <<<"$extra"; fi
  } > "$envf"
  incus file push -q "$envf" "$ct/etc/ssle/env"
  rm -f "$envf"

  # Unprivileged service user
  incus exec "$ct" -- bash -c "
    id ssle >/dev/null 2>&1 || useradd --system --home /var/lib/ssle --shell /usr/sbin/nologin ssle
    chown -R ssle:ssle /var/lib/ssle /var/log/ssle
  "
  # systemd unit: the module ships its own (modules/<kind>/ssle-<kind>.service)
  incus file push -q "$ROOT/modules/$kind/ssle-$kind.service" \
    "$ct/etc/systemd/system/ssle-$kind.service"
  incus exec "$ct" -- bash -c "
    systemctl daemon-reload
    systemctl enable ssle-$kind.service >/dev/null 2>&1
    systemctl restart ssle-$kind.service
  "
}

while IFS='|' read -r -u 3 ct kind binary port node rack dc extra; do
  ct=$(trim "$ct"); [[ -z "$ct" ]] && continue
  if [[ ${#ONLY[@]} -gt 0 ]] && [[ ! " ${ONLY[*]} " =~ " $ct " ]]; then continue; fi
  deploy_one "$ct" "$(trim "$kind")" "$(trim "$binary")" "$(trim "$port")" \
             "$(trim "$node")" "$(trim "$rack")" "$(trim "$dc")" "$(trim "$extra")"
  if [[ "$ct" == "registry" ]]; then
    echo "  waiting for registry to answer..."
    for _ in $(seq 1 30); do
      incus exec registry -- curl -sf http://127.0.0.1:5050/health >/dev/null && break
      sleep 1
    done
  fi
done 3<<<"$TOPOLOGY"

echo
incus list -c ns4 -f table
