#!/usr/bin/env bash
# Compile the C++ services inside a persistent build container and copy the
# binaries to build/bin/ on the VM, ready for deploy-services.sh to push.
#
# The build container is kept between runs so CMake's cache and object files
# survive, making rebuilds fast. Use --clean to start from scratch.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILDER="ssle-builder"
OUT="$ROOT/build/bin"
BINARIES="ssle-registry ssle-storage ssle-ingestion ssle-analytics ssle-sensor"

[[ "${1:-}" == "--clean" ]] && incus delete -f "$BUILDER" >/dev/null 2>&1 || true

if ! incus info "$BUILDER" >/dev/null 2>&1; then
  echo "==> Creating build container"
  incus launch ssle-build "$BUILDER" >/dev/null
  for _ in $(seq 1 60); do
    incus list "$BUILDER" -c4 -f csv | grep -qE '10\.255\.255\.' && break
    sleep 1
  done
elif [[ "$(incus list "$BUILDER" -cs -f csv)" != "RUNNING" ]]; then
  incus start "$BUILDER"
  sleep 3
fi

echo "==> Syncing sources"
incus exec "$BUILDER" -- rm -rf /src
incus exec "$BUILDER" -- mkdir -p /src
# Push the module tree intact (/src/modules/...) so the top-level CMakeLists'
# add_subdirectory(modules/<kind>) paths resolve. -r copies the dir itself.
incus file push -r -q "$ROOT/modules" "$BUILDER/src/"
incus file push -q "$ROOT/CMakeLists.txt" "$BUILDER/src/CMakeLists.txt"

echo "==> Compiling"
incus exec "$BUILDER" -- bash -c '
  set -e
  cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build /build -j"$(nproc)" 2>&1 | grep -viE "^\[|Building|Linking|Scanning|Consolidate" || true
'

echo "==> Collecting binaries"
mkdir -p "$OUT"
for b in $BINARIES; do
  # CMake places each executable under build/modules/<kind>/ (module layout).
  incus file pull -q "$BUILDER/build/modules/${b#ssle-}/$b" "$OUT/$b"
  chmod +x "$OUT/$b"
done

incus stop "$BUILDER"   # keep it for the next build, but not running
ls -la "$OUT" | awk 'NR>1 {printf "  %-18s %8.1f KiB\n", $9, $5/1024}'
echo "Binaries in ${OUT#$ROOT/}"
