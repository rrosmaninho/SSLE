#!/usr/bin/env bash
# Build two Incus images:
#   ssle-build - Debian 13 + g++/cmake + dev headers (compiles the services)
#   ssle-base  - Debian 13 + runtime shared libraries only (runs them)
#
# Splitting them keeps the service containers small and free of a compiler,
# which also means a compromised service container has no toolchain to build
# with (relevant to the C2 threat).
#
# Run as a user in incus-admin. Re-run to rebuild.
set -euo pipefail

RUNTIME_PKGS="libcpp-httplib0.18 libsqlite3-0 libssl3 ca-certificates curl"
BUILD_PKGS="g++ make cmake libcpp-httplib-dev nlohmann-json3-dev libsqlite3-dev libssl-dev"

build_image() {
  local alias="$1" pkgs="$2" desc="$3"
  local builder="${alias}-builder"
  echo "==> Building image: $alias"
  incus delete -f "$builder" >/dev/null 2>&1 || true
  incus launch images:debian/13 "$builder" >/dev/null

  for _ in $(seq 1 30); do
    incus exec "$builder" -- getent hosts deb.debian.org >/dev/null 2>&1 && break
    sleep 1
  done

  incus exec "$builder" -- env DEBIAN_FRONTEND=noninteractive bash -c "
    set -e
    apt-get update -q
    apt-get install -y -q --no-install-recommends $pkgs
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    mkdir -p /opt/ssle /var/lib/ssle /var/log/ssle
  "

  incus stop "$builder"
  incus image delete "$alias" >/dev/null 2>&1 || true
  incus publish "$builder" --alias "$alias" description="$desc" >/dev/null
  incus delete "$builder"
}

build_image ssle-base  "$RUNTIME_PKGS" "SSLE runtime: Debian 13 + httplib/sqlite3 shared libs"
build_image ssle-build "$RUNTIME_PKGS $BUILD_PKGS" "SSLE build: Debian 13 + g++/cmake + dev headers"

incus image list ssle- -f table -c ldsu
