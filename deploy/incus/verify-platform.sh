#!/usr/bin/env bash
# Sanity check for the platform + containment. Run as a user in incus-admin
# (no sudo needed). Launches a throwaway container and probes from inside it.
set -uo pipefail

CT="nettest-$$"
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

# Probe a TCP port from inside the container. Returns 0 if it connects.
probe() { incus exec "$CT" -- timeout 4 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null; }

expect_open()    { if probe "$1" "$2"; then ok "$3"; else bad "$3"; fi; }
expect_blocked() { if probe "$1" "$2"; then bad "$3"; else ok "$3"; fi; }

echo "==> Host checks"
systemctl is-active --quiet ssle-guard && ok "ssle-guard firewall loaded" || bad "ssle-guard firewall loaded"
incus network get incus-default bridge.external_interfaces | grep -q ens19 \
  && ok "ens19 (vmbr1) attached to incus-default" || bad "ens19 (vmbr1) attached to incus-default"
[[ "$(incus network get incus-default ipv6.address)" == "none" ]] \
  && ok "lab is IPv4-only" || bad "lab is IPv4-only"
[[ "$(cat /proc/sys/vm/max_map_count)" -ge 262144 ]] && ok "vm.max_map_count" || bad "vm.max_map_count"

echo "==> Launching $CT"
incus launch images:debian/13 "$CT" >/dev/null || { echo "launch failed"; exit 1; }
trap 'incus delete -f "$CT" >/dev/null 2>&1' EXIT

ip=""
for _ in $(seq 1 30); do
  ip=$(incus list "$CT" -c4 -f csv | grep -oE '10\.255\.255\.[0-9]+' || true)
  [[ -n "$ip" ]] && break; sleep 1
done
[[ -n "$ip" ]] && ok "container got lab IP $ip" || bad "container got lab IP"

echo "==> From inside the lab"
incus exec "$CT" -- getent hosts deb.debian.org >/dev/null && ok "DNS resolves" || bad "DNS resolves"
expect_open    deb.debian.org 80 "internet reachable (deb.debian.org:80)"
expect_blocked 10.20.4.1   443 "home gateway 10.20.4.1 blocked"
expect_blocked 10.20.4.2   53  "home DNS 10.20.4.2 blocked"
expect_blocked 10.20.4.252 22  "other LAN host 10.20.4.252 blocked"
expect_blocked 192.168.1.1 80  "other private ranges blocked"
expect_blocked 10.255.255.1 22 "VM's own SSH blocked from the lab"

echo
echo "Result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
