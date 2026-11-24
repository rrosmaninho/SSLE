#!/usr/bin/env bash
# Phase 1 platform setup for the SSLE VM. Run once as root:
#   sudo bash deploy/incus/setup-platform.sh
# Safe to re-run (each step checks current state first).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB_USER="${SUDO_USER:-rrosmaninho}"
LAB_NIC="ens19"          # vmbr1 - project network
MGMT_NIC="ens18"         # vmbr0 - management / home LAN

step() { echo -e "\n==> $*"; }

# ---------------------------------------------------------------------------
step "Disable services that advertise the VM on the home LAN (avahi, cups)"
for s in avahi-daemon.socket avahi-daemon.service cups.socket cups.path cups.service cups-browsed.service; do
  systemctl disable --now "$s" 2>/dev/null || true
done

# ---------------------------------------------------------------------------
step "Release $LAB_NIC from NetworkManager (it becomes a port of the Incus bridge)"
cat > /etc/NetworkManager/conf.d/99-ssle-unmanaged.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${LAB_NIC}
EOF
# ens18 is run by dhcpcd (ifupdown), not NM. Stop NM from rewriting
# /etc/resolv.conf with an empty file whenever it reloads.
cat > /etc/NetworkManager/conf.d/99-ssle-dns.conf <<'EOF'
[main]
dns=none
rc-manager=unmanaged
EOF
nmcli -t -f NAME,DEVICE con show | awk -F: -v d="$LAB_NIC" '$2==d{print $1}' |
  while read -r c; do nmcli con delete "$c" || true; done
systemctl reload NetworkManager
ip addr flush dev "$LAB_NIC"
ip link set "$LAB_NIC" up

# Restore resolv.conf from dhcpcd's lease if something already blanked it.
if ! grep -q '^nameserver' /etc/resolv.conf; then
  dhcpcd -n "$MGMT_NIC" >/dev/null 2>&1 || true
  sleep 3
fi
if ! grep -q '^nameserver' /etc/resolv.conf; then
  echo "WARN: dhcpcd did not restore DNS; writing fallback resolv.conf"
  printf 'domain localdomain\nnameserver 10.20.4.2\n' > /etc/resolv.conf
fi
getent hosts deb.debian.org >/dev/null || { echo "DNS still broken, aborting" >&2; exit 1; }

# ---------------------------------------------------------------------------
step "Kernel tuning (nested K3s, Wazuh indexer, many containers)"
cat > /etc/sysctl.d/99-incus-k3s.conf <<'EOF'
# Nested K3s
vm.overcommit_memory = 1
kernel.panic = 10
kernel.panic_on_oops = 1
# Wazuh indexer (OpenSearch) - containers share the VM kernel
vm.max_map_count = 262144
# Many containers
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 1048576
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
step "Install containment firewall (ssle-guard) BEFORE Incus starts routing"
apt-get install -y nftables >/dev/null
install -D -m 0644 "$HERE/ssle-guard.nft" /etc/nftables.d/ssle-guard.nft
install -m 0755 "$HERE/lab-lockdown.sh" /usr/local/sbin/lab-lockdown

cat > /etc/systemd/system/ssle-guard.service <<'EOF'
[Unit]
Description=SSLE lab containment firewall
DefaultDependencies=no
Before=network-pre.target incus.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/ssle-guard.nft
ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssle-guard.nft

[Install]
WantedBy=multi-user.target
EOF

# Fail closed: Incus refuses to start if the guard did not load.
mkdir -p /etc/systemd/system/incus.service.d
cat > /etc/systemd/system/incus.service.d/10-ssle-guard.conf <<'EOF'
[Unit]
Requires=ssle-guard.service
After=ssle-guard.service
EOF

# Debian's stock nftables.service runs "flush ruleset", which would wipe
# Incus's tables. Keep it off; ssle-guard.service replaces it.
systemctl disable --now nftables.service 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now ssle-guard.service

# ---------------------------------------------------------------------------
step "Install Incus"
apt-get install -y incus >/dev/null
usermod -aG incus-admin "$LAB_USER"
systemctl enable --now incus.socket incus.service

if ! incus storage show default >/dev/null 2>&1; then
  incus admin init --minimal
fi

# ---------------------------------------------------------------------------
step "Replace incusbr0 with incus-default (10.255.255.1/24, NAT, IPv4-only, bridged to $LAB_NIC)"
if incus network show incusbr0 >/dev/null 2>&1; then
  incus profile device remove default eth0 2>/dev/null || true
  incus network delete incusbr0
fi
if ! incus network show incus-default >/dev/null 2>&1; then
  incus network create incus-default \
    ipv4.address=10.255.255.1/24 \
    ipv4.nat=true \
    ipv6.address=none \
    bridge.external_interfaces="$LAB_NIC"
fi
if ! incus profile device show default | grep -q '^eth0:'; then
  incus profile device add default eth0 nic network=incus-default name=eth0
fi

# ---------------------------------------------------------------------------
step "Create privileged 'k3s' profile (use ONLY for K3s nodes, never for attack targets)"
incus profile show k3s >/dev/null 2>&1 || incus profile create k3s
incus profile edit k3s <<'EOF'
description: Privileged profile for nested K3s nodes
config:
  security.privileged: "true"
  security.nesting: "true"
  linux.kernel_modules: ip_tables,ip6_tables,nf_nat,overlay,br_netfilter
  raw.lxc: |
    lxc.apparmor.profile=unconfined
    lxc.cgroup2.devices.allow=a
    lxc.mount.auto=proc:rw sys:rw cgroup:rw
    lxc.cap.drop=
devices:
  kmsg:
    path: /dev/kmsg
    source: /dev/kmsg
    type: unix-char
  eth0:
    name: eth0
    network: incus-default
    type: nic
  root:
    path: /
    pool: default
    type: disk
EOF

# ---------------------------------------------------------------------------
step "Done"
echo "Log out and back in (incus-admin group), then run:"
echo "  bash deploy/incus/verify-platform.sh"
