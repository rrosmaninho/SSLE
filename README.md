# SSLE Project 1 — Threat Detection, Monitoring and Prevention

A service-oriented telemetry architecture built to scale, with monitoring, a
SIEM, and detection-and-response for three threats (DDoS, C2/APT, DNS
hijacking). Security in Large-Scale Systems, University of Aveiro.

## What is here

| Path | Contents |
|---|---|
| `modules/<service>/` | One self-contained module per service: `src/` (C++20), `CMakeLists.txt`, `Dockerfile`, `ssle-<service>.service` (systemd unit), `<service>.env.example` |
| `modules/common/` | Shared library: `include/ssle/ssle.hpp` + `src/ssle.cpp` (identity, registry client, logging, Prometheus formatting) |
| `modules/monitoring/` | Prometheus config, alert rules, Alertmanager (root-cause inhibition) |
| `modules/siem/` | Wazuh custom decoders, rules, active-response scripts, agent config |
| `deploy/incus/` | Platform setup + containment (`ssle-guard.nft`, `lab-lockdown.sh`), build, deploy and verify scripts for the primary Incus deployment |
| `deploy/k8s/` | Kubernetes manifests + K3s cluster/build/deploy/verify scripts (Guide 2 §5) |
| `threats/ddos/` | DDoS experiment + capture harnesses + post-mortem |
| `threats/c2/` | C2/APT experiment (Metasploit) + post-mortem |
| `threats/dns-hijack/` | DNS hijack + protective resolver + post-mortem |
| `threats/attack-surface-probe.sh` | Measures the attack surface from an attacker container |
| `evidence/` | Recorded output from every verification and experiment |

The top-level `CMakeLists.txt` builds every module (`add_subdirectory(modules/<kind>)`).

## Architecture at a glance

```
 sensors ──POST /ingest──> ingestion ──/store──> storage (SQLite)
    │                          │                     │
    └── all register/discover through ──> REGISTRY <─┘── analytics
                                             │
  Prometheus + Alertmanager  ◄── /sd, /metrics (discovery-driven scraping)
  Wazuh SIEM (agents on every service container)
```

All services discover each other through the registry using hierarchical names
(`sensor-03.node2.rack1.dc-aveiro.pt-centro.pt`). Everything runs in unprivileged
Incus containers on an isolated network; containment is enforced by nftables in
the VM, a `lab-lockdown` egress switch, and the Proxmox firewall.

## Reproducing it

Every phase ships a verification or experiment script; results are saved under
`evidence/`.

```bash
# Platform + base architecture
bash deploy/incus/verify-platform.sh        # containment holds
bash deploy/incus/build-base-image.sh       # runtime + build images
bash deploy/incus/build-services.sh         # compile the C++ services
bash deploy/incus/deploy-services.sh        # deploy to containers
bash deploy/incus/verify-services.sh --full # 28 checks: discovery, data flow, self-healing

# Monitoring + SIEM
bash deploy/incus/deploy-monitoring.sh      # Prometheus + Alertmanager
bash deploy/incus/verify-monitoring.sh --full # + live fault-injection / inhibition
bash deploy/incus/deploy-siem.sh            # Wazuh rules + agents
bash deploy/incus/verify-siem.sh --full     # rules exercised through the live ruleset

# Risk management
bash threats/attack-surface-probe.sh        # measure the attack surface

# The three threats (each: baseline -> attack -> detect -> respond -> post-mortem)
bash threats/ddos/run-ddos.sh                   # DDoS
sudo lab-lockdown on; bash threats/c2/run-c2.sh # C2 (egress locked first)
bash threats/dns-hijack/run-dns.sh              # DNS hijack

# Scalability
bash deploy/incus/scalability-eval.sh 10 50 100

# K3s / Kubernetes packaging (Guide 2 — parallel to the Incus deployment)
bash deploy/k8s/setup-cluster.sh            # 2-node K3s cluster + docker build container
bash deploy/k8s/build-images.sh             # package the 5 services as images, load into k3s
bash deploy/k8s/deploy-k8s.sh               # kubectl apply deploy/k8s/ manifests
bash deploy/k8s/verify-k3s.sh               # data flow + `kubectl scale` sensor nodes
bash deploy/k8s/teardown-k3s.sh             # remove the cluster (Incus stack untouched)
```

The K3s track is a **parallel PaaS packaging** of the same five services
(Guide 2 §5), not a replacement for the Incus deployment, which stays the
primary. See `deploy/k8s/` for the manifests. It needs lab internet
egress (`lab-lockdown off`) only during `setup-cluster`/`build-images`; the
running cluster pulls nothing (images are imported offline into containerd).

## Accessing the dashboards

The lab network is isolated. Reach the monitoring and SIEM UIs with an SSH
tunnel rather than publishing ports:

```bash
ssh -L 9090:<prom-ip>:9090 -L 9093:<am-ip>:9093 -L 8443:<wazuh-ip>:443 rrosmaninho@<vm>
# then http://localhost:9090 , http://localhost:9093 , https://localhost:8443
```

## Honest limitations (by design)

The registry is a single in-memory instance, storage is single-writer SQLite,
and Wazuh is a single node; the registry and monitoring write endpoints are
unauthenticated. These gaps are left in place because each threat experiment is
meaningful only because the matching weakness exists, and they are the bridge to
Project 2 (attack-tolerance mechanisms). See the attack-defense trees and the
report's conclusions for the full list.

## Acknowledgement of use of AI tools

I acknowledge the use of AI tools to help write auxiliary scripts and to proofread the written report.
The architecture, experiments, design decisions and conclusions are my own, and every quantitative claim is traceable to its raw evidence under `evidence/`.
