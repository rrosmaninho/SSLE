# SSLE registry service image (Guide 2 §5 — package the services as Docker images for K3s).
#
# Wraps the pre-compiled ssle-registry binary on a runtime-only base: there is NO
# compiler in the image, matching the Incus ssle-base runtime (a compromised
# container has no toolchain). Build context is the repository build/ output:
#
#   docker build -f modules/registry/Dockerfile -t ssle/registry:v1 \
#     --build-arg BIN=build/bin/ssle-registry .
#
# The binary is compiled on Debian 13 (deploy/incus/build-services.sh) against
# the same shared libraries installed here, so debian:trixie-slim is an exact
# runtime match. Built INSIDE the Incus 'docker' container, never on the VM root
# (Guide 2 warning: Incus + Docker on the same host OS break each other).
FROM debian:trixie-slim

ARG BIN=build/bin/ssle-registry

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libcpp-httplib0.18 libsqlite3-0 libssl3 ca-certificates curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user owning only its own data/log dirs (least privilege,
# mirrors the systemd User=ssle hardening of the Incus deployment).
RUN useradd --system --home /var/lib/ssle --shell /usr/sbin/nologin ssle \
 && mkdir -p /opt/ssle /var/lib/ssle /var/log/ssle \
 && chown -R ssle:ssle /var/lib/ssle /var/log/ssle

COPY ${BIN} /opt/ssle/ssle-registry
RUN chmod 0755 /opt/ssle/ssle-registry

USER ssle
WORKDIR /var/lib/ssle
ENTRYPOINT ["/opt/ssle/ssle-registry"]
