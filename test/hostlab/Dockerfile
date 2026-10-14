# F3b-002: the Linux/systemd host lab (R2:29 d, ADR 0021 e.1). Ubuntu with systemd as PID 1 and the pinned
# Headscale v0.29.4 .deb (the package ships the unit and the headscale system user), so the host helper's
# .path/oneshot units can be tried on a real systemd. Lab only (ADR 0014): nothing here is hardened.
# No secret is built in: the OIDC client secret is copied in by hostlab.sh at runtime.
FROM ubuntu:24.04

ARG HEADSCALE_VERSION=0.29.4
ARG HEADSCALE_SHA256_AMD64=1f65364716ae1fcc3845b1a65a47583469022e9c6f194dfdfeb25403f89f0841
ARG HEADSCALE_SHA256_ARM64=021a4aeb2106d09c0e6fb5f936acffcbcdea213ef8882b19ea91b03783e1f816
ARG TARGETARCH

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates curl socat sqlite3 \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) sha="$HEADSCALE_SHA256_AMD64" ;; \
      arm64) sha="$HEADSCALE_SHA256_ARM64" ;; \
      *) echo "hostlab: unsupported architecture TARGETARCH=${arch}" >&2; exit 1 ;; \
    esac; \
    deb="headscale_${HEADSCALE_VERSION}_linux_${arch}.deb"; \
    curl -fsSL -o "/tmp/$deb" "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/$deb"; \
    echo "$sha  /tmp/$deb" | sha256sum -c -; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y "/tmp/$deb"; \
    rm -f "/tmp/$deb"

# Only what systemd needs in a container: no network/DNS daemons (the container shares the host network
# and keeps Docker's resolv.conf), and Headscale starts only once hostlab.sh has written its config.
RUN systemctl mask systemd-networkd.service systemd-resolved.service systemd-timesyncd.service \
 && systemctl disable headscale.service

# ADR 0021 b layout. requests/ and results/ are bind-mounted from the Mac by hostlab.sh; private/ stays here.
RUN install -d -m 0755 /var/lib/tagcess-headscale /var/lib/tagcess-headscale/requests /var/lib/tagcess-headscale/results \
 && install -d -m 0700 /var/lib/tagcess-headscale/private

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
