# F6-001: the two local Linux/systemd targets of the installer tests (model: test/hostlab). Ubuntu 24.04 with
# systemd as PID 1 and sshd, so Ansible connects the way it does to a real host.
#   bare  : nothing installed beyond systemd, sshd and Python 3 (the fresh-mode roles are tried here).
#   adopt : the existing installation's vpn-host shape (example.test names): Headscale 0.29.4 in
#           policy file mode, Caddy 2.8.4 with snippets + sites/*.caddy (20 sites), certbot with three
#           self-signed "wildcard" certificates, oauth2-proxy 7.15.4 under systemd (stopped), Docker, the
#           Tailscale package, and Headplane/WireGuard placeholders the installer must never touch.
# Test-only (ADR 0014 rules: nothing hardened). The placeholder secrets are random values generated at build
# time inside the image; none is in the repo.
FROM ubuntu:24.04 AS base

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server python3 python3-apt ca-certificates curl iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Only what systemd needs in a container; ssh is the Ansible connection (key installed by adopttarget.sh).
RUN systemctl mask systemd-networkd.service systemd-resolved.service systemd-timesyncd.service \
      getty@tty1.service console-getty.service \
 && systemctl enable ssh.service \
 && install -d -m 0700 /root/.ssh \
 && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\n' >/etc/ssh/sshd_config.d/10-adopttarget.conf \
 && sed -i 's/^AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

FROM base AS bare
LABEL tagcess.adopttarget.shape=bare

FROM base AS adopt
LABEL tagcess.adopttarget.shape=adopt

ARG TARGETARCH
ARG HEADSCALE_VERSION=0.29.4
ARG HEADSCALE_SHA256_AMD64=1f65364716ae1fcc3845b1a65a47583469022e9c6f194dfdfeb25403f89f0841
ARG HEADSCALE_SHA256_ARM64=021a4aeb2106d09c0e6fb5f936acffcbcdea213ef8882b19ea91b03783e1f816
ARG CADDY_VERSION=2.8.4
ARG CADDY_SHA256_AMD64=8ea1c5dd7736307e4b4baab2a3ffe51f28f4e344536cbc32f3e4bf12e65d79cd
ARG CADDY_SHA256_ARM64=8ada2c4ef24feeb1eb899fd31a50e73e13813bc993d1149f4ab4bc07ceda5a90
ARG OAUTH2_PROXY_VERSION=7.15.4
ARG OAUTH2_PROXY_SHA256_AMD64=4fbe902189aab713d9c0519b90a645032d4636ecb523dc36f5cc312d8ebef1e2
ARG OAUTH2_PROXY_SHA256_ARM64=b3fb0b61aecfb4b776dccb6daff406676ed0ead74245dc6e4bdf71f993eb1710

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sqlite3 socat openssl gnupg certbot docker.io docker-compose-v2 \
 && curl -fsSL -o /usr/share/keyrings/tailscale-archive-keyring.gpg https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg \
 && echo 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu noble main' \
      >/etc/apt/sources.list.d/tailscale.list \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tailscale \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) hs="$HEADSCALE_SHA256_AMD64"; cd="$CADDY_SHA256_AMD64"; op="$OAUTH2_PROXY_SHA256_AMD64" ;; \
      arm64) hs="$HEADSCALE_SHA256_ARM64"; cd="$CADDY_SHA256_ARM64"; op="$OAUTH2_PROXY_SHA256_ARM64" ;; \
      *) echo "adopttarget: unsupported architecture $arch" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSLO "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${arch}.deb"; \
    echo "$hs  headscale_${HEADSCALE_VERSION}_linux_${arch}.deb" | sha256sum -c -; \
    curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${arch}.deb"; \
    echo "$cd  caddy_${CADDY_VERSION}_linux_${arch}.deb" | sha256sum -c -; \
    curl -fsSLO "https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v${OAUTH2_PROXY_VERSION}/oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-${arch}.tar.gz"; \
    echo "$op  oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-${arch}.tar.gz" | sha256sum -c -; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y "./headscale_${HEADSCALE_VERSION}_linux_${arch}.deb" "./caddy_${CADDY_VERSION}_linux_${arch}.deb"; \
    tar xzf "oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-${arch}.tar.gz"; \
    install -m 0755 "oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-${arch}/oauth2-proxy" /usr/local/bin/oauth2-proxy; \
    rm -rf /tmp/*

COPY fixtures/adopt/ /

# Users, placeholder secrets and the three self-signed certificate groups. Every value is random and lives
# only in this test image.
RUN set -eu; \
    useradd --system --no-create-home --shell /usr/sbin/nologin oauth2-proxy; \
    umask 077; \
    openssl rand -hex 24 >/etc/headscale/oidc_client_secret; \
    chown root:headscale /etc/headscale/oidc_client_secret; chmod 0640 /etc/headscale/oidc_client_secret; \
    openssl rand -hex 24 >/etc/oauth2-proxy/client_secret; \
    openssl rand -base64 32 | tr -d '\n' | head -c 32 >/etc/oauth2-proxy/cookie_secret; \
    chown root:oauth2-proxy /etc/oauth2-proxy/client_secret /etc/oauth2-proxy/cookie_secret; \
    chmod 0640 /etc/oauth2-proxy/client_secret /etc/oauth2-proxy/cookie_secret; \
    chmod 0750 /etc/oauth2-proxy; chgrp oauth2-proxy /etc/oauth2-proxy; \
    install -d -m 0755 /etc/letsencrypt/renewal; \
    for n in internal.a.example.test b.example.test c.example.test; do \
      install -d -m 0750 -g caddy "/etc/letsencrypt/archive/$n" "/etc/letsencrypt/live/$n"; \
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=$n" \
        -addext "subjectAltName=DNS:$n,DNS:*.$n" \
        -keyout "/etc/letsencrypt/archive/$n/privkey1.pem" -out "/etc/letsencrypt/archive/$n/fullchain1.pem" 2>/dev/null; \
      chgrp caddy "/etc/letsencrypt/archive/$n/privkey1.pem"; chmod 0640 "/etc/letsencrypt/archive/$n/privkey1.pem"; \
      chmod 0644 "/etc/letsencrypt/archive/$n/fullchain1.pem"; \
      ln -s "../../archive/$n/fullchain1.pem" "/etc/letsencrypt/live/$n/fullchain.pem"; \
      ln -s "../../archive/$n/privkey1.pem" "/etc/letsencrypt/live/$n/privkey.pem"; \
      printf 'version = 2.9.0\narchive_dir = /etc/letsencrypt/archive/%s\ncert = /etc/letsencrypt/live/%s/fullchain.pem\nprivkey = /etc/letsencrypt/live/%s/privkey.pem\nfullchain = /etc/letsencrypt/live/%s/fullchain.pem\n\n[renewalparams]\nauthenticator = dns-cloudflare\n' "$n" "$n" "$n" "$n" >"/etc/letsencrypt/renewal/$n.conf"; \
    done; \
    chgrp caddy /etc/letsencrypt/live /etc/letsencrypt/archive; chmod 0750 /etc/letsencrypt/live /etc/letsencrypt/archive; \
    chmod 0644 /etc/caddy/Caddyfile /etc/caddy/sites/*.caddy /etc/headscale/config.yaml /etc/headscale/policy.hujson; \
    chown root:headscale /etc/headscale/extra-records.json; chmod 0640 /etc/headscale/extra-records.json; \
    install -d -m 0755 /var/lib/headplane

# Start state: Headscale, Caddy, Docker and tailscaled run; oauth2-proxy is installed but stopped and
# disabled (adopt, 2026-09-30); the WireGuard UI placeholder is "present".
RUN systemctl enable headscale.service caddy.service docker.service tailscaled.service wireguard-ui.service zitadel-discovery-stub.service \
 && systemctl disable oauth2-proxy.service 2>/dev/null || true
