#!/usr/bin/env bash
# Run ON lab-vpn as root: a wildcard certificate for DOMAIN via Cloudflare DNS-01 (the zitadel system
# template needs /etc/letsencrypt/live/<cert>/, install-map blocker B1). The Cloudflare token is read
# from the CF_API_TOKEN line of CF_ENV on the host, never passed on the command line or stored in the repo.
#   DOMAIN default lab.example.com, EMAIL default admin@$DOMAIN, CF_ENV default /etc/caddy-secrets/cf.env
set -euo pipefail
DOMAIN=${DOMAIN:-lab.example.com}
EMAIL=${EMAIL:-admin@$DOMAIN}
CF_ENV=${CF_ENV:-/etc/caddy-secrets/cf.env}
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq certbot python3-certbot-dns-cloudflare >/dev/null
install -d -m 0700 /root/.secrets
(umask 077 && { printf 'dns_cloudflare_api_token = '; grep -m1 '^CF_API_TOKEN=' "$CF_ENV" | cut -d= -f2-; } >/root/.secrets/cloudflare.ini)
certbot certonly -n --agree-tos -m "$EMAIL" --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
	--dns-cloudflare-propagation-seconds 30 --cert-name "$DOMAIN" -d "$DOMAIN" -d "*.$DOMAIN"
chgrp caddy /etc/letsencrypt/live /etc/letsencrypt/archive && chmod 0750 /etc/letsencrypt/live /etc/letsencrypt/archive
install -d /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/caddy.sh <<HOOK
#!/bin/sh
chgrp -R caddy /etc/letsencrypt/archive/$DOMAIN && chmod 0640 /etc/letsencrypt/archive/$DOMAIN/privkey*.pem
systemctl reload caddy
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/caddy.sh
/etc/letsencrypt/renewal-hooks/deploy/caddy.sh
ls -l "/etc/letsencrypt/live/$DOMAIN/"
