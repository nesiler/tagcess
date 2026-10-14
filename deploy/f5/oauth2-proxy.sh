#!/usr/bin/env bash
# Run ON lab-vpn as root: oauth2-proxy (v7.15.4) container for the tagcess gate, following
# deploy/oauth2-proxy.example.cfg (one shared 1 h cookie, sign-out via the Zitadel host). The client id,
# client secret and cookie secret are copied from the seed's env file on the host into a 0600 env file;
# they never appear in this script or the repo.
#   SEED_ENV default /root/f5/seed/.env, DOMAIN default lab.example.com
set -euo pipefail
SEED_ENV=${SEED_ENV:-/root/f5/seed/.env}
DOMAIN=${DOMAIN:-lab.example.com}
install -d -m 0750 /etc/oauth2-proxy
cat >/etc/oauth2-proxy/oauth2-proxy.cfg <<CFG
provider = "oidc"
oidc_issuer_url = "https://auth.$DOMAIN"
oidc_groups_claim = "groups"
scope = "openid profile email"
http_address = "127.0.0.1:4180"
upstreams = ["static://202"]
reverse_proxy = true
set_xauthrequest = true
skip_provider_button = true
email_domains = ["*"]
cookie_name = "_tagcess_gate"
cookie_domains = [".$DOMAIN"]
cookie_secure = true
cookie_samesite = "lax"
cookie_expire = "1h"
cookie_refresh = "0"
whitelist_domains = [".$DOMAIN"]
CFG
(umask 077 && grep -E '^OAUTH2_PROXY_(CLIENT_ID|CLIENT_SECRET|COOKIE_SECRET)=' "$SEED_ENV" >/etc/oauth2-proxy/env)
docker rm -f oauth2-proxy >/dev/null 2>&1 || true
docker run -d --name oauth2-proxy --restart unless-stopped --network host --read-only \
	--env-file /etc/oauth2-proxy/env -v /etc/oauth2-proxy/oauth2-proxy.cfg:/etc/oauth2-proxy.cfg:ro \
	quay.io/oauth2-proxy/oauth2-proxy:v7.15.4 --config=/etc/oauth2-proxy.cfg >/dev/null
sleep 6
curl -fsS http://127.0.0.1:4180/ping && echo
