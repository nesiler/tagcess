#!/usr/bin/env bash
# Run ON lab-vpn as root, once, before the first `compose up`.
# Creates tagcess's directories with the owners/modes compose expects, installs the secret FILES from
# SECRETS_DIR (never their content here), seeds the MagicDNS records file and moves the Cloudflare
# token out of /etc/caddy (tagcess may write that directory).
#   SECRETS_DIR      host directory holding webhook-signing-key, groups-signing-key, zitadel-key.json
#                    (default /root/f5/secrets; created by the Zitadel seed, never in the repo)
#   AUTH_PRIVATE_IP  the manual MagicDNS record for the Zitadel host until the first import (optional)
#   AUTH_HOST        default auth.lab.example.com
set -euo pipefail
SECRETS_DIR=${SECRETS_DIR:-/root/f5/secrets}
AUTH_HOST=${AUTH_HOST:-auth.lab.example.com}

install -d -o 10001 -g 10001 -m 0711 /var/lib/tagcess
install -d -o 10001 -g headscale -m 2750 /var/lib/tagcess/dns
install -d -o 10001 -g 10001 -m 0700 /var/lib/tagcess-credentials
install -d -o 10001 -g caddy -m 0750 /run/tagcess
echo 'd /run/tagcess 0750 10001 caddy -' >/etc/tmpfiles.d/tagcess.conf
install -d -o root -g 10001 -m 0750 /etc/tagcess /etc/tagcess/secrets
for f in webhook-signing-key groups-signing-key zitadel-key.json; do
	# Copy, never echo: the signing keys are read raw and a trailing newline breaks HMAC.
	install -m 0640 -o root -g 10001 "$SECRETS_DIR/$f" "/etc/tagcess/secrets/$f"
done

rec=/var/lib/tagcess/dns/extra-records.json
if [ ! -f "$rec" ]; then
	if [ -n "${AUTH_PRIVATE_IP:-}" ]; then
		printf '[\n  {\n    "name": "%s",\n    "type": "A",\n    "value": "%s"\n  }\n]\n' "$AUTH_HOST" "$AUTH_PRIVATE_IP" >"$rec"
	else
		printf '[]\n' >"$rec"
	fi
fi
chown 10001:headscale "$rec" && chmod 0640 "$rec"
sudo -u headscale cat "$rec" >/dev/null
echo "Headscale config: set dns.extra_records_path: $rec (remove inline extra_records), then: headscale configtest"

# Headscale socket directory survives restarts (F5 K1).
install -D -m 0644 "$(dirname "$0")/../headscale-preserve.conf" /etc/systemd/system/headscale.service.d/preserve.conf

# The Cloudflare token must not sit in a directory tagcess can write.
install -d -m 0700 /etc/caddy-secrets
if [ -f /etc/caddy/cf.env ]; then mv /etc/caddy/cf.env /etc/caddy-secrets/cf.env; fi
if [ -f /etc/caddy-secrets/cf.env ]; then
	chmod 0600 /etc/caddy-secrets/cf.env
	install -d /etc/systemd/system/caddy.service.d
	printf '[Service]\nEnvironmentFile=/etc/caddy-secrets/cf.env\n' >/etc/systemd/system/caddy.service.d/cf.conf
fi
chown 10001:caddy /etc/caddy && chmod 0755 /etc/caddy
systemctl daemon-reload
