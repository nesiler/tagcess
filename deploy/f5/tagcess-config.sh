#!/usr/bin/env bash
# Run ON lab-vpn as root: write /etc/tagcess/config.yaml for the F5 lab and install the site seed.
# Only public identifiers go in: the Zitadel project id is read from the seed's env file on the host,
# the gate client id (oauth2-proxy app, public) is passed in. Secrets stay files under /etc/tagcess/secrets.
#   SEED_ENV         seed output with ZITADEL_PROJECT_ID (default /root/f5/seed/.env)
#   GATE_CLIENT_ID   oauth2-proxy app client id (optional; empty = cookie-only sign-out link)
#   DOMAIN           default lab.example.com; VPN_TS_IP default 100.64.0.1; K8S_TS_IP default 100.64.0.5
set -euo pipefail
SEED_ENV=${SEED_ENV:-/root/f5/seed/.env}
DOMAIN=${DOMAIN:-lab.example.com}
VPN_TS_IP=${VPN_TS_IP:-100.64.0.1}
K8S_TS_IP=${K8S_TS_IP:-100.64.0.5}
PID=$(grep -m1 '^ZITADEL_PROJECT_ID=' "$SEED_ENV" | cut -d= -f2- | tr -d "\"'")
[ -n "$PID" ] || { echo "ZITADEL_PROJECT_ID not found in $SEED_ENV" >&2; exit 1; }

cfg=/etc/tagcess/config.yaml
[ ! -f "$cfg" ] || cp "$cfg" "$cfg.bak.$(date +%Y%m%d%H%M%S)"
cat >"$cfg" <<CFG
data_dir: /var/lib/tagcess
k8s_auth_dir: /var/lib/tagcess-credentials
ui:
  socket: /run/tagcess/ui.sock
  socket_group: caddy
  socket_mode: "0660"
hook:
  listen: $VPN_TS_IP:9443
  signing_key_file: /etc/tagcess/secrets/webhook-signing-key
  groups_signing_key_file: /etc/tagcess/secrets/groups-signing-key
headscale:
  socket: /var/run/headscale/headscale.sock
hostapply:
  requests_dir: /var/lib/tagcess-headscale/requests
  results_dir: /var/lib/tagcess-headscale/results
zitadel:
  issuer: https://auth.$DOMAIN
  project_id: "$PID"
  key_file: /etc/tagcess/secrets/zitadel-key.json
  oauth2_proxy_app: oauth2-proxy
caddy:
  admin_url: http://127.0.0.1:2019
  caddyfile_path: /etc/caddy/Caddyfile
dns:
  records_path: /var/lib/tagcess/dns/extra-records.json
sync:
  interval: 5m
sites:
  allowed_domains: [$DOMAIN]
  allowed_targets: [$K8S_TS_IP]
  zitadel_internal_sources: [10.0.0.0/16, 127.0.0.1/32, "::1/128"]
  acme_email: admin@$DOMAIN
  certificates: [$DOMAIN]
  vpn_address: $VPN_TS_IP
  tagcess_host: tagcess.$DOMAIN
  seed_file: /var/lib/tagcess/seed-sites.json
CFG
if [ -n "${GATE_CLIENT_ID:-}" ]; then printf 'gate:\n  client_id: "%s"\n' "$GATE_CLIENT_ID" >>"$cfg"; fi
chmod 0644 "$cfg"
sed "s/lab\.example\.com/$DOMAIN/g" "$(dirname "$0")/seed-sites.json" >/var/lib/tagcess/seed-sites.json
chown 10001:10001 /var/lib/tagcess/seed-sites.json && chmod 0644 /var/lib/tagcess/seed-sites.json
echo "wrote $cfg; check it with deploy.sh (tagcess -check) before compose up"
