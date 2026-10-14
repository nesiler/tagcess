#!/usr/bin/env bash
# make lab-up: Zitadel on the developer's k3s lab (namespace tagcess-lab) -> health -> PAT -> seed -> local Headscale.
# Idempotent: rerunning upgrades in place. Secrets are generated on the first run, kept in cluster Secrets
# and never written to the repo. Nothing outside tagcess-lab is written (lib.sh).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for tool in kubectl helm openssl curl docker go tailscale; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
lab_guard

echo "lab: namespace, quota, database"
k apply -f "$LAB_DIR/namespace.yaml"
k apply -f "$LAB_DIR/quota.yaml"

# Generated once; an existing Secret is never replaced (it belongs to the database that already exists).
new_secret() { # name, then KEY=VALUE lines on stdin
  if k get secret "$1" >/dev/null 2>&1; then cat >/dev/null; return; fi
  k create secret generic "$1" --from-env-file=/dev/stdin >/dev/null
  echo "lab: created Secret $1"
}
# One password feeds two Secrets (Postgres' own, and the env Secret the chart reads). Each is checked on its
# own, so an interrupted first run is repaired: a missing one is rebuilt from the one that exists.
dbpw=""
if k get secret zitadel-db >/dev/null 2>&1; then
  dbpw="$(k get secret zitadel-db -o go-template='{{index .data "password"}}' | base64 -d)"
else
  dbpw="$(openssl rand -hex 16)"
  printf 'password=%s\n' "$dbpw" | new_secret zitadel-db
fi
printf 'ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=%s\nZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=%s\n' "$dbpw" "$dbpw" | new_secret zitadel-db-env
unset dbpw
# The masterkey must be exactly 32 characters: 16 random bytes as hex.
if ! k get secret zitadel-masterkey >/dev/null 2>&1; then
  printf 'masterkey=%s\n' "$(openssl rand -hex 16)" | new_secret zitadel-masterkey
fi

k apply -f "$LAB_DIR/postgres.yaml"
copy_wildcard_tls
k rollout status statefulset/zitadel-db --timeout=180s

echo "lab: zitadel (chart 10.0.6, image v4.16.0)"
h repo add zitadel https://charts.zitadel.com >/dev/null 2>&1 || true
h repo update zitadel >/dev/null
values="$(lab_values)"
h upgrade --install zitadel zitadel/zitadel --version 10.0.6 -f "$values" --wait --timeout 15m
[ "$values" = "$LAB_DIR/zitadel-values.yaml" ] || rm -f "$values"

echo "lab: waiting for https://$LAB_HOST"
ok=""
for _ in $(seq 1 90); do
  code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "https://$LAB_HOST/debug/healthz" || true)"
  [ "$code" = 200 ] && { ok=1; break; }
  sleep 5
done
[ -n "$ok" ] || die "https://$LAB_HOST did not become healthy (last status: ${code:-none})"

echo "lab: bootstrap PAT"
patdir="$COMPOSE_DIR/$LAB_SECRETS_REL"
umask 077
mkdir -p "$patdir"
k get secret "$LAB_PAT_SECRET" -o go-template='{{range $k, $v := .data}}{{$v}}{{end}}' | base64 -d >"$patdir/bootstrap-pat" \
  || die "Secret $LAB_PAT_SECRET is missing: the first install was interrupted and the PAT is lost. Run 'make lab-down' and 'make lab-up' again"
[ -s "$patdir/bootstrap-pat" ] || die "Secret $LAB_PAT_SECRET is empty. Run 'make lab-down' and 'make lab-up' again"

# F1-021: the login v2 client's signing key (the chart's SystemAPIUsers "login-client"). The e2e
# test signs the same JWT the login UI uses to call the session/OIDC APIs, so it can complete a real
# login without a browser. Lives only in the gitignored secrets dir, like the PAT.
k get secret zitadel-login-service-key -o go-template='{{index .data "tls.key"}}' | base64 -d >"$patdir/login-client-key.pem" \
  || die "Secret zitadel-login-service-key is missing; the login v2 client key is required by the e2e tests"
[ -s "$patdir/login-client-key.pem" ] || die "Secret zitadel-login-service-key has no tls.key"

# F1-020: the Actions v2 target points at the developer's machine over Tailscale (the same path
# production uses, ADR 0003; the lab Zitadel's HTTPClient.DenyList is overridden for it in
# test/lab/zitadel-values.yaml). The webhook receiver is the integration test (or tagcess) on :9443.
webhook_ip="$(tailscale ip -4)"
webhook_ip="${webhook_ip%%$'\n'*}"
[ -n "$webhook_ip" ] || die "tailscale ip -4 returned no address; the webhook target needs a tailnet address"
export TAGCESS_WEBHOOK_URL="http://$webhook_ip:9443/hook"
# F1-026: the groups claim rest_call target also calls the developer's machine (same receiver,
# different path). The integration tests derive it from the webhook endpoint.
export TAGCESS_GROUPS_URL="http://$webhook_ip:9443/groups"

echo "lab: seed"
(cd "$REPO_DIR" && go run ./test/compose/seed/cmd -phase=zitadel -compose-dir=test/compose)

echo "lab: local compose (Headscale, Caddy, oauth2-proxy; OIDC issuer https://$LAB_HOST)"
# F2-006 (ADR 0013): Headscale's dns.extra_records_path file must exist before headscale
# starts or the container refuses to start (NewExtraRecordsManager). Seeded once, then
# owned by the F2-006 integration tests and tagcess itself.
mkdir -p "$COMPOSE_DIR/dns"
[ -f "$COMPOSE_DIR/dns/extra-records.json" ] || printf '[]\n' >"$COMPOSE_DIR/dns/extra-records.json"
export HEADSCALE_OIDC_ISSUER="https://$LAB_HOST"
docker compose -f "$COMPOSE_DIR/compose.yaml" up -d --wait
# Headscale's fsnotify watcher on extra-records.json can stay attached to an old inode after the host
# rewrote the file atomically (macOS bind mount). A restart on every lab-up re-attaches it; --wait on
# `up` ran before, so health is awaited again here, before the headscale seed phase.
docker compose -f "$COMPOSE_DIR/compose.yaml" restart headscale
docker compose -f "$COMPOSE_DIR/compose.yaml" up -d --wait headscale
(cd "$REPO_DIR" && go run ./test/compose/seed/cmd -phase=headscale -compose-dir=test/compose)
echo "lab: up (webhook target $TAGCESS_WEBHOOK_URL). Run the tests with 'make lab-integration'."
