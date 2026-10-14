#!/usr/bin/env bash
# Test stand-in for cmd/tagcess-zitadel-adopt (F6-006 role tests): records its arguments, answers like the real
# tool. FAKE_ZITADEL_LOG: where the arguments go; FAKE_ZITADEL_FAIL=1: fail like an unreachable Zitadel.
# FAKE_WEBHOOK_KEY / FAKE_GROUPS_KEY: a newly created Actions target's signing key (written once to <out>/webhook-signing-key,
# <out>/groups-signing-key and reported). FAKE_SECRETS_EMPTY=1: report no secret paths (a rerun that "forgets" them).
# FAKE_MISSING_JSON: the JSON list for missing_secrets.
set -eu
printf '%s\n' "$*" >>"${FAKE_ZITADEL_LOG:?}"
if [ "${FAKE_ZITADEL_FAIL:-}" = 1 ]; then
  echo "tagcess-zitadel-adopt: zitadel unreachable or the admin credential was refused; nothing was written" >&2
  exit 1
fi
dry=false; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=true ;;
    --secret-out-dir) out="$2"; shift ;;
  esac
  shift
done
secrets='{}'
if [ "$dry" = false ] && [ "${FAKE_SECRETS_EMPTY:-}" != 1 ]; then
  mkdir -p "$out" && chmod 0700 "$out"
  printf 'FAKE-CLIENT-SECRET-MARKER-9d1' >"$out/headscale_oidc_client_secret" && chmod 0600 "$out/headscale_oidc_client_secret"
  secrets="\"headscale_oidc_client_secret\": \"$out/headscale_oidc_client_secret\""
  if [ -n "${FAKE_WEBHOOK_KEY:-}" ]; then
    [ -s "$out/webhook-signing-key" ] || { printf '%s' "$FAKE_WEBHOOK_KEY" >"$out/webhook-signing-key" && chmod 0600 "$out/webhook-signing-key"; }
    secrets="$secrets, \"webhook_signing_key\": \"$out/webhook-signing-key\""
  fi
  if [ -n "${FAKE_GROUPS_KEY:-}" ]; then
    [ -s "$out/groups-signing-key" ] || { printf '%s' "$FAKE_GROUPS_KEY" >"$out/groups-signing-key" && chmod 0600 "$out/groups-signing-key"; }
    secrets="$secrets, \"groups_signing_key\": \"$out/groups-signing-key\""
  fi
  secrets="{$secrets}"
fi
cat <<JSON
{"dry_run": $dry, "changed": $([ "$dry" = true ] && echo false || echo true), "org_id": "org-1", "project_id": "${FAKE_PROJECT_ID:-p-777}",
 "apps": {"headscale": {"app_id": "a-1", "client_id": "hs-client-1"}, "oauth2-proxy": {"app_id": "a-2", "client_id": "${FAKE_OP_CLIENT:-op-client-2}"}},
 "plan": [{"object": "project vpn", "action": "exists", "detail": "p-777"}, {"object": "app headscale", "action": "create", "detail": ""}],
 "report": {"service_user": {"exists": false}, "unroled_users": 2},
 "guide": [{"id": "zitadel-service-user", "title": "tagcess servis kullanıcısını konsoldan tamamla (ADR 0009)", "steps": ["Konsolda servis kullanıcısını aç."], "blocking": true},
           {"id": "zitadel-groups-v1-to-v2", "title": "groups claim'ini Actions v1'den v2'ye elle geçir (karar 2)", "steps": ["Elle geçir."], "blocking": false}],
 "secrets": $secrets, "missing_secrets": ${FAKE_MISSING_JSON:-[]}}
JSON
