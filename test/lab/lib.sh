#!/usr/bin/env bash
# Shared by up.sh, down.sh and the Makefile's lab targets (F1-024, ADR 0014).
# kubectl and helm are only ever called through k() and h() below: they pin the namespace, so a script
# cannot write anywhere but tagcess-lab. Reads elsewhere (node name, the wildcard TLS Secret) are the only exceptions
# in this file.
#
# The developer's own lab (domain, node, kubeconfig, wildcard TLS Secret) is never committed. It comes from the
# environment or from an untracked file, ${TAGCESS_LAB_ENV:-$HOME/.config/tagcess/lab.env}, with KEY=VALUE lines:
#   TAGCESS_LAB_DOMAIN               lab DNS domain (default lab.example.com)
#   TAGCESS_LAB_ZITADEL_HOST         lab Zitadel host (default tagcess-zitadel.$TAGCESS_LAB_DOMAIN)
#   TAGCESS_LAB_NODE                 the lab cluster's only node name (default lab-k3s)
#   LAB_KUBECONFIG                   kubeconfig of the lab cluster (default ~/.kube/config-lab)
#   TAGCESS_LAB_WILDCARD_TLS_SECRET  wildcard TLS Secret in namespace default (default wildcard-lab-tls)
# The environment wins over the file. The Go side reads the same names (test/labenv).
LAB_ENV_FILE="${TAGCESS_LAB_ENV:-$HOME/.config/tagcess/lab.env}"
lab_env_value() { # lab_env_value NAME: the value of NAME's last NAME=VALUE line in the lab env file, quotes removed
  [ -f "$LAB_ENV_FILE" ] || return 0
  sed -n "s/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}$1=//p" "$LAB_ENV_FILE" | tail -n 1 | sed "s/^[\"']//; s/[\"']\$//"
}
for _v in TAGCESS_LAB_DOMAIN TAGCESS_LAB_ZITADEL_HOST TAGCESS_LAB_NODE LAB_KUBECONFIG TAGCESS_LAB_WILDCARD_TLS_SECRET; do
  if [ -z "${!_v:-}" ]; then
    _val="$(lab_env_value "$_v")"
    [ -z "$_val" ] || printf -v "$_v" '%s' "$_val"
  fi
done
unset _v _val
LAB_DOMAIN="${TAGCESS_LAB_DOMAIN:-lab.example.com}"
LAB_NS="tagcess-lab"
LAB_HOST="${TAGCESS_LAB_ZITADEL_HOST:-tagcess-zitadel.$LAB_DOMAIN}"
LAB_NODE="${TAGCESS_LAB_NODE:-lab-k3s}"
# zitadel-values.yaml names this placeholder host; lab_values writes a copy with LAB_HOST.
LAB_VALUES_HOST="tagcess-zitadel.lab.example.com"
# The seed tool and the Go tests resolve the same host (test/labenv).
export TAGCESS_LAB_DOMAIN="$LAB_DOMAIN" TAGCESS_LAB_ZITADEL_HOST="$LAB_HOST"
# The chart writes the machine user's PAT to Secret <username>-pat (username: values.yaml).
LAB_PAT_SECRET="tagcess-seed-pat"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
COMPOSE_DIR="$REPO_DIR/test/compose"

export KUBECONFIG="${LAB_KUBECONFIG:-$HOME/.kube/config-lab}"

# lab_values prints the path of zitadel-values.yaml with LAB_HOST in place of the placeholder host (a temp copy
# when they differ). The values file holds no secret.
lab_values() {
  local out
  if [ "$LAB_HOST" = "$LAB_VALUES_HOST" ]; then
    printf '%s\n' "$LAB_DIR/zitadel-values.yaml"
    return
  fi
  case $LAB_HOST in '' | *[!a-z0-9.-]*) die "TAGCESS_LAB_ZITADEL_HOST is not a host name: '$LAB_HOST'" ;; esac
  out="$(mktemp "${TMPDIR:-/tmp}/tagcess-lab-values.XXXXXX")"
  sed "s/tagcess-zitadel\.lab\.example\.com/$LAB_HOST/g" "$LAB_DIR/zitadel-values.yaml" >"$out"
  printf '%s\n' "$out"
}

k() { kubectl -n "$LAB_NS" "$@"; }
h() { helm --namespace "$LAB_NS" "$@"; }

# Where lab secrets live, relative to test/compose. The seed tool and the integration tests default to the
# same place and to $LAB_HOST:443 over TLS (test/compose/seed/endpoint.go), so no env is needed.
LAB_SECRETS_REL=".secrets/lab"

die() { echo "lab: $*" >&2; exit 1; }

# Refuse to run against any cluster but the lab node, whatever KUBECONFIG points at.
lab_guard() {
  local nodes
  nodes="$(kubectl get nodes -o name 2>&1)" || die "cannot reach the cluster with KUBECONFIG=$KUBECONFIG: $nodes"
  [ "$nodes" = "node/$LAB_NODE" ] || die "KUBECONFIG=$KUBECONFIG is not the lab cluster (nodes: $nodes)"
}

# ADR 0014: no Certificate is requested (Let's Encrypt limits). The existing wildcard TLS Secret for *.lab.example.com
# is read from namespace default and copied into tagcess-lab under the name the Ingress uses. The source is only
# read; the key material goes through pipes and process substitution, never a file, a log or an argument.
WILDCARD_TLS_NS="default"
WILDCARD_TLS_SECRET="${TAGCESS_LAB_WILDCARD_TLS_SECRET:-wildcard-lab-tls}"
LAB_TLS_SECRET="tagcess-zitadel-tls"

copy_wildcard_tls() {
  local crt key
  crt="$(kubectl -n default get secret "$WILDCARD_TLS_SECRET" -o go-template='{{index .data "tls.crt"}}')" \
    || die "cannot read Secret $WILDCARD_TLS_SECRET in namespace $WILDCARD_TLS_NS"
  key="$(kubectl -n default get secret "$WILDCARD_TLS_SECRET" -o go-template='{{index .data "tls.key"}}')" \
    || die "cannot read Secret $WILDCARD_TLS_SECRET in namespace $WILDCARD_TLS_NS"
  [ -n "$crt" ] && [ -n "$key" ] || die "Secret $WILDCARD_TLS_SECRET has no tls.crt/tls.key"
  k create secret tls "$LAB_TLS_SECRET" --cert=<(printf '%s' "$crt" | base64 -d) --key=<(printf '%s' "$key" | base64 -d) \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  unset crt key
}
