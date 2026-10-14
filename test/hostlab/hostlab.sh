#!/usr/bin/env bash
# F3b-002: the Linux/systemd host lab on OrbStack. `hostlab.sh up` builds the image, starts one privileged
# systemd container (host network) with the pinned Headscale v0.29.4, installs the config and the lab OIDC
# secret, relays Headscale's gRPC unix socket to a free loopback port and verifies itself (AC1, AC2);
# `down` removes the container and the temporary directory (AC3). Lab only (ADR 0014): nothing is hardened,
# production is never touched, and the lab Zitadel (the developer's k3s) is only an OIDC issuer here: this script
# has no cluster access at all.
#
# Layout (ADR 0021 b), inside the container: /var/lib/tagcess-headscale/{requests,results,private}.
# requests/ and results/ are bind-mounted from $STATE on the Mac; private/ and /etc/headscale stay inside.
#
# The Mac directory is a fresh mktemp -d per `up` (OrbStack's file sharing shows a deleted-and-recreated path
# to the container unreliably); the container's label records it so `down` can remove it.
#
# Settings (environment): HOSTLAB_HTTP_PORT (8090, the
# callback port registered in the lab Zitadel), HOSTLAB_METRICS_PORT (9091), HOSTLAB_GRPC_PORT (50443).
# After `up`, <state dir>/lab.env holds HOSTLAB_NAME, HOSTLAB_HTTP_ADDR, HOSTLAB_GRPC_ADDR and HOSTLAB_STATE.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$HERE/../.." && pwd)"
# The lab Zitadel host (the developer's lab.env or env; test/lab/lib.sh).
LAB_HOST="$(bash -c '. "$1/test/lab/lib.sh" && printf %s "$LAB_HOST"' _ "$REPO_DIR")"
ENV_FILE="$REPO_DIR/test/compose/.env"

NAME="tagcess-hostlab"
IMAGE="tagcess-hostlab:0.29.4"
HTTP_PORT="${HOSTLAB_HTTP_PORT:-8090}"
METRICS_PORT="${HOSTLAB_METRICS_PORT:-9091}"
GRPC_PORT="${HOSTLAB_GRPC_PORT:-50443}"
ROOT_IN="/var/lib/tagcess-headscale"

say() { echo "hostlab: $*"; }
die() { echo "hostlab: $*" >&2; exit 1; }
in_lab() { docker exec "$NAME" "$@"; }
in_lab_stdin() { docker exec -i "$NAME" "$@"; } # for commands that read a pipe

# env_value reads KEY from the seed's .env without sourcing it; the value only travels through pipes.
env_value() {
  local v
  v="$(grep -m1 "^$1=" "$ENV_FILE" | cut -d= -f2-)" || true
  v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
  printf '%s' "$v"
}

free_port() {
  local p
  for _ in $(seq 1 50); do
    p=$((50500 + RANDOM % 500))
    nc -z 127.0.0.1 "$p" 2>/dev/null || { echo "$p"; return; }
  done
  die "no free loopback port found for the gRPC relay"
}

down() {
  local dir
  dir="$(docker inspect -f '{{index .Config.Labels "tagcess.hostlab.state"}}' "$NAME" 2>/dev/null || true)"
  docker rm -f -v "$NAME" >/dev/null 2>&1 || true
  # Only ever delete a directory this script created.
  case "$(basename "${dir:-x}")" in
    tagcess-hostlab.*) rm -rf "$dir" ;;
  esac
  say "down: container $NAME and its temporary directory removed (the lab Zitadel was not touched)"
}

fail_logs() {
  echo "hostlab: FAILED: $*" >&2
  docker exec "$NAME" journalctl -u headscale -u tagcess-hostlab-grpc --no-pager -n 30 >&2 2>/dev/null || true
  echo "hostlab: the container is left running for inspection; 'make hostlab-down' removes it" >&2
  exit 1
}

up() {
  for tool in docker curl nc; do command -v "$tool" >/dev/null || die "$tool is required"; done
  docker info >/dev/null 2>&1 || die "docker (OrbStack) is not reachable"
  [ -r "$ENV_FILE" ] || die "$ENV_FILE is missing: run 'make lab-up' first (the seed writes the OIDC client there)"
  local client_id
  client_id="$(env_value HEADSCALE_OIDC_CLIENT_ID)"
  [ -n "$client_id" ] && [ -n "$(env_value HEADSCALE_OIDC_CLIENT_SECRET)" ] \
    || die "HEADSCALE_OIDC_CLIENT_ID/SECRET are not in $ENV_FILE: run 'make lab-up' first"
  down >/dev/null # always start from nothing
  # A listener we did not start would answer /health for us and hide a failed start.
  if nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null; then
    die "127.0.0.1:$HTTP_PORT is in use (the compose Headscale uses the same ports; stop it or set HOSTLAB_HTTP_PORT, HOSTLAB_METRICS_PORT, HOSTLAB_GRPC_PORT)"
  fi
  say "building $IMAGE"
  docker build -q -t "$IMAGE" "$HERE" >/dev/null

  STATE="$(mktemp -d "${TMPDIR:-/tmp}/tagcess-hostlab.XXXXXX")"
  STATE="$(cd "$STATE" && pwd -P)"
  mkdir "$STATE/requests" "$STATE/results"
  chmod 0755 "$STATE" "$STATE/requests" "$STATE/results"
  local relay
  relay="$(free_port)"

  say "starting $NAME (privileged systemd, host network)"
  docker run -d --name "$NAME" --privileged --network host --label "tagcess.hostlab.state=$STATE" \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    -v "$STATE/requests:$ROOT_IN/requests" -v "$STATE/results:$ROOT_IN/results" \
    "$IMAGE" >/dev/null || { rm -rf "$STATE"; die "docker run failed"; }
  local state=""
  for _ in $(seq 1 60); do
    state="$(in_lab systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  case "$state" in running|degraded) ;; *) fail_logs "systemd did not come up (state: ${state:-none})" ;; esac

  say "installing the Headscale config and the OIDC secret"
  sed -e "s|@HTTP_PORT@|$HTTP_PORT|g" -e "s|@METRICS_PORT@|$METRICS_PORT|g" -e "s|@GRPC_PORT@|$GRPC_PORT|g" \
      -e "s|@OIDC_CLIENT_ID@|$client_id|g" -e "s|@LAB_ZITADEL_HOST@|$LAB_HOST|g" "$HERE/headscale.config.yaml.tmpl" \
    | in_lab_stdin sh -c 'cat >/etc/headscale/config.yaml.new && chmod 0644 /etc/headscale/config.yaml.new && mv /etc/headscale/config.yaml.new /etc/headscale/config.yaml'
  # The secret goes through a pipe into a file readable only by root and the headscale service user.
  printf '%s' "$(env_value HEADSCALE_OIDC_CLIENT_SECRET)" \
    | in_lab_stdin install -m 0640 -o root -g headscale /dev/stdin /etc/headscale/oidc_client_secret
  cat <<UNIT | in_lab_stdin sh -c 'cat >/etc/systemd/system/tagcess-hostlab-grpc.service'
[Unit]
Description=Relay Headscale's gRPC unix socket to a loopback TCP port (hostlab)
After=headscale.service

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:$relay,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/var/run/headscale/headscale.sock
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
  in_lab systemctl daemon-reload
  in_lab systemctl enable --now headscale.service tagcess-hostlab-grpc.service >/dev/null 2>&1 \
    || fail_logs "could not enable headscale.service"

  say "waiting for http://127.0.0.1:$HTTP_PORT/health"
  local code=""
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/health" || true)"
    [ "$code" = 200 ] && break
    sleep 1
  done

  # AC1: service active, pinned version, /health 200, gRPC readable (through the unix socket and the relay).
  [ "$code" = 200 ] || fail_logs "/health answered '${code:-none}', want 200"
  [ "$(in_lab systemctl is-active headscale.service)" = active ] || fail_logs "headscale.service is not active"
  in_lab headscale version | grep -q '^headscale version v0\.29\.4$' || fail_logs "headscale version is not v0.29.4"
  in_lab headscale users list >/dev/null || fail_logs "headscale users list (gRPC over the unix socket) failed"
  nc -z 127.0.0.1 "$relay" >/dev/null || fail_logs "the gRPC relay is not listening on 127.0.0.1:$relay"
  say "ok: headscale.service active, v0.29.4, /health 200, gRPC readable"

  # AC2: ADR 0021 b layout. Directories and modes inside; requests/ and results/ shared with the Mac, private/ not.
  [ "$(in_lab stat -c '%a %U' "$ROOT_IN/private")" = "700 root" ] || fail_logs "$ROOT_IN/private is not root 0700"
  # The Mac directories were just recreated; give OrbStack's file sharing a moment to show them.
  local shared=""
  for _ in $(seq 1 10); do
    if in_lab test -d "$ROOT_IN/requests" && in_lab test -d "$ROOT_IN/results" \
      && in_lab mountpoint -q "$ROOT_IN/requests" && in_lab mountpoint -q "$ROOT_IN/results"; then shared=1; break; fi
    sleep 1
  done
  [ -n "$shared" ] || fail_logs "requests/ and results/ are not bind-mounted directories in the container"
  ! in_lab mountpoint -q "$ROOT_IN/private" || fail_logs "private/ must not be a mount"
  [ ! -e "$STATE/private" ] || fail_logs "private/ is visible on the Mac"
  touch "$STATE/requests/.probe" && in_lab test -e "$ROOT_IN/requests/.probe" || fail_logs "requests/ is not shared Mac -> container"
  in_lab touch "$ROOT_IN/results/.probe" && [ -e "$STATE/results/.probe" ] || fail_logs "results/ is not shared container -> Mac"
  rm -f "$STATE/requests/.probe" "$STATE/results/.probe"
  say "ok: $ROOT_IN/{requests,results} shared with $STATE, private root 0700 and container-only"

  cat >"$STATE/lab.env" <<ENV
HOSTLAB_NAME=$NAME
HOSTLAB_STATE=$STATE
HOSTLAB_HTTP_ADDR=127.0.0.1:$HTTP_PORT
HOSTLAB_GRPC_ADDR=127.0.0.1:$relay
ENV
  say "up: http 127.0.0.1:$HTTP_PORT, grpc 127.0.0.1:$relay, requests/results in $STATE (details: $STATE/lab.env)"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) die "usage: $0 up|down" ;;
esac
