#!/usr/bin/env bash
# F6-001: the local installer test targets (model: test/hostlab). `up` builds the image for SHAPE, starts one
# privileged systemd container reachable over ssh on a random loopback port, and verifies its shape;
# `down` removes the container, its volumes, the temporary directory and the ssh key. Never touches a
# real host: the only network peer is the local Docker (OrbStack).
#
#   SHAPE=adopt  existing installation vpn-host shape (Headscale 0.29.4 file mode, Caddy 2.8.4 + 20 site files, stopped
#                oauth2-proxy, Docker, Tailscale joined as tag:vpn-server, Headplane/WireGuard placeholders)
#   SHAPE=bare   empty Ubuntu 24.04: systemd, sshd, Python 3 only
#
# Settings (environment): SHAPE (adopt), ADOPT_TARGET_NAME (tagcess-adopttarget-<shape>),
# ADOPT_TARGET_DOCKER (1; 0 skips the Docker-in-Docker volumes and the Docker check).
# After `up`, <state>/target.env holds ADOPT_TARGET_NAME, ADOPT_TARGET_SHAPE, ADOPT_TARGET_STATE,
# ADOPT_TARGET_SSH_PORT, ADOPT_TARGET_SSH_KEY and ADOPT_TARGET_INVENTORY (an Ansible inventory with the
# host in the `vpn` group); the last line of stdout is the path of target.env.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHAPE_SET="${SHAPE:+1}"
SHAPE="${SHAPE:-adopt}"
DOCKER_IN="${ADOPT_TARGET_DOCKER:-1}"

say() { echo "adopttarget: $*" >&2; }
die() { echo "adopttarget: $*" >&2; exit 1; }

case "$SHAPE" in adopt|bare) ;; *) die "SHAPE must be adopt or bare, got '$SHAPE'" ;; esac
NAME="${ADOPT_TARGET_NAME:-tagcess-adopttarget-$SHAPE}"
case "$NAME" in tagcess-adopttarget-*|tagcess-at-*) ;; *) die "ADOPT_TARGET_NAME must start with tagcess-adopttarget- or tagcess-at-" ;; esac
IMAGE="tagcess-adopttarget:$SHAPE"

in_target() { docker exec "$NAME" "$@"; }

remove() { # name
  local n="$1" dir
  dir="$(docker inspect -f '{{index .Config.Labels "tagcess.adopttarget.state"}}' "$n" 2>/dev/null || true)"
  docker rm -f -v "$n" >/dev/null 2>&1 || true
  # Only ever delete a directory this script created.
  case "$(basename "${dir:-x}")" in
    tagcess-adopttarget.*) rm -rf "$dir" ;;
  esac
}

down() {
  if [ -n "${ADOPT_TARGET_NAME:-}" ] || [ -n "${SHAPE_SET:-}" ]; then
    remove "$NAME"
    say "down: $NAME, its volumes, temporary directory and ssh key removed"
    return
  fi
  remove tagcess-adopttarget-adopt
  remove tagcess-adopttarget-bare
  say "down: tagcess-adopttarget-{adopt,bare}, their volumes, temporary directories and ssh keys removed"
}

fail() {
  echo "adopttarget: FAILED: $*" >&2
  docker exec "$NAME" systemctl --failed --no-legend >&2 2>/dev/null || true
  echo "adopttarget: the container is left running for inspection; 'make adopt-target-down' removes it" >&2
  exit 1
}

up() {
  command -v docker >/dev/null || die "docker is required"
  command -v ssh-keygen >/dev/null || die "ssh-keygen is required"
  docker info >/dev/null 2>&1 || die "docker (OrbStack) is not reachable"
  remove "$NAME" # always start from nothing (AC7)
  say "building $IMAGE"
  docker build -q --target "$SHAPE" -t "$IMAGE" "$HERE" >/dev/null

  local state
  state="$(mktemp -d "${TMPDIR:-/tmp}/tagcess-adopttarget.XXXXXX")"
  state="$(cd "$state" && pwd -P)"
  ssh-keygen -q -t ed25519 -N '' -C "tagcess-adopttarget" -f "$state/id_ed25519"

  local vols=()
  # Docker-in-Docker needs real volumes; bare gets them too (the fresh host phase installs Docker there).
  if [ "$DOCKER_IN" = 1 ]; then vols=(-v /var/lib/docker -v /var/lib/containerd); fi
  say "starting $NAME (privileged systemd, ssh on a random loopback port)"
  docker run -d --name "$NAME" --hostname "${NAME#tagcess-}" --privileged --cgroupns=host \
    --label "tagcess.adopttarget.state=$state" --label "tagcess.adopttarget.shape=$SHAPE" \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp ${vols[@]+"${vols[@]}"} -p 127.0.0.1::22 \
    "$IMAGE" >/dev/null || { rm -rf "$state"; die "docker run failed"; }

  local st=""
  for _ in $(seq 1 90); do
    st="$(in_target systemctl is-system-running 2>/dev/null || true)"
    case "$st" in running|degraded) break ;; esac
    sleep 1
  done
  case "$st" in running|degraded) ;; *) fail "systemd did not come up (state: ${st:-none})" ;; esac
  docker cp "$state/id_ed25519.pub" "$NAME:/root/.ssh/authorized_keys" >/dev/null
  in_target sh -c 'chown root:root /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys'

  local port
  port="$(docker port "$NAME" 22/tcp | head -1 | sed 's/.*://')"
  [ -n "$port" ] || fail "no published ssh port"

  if [ "$SHAPE" = adopt ]; then verify_adopt; else verify_bare; fi

  local ok=""
  for _ in $(seq 1 30); do
    if ssh -i "$state/id_ed25519" -p "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR root@127.0.0.1 'python3 -c "print(1)"' >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ -n "$ok" ] || fail "ssh with python3 is not reachable on 127.0.0.1:$port"

  cat >"$state/inventory.yml" <<INV
# Generated by test/adopttarget/adopttarget.sh for $NAME (removed by down). Not a real host.
all:
  children:
    vpn:
      hosts:
        $NAME:
          ansible_host: 127.0.0.1
          ansible_port: $port
          ansible_user: root
          ansible_ssh_private_key_file: $state/id_ed25519
          ansible_ssh_common_args: "-o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
          ansible_python_interpreter: /usr/bin/python3
INV
  cat >"$state/target.env" <<ENV
ADOPT_TARGET_NAME=$NAME
ADOPT_TARGET_SHAPE=$SHAPE
ADOPT_TARGET_STATE=$state
ADOPT_TARGET_SSH_PORT=$port
ADOPT_TARGET_SSH_KEY=$state/id_ed25519
ADOPT_TARGET_INVENTORY=$state/inventory.yml
ADOPT_TARGET_DOCKER=$DOCKER_IN
ENV
  say "up: $NAME ($SHAPE), ssh root@127.0.0.1:$port, details in $state/target.env"
  echo "$state/target.env"
}

verify_adopt() {
  local s
  for s in headscale caddy tailscaled ssh; do
    [ "$(in_target systemctl is-active "$s.service" 2>/dev/null || true)" = active ] || fail "$s.service is not active"
  done
  if [ "$DOCKER_IN" = 1 ]; then
    [ "$(in_target systemctl is-active docker.service 2>/dev/null || true)" = active ] || fail "docker.service is not active"
  fi
  in_target headscale configtest >/dev/null 2>&1 || fail "headscale configtest failed"
  in_target headscale version | grep -q 'v0\.29\.4' || fail "headscale is not v0.29.4"
  in_target caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || fail "caddy validate failed"
  in_target caddy version | grep -q '^v2\.8\.4' || fail "caddy is not v2.8.4"
  in_target grep -Eq '^[[:space:]]+mode:[[:space:]]+file' /etc/headscale/config.yaml || fail "policy is not in file mode"
  in_target headscale policy check -f /etc/headscale/policy.hujson >/dev/null 2>&1 || fail "policy check failed"
  [ "$(in_target systemctl is-active oauth2-proxy.service 2>/dev/null || true)" != active ] || fail "oauth2-proxy must be stopped"
  [ "$(in_target systemctl is-enabled oauth2-proxy.service 2>/dev/null || true)" = disabled ] || fail "oauth2-proxy must be disabled"
  local files role api only
  files="$(in_target sh -c 'ls /etc/caddy/sites/*.caddy | wc -l' | tr -d ' ')"
  role="$(in_target sh -c 'grep -l "import vpn_site " /etc/caddy/sites/*.caddy | wc -l' | tr -d ' ')"
  api="$(in_target sh -c 'grep -l "import vpn_site_api " /etc/caddy/sites/*.caddy | wc -l' | tr -d ' ')"
  only="$(in_target sh -c 'grep -l "import vpn_only " /etc/caddy/sites/*.caddy | wc -l' | tr -d ' ')"
  if ! { [ "$files" = 20 ] && [ "$((role + api))" = 16 ] && [ "$api" = 5 ] && [ "$only" = 4 ]; }; then
    fail "sites/ layout is $files files, $((role + api)) role ($api api), $only vpn_only; want 20, 16 (5), 4"
  fi
  # The existing installation's vpn-host is a tagged tailnet node; join this one the same way (pre-auth key in memory only).
  # shellcheck disable=SC2016 # expanded by the target's shell
  in_target sh -c '
    set -e
    headscale users create vpn-server >/dev/null 2>&1 || true
    uid=$(headscale users list -o json | python3 -c "import json,sys;print([u[\"id\"] for u in json.load(sys.stdin) if u[\"name\"]==\"vpn-server\"][0])")
    key=$(headscale preauthkeys create --user "$uid" --expiration 10m --tags tag:vpn-server 2>/dev/null | tail -1)
    tailscale up --login-server http://127.0.0.1:8080 --authkey "$key" --hostname vpn-host-like --accept-dns=false >/dev/null' \
    || fail "tailscale join failed"
  in_target tailscale ip -4 | grep -q '^100\.' || fail "no tailnet IP"
  say "ok: adopt shape (Headscale configtest + file mode, caddy validate, oauth2-proxy stopped, 20 sites: 16 role (5 api), 4 vpn_only)"
}

verify_bare() {
  local c
  for c in headscale caddy oauth2-proxy docker tailscale tailscaled certbot; do
    ! in_target sh -c "command -v $c" >/dev/null 2>&1 || fail "$c must not be installed in the bare shape"
  done
  in_target python3 -c 'import sys; sys.exit(0)' || fail "python3 missing"
  say "ok: bare shape (no Headscale, Caddy, oauth2-proxy, Docker, Tailscale, certbot)"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) die "usage: SHAPE=adopt|bare $0 up|down" ;;
esac
