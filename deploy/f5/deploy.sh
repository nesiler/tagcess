#!/usr/bin/env bash
# Deploy the working tree to the F5 lab host (lab-vpn): rsync the source, build the image with the
# host's caddy/headscale GIDs, check the config, recreate the tagcess container and show its start
# line. Runs on the developer machine. Lab only: never point it at a production host.
#
# Usage: F5_ENV=~/f5-env.sh deploy/f5/deploy.sh [--dry-run] [--restart-oauth2-proxy]
#   --dry-run  print the rsync target and the rsync -n preview, change nothing.
#   F5_ENV   file with VPN_IP, SSH_KEY and REMOTE_SRC (see env.example.sh); nothing secret.
set -euo pipefail

# rsync --delete empties the target, so REMOTE_SRC must be a directory named "src" below the lab root
# (/root/f5): absolute, no ".." segment. "/", "/root", "/root/f5" (seed and secrets live there) fail.
LAB_ROOT=/root/f5
check_remote_src() {
	local p=$1
	case "$p" in
	*/../* | */.. | ../* | .. | */./* | */. | *//*) echo "REMOTE_SRC refused (relative segment): $p" >&2; return 1 ;;
	esac
	if [[ "$p" != "$LAB_ROOT"/*/src && "$p" != "$LAB_ROOT"/src ]]; then
		echo "REMOTE_SRC refused (must be $LAB_ROOT/**/src): $p" >&2
		return 1
	fi
	if [[ ! "$p" =~ ^[A-Za-z0-9._/-]+$ ]]; then
		echo "REMOTE_SRC refused (unexpected characters): $p" >&2
		return 1
	fi
}
# Tests source this file for the guard only.
[ "${DEPLOY_SOURCE_ONLY:-}" = 1 ] && return 0

: "${F5_ENV:?F5_ENV must point to the lab env file (see deploy/f5/env.example.sh)}"
# shellcheck source=/dev/null
. "$F5_ENV"
: "${VPN_IP:?VPN_IP missing in $F5_ENV}" "${SSH_KEY:?SSH_KEY missing in $F5_ENV}"
REMOTE_SRC=${REMOTE_SRC:-/root/f5/src}
check_remote_src "$REMOTE_SRC"
RESTART_PROXY=0
DRY_RUN=0
for a in "$@"; do
	case "$a" in
	--restart-oauth2-proxy) RESTART_PROXY=1 ;;
	--dry-run) DRY_RUN=1 ;;
	*) echo "unknown argument: $a" >&2; exit 2 ;;
	esac
done

REPO=$(cd "$(dirname "$0")/../.." && pwd)
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "root@$VPN_IP")

RSYNC=(rsync -a --delete --exclude .git --exclude /bin --exclude /dist --exclude '*.db'
	--exclude /seed --exclude /secrets)
echo "rsync --delete target: root@$VPN_IP:$REMOTE_SRC/ (from $REPO/)"
if [ "$DRY_RUN" = 1 ]; then
	"${RSYNC[@]}" -n -v -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new" "$REPO/" "root@$VPN_IP:$REMOTE_SRC/"
	echo "dry run: nothing changed"
	exit 0
fi
"${RSYNC[@]}" -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new" "$REPO/" "root@$VPN_IP:$REMOTE_SRC/"

"${SSH[@]}" REMOTE_SRC="$REMOTE_SRC" RESTART_PROXY="$RESTART_PROXY" bash -s <<'REMOTE'
set -euo pipefail
cd "$REMOTE_SRC"
CADDY_GID=$(getent group caddy | cut -d: -f3)
HEADSCALE_GID=$(getent group headscale | cut -d: -f3)
export CADDY_GID HEADSCALE_GID
docker build -q -f deploy/Dockerfile --build-arg CADDY_GID="$CADDY_GID" --build-arg HEADSCALE_GID="$HEADSCALE_GID" -t tagcess:latest . >/dev/null
docker run --rm -v /etc/tagcess/config.yaml:/c.yaml:ro -v /etc/tagcess/secrets:/etc/tagcess/secrets:ro \
	tagcess:latest -config /c.yaml -check
if [ "$RESTART_PROXY" = 1 ]; then docker restart oauth2-proxy >/dev/null; fi
docker compose -f deploy/compose.yaml up -d --no-build --force-recreate
sleep 8
docker logs tagcess 2>&1 | grep -E 'tagcess started|level=ERROR' | tail -3
REMOTE
