#!/usr/bin/env bash
# Installs the tagcess Headscale host helper (ADR 0008, ADR 0021): the binary, the three systemd
# units and the /var/lib/tagcess-headscale layout (requests/ writable by the tagcess container,
# results/ readable by it, private/ root-only). The script is idempotent and never reads or writes
# the Headscale config; it never stops, starts or restarts the Headscale service.
#
# Usage:
#   install.sh --binary FILE --sha256 HEX [--request-uid UID] [--health URL]
#
# The committed units carry the production defaults; only the two values that differ per host are
# rendered here: --request-uid (the uid that publishes a request; the tagcess container in
# production, 0 in the lab bind mount) and --health (Headscale's loopback /health address).
set -euo pipefail

BIN_DIR=/usr/local/bin
BIN="$BIN_DIR/tagcess-hshelper"
UNIT_DIR=/etc/systemd/system
ROOT_DIR=/var/lib/tagcess-headscale
REQUEST_UID=10001
HEALTH_URL=http://127.0.0.1:8080/health
BINARY=
SHA256=

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --sha256) SHA256="${2:-}"; shift 2 ;;
    --request-uid) REQUEST_UID="${2:-}"; shift 2 ;;
    --health) HEALTH_URL="${2:-}"; shift 2 ;;
    -h|--help) echo "usage: install.sh --binary FILE --sha256 HEX [--request-uid UID] [--health URL]"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "must run as root"
[ -n "$BINARY" ] && [ -f "$BINARY" ] || die "--binary FILE is required and must exist"
[ -n "$SHA256" ] || die "--sha256 HEX is required"
case "$REQUEST_UID" in ''|*[!0-9]*) die "--request-uid must be a number" ;; esac
[[ "$HEALTH_URL" =~ ^http://(127\.0\.0\.1|localhost):[0-9]+/health$ ]] ||
  die "--health must be a loopback http /health URL"

# 1. Copy the caller's binary to a root-owned private temp file and verify the SHA-256 on that copy,
# so the path the caller controls cannot change between the check and the install (TOCTOU).
BIN_TMP="$(mktemp)"
trap 'rm -f "$BIN_TMP"' EXIT
install -m 0755 -o root -g root "$BINARY" "$BIN_TMP"
printf '%s  %s\n' "$SHA256" "$BIN_TMP" | sha256sum -c - >/dev/null || die "binary SHA-256 does not match"

# 2. Install the verified copy (idempotent).
install -m 0755 -o root -g root "$BIN_TMP" "$BIN"

# 3. The shared directories (ADR 0021 b). `install -d` is idempotent, so a second run is a no-op.
install -d -m 0755 -o root -g root "$ROOT_DIR"
install -d -m 0700 -o "$REQUEST_UID" -g "$REQUEST_UID" "$ROOT_DIR/requests"
install -d -m 0755 -o root -g root "$ROOT_DIR/results"
install -d -m 0700 -o root -g root "$ROOT_DIR/private"

# 4. Render the per-host values into a private temp dir, verify them there, and only then install
# them, so an invalid unit never reaches /etc/systemd/system.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_TMP="$(mktemp -d)"
trap 'rm -f "$BIN_TMP"; rm -rf "$UNIT_TMP"' EXIT
UNITS=(tagcess-hshelper.path tagcess-hshelper.service tagcess-hshelper-boot.service)
for unit in "${UNITS[@]}"; do
  sed -e "s#--request-uid 10001#--request-uid $REQUEST_UID#g" \
      -e "s#http://127.0.0.1:8080/health#$HEALTH_URL#g" \
      "$HERE/$unit" >"$UNIT_TMP/$unit"
  chmod 0644 "$UNIT_TMP/$unit"
done

# 5. Validate the rendered units, then install them and enable boot + .path (idempotent; this never
# touches Headscale).
systemd-analyze verify "$UNIT_TMP/tagcess-hshelper.path" \
  "$UNIT_TMP/tagcess-hshelper.service" \
  "$UNIT_TMP/tagcess-hshelper-boot.service"

for unit in "${UNITS[@]}"; do
  install -m 0644 -o root -g root "$UNIT_TMP/$unit" "$UNIT_DIR/$unit"
done

systemctl daemon-reload
systemctl enable --now tagcess-hshelper-boot.service
systemctl enable --now tagcess-hshelper.path

echo "install.sh: installed the tagcess Headscale host helper (request uid $REQUEST_UID)"
