#!/usr/bin/env bash
# make lab-down: removes namespace tagcess-lab (and with it the database volume), removes the local Headscale, its relay and volumes
# and deletes the lab secrets from test/compose/.secrets/lab and test/compose/.env.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

docker compose -f "$COMPOSE_DIR/compose.yaml" down -v
lab_guard
k delete namespace "$LAB_NS" --ignore-not-found --wait
rm -rf "$COMPOSE_DIR/$LAB_SECRETS_REL" "$COMPOSE_DIR/.env"
echo "lab: down"
