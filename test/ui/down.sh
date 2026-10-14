#!/usr/bin/env bash
# make ui-down: stop the stack `make ui` started. Keeps the tagcess volumes and .env/.secrets so
# the next `make ui` is fast; use `make lab-down` to remove the lab and the secrets.
set -euo pipefail

UI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$UI_DIR/../.." && pwd)"
COMPOSE_DIR="$REPO_DIR/test/compose"

docker compose -f "$COMPOSE_DIR/compose.yaml" -f "$COMPOSE_DIR/ui.compose.yaml" down --remove-orphans
echo "ui: down"
