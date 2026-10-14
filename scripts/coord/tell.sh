#!/usr/bin/env bash
# Child -> coordinator report. Usage: tell.sh question|done|blocked "<message>"  (wrapper around `ak tell`)
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/agent-kit/ak" tell "$@"
