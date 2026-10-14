#!/usr/bin/env bash
# Harness hook: records a turn end ("idle") or process exit ("exit"). Wrapper around `ak hook`; never fails the caller.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/agent-kit/ak" hook "$@"
