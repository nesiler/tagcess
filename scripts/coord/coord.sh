#!/usr/bin/env bash
# Coordinator entry point of tagcess. Thin wrapper around agent-kit's dispatcher (scripts/agent-kit/ak);
# commands: spawn, send, status, peek, log, wait, kill, clean, attach, profiles, equiv, review-for, verify, doctor.
# Terminal layer: Herdr when the coordinator runs inside a Herdr pane, tmux otherwise.
# Run state lives outside the repo: $COORD_STATE_DIR (default ~/.local/state/tagcess-coord).
#
# Profiles: the repo file (.agents/coord/profiles.conf) only holds the test profile. Real profiles are machine setup:
# the agent-kit machine library (~/.config/agent-kit/profiles.conf) and an optional tagcess-local file
# ($TAGCESS_PROFILES_LOCAL, default ~/.config/tagcess/profiles.conf). The local file wins over the repo file,
# the repo file wins over the machine library.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export AK_ROOT=$ROOT
export AK_TMUX_PREFIX=${AK_TMUX_PREFIX:-tc-}
export COORD_STATE_DIR=${COORD_STATE_DIR:-$HOME/.local/state/tagcess-coord}
export AK_FAKE_AGENT=${AK_FAKE_AGENT:-$ROOT/scripts/coord/testdata/fake-agent.sh}
# Developer-local settings (untracked), e.g. AK_DOCTOR_PROXY_URL.
[ -f "$HOME/.config/tagcess/coord.env" ] && . "$HOME/.config/tagcess/coord.env"
# Optional LLM proxy health check in `doctor` (empty = skipped).
export AK_DOCTOR_PROXY_URL=${AK_DOCTOR_PROXY_URL:-}
export AK_DOCTOR_PROXY_KEY_FILE=${AK_DOCTOR_PROXY_KEY_FILE:-}

local_profiles=${TAGCESS_PROFILES_LOCAL-$HOME/.config/tagcess/profiles.conf}
if [ -z "${COORD_PROFILES:-}" ] && [ -n "$local_profiles" ] && [ -s "$local_profiles" ]; then
  mkdir -p "$COORD_STATE_DIR"
  merged=$COORD_STATE_DIR/profiles.merged.conf
  cat "$local_profiles" "$ROOT/.agents/coord/profiles.conf" > "$merged.tmp" && mv "$merged.tmp" "$merged"
  export COORD_PROFILES=$merged
fi
exec "$ROOT/scripts/agent-kit/ak" "$@"
