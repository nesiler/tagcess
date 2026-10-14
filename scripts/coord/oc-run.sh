#!/usr/bin/env bash
# oc-run.sh MODEL: run one OpenCode task non-interactively with an explicit model (ak profile kind "shell").
# `opencode run -m` resolves the model per request, which is more reliable than a TUI that attaches to a shared
# background service. --standalone gives the run its own server, so killing the client stops the session.
# The OpenCode install is chosen by the caller's environment (XDG_* from the profile's env column); nothing is
# hard-coded here. Follow-ups continue the same session: oc-run.sh MODEL --session <id> "<message>".
set -euo pipefail
model=${1:?usage: oc-run.sh provider/model [--session ID] [MESSAGE]}
shift
if [ $# -eq 0 ]; then
  set -- "$(cat "${AK_RUN:?AK_RUN not set}/prompt.md")"
fi
exec opencode run --standalone --auto -m "$model" --title "${AK_SESSION:-oc-run}" "$@"
