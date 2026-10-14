#!/usr/bin/env bash
# ui-view.sh NAME CHILD...: show several ak child sessions (tmux backend) tiled in one tmux session, read-only.
# Each pane redraws the child's screen every 2s with capture-pane, so no keystroke can reach the child and the
# child's window size never changes. Detach with the tmux prefix + d; `tmux kill-session -t NAME` closes it.
# Example: scripts/coord/ui-view.sh ui-view-1 issue-12 issue-13 issue-14
set -euo pipefail
prefix=${AK_TMUX_PREFIX:-tc-}
view=${1:?usage: ui-view.sh VIEW_NAME CHILD...}
shift
[ $# -gt 0 ] || { echo "ui-view.sh: no child sessions given" >&2; exit 2; }
# shellcheck disable=SC2016 # expanded inside each pane
loop='while :; do out=$(tmux capture-pane -p -e -J -t "='"$prefix"'$S:" 2>/dev/null | grep -v "^[[:space:]]*$" | tail -n $(($(tput lines)-1))) || out="('"$prefix"'$S not found)"; printf "\033[H\033[2J\033[7m %s \033[0m\n%s" "$S" "$out"; sleep 2; done'
tmux kill-session -t "=$view" 2>/dev/null || true
tmux new-session -d -s "$view" -x "$(tput cols)" -y "$(tput lines)" "S=$1; $loop"
shift
for child in "$@"; do
  tmux split-window -t "$view" "S=$child; $loop"
  tmux select-layout -t "$view" tiled >/dev/null
done
if [ -n "${TMUX:-}" ]; then tmux switch-client -t "$view"; else tmux attach -t "$view"; fi
