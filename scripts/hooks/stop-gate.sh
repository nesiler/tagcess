#!/usr/bin/env bash
# Claude Stop hook: when Go or agent files changed, "make check-fast" must pass before the turn ends.
# The second attempt in a row is let through (stop_hook_active), so a blocked turn can explain itself instead of looping.
input=$(cat)
[ "$(echo "$input" | jq -r '.stop_hook_active // false')" = true ] && exit 0
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

# The coordinator session writes no code. While a child writer (task/fix/test) is alive, a red tree is the child's
# test-first work in progress, so the coordinator's turn must not be blocked by it. Child sessions still get the gate.
if [ -z "${COORD_SESSION:-}" ] && scripts/coord/coord.sh status 2>/dev/null | awk 'NR>1 && ($3=="task"||$3=="fix"||$3=="test") && $6=="yes"{f=1} END{exit !f}'; then
  exit 0
fi

changed=$(git status --porcelain --untracked-files=all | grep -E '\.go$|go\.(mod|sum)$|\.agents/agents/' || true)
[ -z "$changed" ] && exit 0

if ! out=$(make -s check-fast 2>&1); then
  echo "Stop gate: 'make check-fast' failed. Fix it, or tell the developer exactly why it cannot pass." >&2
  echo "$out" | tail -40 >&2
  exit 2
fi
exit 0
