#!/usr/bin/env bash
# Test double for a child agent (profile "fake"). It asks one question, waits for the answer on
# stdin (what `coord.sh send` types), reports done with the answer, then idles like a real TUI.
tell=$COORD_ROOT/scripts/coord/tell.sh
printf 'fake agent up; prompt has %s lines\n' "$(printf '%s\n' "$1" | wc -l | tr -d ' ')"
grep -q 'Coordinator protocol' <<< "$1" || { "$tell" blocked "protocol missing from prompt"; exit 1; }
"$tell" question "fake: ready?"
IFS= read -r answer
"$tell" "done" "fake: got '$answer'"
while IFS= read -r line; do
  echo "fake: turn '$line'"
  "$COORD_HOOK" fake idle
  [ "$line" = double ] && "$COORD_HOOK" fake idle   # like Codex: two notifications per turn
done
