#!/usr/bin/env bash
# shellcheck disable=SC2034  # out/ev are read inside the eval of check()
# End-to-end test for scripts/coord with the "fake" profile. Uses a private tmux socket and a
# temporary state dir, so it never touches real coordinator sessions.
set -u
cd "$(dirname "$0")/../.." || exit 1
C=scripts/coord/coord.sh
tmp=$(mktemp -d)
export TAGCESS_PROFILES_LOCAL="" COORD_BACKEND=tmux COORD_STATE_DIR=$tmp/state COORD_TMUX_SOCKET="coord-test-$$" COORD_NOTIFY=0 COORD_WAIT_INTERVAL=0.3 COORD_WAIT_GRACE=0.5
trap 'tmux -L "$COORD_TMUX_SOCKET" kill-server 2>/dev/null; rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then :; else echo "coord-test: FAIL: $1" >&2; fail=1; fi; }

echo "Say hi." > "$tmp/prompt.md"
out=$($C spawn --name t1 --profile fake --role task --dir "$tmp" --prompt-file "$tmp/prompt.md")
check "spawn prints the session" '[[ "$out" == *"spawned t1"* ]]'

ev=$($C wait --timeout 20)
check "wait reports the question" '[[ "$ev" == *"\"kind\":\"question\""* && "$ev" == *"fake: ready?"* ]]'
check "state is question" '[ "$(jq -r ".[0].state" <<< "$($C status --json)")" = question ]'

# Single-tree rule: a second code-writing session in the same dir is refused; a review is not.
$C spawn --name t2 --profile fake --role fix --dir "$tmp" --prompt-file "$tmp/prompt.md" >/dev/null 2>&1
check "second writer is refused (exit 60)" '[ $? -eq 60 ]'
check "refused spawn leaves no run dir" '[ ! -e "$COORD_STATE_DIR/t2" ]'
out=$(printf 'Review it.\n' | $C spawn --name r1 --profile fake --role review --dir "$tmp" --prompt-file -)
check "reviewer may run in parallel" '[[ "$out" == *"spawned r1"* ]]'
$C wait --timeout 20 >/dev/null
$C kill r1 >/dev/null

$C send t1 "yes, go on" >/dev/null
ev=$($C wait --timeout 20)
check "wait reports done with the answer" '[[ "$ev" == *"\"kind\":\"done\""* && "$ev" == *"got '\''yes, go on'\''"* ]]'

# A turn that ends without a report surfaces as idle.
$C send t1 "one more" >/dev/null
ev=$($C wait --timeout 20)
check "turn end without report is idle" '[[ "$ev" == *"\"kind\":\"idle\""* ]]'
$C send t1 double >/dev/null
ev=$($C wait --timeout 20)
check "back-to-back idles collapse into one" '[ "$(grep -c "\"kind\":\"idle\"" <<< "$ev")" = 1 ]'
check "peek shows the screen" '[[ "$($C peek t1 -n 5)" == *"fake: turn '\''one more'\''"* ]]'

$C clean t1 >/dev/null 2>&1
check "clean refuses a running session" '[ -d "$COORD_STATE_DIR/t1" ]'
$C clean t1 --force >/dev/null
check "clean archives the run dir" 'ls "$COORD_STATE_DIR"/archive/*-t1/final-screen.txt >/dev/null 2>&1'

# A child that dies is reported as exit (agent ended) or dead (session gone).
$C clean r1 >/dev/null
printf 'x\n' | $C spawn --name t3 --profile fake --role task --dir "$tmp" --prompt-file - >/dev/null
$C wait --timeout 20 >/dev/null
tmux -L "$COORD_TMUX_SOCKET" kill-session -t tc-t3
ev=$($C wait --timeout 20)
check "killed session is reported dead" '[[ "$ev" == *"\"kind\":\"dead\""* ]]'

$C clean t3 >/dev/null

# Review fixes: spawn/wait race, clean during wait, half-written lines, literal scope text.
( COORD_WAIT_INTERVAL=0.02 $C wait --timeout 3 > "$tmp/bg1" 2>&1; echo $? > "$tmp/bg1.rc" ) &
printf 'x\n' | $C spawn --name t5 --profile fake --role other --dir "$tmp" --scope 'docs & tests \ a|b' --prompt-file - >/dev/null
wait
check "spawn racing a wait is never reported dead" '! $C log t5 | grep -q " dead/"'
check "scope text is copied literally" 'grep -qF "docs & tests \ a|b" "$COORD_STATE_DIR/t5/prompt.md"'
$C wait --timeout 5 >/dev/null
printf '{"kind":"do' >> "$COORD_STATE_DIR/t5/events.jsonl"
$C wait --timeout 2 >/dev/null 2>&1
check "a half-written line does not crash wait (timeout 124)" '[ $? -eq 124 ]'
( $C wait --timeout 3 > /dev/null 2>&1; echo $? > "$tmp/bg2.rc" ) &
sleep 0.5; $C clean t5 --force >/dev/null
wait
check "clean during wait does not crash it" '[ "$(cat "$tmp/bg2.rc")" = 124 ]'

mkdir -p "$tmp/gen" && echo keep > "$tmp/gen/NOTES.md"
scripts/gen-opencode-agents.sh "$tmp/gen" >/dev/null
check "opencode generator keeps foreign Markdown" '[ -f "$tmp/gen/NOTES.md" ]'

$C spawn --name 'Bad Name' --profile fake --role task --prompt-file "$tmp/prompt.md" >/dev/null 2>&1
check "invalid name is rejected" '[ $? -eq 2 ]'
$C spawn --name t4 --profile nope --role task --prompt-file "$tmp/prompt.md" >/dev/null 2>&1
check "unknown profile is rejected" '[ $? -eq 2 ]'

[ "$fail" -eq 0 ] && echo "coord-test: ok" || exit 1
