#!/bin/sh
# Fake ansible-playbook for the install.sh tests (F6-009): never connects anywhere.
# Logs every call (its arguments on one line) to FAKE_AP_LOG and plays the phase outputs from FAKE_AP_DIR:
#   preflight.json      copied to <env>/preflight.json on a --tags preflight call
#   guide-<phase>.md    copied to <env>/guide/<phase>.md (and guide-<phase>.json to .json)
#   rc-<phase>          the exit code of that phase's call (default 0)
inv=""
tags=""
prev=""
for a in "$@"; do
	if [ "$prev" = "-i" ] && [ -z "$inv" ]; then inv=$a; fi
	if [ "$prev" = "--tags" ]; then tags=$a; fi
	prev=$a
done
envdir=$(dirname "$inv")
printf '%s\n' "$*" >>"$FAKE_AP_LOG"
if [ "$tags" = preflight ] && [ -f "$FAKE_AP_DIR/preflight.json" ]; then
	cp "$FAKE_AP_DIR/preflight.json" "$envdir/preflight.json"
fi
if [ -f "$FAKE_AP_DIR/guide-$tags.md" ]; then
	mkdir -p "$envdir/guide"
	cp "$FAKE_AP_DIR/guide-$tags.md" "$envdir/guide/$tags.md"
	[ -f "$FAKE_AP_DIR/guide-$tags.json" ] && cp "$FAKE_AP_DIR/guide-$tags.json" "$envdir/guide/$tags.json"
fi
echo "PLAY RECAP (fake) tags=$tags"
rc=0
if [ -f "$FAKE_AP_DIR/rc-$tags" ]; then rc=$(cat "$FAKE_AP_DIR/rc-$tags"); fi
exit "$rc"
