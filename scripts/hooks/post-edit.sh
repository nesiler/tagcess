#!/usr/bin/env bash
# Claude PostToolUse(Edit|Write) hook: formats edited Go files.
f=$(jq -r '.tool_input.file_path // empty')
case "$f" in *.go) ;; *) exit 0 ;; esac
[ -f "$f" ] || exit 0
if command -v goimports >/dev/null 2>&1; then goimports -w "$f"; else gofmt -w "$f"; fi
exit 0
