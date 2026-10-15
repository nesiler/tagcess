#!/usr/bin/env bash
# TestNotices_Stale : `make notices-check` passes on the committed THIRD_PARTY_NOTICES and
# fails when the file is out of date, with `make notices` bringing it back. Runs in a
# throwaway copy of the repo so the working tree is never touched.
set -u
cd "$(dirname "$0")/.."
root=$(pwd)
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "notices-test: FAIL: $1" >&2; fail=1; }

# Copy tracked and new (non-ignored) files that still exist.
git ls-files --cached --others --exclude-standard -z |
  while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
  tar --null -T - -cf - | tar -xf - -C "$tmp"

cd "$tmp" || exit 1
go run ./tools/notices check >/dev/null 2>&1 || bad "notices-check fails on the committed file"

# A dependency change without regenerating leaves the file stale.
printf '\n| `example.com/added` | v1.0.0 | MIT | https://example.com |\n' >> THIRD_PARTY_NOTICES
go run ./tools/notices check >/dev/null 2>&1 && bad "notices-check missed a stale file"

go run ./tools/notices generate >/dev/null 2>&1 || bad "notices generate failed"
go run ./tools/notices check >/dev/null 2>&1 || bad "notices-check still fails after regenerating"

cd "$root"
[ "$fail" = 0 ] && echo "notices-test: ok"
exit "$fail"
