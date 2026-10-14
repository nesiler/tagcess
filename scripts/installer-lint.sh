#!/usr/bin/env bash
# Lint the installer when the tools exist. ansible-lint checks deploy/ansible, shellcheck checks
# deploy/*.sh, deploy/**/*.sh and the test target script. A missing tool is reported "skipped" and is never
# counted as a PASS (no "ok" line for it); it does not fail `make check` on a machine without the tool.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
if command -v ansible-lint >/dev/null 2>&1; then
  # Ansible refuses non-blocking stdio (some terminals/hooks): run it through a pipe (pipefail keeps the status).
  if (cd deploy/ansible && ANSIBLE_CONFIG=ansible.cfg ansible-lint --nocolor -q . </dev/null 2>&1 | cat); then
    echo "installer-lint: ansible-lint ok (deploy/ansible)"
  else
    echo "installer-lint: ansible-lint FAILED (deploy/ansible)" >&2
    status=1
  fi
else
  echo "installer-lint: ansible-lint skipped (not installed; this is not a PASS)"
fi

if command -v shellcheck >/dev/null 2>&1; then
  files=$(find deploy test/adopttarget -name '*.sh' -not -path '*/testdata/*' | sort)
  # shellcheck disable=SC2086 # file list, no spaces in repo paths
  if shellcheck -x $files; then
    echo "installer-lint: shellcheck ok ($(echo "$files" | wc -l | tr -d ' ') files)"
  else
    echo "installer-lint: shellcheck FAILED" >&2
    status=1
  fi
else
  echo "installer-lint: shellcheck skipped (not installed; this is not a PASS)"
fi
exit "$status"
