#!/usr/bin/env bash
# Claude PreToolUse(Bash) guard: blocks write-like commands aimed at protected (production) systems.
# A safety net only. The rule is still "production is read-only" (AGENTS.md).
#
# The protected host, address, kube context and kubeconfig patterns are local and never committed:
#   - $HOME/.config/tagcess/guard-patterns.txt: one extended regex per line; blank lines and # comments ignored
#   - TAGCESS_GUARD_PATTERNS: more extended regexes, one per line
# With neither present the guard allows everything.
cmd=$(jq -r '.tool_input.command // empty')
[ -z "$cmd" ] && exit 0

patterns_file="${HOME:-}/.config/tagcess/guard-patterns.txt"
pats=$(
	{
		if [ -n "${HOME:-}" ] && [ -f "$patterns_file" ]; then cat "$patterns_file"; fi
		printf '%s\n' "${TAGCESS_GUARD_PATTERNS:-}"
	} | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | grep -vE '^(#|$)' | paste -sd '|' -
)
[ -z "$pats" ] && exit 0

# A command touches a protected system when it reaches a protected host over ssh/scp/rsync/sftp, or names a
# protected context or kubeconfig in a kubectl call or a KUBECONFIG-style variable.
prod="(ssh|scp|rsync|sftp)[^|;&]*($pats)|kubectl[^|;&]*($pats)|KUBECONFIG=[^ ]*($pats)"
echo "$cmd" | grep -qE "$prod" || exit 0

block() { echo "BLOCKED by prod guard: $1. Production is read-only; ask the developer if a change is really intended." >&2; exit 2; }

echo "$cmd" | grep -qE '(^|[;&| (])(scp|rsync|sftp)[[:space:]]' && block "file transfer to/from production"

# Drop the harmless redirects before looking for writes to files.
clean=$(echo "$cmd" | sed -E 's#[0-9]*>>?[[:space:]]*/dev/null##g; s#[0-9]*>&[0-9]##g; s#->##g')
# A redirect is ">" or ">>" followed by a path-like target: /x, ~/x, ./x, ../x, $VAR or a bare file name.
# Comparisons and markup inside quoted jq/sed/awk code ("length > 0", "<id>", ">=") do not match.
redirect="(^|[^-=<>!])>>?[[:space:]]*(/|~|\\.\\.?/|\\\$|[A-Za-z_][A-Za-z0-9_.-]*([[:space:]]|\$|[;&|)'\"]))"
echo "$clean" | grep -qE "$redirect" && block "output redirection into a file"

write='systemctl[[:space:]]+(start|stop|restart|reload|enable|disable|mask|unmask|edit|daemon-reload|kill)'
write+='|(^|[^[:alnum:]_.-])(rm|mv|cp|tee|truncate|chmod|chown|ln|mkdir|touch|dd|install|reboot|shutdown|apt|apt-get|dpkg|snap|useradd|usermod|passwd|crontab)[[:space:]]'
write+='|sed[[:space:]]+(-[a-zA-Z]*i|--in-place)'
write+='|kubectl[^|;&]*[[:space:]](apply|create|delete|edit|patch|replace|scale|rollout|label|annotate|cordon|uncordon|drain|taint|set|exec|cp|port-forward)([[:space:]]|$)'
write+='|headscale[^|;&]*[[:space:]](create|delete|destroy|expire|rename|register|move|tag|tags|approve|approve-routes|set|backfillips|serve|migrate)([[:space:]]|$)'
write+='|docker[[:space:]]+(compose|rm|rmi|stop|start|restart|run|kill|exec|pull|update|cp)'
write+='|make[[:space:]]+(k8s-lab|f4-e2e)|lab\.sh'
write+='|caddy[[:space:]]+(reload|stop|start|run|adapt[^|]*--overwrite)'
write+='|certbot[[:space:]]+(renew|certonly|delete|revoke|run)'
write+='|curl[^|;&]*(-X[[:space:]]*|--request[[:space:]]+)(POST|PUT|PATCH|DELETE)|curl[^|;&]*[[:space:]](-d|--data)'
echo "$clean" | grep -qE "$write" && block "write-like command"
exit 0
