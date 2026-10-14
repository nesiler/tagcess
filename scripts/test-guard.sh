#!/usr/bin/env bash
# Regression tests for scripts/hooks/guard-bash.sh. Run by `make check`.
set -u
cd "$(dirname "$0")/.."
G=scripts/hooks/guard-bash.sh
fail=0
# A private HOME, so the developer's own ~/.config/tagcess/guard-patterns.txt never changes the result.
TEST_HOME=$(mktemp -d)
trap 'rm -rf "$TEST_HOME"' EXIT
export HOME="$TEST_HOME"
# Generic protected systems: two hosts, their RFC 5737 public addresses, two tailnet addresses and a
# production kubeconfig/context name.
export TAGCESS_GUARD_PATTERNS='vpn-host
k8s-host
203\.0\.113\.10
203\.0\.113\.20
100\.64\.0\.[45]
config-prod'
t() {
  printf '%s' "$2" | jq -Rs '{tool_input:{command:.}}' | "$G" 2>/dev/null
  r=$?
  if [ "$r" != "$1" ]; then echo "guard: FAIL (got $r, want $1): $2" >&2; fail=1; fi
}
# Allowed: read-only commands, including > inside quoted jq/sed/awk code.
t 0 "ssh vpn-host 'headscale users list -o json 2>/dev/null | jq -c \"[.[] | (.tags|length) > 0]\"'"
t 0 "ssh vpn-host 'headscale users list -o json' | sed -E 's#/[0-9]+\$#/<id>#'"
t 0 "ssh vpn-host 'awk \"\$3 >= 5\" /etc/passwd'"
t 0 "ssh -o HostKeyAlias=203.0.113.10 vpn-host 'systemctl status caddy; docker inspect headplane --format \"{{.Source}} -> {{.Destination}}\" 2>&1 | grep -viE secret'"
t 0 "ssh k8s-host 'kubectl get pods -A 2>/dev/null; kubectl logs -n zitadel deploy/zitadel --tail 50'"
t 0 "ssh vpn-host 'cat /etc/caddy/Caddyfile | grep -v token; ls -la /etc/headscale'"
t 0 "rm -rf /tmp/foo && echo x > local.txt"
t 0 "kubectl --kubeconfig ~/.kube/config-lab get pods"
t 0 "TAGCESS_K8S_LAB_KUBECONFIG=~/.kube/config-lab TAGCESS_K8S_LAB_CONTEXT=lab make k8s-lab"
t 0 "make f4-e2e"
# Blocked: writes against production.
t 2 "ssh vpn-host 'echo x > /etc/headscale/policy.hujson'"
t 2 "ssh vpn-host 'echo x >/etc/x'"
t 2 "ssh vpn-host 'echo x >> ~/notes'"
t 2 "ssh vpn-host 'cat a > b.txt'"
t 2 "ssh vpn-host 'cat a > ./b'"
t 2 "ssh vpn-host 'cat a > \$F'"
t 2 "ssh vpn-host 'echo 1>/etc/x'"
t 2 "ssh vpn-host 'systemctl reload caddy'"
t 2 "ssh vpn-host 'sudo sed -i s/a/b/ /etc/caddy/Caddyfile'"
t 2 "ssh vpn-host 'headscale nodes expire -i 3'"
t 2 "ssh vpn-host 'headscale policy set -f x'"
t 2 "ssh k8s-host 'kubectl delete pod x'"
t 2 "scp foo vpn-host:/tmp/"
t 2 "ssh vpn-host 'rm /tmp/x'"
t 2 "ssh vpn-host 'docker restart headplane'"
t 2 "kubectl --kubeconfig ~/.kube/config-prod apply -f x.yaml"
t 2 "ssh vpn-host 'curl -X POST localhost:2019/load'"
t 2 "ssh 100.64.0.4 'caddy reload'"
# The lab entry points aimed at a production kubeconfig.
t 2 "TAGCESS_K8S_LAB_KUBECONFIG=~/.kube/config-prod-admin make k8s-lab"
t 2 "TAGCESS_K8S_LAB_KUBECONFIG=~/.kube/config-prod-admin make f4-e2e"
t 2 "TAGCESS_K8S_LAB_KUBECONFIG=~/.kube/config-prod-admin test/k8s/lab.sh up"
t 2 "KUBECONFIG=~/.kube/config-prod-admin make k8s-lab"

# Patterns from the local file only: the same protection, comments and blank lines ignored.
unset TAGCESS_GUARD_PATTERNS
mkdir -p "$HOME/.config/tagcess"
printf '# protected systems\n\n  vpn-host  \nconfig-prod\n' >"$HOME/.config/tagcess/guard-patterns.txt"
t 2 "ssh vpn-host 'systemctl reload caddy'"
t 2 "KUBECONFIG=~/.kube/config-prod-admin make k8s-lab"
t 0 "ssh vpn-host 'systemctl status caddy'"
t 0 "ssh k8s-host 'kubectl delete pod x'"
# File and environment together.
export TAGCESS_GUARD_PATTERNS='k8s-host'
t 2 "ssh vpn-host 'systemctl reload caddy'"
t 2 "ssh k8s-host 'kubectl delete pod x'"

# Neither file nor environment: the guard allows everything.
unset TAGCESS_GUARD_PATTERNS
rm -f "$HOME/.config/tagcess/guard-patterns.txt"
t 0 "ssh vpn-host 'systemctl reload caddy'"
t 0 "scp foo vpn-host:/tmp/"
t 0 "KUBECONFIG=~/.kube/config-prod-admin make k8s-lab"
# A file with only comments protects nothing either.
printf '# nothing yet\n\n' >"$HOME/.config/tagcess/guard-patterns.txt"
t 0 "ssh vpn-host 'systemctl reload caddy'"
[ "$fail" -eq 0 ] && echo "guard: ok" || exit 1
