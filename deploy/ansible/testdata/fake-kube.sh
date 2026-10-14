#!/bin/sh
# Fake kubectl/helm for the zitadel_install tests (F6-012): logs "<name> <args>" to FAKE_KUBE_LOG and answers the
# reads the role makes. FAKE_PAT is the PAT the fake Secret holds; FAKE_EXISTING=1 makes every Secret exist.
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >>"$FAKE_KUBE_LOG"
case "$*" in
*"get nodes"*) printf '%s\n' "${FAKE_NODES:-node/lab-k8s}" ;;
*"get secret tagcess-seed-pat"*) printf '%s' "$FAKE_PAT" | base64 ;;
*"get secret wildcard-tls -o json"*) printf '{"data":{"tls.crt":"Y3J0","tls.key":"a2V5"}}\n' ;;
*"get secret zitadel-db -o"*) printf 'cHc=' ;;
*"get secret"*) [ "${FAKE_EXISTING:-}" = 1 ] || exit 1 ;;
*"apply -f -"*) cat >/dev/null; echo "applied" ;;   # reads the manifest like kubectl does (a closed pipe breaks the producer)
*apply*) echo "applied" ;;
*"create secret"*) cat >/dev/null ;;      # kubectl reads --from-env-file=/dev/stdin; a closed pipe gives the producer SIGPIPE (rc 141) under pipefail
esac
exit 0
