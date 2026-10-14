#!/bin/sh
# Test stand-in for `tagcess -k8s-manifest` (F6-007): prints a fixed manifest and records its arguments.
printf '%s\n' "$*" >>"${FAKE_MANIFEST_LOG:-/dev/null}"
cat <<'YAML'
# tagcess read-only access (fake manifest for the installer tests)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "tagcess-reader"
  namespace: "tagcess"
YAML
