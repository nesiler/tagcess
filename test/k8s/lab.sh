#!/usr/bin/env bash
# F4-033: kubectl wrapper of the opt-in personal k3s test bed (test/k8s/lab.go drives it; the decisions
# live in Go). It runs with the bootstrap (admin) identity from KUBECONFIG, which only lab.go hands
# over, and writes only objects of one run: namespace tagcess-k8s-lab-<run> and the cluster-scope RBAC
# objects named tagcess-k8s-lab-<run>-*, all labelled tagcess.io/k8s-lab=<run>. Lab only (ADR 0014):
# it never touches production, CRDs, controllers, issuers or the firewall, and it never prints a
# credential except the short-lived ServiceAccount token that `token` is for.
#
#   lab.sh version|ingressclasses|traefik|server|ca     read-only facts for the preflight
#   lab.sh up <run> <ingress-class>                      namespace, quota, fixture, read-only SA + RBAC
#   lab.sh token <run>                                   short-lived token of the read-only SA (stdout)
#   lab.sh revoke <run>                                  recreate the read-only SA: every token issued so far is
#                                                        rejected with 401 (F4-034; stands in for an expired token)
#   lab.sh conflict <run> <ingress-class>                add one Ingress with overlapping paths and a second Service
#   lab.sh down <run>                                    delete this run's objects
#   lab.sh leftovers <run>                               list this run's objects that still exist
set -euo pipefail

die() { echo "k8s-lab: $*" >&2; exit 1; }

[ -n "${KUBECONFIG:-}" ] && [ -f "$KUBECONFIG" ] || die "KUBECONFIG must point at the bootstrap kubeconfig"
[ -n "${TAGCESS_K8S_LAB_CONTEXT:-}" ] || die "TAGCESS_K8S_LAB_CONTEXT must name the personal k3s context"
# Every call names the context; the kubeconfig's current-context is never relied on.
kubectl() { command kubectl --context "$TAGCESS_K8S_LAB_CONTEXT" "$@"; }
# Production guard (rule 1): anything that writes only runs against a clearly-k3s cluster.
require_k3s() {
  local v
  v="$(kubectl version -o json)" || die "cannot read the cluster version"
  case "$v" in
    *'+k3s'*) ;;
    *) die "refusing: the cluster is not clearly the personal k3s (server version has no +k3s)" ;;
  esac
}
sub="${1:-}"
run="${2:-}"

case "$sub" in
  version|ingressclasses|traefik|server|ca) ;;
  up|down|leftovers|token|revoke|conflict)
    [[ "$run" =~ ^[a-f0-9]{6,16}$ ]] || die "invalid run id"
    ;;
  *) die "usage: lab.sh version|ingressclasses|traefik|server|ca | up|conflict <run> <class> | token|revoke|down|leftovers <run>" ;;
esac

NS="tagcess-k8s-lab-$run"
LABEL="tagcess.io/k8s-lab"
SA="tagcess-reader"

case "$sub" in
  up|conflict) [[ "${3:-}" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || die "invalid ingress class" ;;
esac
case "$sub" in
  up|token|revoke|conflict|down) require_k3s ;;
esac

case "$sub" in
  version)        kubectl version -o json ;;
  ingressclasses) kubectl get ingressclass -o json ;;
  traefik)        kubectl get deployments --all-namespaces -l app.kubernetes.io/name=traefik -o json ;;
  server)         kubectl config view --minify -o 'jsonpath={.clusters[0].cluster.server}' ;;
  ca)
    ca="$(kubectl config view --minify --raw -o 'jsonpath={.clusters[0].cluster.certificate-authority-data}')"
    [ -n "$ca" ] || die "kubeconfig has no certificate-authority-data (TLS verification is never disabled)"
    printf '%s' "$ca"
    ;;
  up)
    class="${3:-}"
    [[ "$class" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || die "invalid ingress class"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    $LABEL: "$run"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: lab-quota
  namespace: $NS
  labels:
    $LABEL: "$run"
spec:
  hard:
    pods: "0"
    services: "5"
    count/ingresses.networking.k8s.io: "5"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $SA
  namespace: $NS
  labels:
    $LABEL: "$run"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: $SA
  namespace: $NS
  labels:
    $LABEL: "$run"
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: $SA
  namespace: $NS
  labels:
    $LABEL: "$run"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: $SA
subjects:
- kind: ServiceAccount
  name: $SA
  namespace: $NS
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $NS-ingressclass-reader
  labels:
    $LABEL: "$run"
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["ingressclasses"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $NS-ingressclass-reader
  labels:
    $LABEL: "$run"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $NS-ingressclass-reader
subjects:
- kind: ServiceAccount
  name: $SA
  namespace: $NS
---
apiVersion: v1
kind: Service
metadata:
  name: fixture
  namespace: $NS
  labels:
    $LABEL: "$run"
spec:
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fixture
  namespace: $NS
  labels:
    $LABEL: "$run"
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
spec:
  ingressClassName: $class
  rules:
  - host: fixture.k8s-lab.test
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: fixture
            port:
              number: 80
EOF
    ;;
  token)
    kubectl create token "$SA" -n "$NS" --duration=20m
    ;;
  revoke)
    # Tokens are bound to the ServiceAccount's UID: a new SA of the same name keeps the RBAC bindings
    # (they name the SA) but rejects every older token.
    kubectl delete serviceaccount "$SA" -n "$NS" --wait=true
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $SA
  namespace: $NS
  labels:
    $LABEL: "$run"
EOF
    ;;
  conflict)
    class="${3:-}"
    [[ "$class" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || die "invalid ingress class"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: fixture-b
  namespace: $NS
  labels:
    $LABEL: "$run"
spec:
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: conflict
  namespace: $NS
  labels:
    $LABEL: "$run"
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
spec:
  ingressClassName: $class
  rules:
  - host: conflict.k8s-lab.test
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: fixture
            port:
              number: 80
      - path: /app
        pathType: Prefix
        backend:
          service:
            name: fixture-b
            port:
              number: 80
EOF
    ;;
  down)
    kubectl delete clusterrolebinding,clusterrole -l "$LABEL=$run" --ignore-not-found
    # Only a namespace this run labelled is ever deleted; an existing namespace of that name without the
    # run label is somebody else's.
    found="$(kubectl get namespace "$NS" -o 'jsonpath={.metadata.name} {.metadata.labels.tagcess\.io/k8s-lab}' --ignore-not-found)"
    if [ -n "$found" ]; then
      [ "${found#"$NS" }" = "$run" ] || die "namespace $NS exists without the run label; not deleting it"
      kubectl delete namespace "$NS" --ignore-not-found --wait=true --timeout=180s
    fi
    ;;
  leftovers)
    kubectl get namespace,clusterrole,clusterrolebinding -l "$LABEL=$run" -o name
    ;;
esac
