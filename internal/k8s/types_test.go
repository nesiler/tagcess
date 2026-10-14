package k8s

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const ingressJSON = `{
  "kind": "IngressList",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {"resourceVersion": "900", "continue": ""},
  "items": [{
    "metadata": {
      "name": "app", "namespace": "web", "uid": "uid-ing-1", "resourceVersion": "123",
      "annotations": {
        "traefik.ingress.kubernetes.io/router.entrypoints": "websecure-internal",
        "kubernetes.io/ingress.class": "traefik",
        "kubectl.kubernetes.io/last-applied-configuration": "{\"data\":\"manifest-body\"}",
        "example.test/anything": "x"
      },
      "managedFields": [{"manager": "kubectl"}]
    },
    "spec": {
      "ingressClassName": "traefik",
      "defaultBackend": {"service": {"name": "fallback", "port": {"number": 80}}},
      "tls": [{"hosts": ["app.example.test"], "secretName": "app-tls-secret"}],
      "rules": [
        {"host": "app.example.test", "http": {"paths": [
          {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "app", "port": {"number": 8080}}}},
          {"path": "/files", "pathType": "Exact", "backend": {"service": {"name": "files", "port": {"name": "http"}}}},
          {"path": "/bucket", "pathType": "ImplementationSpecific", "backend": {"resource": {"apiGroup": "example.test", "kind": "Bucket", "name": "b1"}}}
        ]}},
        {"host": "*.wild.example.test"}
      ]
    },
    "status": {"loadBalancer": {"ingress": [{"ip": "10.9.9.9"}]}}
  }]
}`

const serviceJSON = `{
  "kind": "ServiceList",
  "apiVersion": "v1",
  "metadata": {"resourceVersion": "901"},
  "items": [{
    "metadata": {"name": "app", "namespace": "web", "uid": "uid-svc-1", "resourceVersion": "55"},
    "spec": {
      "type": "LoadBalancer", "clusterIP": "10.43.0.10", "externalIPs": ["10.1.2.50"],
      "ports": [{"name": "http", "protocol": "TCP", "port": 80, "targetPort": 8080, "nodePort": 31080}],
      "selector": {"app": "app"}
    },
    "status": {"loadBalancer": {"ingress": [{"ip": "10.1.2.60"}, {"hostname": "lb.example.test"}]}}
  }, {
    "metadata": {"name": "ext", "namespace": "web", "uid": "uid-svc-2", "resourceVersion": "56"},
    "spec": {"type": "ExternalName", "externalName": "db.example.test"}
  }]
}`

const ingressClassJSON = `{
  "kind": "IngressClassList",
  "apiVersion": "networking.k8s.io/v1",
  "metadata": {"resourceVersion": "902"},
  "items": [{
    "metadata": {
      "name": "traefik", "uid": "uid-class-1", "resourceVersion": "7",
      "annotations": {"ingressclass.kubernetes.io/is-default-class": "true"}
    },
    "spec": {"controller": "traefik.io/ingress-controller", "parameters": {"kind": "Params", "name": "p"}}
  }]
}`

// AC6: Ingress, Service and IngressClass fixtures decode with route, class, namespace/UID/
// resourceVersion, pathType, backend and Service gate metadata; nothing that carries a Secret
// reference or manifest body is kept.
func TestK8sTypes_MetadataDecode(t *testing.T) {
	t.Run("ingress", func(t *testing.T) {
		got, err := decodeList[Ingress](strings.NewReader(ingressJSON), "IngressList")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := []Ingress{{
			Metadata: ObjectMeta{
				Name: "app", Namespace: "web", UID: "uid-ing-1", ResourceVersion: "123",
				Annotations: map[string]string{
					"traefik.ingress.kubernetes.io/router.entrypoints": "websecure-internal",
					"kubernetes.io/ingress.class":                      "traefik",
				},
			},
			Spec: IngressSpec{
				IngressClassName: "traefik",
				DefaultBackend:   &IngressBackend{Service: &ServiceBackend{Name: "fallback", Port: ServiceBackendPort{Number: 80}}},
				TLS:              []IngressTLS{{Hosts: []string{"app.example.test"}}},
				Rules: []IngressRule{
					{Host: "app.example.test", HTTP: &HTTPRuleValue{Paths: []HTTPPath{
						{Path: "/", PathType: "Prefix", Backend: IngressBackend{Service: &ServiceBackend{Name: "app", Port: ServiceBackendPort{Number: 8080}}}},
						{Path: "/files", PathType: "Exact", Backend: IngressBackend{Service: &ServiceBackend{Name: "files", Port: ServiceBackendPort{Name: "http"}}}},
						{Path: "/bucket", PathType: "ImplementationSpecific", Backend: IngressBackend{Resource: &ResourceRef{APIGroup: "example.test", Kind: "Bucket", Name: "b1"}}},
					}}},
					{Host: "*.wild.example.test"},
				},
			},
		}}
		if !reflect.DeepEqual(got.Items, want) {
			t.Fatalf("items = %+v\nwant   %+v", got.Items, want)
		}
		raw, _ := json.Marshal(got.Items)
		for _, leak := range []string{"app-tls-secret", "manifest-body", "managedFields", "example.test/anything"} {
			if strings.Contains(string(raw), leak) {
				t.Errorf("decoded metadata keeps %q: %s", leak, raw)
			}
		}
	})

	t.Run("service", func(t *testing.T) {
		got, err := decodeList[Service](strings.NewReader(serviceJSON), "ServiceList")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := []Service{{
			Metadata: ObjectMeta{Name: "app", Namespace: "web", UID: "uid-svc-1", ResourceVersion: "55"},
			Spec: ServiceSpec{
				Type: "LoadBalancer", ClusterIP: "10.43.0.10", ExternalIPs: []string{"10.1.2.50"},
				Ports: []ServicePort{{Name: "http", Protocol: "TCP", Port: 80, NodePort: 31080}},
			},
			Status: ServiceStatus{LoadBalancer: LoadBalancerStatus{Ingress: []LoadBalancerIngress{{IP: "10.1.2.60"}, {Hostname: "lb.example.test"}}}},
		}, {
			Metadata: ObjectMeta{Name: "ext", Namespace: "web", UID: "uid-svc-2", ResourceVersion: "56"},
			Spec:     ServiceSpec{Type: "ExternalName", ExternalName: "db.example.test"},
		}}
		if !reflect.DeepEqual(got.Items, want) {
			t.Fatalf("items = %+v\nwant   %+v", got.Items, want)
		}
	})

	t.Run("ingressclass", func(t *testing.T) {
		got, err := decodeList[IngressClass](strings.NewReader(ingressClassJSON), "IngressClassList")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := []IngressClass{{
			Metadata: ObjectMeta{
				Name: "traefik", UID: "uid-class-1", ResourceVersion: "7",
				Annotations: map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"},
			},
			Spec: IngressClassSpec{Controller: "traefik.io/ingress-controller"},
		}}
		if !reflect.DeepEqual(got.Items, want) {
			t.Fatalf("items = %+v\nwant   %+v", got.Items, want)
		}
	})

	t.Run("list envelope", func(t *testing.T) {
		got, err := decodeList[IngressClass](strings.NewReader(`{"kind":"IngressClassList","metadata":{"continue":"tok"},"items":null}`), "IngressClassList")
		if err != nil || got.Metadata.Continue != "tok" || len(got.Items) != 0 {
			t.Fatalf("got %+v, %v; want continue tok and no items", got, err)
		}
		for _, body := range []string{`{"kind":"IngressClassList","items":[]}`, `{"kind":"IngressClassList","metadata":{},"items":[]}`} {
			if got, err := decodeList[IngressClass](strings.NewReader(body), "IngressClassList"); err != nil || len(got.Items) != 0 {
				t.Errorf("%s: got %+v, %v; want an empty page", body, got, err)
			}
		}
	})

	t.Run("errors carry no response text", func(t *testing.T) {
		const echo = "secret-echo-value"
		echoes := func(err error) bool {
			for ; err != nil; err = errors.Unwrap(err) {
				if strings.Contains(err.Error(), echo) {
					return true
				}
			}
			return false
		}
		// Positive control: the check sees an echo anywhere in a wrapped chain.
		if !echoes(fmt.Errorf("outer: %w", fmt.Errorf("kind %q", echo))) {
			t.Fatal("control failed: echo not detected")
		}
		for name, body := range map[string]string{
			"wrong kind": `{"kind":"` + echo + `","items":[]}`,
			"bad value":  `{"kind":"IngressClassList","items":[{"metadata":{"name":"` + echo + `","uid":5}}]}`,
			"bad json":   `{"kind":"` + echo + `",`,
			"no items":   `{"kind":"IngressClassList","note":"` + echo + `"}`,
		} {
			_, err := decodeList[IngressClass](strings.NewReader(body), "IngressClassList")
			if err == nil {
				t.Errorf("%s: decode succeeded", name)
				continue
			}
			if echoes(err) {
				t.Errorf("%s: error %q echoes the response", name, err)
			}
		}
	})

	t.Run("rejects", func(t *testing.T) {
		for name, body := range map[string]string{
			"not json":                          `{nope`,
			"trailing":                          `{"kind":"IngressClassList","items":[]} {}`,
			"wrong kind":                        `{"kind":"ServiceList","items":[]}`,
			"missing kind":                      `{"items":[]}`,
			"missing items":                     `{"kind":"IngressClassList"}`,
			"missing items with empty continue": `{"kind":"IngressClassList","metadata":{"continue":""}}`,
			"bad type":                          `{"kind":"IngressClassList","items":[{"metadata":{"name":5}}]}`,
		} {
			if _, err := decodeList[IngressClass](strings.NewReader(body), "IngressClassList"); err == nil {
				t.Errorf("%s: decode succeeded, want an error", name)
			}
		}
	})
}
