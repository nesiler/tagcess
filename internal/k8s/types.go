package k8s

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// The types below are the part of the Kubernetes REST objects the first F4 profile reads
// (networking.k8s.io/v1 Ingress and IngressClass, core/v1 Service). Field names and JSON tags follow
// the API, so a decoded object reads like the manifest. Nothing here asks for or keeps Secret
// content: an Ingress TLS entry keeps its hosts but not its secretName, and annotations are limited
// to the few that name a class or a Traefik entry point (see keepAnnotation).

// ObjectMeta is the identity of an object and the version it was read at.
type ObjectMeta struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// keepAnnotation reports whether an annotation is class or entry-point metadata. Everything else
// (for example kubectl's last-applied manifest) can hold arbitrary text and is dropped.
func keepAnnotation(key string) bool {
	switch key {
	case "kubernetes.io/ingress.class", "ingressclass.kubernetes.io/is-default-class":
		return true
	}
	return strings.HasPrefix(key, "traefik.ingress.kubernetes.io/")
}

// UnmarshalJSON decodes the metadata and keeps only the allowed annotations.
func (m *ObjectMeta) UnmarshalJSON(b []byte) error {
	type plain ObjectMeta
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	kept := map[string]string{}
	for k, v := range p.Annotations {
		if keepAnnotation(k) {
			kept[k] = v
		}
	}
	p.Annotations = nil
	if len(kept) > 0 {
		p.Annotations = kept
	}
	*m = ObjectMeta(p)
	return nil
}

// Ingress is a networking.k8s.io/v1 Ingress.
type Ingress struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     IngressSpec `json:"spec"`
}

// IngressSpec holds the class and the routes. The class name alone says nothing about which
// controller serves the Ingress or whether it is internal or public.
type IngressSpec struct {
	IngressClassName string          `json:"ingressClassName,omitempty"`
	DefaultBackend   *IngressBackend `json:"defaultBackend,omitempty"`
	TLS              []IngressTLS    `json:"tls,omitempty"`
	Rules            []IngressRule   `json:"rules,omitempty"`
}

// IngressTLS lists the hosts a TLS entry covers. The certificate Secret's name is not kept.
type IngressTLS struct {
	Hosts []string `json:"hosts,omitempty"`
}

// IngressRule is one host (possibly empty or a wildcard) and its paths.
type IngressRule struct {
	Host string         `json:"host,omitempty"`
	HTTP *HTTPRuleValue `json:"http,omitempty"`
}

// HTTPRuleValue is the list of paths of a rule.
type HTTPRuleValue struct {
	Paths []HTTPPath `json:"paths,omitempty"`
}

// HTTPPath is a path, its match type (Exact, Prefix or ImplementationSpecific) and its backend.
type HTTPPath struct {
	Path     string         `json:"path,omitempty"`
	PathType string         `json:"pathType,omitempty"`
	Backend  IngressBackend `json:"backend"`
}

// IngressBackend is a Service or, for an unsupported kind, a resource reference.
type IngressBackend struct {
	Service  *ServiceBackend `json:"service,omitempty"`
	Resource *ResourceRef    `json:"resource,omitempty"`
}

// ServiceBackend names a Service and the port by name or number.
type ServiceBackend struct {
	Name string             `json:"name,omitempty"`
	Port ServiceBackendPort `json:"port"`
}

// ServiceBackendPort is a port name or a number; one of them is set.
type ServiceBackendPort struct {
	Name   string `json:"name,omitempty"`
	Number int    `json:"number,omitempty"`
}

// ResourceRef is a non-Service backend (a typed local object reference).
type ResourceRef struct {
	APIGroup string `json:"apiGroup,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Service is a core/v1 Service. Type, ports, external IPs and the load balancer status are the
// candidate gates; none of them proves reachability.
type Service struct {
	Metadata ObjectMeta    `json:"metadata"`
	Spec     ServiceSpec   `json:"spec"`
	Status   ServiceStatus `json:"status"`
}

// ServiceSpec is the gate-relevant part of a Service spec.
type ServiceSpec struct {
	Type         string        `json:"type,omitempty"`
	ClusterIP    string        `json:"clusterIP,omitempty"`
	ExternalName string        `json:"externalName,omitempty"`
	ExternalIPs  []string      `json:"externalIPs,omitempty"`
	Ports        []ServicePort `json:"ports,omitempty"`
}

// ServicePort is one Service port.
type ServicePort struct {
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	NodePort int    `json:"nodePort,omitempty"`
}

// ServiceStatus carries the load balancer status.
type ServiceStatus struct {
	LoadBalancer LoadBalancerStatus `json:"loadBalancer"`
}

// LoadBalancerStatus lists the addresses the load balancer reports.
type LoadBalancerStatus struct {
	Ingress []LoadBalancerIngress `json:"ingress,omitempty"`
}

// LoadBalancerIngress is one reported load balancer address.
type LoadBalancerIngress struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// IngressClass is a cluster-scoped networking.k8s.io/v1 IngressClass.
type IngressClass struct {
	Metadata ObjectMeta       `json:"metadata"`
	Spec     IngressClassSpec `json:"spec"`
}

// IngressClassSpec names the controller that implements the class.
type IngressClassSpec struct {
	Controller string `json:"controller,omitempty"`
}

// list is one page of a Kubernetes list response.
type list[T any] struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []T `json:"items"`
}

// Decode failures are these fixed errors and never carry response text (a wrong "kind" or a
// malformed value could echo anything the server sent, including the bearer value).
var (
	errBadJSON      = errors.New("list response is not valid JSON for this resource")
	errTrailingData = errors.New("list response has trailing data")
	errWrongKind    = errors.New("list response has a different kind")
	errNoItems      = errors.New("list response has no items field")
)

// decodeList decodes one list page. The list kind must be wantKind, so an answer for another
// resource is never taken for an empty list of this one, and the items field must be present
// (empty or null is a valid empty page), so a bare {"kind":...} is never an empty inventory.
func decodeList[T any](r io.Reader, wantKind string) (list[T], error) {
	var raw struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items json.RawMessage `json:"items"` // nil only when the field is absent
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return list[T]{}, errBadJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return list[T]{}, errTrailingData
	}
	if raw.Kind != wantKind {
		return list[T]{}, errWrongKind
	}
	if raw.Items == nil {
		return list[T]{}, errNoItems
	}
	l := list[T]{Kind: raw.Kind}
	l.Metadata.Continue = raw.Metadata.Continue
	if err := json.Unmarshal(raw.Items, &l.Items); err != nil {
		return list[T]{}, errBadJSON
	}
	return l, nil
}
