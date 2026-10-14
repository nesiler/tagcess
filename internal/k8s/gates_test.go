package k8s

import (
	"reflect"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// Builders. Everything is in memory; the evaluation never touches a network
// (declared metadata only, F4-020 / R3 B-05 / ADR 0031).
// ---------------------------------------------------------------------------

const gateHost = "app.example.test"

func gateService(name, namespace, typ string, ports ...ServicePort) Service {
	s := Service{Metadata: ObjectMeta{Name: name, Namespace: namespace}}
	s.Spec.Type = typ
	s.Spec.Ports = ports
	return s
}

func gateInput(inv Inventory, hosts ...ManagedHost) GateInput {
	return GateInput{Inventory: inv, Profile: traefikProfile(), Hosts: hosts}
}

func gateInventory(entrypoints string, services []Service, rules ...IngressRule) Inventory {
	p := traefikProfile()
	return Inventory{
		Ingresses:      []Ingress{routeIngress("app", "web", "uid-app", "traefik", entrypoints, rules...)},
		Services:       services,
		IngressClasses: []IngressClass{routeClass("traefik", p.Controller, false)},
	}
}

func findGate(t *testing.T, cs []GateCandidate, kind GateKind) GateCandidate {
	t.Helper()
	for _, c := range cs {
		if c.Kind == kind {
			return c
		}
	}
	t.Fatalf("no %q candidate in %+v", kind, cs)
	return GateCandidate{}
}

// ---------------------------------------------------------------------------
// AC1
// ---------------------------------------------------------------------------

// AC1: a managed host whose route is bound to an entrypoint other than the declared internal one
// yields a wrong-entrypoint candidate with host/path/backend and the source Ingress. It is declared
// metadata: no network access is claimed.
func TestTwoGateCandidatesWrongEntryPoint(t *testing.T) {
	p := traefikProfile()
	managed := ManagedHost{Site: "app", Host: gateHost}
	rule := routeRule(gateHost, routePath("/files", "Prefix", "app", 8080))
	clusterIPApp := []Service{gateService("app", "web", "ClusterIP", ServicePort{Name: "http", Port: 8080})}

	t.Run("public entrypoint is a candidate with provenance", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure", clusterIPApp, rule), managed))
		var wrong []GateCandidate
		for _, c := range rep.Candidates {
			if c.Kind == GateWrongEntryPoint {
				wrong = append(wrong, c)
			}
		}
		if len(wrong) != 1 {
			t.Fatalf("candidates = %+v, want exactly one wrong-entrypoint candidate", rep.Candidates)
		}
		want := GateCandidate{
			Site: "app", Host: gateHost, Path: "/files", PathType: PathPrefix,
			Kind: GateWrongEntryPoint, Status: GateStatusCandidate,
			Namespace: "web", Ingress: "app", UID: "uid-app",
			Backend: Backend{Service: "app", PortNumber: 8080},
			Address: p.Public[0].Address, Port: p.Public[0].Port, EntryPoint: p.Public[0].EntryPoint,
			TLS: true, Reachability: ReachabilityNotMeasured, Basis: BasisDeclaredProfile,
		}
		if got := wrong[0]; !reflect.DeepEqual(got, want) {
			t.Fatalf("candidate = %+v\nwant       %+v", got, want)
		}
	})

	t.Run("an Ingress bound to both entrypoints flags only the other one", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal,websecure", clusterIPApp, rule), managed))
		var wrong []GateCandidate
		for _, c := range rep.Candidates {
			if c.Kind == GateWrongEntryPoint {
				wrong = append(wrong, c)
			}
		}
		if len(wrong) != 1 || wrong[0].EntryPoint != "websecure" {
			t.Fatalf("candidates = %+v, want one for the public entrypoint only", rep.Candidates)
		}
		if !slices.Contains(wrong[0].Context, ContextCaddyProxy) {
			t.Errorf("context = %v, want the expected Caddy to internal proxy named", wrong[0].Context)
		}
	})

	t.Run("internal entrypoint only is no candidate", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal", clusterIPApp, rule), managed))
		if len(rep.Candidates) != 0 {
			t.Fatalf("candidates = %+v, want none", rep.Candidates)
		}
	})

	t.Run("unmanaged host is not evaluated", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure", clusterIPApp, rule), ManagedHost{Site: "other", Host: "other.example.test"}))
		if len(rep.Candidates) != 0 {
			t.Fatalf("candidates = %+v, want none for an unmanaged host", rep.Candidates)
		}
	})

	t.Run("host match ignores case", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure", clusterIPApp, rule), ManagedHost{Site: "app", Host: "APP.Example.Test"}))
		if len(rep.Candidates) != 1 {
			t.Fatalf("candidates = %+v, want one", rep.Candidates)
		}
	})
}

// AC1: the backend Service's LoadBalancer, NodePort and externalIPs paths are candidates bound to the
// route's host/path/backend; a Service that is only ClusterIP, or one in another namespace, is not.
func TestTwoGateCandidatesServiceExposurePaths(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	rule := routeRule(gateHost, routePath("/", "Prefix", "app", 80))
	port := func(extra ServicePort) ServicePort {
		extra.Name, extra.Port, extra.Protocol = "http", 80, "TCP"
		return extra
	}
	lb := func(ip, hostname string) Service {
		s := gateService("app", "web", "LoadBalancer", port(ServicePort{}))
		s.Status.LoadBalancer.Ingress = []LoadBalancerIngress{{IP: ip, Hostname: hostname}}
		return s
	}

	cases := []struct {
		name     string
		services []Service
		nodes    []string
		want     []GateCandidate // Kind, Address, Port compared
	}{
		{
			name:     "load balancer address",
			services: []Service{lb("198.51.100.7", "")},
			want:     []GateCandidate{{Kind: GateLoadBalancer, Address: "198.51.100.7", Port: 80}},
		},
		{
			name:     "load balancer hostname only",
			services: []Service{lb("", "lb.example.test")},
			want:     []GateCandidate{{Kind: GateLoadBalancer, Address: "lb.example.test", Port: 80}},
		},
		{
			name:     "load balancer without a reported address is still a candidate, not measurable",
			services: []Service{gateService("app", "web", "LoadBalancer", port(ServicePort{}))},
			want:     []GateCandidate{{Kind: GateLoadBalancer, Address: "", Port: 80}},
		},
		{
			name: "load balancer with an allocated node port is also a node port candidate", // B-M-5
			services: func() []Service {
				s := lb("198.51.100.7", "")
				s.Spec.Ports[0].NodePort = 30090
				return []Service{s}
			}(),
			nodes: []string{"10.0.0.21"},
			want: []GateCandidate{
				{Kind: GateLoadBalancer, Address: "198.51.100.7", Port: 80},
				{Kind: GateNodePort, Address: "10.0.0.21", Port: 30090},
			},
		},
		{
			name:     "node port uses the approved node addresses",
			services: []Service{gateService("app", "web", "NodePort", port(ServicePort{NodePort: 30080}))},
			nodes:    []string{"10.0.0.21", "10.0.0.22"},
			want: []GateCandidate{
				{Kind: GateNodePort, Address: "10.0.0.21", Port: 30080},
				{Kind: GateNodePort, Address: "10.0.0.22", Port: 30080},
			},
		},
		{
			name:     "node port without approved node addresses is not measurable",
			services: []Service{gateService("app", "web", "NodePort", port(ServicePort{NodePort: 30080}))},
			want:     []GateCandidate{{Kind: GateNodePort, Address: "", Port: 30080}},
		},
		{
			name: "external IPs",
			services: func() []Service {
				s := gateService("app", "web", "ClusterIP", port(ServicePort{}))
				s.Spec.ExternalIPs = []string{"192.0.2.9", "192.0.2.10"}
				return []Service{s}
			}(),
			want: []GateCandidate{
				{Kind: GateExternalIP, Address: "192.0.2.10", Port: 80},
				{Kind: GateExternalIP, Address: "192.0.2.9", Port: 80},
			},
		},
		{
			name:     "node port type without an allocated node port",
			services: []Service{gateService("app", "web", "NodePort", port(ServicePort{}))},
			nodes:    []string{"10.0.0.21"},
		},
		{
			name:     "cluster IP only",
			services: []Service{gateService("app", "web", "ClusterIP", port(ServicePort{}))},
		},
		{
			name:     "same name in another namespace is another Service",
			services: []Service{gateService("app", "other", "NodePort", port(ServicePort{NodePort: 30080})), gateService("app", "web", "ClusterIP", port(ServicePort{}))},
			nodes:    []string{"10.0.0.21"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gateInput(gateInventory("websecure-internal", tc.services, rule), managed)
			in.NodeAddresses = tc.nodes
			rep := EvaluateGates(in)
			if len(rep.Candidates) != len(tc.want) {
				t.Fatalf("candidates = %+v, want %d", rep.Candidates, len(tc.want))
			}
			for i, w := range tc.want {
				got := rep.Candidates[i]
				if got.Kind != w.Kind || got.Address != w.Address || got.Port != w.Port {
					t.Errorf("candidate %d = %s %q:%d, want %s %q:%d", i, got.Kind, got.Address, got.Port, w.Kind, w.Address, w.Port)
				}
				// Provenance and no invented network evidence.
				if got.Host != gateHost || got.Path != "/" || got.Backend != (Backend{Service: "app", PortNumber: 80}) ||
					got.Namespace != "web" || got.Ingress != "app" || got.UID != "uid-app" {
					t.Errorf("candidate %d lost host/path/backend/source: %+v", i, got)
				}
				if got.Status != GateStatusCandidate || got.Reachability != ReachabilityNotMeasured || got.Basis != BasisDeclaredProfile {
					t.Errorf("candidate %d status/reachability/basis = %q/%q/%q", i, got.Status, got.Reachability, got.Basis)
				}
			}
		})
	}

	t.Run("named backend port picks the matching Service port", func(t *testing.T) {
		svc := gateService("app", "web", "NodePort",
			ServicePort{Name: "metrics", Port: 9090, NodePort: 30090},
			ServicePort{Name: "web", Port: 8080, NodePort: 30088})
		named := routeRule(gateHost, HTTPPath{
			Path: "/", PathType: "Prefix",
			Backend: IngressBackend{Service: &ServiceBackend{Name: "app", Port: ServiceBackendPort{Name: "web"}}},
		})
		in := gateInput(gateInventory("websecure-internal", []Service{svc}, named), managed)
		in.NodeAddresses = []string{"10.0.0.21"}
		rep := EvaluateGates(in)
		if len(rep.Candidates) != 1 || rep.Candidates[0].Port != 30088 {
			t.Fatalf("candidates = %+v, want the node port of the named port only", rep.Candidates)
		}
	})
}

// ---------------------------------------------------------------------------
// AC2
// ---------------------------------------------------------------------------

// AC2: the expected Caddy to internal proxy, an intentional open site and an API exemption are named
// next to the alternative path; none of them removes the candidate or its risk.
func TestTwoGateCandidatesExpectedProxyAndExemptions(t *testing.T) {
	rule := routeRule(gateHost, routePath("/", "Prefix", "app", 80))
	svc := gateService("app", "web", "ClusterIP", ServicePort{Name: "http", Port: 80})
	svc.Spec.ExternalIPs = []string{"192.0.2.9"}
	plain := ManagedHost{Site: "app", Host: gateHost}

	t.Run("expected proxy only", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal", []Service{svc}, rule), plain))
		c := findGate(t, rep.Candidates, GateExternalIP)
		if c.Status != GateStatusCandidate || !slices.Equal(c.Context, []GateContext{ContextCaddyProxy}) {
			t.Fatalf("candidate = %+v, want a candidate with the Caddy proxy context only", c)
		}
	})

	t.Run("intentional open and API exemption are named, risk stays", func(t *testing.T) {
		h := ManagedHost{Site: "app", Host: gateHost, IntentionalOpen: true, APIExemption: true}
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal,websecure", []Service{svc}, rule), h))
		if len(rep.Candidates) != 2 {
			t.Fatalf("candidates = %+v, want the entrypoint and the external IP candidate", rep.Candidates)
		}
		want := []GateContext{ContextCaddyProxy, ContextIntentionalOpen, ContextAPIExemption}
		for _, c := range rep.Candidates {
			if c.Status != GateStatusCandidate {
				t.Errorf("%s status = %q, an expected context must not clear the candidate", c.Kind, c.Status)
			}
			if !slices.Equal(c.Context, want) {
				t.Errorf("%s context = %v, want %v", c.Kind, c.Context, want)
			}
		}
	})

	t.Run("an internal route to another backend is not the expected proxy", func(t *testing.T) {
		inv := gateInventory("websecure-internal", []Service{svc}, rule)
		inv.Ingresses = append(inv.Ingresses, routeIngress("other", "web", "uid-other", "traefik", "websecure",
			routeRule(gateHost, routePath("/other", "Prefix", "other", 80))))
		inv.Services = append(inv.Services, gateService("other", "web", "ClusterIP", ServicePort{Port: 80}))
		rep := EvaluateGates(gateInput(inv, plain))
		for _, c := range rep.Candidates {
			if c.Backend.Service == "other" && slices.Contains(c.Context, ContextCaddyProxy) {
				t.Errorf("%s for backend %q names an expected proxy that points elsewhere", c.Kind, c.Backend.Service)
			}
		}
		if len(rep.Candidates) == 0 {
			t.Fatal("no candidates, test is vacuous")
		}
	})

	t.Run("no internal route, no expected proxy context", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure", []Service{svc}, rule), plain))
		for _, c := range rep.Candidates {
			if slices.Contains(c.Context, ContextCaddyProxy) {
				t.Errorf("%s names an expected proxy although the host has no internal route", c.Kind)
			}
		}
	})
}

// AC2: a profile that cannot say which entrypoint is internal, a route conflict and an Ingress the
// profile cannot interpret leave the finding unknown, never a confirmed candidate or a clean result.
func TestTwoGateCandidatesIncompleteProfileIsUnknown(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	rule := routeRule(gateHost, routePath("/", "Prefix", "app", 80))

	t.Run("profile without internal listener", func(t *testing.T) {
		in := gateInput(gateInventory("websecure", nil, rule), managed)
		in.Profile.Internal = nil
		rep := EvaluateGates(in)
		c := findGate(t, rep.Candidates, GateWrongEntryPoint)
		if c.Status != GateStatusUnknown || !slices.Contains(c.Reasons, ReasonProfileIncomplete) {
			t.Fatalf("candidate = %+v, want unknown with %q", c, ReasonProfileIncomplete)
		}
	})

	t.Run("route conflict", func(t *testing.T) {
		inv := gateInventory("websecure", nil, routeRule(gateHost,
			routePath("/a", "Prefix", "svc1", 80), routePath("/a/b", "Prefix", "svc2", 80)))
		svc2 := gateService("svc2", "web", "LoadBalancer", ServicePort{Port: 80})
		svc2.Status.LoadBalancer.Ingress = []LoadBalancerIngress{{IP: "198.51.100.7"}}
		inv.Services = []Service{
			gateService("svc1", "web", "ClusterIP", ServicePort{Port: 80}),
			svc2, // B-L-9: a Service candidate of a conflicting route is downgraded too
		}
		rep := EvaluateGates(gateInput(inv, managed))
		if len(rep.Candidates) != 3 || !slices.ContainsFunc(rep.Candidates, func(c GateCandidate) bool { return c.Kind == GateLoadBalancer }) {
			t.Fatalf("candidates = %+v, want both conflicting routes kept (two wrong-entrypoint, one load balancer)", rep.Candidates)
		}
		for _, c := range rep.Candidates {
			if c.Status != GateStatusUnknown || !slices.Contains(c.Reasons, ReasonRouteConflict) {
				t.Errorf("candidate = %+v, want unknown with %q", c, ReasonRouteConflict)
			}
		}
	})

	t.Run("Ingress the profile cannot interpret", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("mystery", nil, rule), managed))
		if len(rep.Candidates) != 1 {
			t.Fatalf("candidates = %+v, want one unknown candidate", rep.Candidates)
		}
		c := rep.Candidates[0]
		if c.Kind != GateUnresolved || c.Status != GateStatusUnknown || !slices.Contains(c.Reasons, ReasonEntryPointUnresolved) ||
			c.Ingress != "app" || c.UID != "uid-app" || c.Host != gateHost {
			t.Fatalf("candidate = %+v, want an unresolved unknown carrying the review reason and source", c)
		}
	})

	t.Run("backend Service missing from the snapshot", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal", nil, rule), managed))
		if len(rep.Candidates) != 1 {
			t.Fatalf("candidates = %+v, want one unknown candidate (the Service cannot be judged)", rep.Candidates)
		}
		c := rep.Candidates[0]
		if c.Kind != GateUnresolved || c.Status != GateStatusUnknown || !slices.Contains(c.Reasons, ReasonServiceNotInSnapshot) {
			t.Fatalf("candidate = %+v", c)
		}
	})

	t.Run("backend port the Service does not have", func(t *testing.T) {
		svc := gateService("app", "web", "NodePort", ServicePort{Name: "http", Port: 8080, NodePort: 30080})
		rep := EvaluateGates(gateInput(gateInventory("websecure-internal", []Service{svc}, rule), managed))
		if len(rep.Candidates) != 1 || rep.Candidates[0].Status != GateStatusUnknown ||
			!slices.Contains(rep.Candidates[0].Reasons, ReasonServicePortUnresolved) {
			t.Fatalf("candidates = %+v, want one unknown with %q", rep.Candidates, ReasonServicePortUnresolved)
		}
	})
}

// ---------------------------------------------------------------------------
// AC7
// ---------------------------------------------------------------------------

// AC7: the report says what was not scanned (Gateway API, Traefik CRDs, other controllers,
// hostNetwork and other paths) even with zero candidates, never offers a universal safe result and
// leaves its input untouched (the evaluation has no write path).
func TestTwoGateCandidatesUnscannedScopeAndNoWrites(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	rule := routeRule(gateHost, routePath("/", "Prefix", "app", 80))
	svc := gateService("app", "web", "ClusterIP", ServicePort{Name: "http", Port: 80})

	for name, inv := range map[string]Inventory{
		"empty inventory":     {},
		"clean internal-only": gateInventory("websecure-internal", []Service{svc}, rule),
	} {
		t.Run(name, func(t *testing.T) {
			in := gateInput(inv, managed)
			before := gateInput(inv, managed)
			rep := EvaluateGates(in)
			if len(rep.Candidates) != 0 {
				t.Fatalf("candidates = %+v, want none", rep.Candidates)
			}
			if rep.Scope.Conclusive {
				t.Fatal("report claims a conclusive/safe result")
			}
			for _, want := range []ScopeItem{UnscannedGatewayAPI, UnscannedTraefikCRD, UnscannedOtherController, UnscannedOtherPaths} {
				if !slices.Contains(rep.Scope.Unscanned, want) {
					t.Errorf("unscanned = %v, want %q", rep.Scope.Unscanned, want)
				}
			}
			labels := rep.Scope.UnscannedLabels()
			for _, want := range []string{"gateway", "crd", "other_controller", "hostnetwork"} {
				if !slices.Contains(labels, want) {
					t.Errorf("labels = %v, want %q", labels, want)
				}
			}
			if !reflect.DeepEqual(in, before) {
				t.Error("EvaluateGates changed its input")
			}
		})
	}

	t.Run("candidates carry the scope too", func(t *testing.T) {
		rep := EvaluateGates(gateInput(gateInventory("websecure", nil, rule), managed))
		if len(rep.Candidates) == 0 || !reflect.DeepEqual(rep.Scope, FirstProfileScope()) {
			t.Fatalf("report = %+v, want candidates under the first profile scope", rep)
		}
	})
}

// B-M-5: a public route of another host to the same backend Service is another way to the managed
// host's backend and must not be dropped.
func TestTwoGateCandidatesSameBackendOtherHost(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	p := traefikProfile()
	svc := gateService("app", "web", "ClusterIP", ServicePort{Port: 80})
	inv := Inventory{
		Ingresses: []Ingress{
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule(gateHost, routePath("/", "Prefix", "app", 80))),
			routeIngress("pub", "web", "uid-pub", "traefik", "websecure", routeRule("other.example.test", routePath("/p", "Prefix", "app", 80))),
			routeIngress("unrelated", "web", "uid-un", "traefik", "websecure", routeRule("third.example.test", routePath("/", "Prefix", "elsewhere", 80))),
		},
		Services:       []Service{svc, gateService("elsewhere", "web", "ClusterIP", ServicePort{Port: 80})},
		IngressClasses: []IngressClass{routeClass("traefik", p.Controller, false)},
	}
	rep := EvaluateGates(gateInput(inv, managed))
	var got []GateCandidate
	for _, c := range rep.Candidates {
		if c.Kind == GateWrongEntryPoint {
			got = append(got, c)
		}
	}
	if len(got) != 1 || got[0].Host != "other.example.test" || got[0].Path != "/p" || got[0].Site != "app" || got[0].Ingress != "pub" || got[0].EntryPoint != "websecure" {
		t.Fatalf("wrong-entrypoint candidates = %+v, want only the other host's public route to the same backend", got)
	}
}

// B-M-6: wildcard, empty-host and default-backend Ingresses can serve the managed host, so the finding
// is unknown for it; a wildcard for a different zone or depth does not.
func TestTwoGateCandidatesCatchAllIngressesAreUnknown(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	p := traefikProfile()
	build := func(extra Ingress) GateReport {
		inv := Inventory{
			Ingresses:      []Ingress{routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule(gateHost, routePath("/", "Prefix", "app", 80))), extra},
			Services:       []Service{gateService("app", "web", "ClusterIP", ServicePort{Port: 80})},
			IngressClasses: []IngressClass{routeClass("traefik", p.Controller, false)},
		}
		return EvaluateGates(gateInput(inv, managed))
	}
	unresolved := func(rep GateReport) (GateCandidate, bool) {
		for _, c := range rep.Candidates {
			if c.Kind == GateUnresolved && c.Status == GateStatusUnknown && c.Ingress != "app" {
				return c, true
			}
		}
		return GateCandidate{}, false
	}
	defBackend := routeIngress("defbe", "web", "uid-defbe", "traefik", "websecure", routeRule("x.example.test", routePath("/", "Prefix", "app", 80)))
	defBackend.Spec.DefaultBackend = &IngressBackend{Service: &ServiceBackend{Name: "app", Port: ServiceBackendPort{Number: 80}}}

	covered := map[string]struct {
		ing  Ingress
		want Reason
	}{
		"single-label wildcard": {routeIngress("wild", "web", "uid-wild", "traefik", "websecure", routeRule("*.example.test", routePath("/", "Prefix", "app", 80))), ReasonWildcardHost},
		"empty host":            {routeIngress("empty", "web", "uid-empty", "traefik", "websecure", routeRule("", routePath("/", "Prefix", "app", 80))), ReasonEmptyHost},
		"default backend":       {defBackend, ReasonDefaultBackend},
	}
	for name, tc := range covered {
		t.Run(name+" covers the managed host", func(t *testing.T) {
			c, ok := unresolved(build(tc.ing))
			if !ok || !slices.Contains(c.Reasons, tc.want) || c.Host != gateHost {
				t.Fatalf("candidate = %+v (found %v), want unknown for %s with %q", c, ok, gateHost, tc.want)
			}
		})
	}
	for name, host := range map[string]string{"another zone": "*.other.test", "two labels deep": "*.app.example.test"} {
		t.Run(name+" does not", func(t *testing.T) {
			ing := routeIngress("wild", "web", "uid-wild", "traefik", "websecure", routeRule(host, routePath("/", "Prefix", "app", 80)))
			if c, ok := unresolved(build(ing)); ok {
				t.Fatalf("candidate = %+v, want none for %s", c, host)
			}
		})
	}
}

// F5 I3: without a declared public listener the internet-exposure check is not performed: the report
// says so and produces no candidates (no invented result). With one declared it still works.
func TestEvaluateGates_NoPublicListenerSkipsExposureCheck(t *testing.T) {
	managed := ManagedHost{Site: "app", Host: gateHost}
	rule := routeRule(gateHost, routePath("/files", "Prefix", "app", 8080))
	clusterIPApp := []Service{gateService("app", "web", "ClusterIP", ServicePort{Name: "http", Port: 8080})}
	in := gateInput(gateInventory("websecure", clusterIPApp, rule), managed)

	with := EvaluateGates(in)
	if !with.PublicChecked || len(with.Candidates) == 0 {
		t.Fatalf("with a public listener: PublicChecked=%v candidates=%d, want the check to run", with.PublicChecked, len(with.Candidates))
	}

	in.Profile.Public = nil
	without := EvaluateGates(in)
	if without.PublicChecked {
		t.Error("PublicChecked = true without a public listener")
	}
	if len(without.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none when the exposure check was not performed", without.Candidates)
	}
}
