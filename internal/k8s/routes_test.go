package k8s

import (
	"reflect"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// Test builders. Everything is built in memory: no cluster, no credential, no
// network (the first F4 profile only interprets declared metadata).
// ---------------------------------------------------------------------------

func traefikProfile() Profile {
	return Profile{
		Controller:     "traefik.io/ingress-controller",
		IngressClasses: []string{"traefik"},
		Namespaces:     []string{"web"},
		Internal:       []Listener{{Address: "10.0.0.10", Port: 443, EntryPoint: "websecure-internal"}},
		Public:         []Listener{{Address: "203.0.113.10", Port: 443, EntryPoint: "websecure"}},
	}
}

func routeClass(name, controller string, isDefault bool) IngressClass {
	c := IngressClass{Metadata: ObjectMeta{Name: name, UID: "uid-class-" + name}}
	c.Spec.Controller = controller
	if isDefault {
		c.Metadata.Annotations = map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"}
	}
	return c
}

func routePath(path, pathType, service string, port int) HTTPPath {
	return HTTPPath{
		Path: path, PathType: pathType,
		Backend: IngressBackend{Service: &ServiceBackend{Name: service, Port: ServiceBackendPort{Number: port}}},
	}
}

func routeRule(host string, paths ...HTTPPath) IngressRule {
	return IngressRule{Host: host, HTTP: &HTTPRuleValue{Paths: paths}}
}

func routeIngress(name, namespace, uid, class, entrypoints string, rules ...IngressRule) Ingress {
	ing := Ingress{Metadata: ObjectMeta{Name: name, Namespace: namespace, UID: uid}}
	ing.Spec.IngressClassName = class
	if entrypoints != "" {
		ing.Metadata.Annotations = map[string]string{
			"traefik.ingress.kubernetes.io/router.entrypoints": entrypoints,
		}
	}
	ing.Spec.Rules = rules
	return ing
}

func hasReason(us []Uncertainty, want Reason) bool {
	for _, u := range us {
		if slices.Contains(u.Reasons, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AC1
// ---------------------------------------------------------------------------

// AC1: a standard Ingress that agrees with the profile's declared class/controller
// and listener mapping is bound to that listener with namespace/UID/host/path/backend
// provenance. The route is declared metadata, never proof of real network access.
func TestTraefikRoutes_ProfileMetadataMapping(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}
	internal := p.Internal[0]
	public := p.Public[0]

	t.Run("explicit class binds the internal listener", func(t *testing.T) {
		ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/files", "Prefix", "app", 8080)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)

		want := Route{
			Namespace: "web", Ingress: "app", UID: "uid-app",
			Host: "app.example.test", Path: "/files", PathType: PathPrefix,
			Backend:  Backend{Service: "app", PortNumber: 8080},
			Listener: internal, Basis: BasisDeclaredProfile,
		}
		if len(rep.Routes) != 1 {
			t.Fatalf("routes = %+v, want exactly one", rep.Routes)
		}
		if got := rep.Routes[0]; !reflect.DeepEqual(got, want) {
			t.Fatalf("route = %+v\nwant   %+v", got, want)
		}
		if len(rep.Uncertainties) != 0 || len(rep.Conflicts) != 0 {
			t.Fatalf("unexpected uncertainty/conflict: %+v %+v", rep.Uncertainties, rep.Conflicts)
		}
	})

	t.Run("public entrypoint binds the public listener", func(t *testing.T) {
		ing := routeIngress("app", "web", "uid-app", "traefik", "websecure",
			routeRule("app.example.test", routePath("/", "Prefix", "app", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
		if len(rep.Routes) != 1 || !reflect.DeepEqual(rep.Routes[0].Listener, public) {
			t.Fatalf("routes = %+v, want one bound to %+v", rep.Routes, public)
		}
	})

	t.Run("unique default class is resolved", func(t *testing.T) {
		ing := routeIngress("app", "web", "uid-app", "", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Exact", "app", 80)))
		def := []IngressClass{routeClass("traefik", p.Controller, true)}
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: def}, p)
		if len(rep.Routes) != 1 {
			t.Fatalf("routes = %+v, want one after default-class resolution", rep.Routes)
		}
	})

	t.Run("profile metadata is not network evidence", func(t *testing.T) {
		ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "app", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
		for _, r := range rep.Routes {
			if r.Basis != BasisDeclaredProfile {
				t.Fatalf("route basis = %q, want declared profile only", r.Basis)
			}
		}
		if rep.Scope.Conclusive {
			t.Fatal("scope must not claim a conclusive/safe result")
		}
	})
}

// ---------------------------------------------------------------------------
// AC2
// ---------------------------------------------------------------------------

// AC2: ambiguous class/default class, a different controller, an unresolvable
// entryPoint, wildcard/empty host, resource backend, defaultBackend or an
// ImplementationSpecific path yields a review-needed uncertainty, not a route.
func TestTraefikRoutes_AmbiguousMetadataRequiresReview(t *testing.T) {
	p := traefikProfile()
	goodClass := []IngressClass{routeClass("traefik", p.Controller, false)}
	okPath := routePath("/", "Prefix", "app", 80)

	resourceBackendPath := HTTPPath{
		Path: "/bucket", PathType: "Prefix",
		Backend: IngressBackend{Resource: &ResourceRef{APIGroup: "example.test", Kind: "Bucket", Name: "b1"}},
	}

	cases := []struct {
		name    string
		ing     Ingress
		classes []IngressClass
		want    Reason
	}{
		{
			"no class and no default class",
			routeIngress("app", "web", "uid-app", "", "websecure-internal", routeRule("app.example.test", okPath)),
			goodClass, ReasonClassAmbiguous,
		},
		{
			"two default classes",
			routeIngress("app", "web", "uid-app", "", "websecure-internal", routeRule("app.example.test", okPath)),
			[]IngressClass{routeClass("traefik", p.Controller, true), routeClass("traefik2", p.Controller, true)},
			ReasonClassAmbiguous,
		},
		{
			"spec class and annotation disagree",
			func() Ingress {
				ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("app.example.test", okPath))
				ing.Metadata.Annotations["kubernetes.io/ingress.class"] = "other"
				return ing
			}(),
			goodClass, ReasonClassAmbiguous,
		},
		{
			"class not covered by the profile",
			routeIngress("app", "web", "uid-app", "nginx", "websecure-internal", routeRule("app.example.test", okPath)),
			[]IngressClass{routeClass("nginx", "k8s.io/ingress-nginx", false)}, ReasonClassUnknown,
		},
		{
			"controller differs from the profile",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("app.example.test", okPath)),
			[]IngressClass{routeClass("traefik", "other.example/controller", false)}, ReasonControllerMismatch,
		},
		{
			"entryPoint is not a declared listener",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-nope", routeRule("app.example.test", okPath)),
			goodClass, ReasonEntryPointUnresolved,
		},
		{
			"entryPoint is missing",
			routeIngress("app", "web", "uid-app", "traefik", "", routeRule("app.example.test", okPath)),
			goodClass, ReasonEntryPointUnresolved,
		},
		{
			"wildcard host",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("*.example.test", okPath)),
			goodClass, ReasonWildcardHost,
		},
		{
			"empty host",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("", okPath)),
			goodClass, ReasonEmptyHost,
		},
		{
			"resource backend",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("app.example.test", resourceBackendPath)),
			goodClass, ReasonResourceBackend,
		},
		{
			"implementation specific path",
			routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("app.example.test", routePath("/x", "ImplementationSpecific", "app", 80))),
			goodClass, ReasonImplementationSpecific,
		},
		{
			"default backend",
			func() Ingress {
				ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal", routeRule("app.example.test", okPath))
				ing.Spec.DefaultBackend = &IngressBackend{Service: &ServiceBackend{Name: "fallback", Port: ServiceBackendPort{Number: 80}}}
				return ing
			}(),
			goodClass, ReasonDefaultBackend,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := InterpretRoutes(Inventory{Ingresses: []Ingress{tc.ing}, IngressClasses: tc.classes}, p)
			if len(rep.Routes) != 0 {
				t.Fatalf("routes = %+v, want none (must stay uncertain)", rep.Routes)
			}
			if !hasReason(rep.Uncertainties, tc.want) {
				t.Fatalf("uncertainties = %+v, want reason %q", rep.Uncertainties, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AC3
// ---------------------------------------------------------------------------

// AC3: under the same ingress and host, path overlap follows Exact/Prefix
// boundaries across all ingresses of a listener and host; a different listener, host or disjoint paths is not a conflict by itself.
func TestTraefikRoutes_PathOverlapSemantics(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	cases := []struct {
		name         string
		a, b         HTTPPath
		wantConflict bool
	}{
		{"same exact path to different backends", routePath("/a", "Exact", "svc1", 80), routePath("/a", "Exact", "svc2", 80), true},
		{"different exact paths", routePath("/a", "Exact", "svc1", 80), routePath("/b", "Exact", "svc2", 80), false},
		{"disjoint prefixes", routePath("/a", "Prefix", "svc1", 80), routePath("/b", "Prefix", "svc2", 80), false},
		{"nested prefixes", routePath("/a", "Prefix", "svc1", 80), routePath("/a/b", "Prefix", "svc2", 80), true},
		{"exact inside prefix", routePath("/a/b", "Exact", "svc1", 80), routePath("/a", "Prefix", "svc2", 80), true},
		{"prefix boundary is not overlap", routePath("/a", "Prefix", "svc1", 80), routePath("/ab", "Prefix", "svc2", 80), false},
		{"root prefix overlaps everything", routePath("/", "Prefix", "svc1", 80), routePath("/x", "Prefix", "svc2", 80), true},
		{"overlap with the same backend", routePath("/a", "Prefix", "svc1", 80), routePath("/a/b", "Prefix", "svc1", 80), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal",
				routeRule("app.example.test", tc.a, tc.b))
			rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
			if got := len(rep.Conflicts) > 0; got != tc.wantConflict {
				t.Fatalf("conflict = %v, want %v (%+v)", got, tc.wantConflict, rep.Conflicts)
			}
		})
	}

	// B-H-2 [Ö]: conflicts are grouped by listener + host across every Ingress and namespace.
	t.Run("cross ingress, same listener, host and path, different backend is a conflict", func(t *testing.T) {
		a := routeIngress("app", "web", "uid-a", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "svc1", 80)))
		b := routeIngress("evil", "web", "uid-b", "traefik", "websecure-internal",
			routeRule("App.Example.Test.", routePath("/", "Prefix", "svc2", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 1 || len(rep.Conflicts[0].Candidates) != 2 {
			t.Fatalf("conflicts = %+v, want one with both candidates", rep.Conflicts)
		}
		if rep.Conflicts[0].UID == "" { // B-L-5
			t.Error("Conflict.UID is not set")
		}
	})
	t.Run("cross namespace with the same service name is a conflict", func(t *testing.T) {
		a := routeIngress("app", "web", "uid-a", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "svc", 80)))
		b := routeIngress("app", "apps", "uid-b", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "svc", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 1 {
			t.Fatalf("conflicts = %+v, want one: same name in another namespace is another backend", rep.Conflicts)
		}
	})
	t.Run("cross ingress, same backend, is no conflict", func(t *testing.T) {
		a := routeIngress("app", "web", "uid-a", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "svc1", 80)))
		b := routeIngress("other", "web", "uid-b", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/", "Prefix", "svc1", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 0 {
			t.Fatalf("conflicts = %+v, want none", rep.Conflicts)
		}
	})
	t.Run("different entrypoint is no conflict", func(t *testing.T) {
		a := routeIngress("app", "web", "uid-a", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/a", "Exact", "svc1", 80)))
		b := routeIngress("other", "web", "uid-b", "traefik", "websecure",
			routeRule("app.example.test", routePath("/a", "Exact", "svc2", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 0 {
			t.Fatalf("conflicts = %+v, want none across entrypoints", rep.Conflicts)
		}
	})
	t.Run("disjoint paths across ingresses are no conflict", func(t *testing.T) {
		a := routeIngress("app", "web", "uid-a", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/a", "Prefix", "svc1", 80)))
		b := routeIngress("other", "web", "uid-b", "traefik", "websecure-internal",
			routeRule("app.example.test", routePath("/b", "Prefix", "svc2", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 0 {
			t.Fatalf("conflicts = %+v, want none for disjoint paths", rep.Conflicts)
		}
	})

	t.Run("separate host is not a conflict", func(t *testing.T) {
		ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal",
			routeRule("a.example.test", routePath("/a", "Exact", "svc1", 80)),
			routeRule("b.example.test", routePath("/a", "Exact", "svc2", 80)))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
		if len(rep.Conflicts) != 0 {
			t.Fatalf("conflicts = %+v, want none across hosts", rep.Conflicts)
		}
	})
}

// ---------------------------------------------------------------------------
// AC4
// ---------------------------------------------------------------------------

// AC4: overlapping routes under the same ingress/host to mismatching backends
// keep every candidate and choose no winner without real route evidence.
func TestConflictDefaultUnknownIsUncertain(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	build := func(paths ...HTTPPath) RouteReport {
		ing := routeIngress("app", "web", "uid-app", "traefik", "websecure-internal",
			routeRule("app.example.test", paths...))
		return InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
	}
	first := routePath("/a", "Prefix", "svc1", 80)
	second := routePath("/a/b", "Prefix", "svc2", 80)

	rep := build(first, second)
	if len(rep.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want exactly one", rep.Conflicts)
	}
	conf := rep.Conflicts[0]
	if conf.Default != nil {
		t.Fatalf("conflict default = %+v, want nil (no proven winner)", conf.Default)
	}
	if len(conf.Candidates) != 2 {
		t.Fatalf("candidates = %+v, want both routes preserved", conf.Candidates)
	}
	if !slices.ContainsFunc(conf.Candidates, func(r Route) bool { return r.Backend.Service == "svc1" }) ||
		!slices.ContainsFunc(conf.Candidates, func(r Route) bool { return r.Backend.Service == "svc2" }) {
		t.Fatalf("candidates = %+v, want both backends", conf.Candidates)
	}

	// Order must not pick a winner: the reversed input yields the same candidate set.
	rev := build(second, first)
	if len(rev.Conflicts) != 1 || !reflect.DeepEqual(rev.Conflicts[0], conf) {
		t.Fatalf("reversed input changed the conflict: %+v vs %+v", rev.Conflicts, conf)
	}
}

// ---------------------------------------------------------------------------
// AC5
// ---------------------------------------------------------------------------

// AC5: the scan scope states that only standard Ingress+Service (and
// IngressClass) are read and that Gateway, Traefik CRDs, other controllers and
// other out-of-scope paths are not scanned; absence is not a safe/closed result.
func TestTraefikRoutes_UnsupportedPathsAreUnscanned(t *testing.T) {
	scope := FirstProfileScope()
	if scope.Conclusive {
		t.Fatal("scope claims a conclusive/safe result")
	}
	for _, want := range []ScopeItem{ScannedIngress, ScannedService, ScannedIngressClass} {
		if !slices.Contains(scope.Scanned, want) {
			t.Errorf("scanned = %v, want %q", scope.Scanned, want)
		}
	}
	for _, want := range []ScopeItem{UnscannedGatewayAPI, UnscannedTraefikCRD, UnscannedOtherController, UnscannedOtherPaths} {
		if !slices.Contains(scope.Unscanned, want) {
			t.Errorf("unscanned = %v, want %q", scope.Unscanned, want)
		}
	}

	rep := InterpretRoutes(Inventory{}, traefikProfile())
	if !reflect.DeepEqual(rep.Scope, scope) {
		t.Fatalf("report scope = %+v, want %+v", rep.Scope, scope)
	}
}
