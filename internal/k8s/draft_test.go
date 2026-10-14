package k8s

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test builders and helpers for the F4-010 host mapping. Everything is in
// memory: the mapping is a pure function over a RouteReport (routes.go), the
// profile, saved drafts and applied sites. No cluster, credential or store.
// ---------------------------------------------------------------------------

func draftByHost(drafts []Draft, host string) (Draft, bool) {
	for _, d := range drafts {
		if d.Host == host {
			return d, true
		}
	}
	return Draft{}, false
}

func managedByID(obs []ManagedObservation, id int64) (ManagedObservation, bool) {
	for _, o := range obs {
		if o.SiteID == id {
			return o, true
		}
	}
	return ManagedObservation{}, false
}

func draftHasRoute(d Draft, backend string) bool {
	return slices.ContainsFunc(d.Routes, func(r Route) bool { return r.Backend.Service == backend })
}

// containsSecret reports whether any string in v (recursively) contains
// "secret". It is the positive check that BuildDrafts never copied an Ingress
// tls.secretName or annotation into a draft.
func containsSecret(v any) bool {
	var walk func(reflect.Value) bool
	walk = func(val reflect.Value) bool {
		switch val.Kind() {
		case reflect.String:
			return strings.Contains(strings.ToLower(val.String()), "secret")
		case reflect.Slice, reflect.Array:
			for i := 0; i < val.Len(); i++ {
				if walk(val.Index(i)) {
					return true
				}
			}
		case reflect.Map:
			iter := val.MapRange()
			for iter.Next() {
				if walk(iter.Key()) || walk(iter.Value()) {
					return true
				}
			}
		case reflect.Struct:
			for i := 0; i < val.NumField(); i++ {
				if walk(val.Field(i)) {
					return true
				}
			}
		case reflect.Pointer, reflect.Interface:
			if !val.IsNil() {
				return walk(val.Elem())
			}
		}
		return false
	}
	return walk(reflect.ValueOf(v))
}

// internalIngress is a standard Ingress bound to the profile's internal
// entrypoint through the matched class, with one host and one path.
func internalIngress(name, namespace, uid, host string, paths ...HTTPPath) Ingress {
	return routeIngress(name, namespace, uid, "traefik", "websecure-internal", routeRule(host, paths...))
}

// ---------------------------------------------------------------------------
// AC1
// ---------------------------------------------------------------------------

// AC1: a valid new host of the known internal profile is mapped to an
// unapplied draft with lowercase host identity, and role selection without a
// role is not complete; an existing multi-host site is not split.
func TestIngressDraftRequiresRolesAndPreservesExistingSite(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	// One host of the applied multi-host site still has a route; the other does
	// not. A splitter would propose a new single-host site; the mapping must not.
	existingSite := ManagedSite{ID: 7, Hosts: []string{"existing.example.test", "second.example.test"},
		AccessChoice: AccessChoiceRole, Roles: []string{"developer"}}

	newHost := internalIngress("new", "web", "uid-new", "New.App.example.test",
		routePath("/files", "Prefix", "newapp", 8080))
	oldHost := internalIngress("old", "web", "uid-old", "existing.example.test",
		routePath("/", "Prefix", "oldapp", 80))

	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{newHost, oldHost}, IngressClasses: classes}, p)
	out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Managed: []ManagedSite{existingSite}, Complete: true})

	got, ok := draftByHost(out.Drafts, "new.app.example.test")
	if !ok {
		t.Fatalf("drafts = %+v, want a draft for the lowercased new host", out.Drafts)
	}
	if got.Target != "https://10.0.0.10:443" || got.Cert != CertAuto {
		t.Fatalf("draft target/cert = %q/%q, want the internal listener and auto", got.Target, got.Cert)
	}
	if got.Complete() {
		t.Fatal("a draft without an access choice must not be complete")
	}

	if _, ok := draftByHost(out.Drafts, "existing.example.test"); ok {
		t.Fatalf("drafts = %+v, must not propose a new site for an applied host", out.Drafts)
	}
	if _, ok := draftByHost(out.Drafts, "second.example.test"); ok {
		t.Fatalf("drafts = %+v, must not split the existing multi-host site", out.Drafts)
	}
	site, ok := managedByID(out.Managed, 7)
	if !ok {
		t.Fatalf("managed observations = %+v, want site 7", out.Managed)
	}
	if !slices.Equal(site.Hosts, existingSite.Hosts) {
		t.Fatalf("managed hosts = %v, want %v (site not split)", site.Hosts, existingSite.Hosts)
	}

	// role selected with an empty list is stored but not complete; a real role
	// completes it; the all-VPN-users choice is open/intentional with no roles.
	roleDraft, err := SetPrivateAccess(got, AccessChoiceRole, nil)
	if err != nil {
		t.Fatalf("SetPrivateAccess(role, empty): %v", err)
	}
	if roleDraft.AccessChoice != AccessChoiceRole || roleDraft.Complete() {
		t.Fatalf("role draft = %+v, want role but incomplete", roleDraft)
	}
	roleDraft, err = SetPrivateAccess(roleDraft, AccessChoiceRole, []string{"developer"})
	if err != nil {
		t.Fatalf("SetPrivateAccess(role, developer): %v", err)
	}
	if !roleDraft.Complete() {
		t.Fatalf("role draft = %+v, want complete with one role", roleDraft)
	}
	openDraft, err := SetPrivateAccess(got, AccessChoiceOpen, nil)
	if err != nil {
		t.Fatalf("SetPrivateAccess(open): %v", err)
	}
	if openDraft.AccessChoice != AccessChoiceOpen || len(openDraft.Roles) != 0 || !openDraft.Complete() {
		t.Fatalf("open draft = %+v, want open/intentional complete with no roles", openDraft)
	}
}

// ---------------------------------------------------------------------------
// AC2
// ---------------------------------------------------------------------------

// AC2: wildcard/empty host, an ambiguous backend/path/class/entry point or an
// unresolved target never yields an auto-applicable draft, and the review
// reason is kept.
func TestIngressDraftAmbiguousRouteRequiresReview(t *testing.T) {
	p := traefikProfile()
	goodClass := []IngressClass{routeClass("traefik", p.Controller, false)}
	okPath := routePath("/", "Prefix", "app", 80)

	resourcePath := HTTPPath{Path: "/bucket", PathType: "Prefix",
		Backend: IngressBackend{Resource: &ResourceRef{APIGroup: "example.test", Kind: "Bucket", Name: "b1"}}}

	cases := []struct {
		name    string
		rep     RouteReport
		profile Profile
		want    Reason
	}{
		{
			"wildcard host",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				internalIngress("app", "web", "uid-app", "*.example.test", okPath),
			}, IngressClasses: goodClass}, p),
			p, ReasonWildcardHost,
		},
		{
			"empty host",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				internalIngress("app", "web", "uid-app", "", okPath),
			}, IngressClasses: goodClass}, p),
			p, ReasonEmptyHost,
		},
		{
			"resource backend",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				internalIngress("app", "web", "uid-app", "app.example.test", resourcePath),
			}, IngressClasses: goodClass}, p),
			p, ReasonResourceBackend,
		},
		{
			"implementation specific path",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				internalIngress("app", "web", "uid-app", "app.example.test", routePath("/x", "ImplementationSpecific", "app", 80)),
			}, IngressClasses: goodClass}, p),
			p, ReasonImplementationSpecific,
		},
		{
			"class not in profile",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				routeIngress("app", "web", "uid-app", "nginx", "websecure-internal", routeRule("app.example.test", okPath)),
			}, IngressClasses: []IngressClass{routeClass("nginx", "k8s.io/ingress-nginx", false)}}, p),
			p, ReasonClassUnknown,
		},
		{
			"entry point unresolved",
			InterpretRoutes(Inventory{Ingresses: []Ingress{
				routeIngress("app", "web", "uid-app", "traefik", "websecure-nope", routeRule("app.example.test", okPath)),
			}, IngressClasses: goodClass}, p),
			p, ReasonEntryPointUnresolved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := BuildDrafts(DraftInputs{Report: tc.rep, Profile: tc.profile, Complete: true})
			for _, d := range out.Drafts {
				// B-M-4: with the access choice made, only the review state keeps it from completing.
				d, err := SetPrivateAccess(d, AccessChoiceOpen, nil)
				if err != nil {
					t.Fatalf("SetPrivateAccess: %v", err)
				}
				if d.Complete() || d.ReviewState != ReviewStateNeeded || !strings.Contains(d.ReviewReason, string(tc.want)) {
					t.Fatalf("draft %+v is auto-applicable or lacks review reason %q", d, tc.want)
				}
			}
			if !hasReason(tc.rep.Uncertainties, tc.want) {
				t.Fatalf("uncertainties = %+v, want reason %q", tc.rep.Uncertainties, tc.want)
			}
			if !hasReason(out.Uncertainties, tc.want) {
				t.Fatalf("draft report uncertainties = %+v, want reason %q preserved", out.Uncertainties, tc.want)
			}
		})
	}

	t.Run("invalid host", func(t *testing.T) {
		ing := internalIngress("bad", "web", "uid-bad", "Bad_Host",
			routePath("/a", "Prefix", "svc1", 80),
			routePath("/a/b", "Prefix", "svc2", 80))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: goodClass}, p)
		out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
		if len(out.Drafts) != 0 {
			t.Fatalf("drafts = %+v, want none for an invalid host", out.Drafts)
		}
		if !hasReason(out.Uncertainties, ReasonInvalidHost) {
			t.Fatalf("uncertainties = %+v, want %q", out.Uncertainties, ReasonInvalidHost)
		}
	})

	t.Run("unresolved target", func(t *testing.T) {
		publicOnly := Profile{
			Controller: "traefik.io/ingress-controller", IngressClasses: []string{"traefik"},
			Namespaces: []string{"web"},
			Public:     []Listener{{Address: "203.0.113.10", Port: 443, EntryPoint: "websecure"}},
		}
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{
			routeIngress("app", "web", "uid-app", "traefik", "websecure", routeRule("app.example.test", okPath)),
		}, IngressClasses: goodClass}, publicOnly)
		out := BuildDrafts(DraftInputs{Report: rep, Profile: publicOnly, Complete: true})
		if len(out.Drafts) != 0 {
			t.Fatalf("drafts = %+v, want none when the profile has no internal target", out.Drafts)
		}
		if !hasReason(out.Uncertainties, ReasonTargetUnresolved) {
			t.Fatalf("uncertainties = %+v, want %q", out.Uncertainties, ReasonTargetUnresolved)
		}
	})
}

// B-M-3/B-M-4/B-L-7: an uncertainty that could cover a draft host (an Ingress-wide one, a wildcard, a
// catch-all) puts that host's draft into review, even after the operator has made an access choice.
func TestIngressDraftUncertaintyReachesDraftReview(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false), routeClass("nginx", "k8s.io/ingress-nginx", false)}
	base := internalIngress("base", "web", "uid-base", "app.example.test", routePath("/", "Prefix", "app", 80))

	draftOf := func(t *testing.T, extra ...Ingress) Draft {
		t.Helper()
		rep := InterpretRoutes(Inventory{Ingresses: append([]Ingress{base}, extra...), IngressClasses: classes}, p)
		out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
		i := slices.IndexFunc(out.Drafts, func(d Draft) bool { return d.Host == "app.example.test" })
		if i < 0 {
			t.Fatalf("no draft for app.example.test in %+v", out.Drafts)
		}
		d, err := SetPrivateAccess(out.Drafts[i], AccessChoiceOpen, nil)
		if err != nil {
			t.Fatalf("SetPrivateAccess: %v", err)
		}
		return d
	}

	t.Run("positive control: a clean host is complete after the access choice", func(t *testing.T) {
		d := draftOf(t)
		if d.ReviewState == ReviewStateNeeded || !d.Complete() {
			t.Fatalf("draft = %+v, want complete", d)
		}
	})

	noEntry := routeIngress("noentry", "web", "uid-noentry", "traefik", "", routeRule("app.example.test", routePath("/x", "Prefix", "other", 80)))
	wrongClass := routeIngress("nginx", "web", "uid-nginx", "nginx", "websecure-internal", routeRule("app.example.test", routePath("/x", "Prefix", "other", 80)))
	catchAll := internalIngress("catchall", "web", "uid-catchall", "", routePath("/", "Prefix", "other", 80))
	defBackend := routeIngress("defbe", "web", "uid-defbe", "traefik", "websecure-internal", routeRule("other.example.test", routePath("/", "Prefix", "other", 80)))
	defBackend.Spec.DefaultBackend = &IngressBackend{Service: &ServiceBackend{Name: "d", Port: ServiceBackendPort{Number: 80}}}
	wildcard := internalIngress("wild", "web", "uid-wild", "*.example.test", routePath("/", "Prefix", "other", 80))

	cases := []struct {
		name  string
		extra Ingress
		want  Reason
	}{
		{"ingress without entrypoints for the same host", noEntry, ReasonEntryPointUnresolved},
		{"ingress of a class the profile does not cover, same host", wrongClass, ReasonClassUnknown},
		{"empty-host ingress covers every host", catchAll, ReasonEmptyHost},
		{"default-backend ingress covers every host", defBackend, ReasonDefaultBackend},
		{"single-label wildcard covers the host", wildcard, ReasonWildcardHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := draftOf(t, tc.extra)
			if d.ReviewState != ReviewStateNeeded || !strings.Contains(d.ReviewReason, string(tc.want)) {
				t.Fatalf("draft review = %q %q, want needed with %q", d.ReviewState, d.ReviewReason, tc.want)
			}
			if d.Complete() {
				t.Errorf("draft %+v is complete although a review is needed", d)
			}
		})
	}

	t.Run("a two-label wildcard match does not cover a deeper host", func(t *testing.T) {
		deep := internalIngress("deep", "web", "uid-deep", "*.example.test", routePath("/", "Prefix", "other", 80))
		base2 := internalIngress("base2", "web", "uid-base2", "a.b.example.test", routePath("/", "Prefix", "app", 80))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{base2, deep}, IngressClasses: classes}, p)
		out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
		if len(out.Drafts) != 1 || out.Drafts[0].ReviewState == ReviewStateNeeded {
			t.Fatalf("drafts = %+v, want a.b.example.test unaffected by *.example.test", out.Drafts)
		}
	})
}

// B-L-8: a host with only public-bound conflicts gets no draft.
func TestIngressDraftPublicOnlyConflictMakesNoDraft(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}
	a := routeIngress("a", "web", "uid-a", "traefik", "websecure", routeRule("pub.example.test", routePath("/", "Prefix", "s1", 80)))
	b := routeIngress("b", "web", "uid-b", "traefik", "websecure", routeRule("pub.example.test", routePath("/", "Prefix", "s2", 80)))
	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b}, IngressClasses: classes}, p)
	if len(rep.Conflicts) != 1 {
		t.Fatalf("setup: conflicts = %+v, want one public conflict", rep.Conflicts)
	}
	out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
	if len(out.Drafts) != 0 {
		t.Fatalf("drafts = %+v, want none for a public-only host", out.Drafts)
	}
}

// ---------------------------------------------------------------------------
// AC3
// ---------------------------------------------------------------------------

// AC3: the proposed target is the profile's internal listener, the certificate
// stays R1's auto/le choice, and no Ingress secretName or annotation is copied
// into the draft or its rules. Public-bound routes are out of scope.
func TestIngressDraft_UsesInternalListenerAndR1Certificate(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	ing := internalIngress("app", "web", "uid-app", "app.example.test", routePath("/", "Prefix", "app", 80))
	ing.Metadata.Annotations["example.test/secret-name"] = "tls-secret"
	ing.Spec.TLS = []IngressTLS{{Hosts: []string{"app.example.test"}}}

	// The ingress carries "secret" somewhere; the scan is meaningful only if it
	// can find it on the input.
	if !containsSecret(ing) {
		t.Fatal("test setup: the ingress must carry a secret marker")
	}

	publicIng := routeIngress("pub", "web", "uid-pub", "traefik", "websecure",
		routeRule("pub.example.test", routePath("/", "Prefix", "pub", 80)))

	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing, publicIng}, IngressClasses: classes}, p)
	out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})

	if len(out.Drafts) != 1 {
		t.Fatalf("drafts = %+v, want exactly the internal host", out.Drafts)
	}
	d := out.Drafts[0]
	if d.Host != "app.example.test" {
		t.Fatalf("draft host = %q, want app.example.test", d.Host)
	}
	if d.Target != "https://10.0.0.10:443" {
		t.Fatalf("draft target = %q, want the profile internal listener", d.Target)
	}
	if d.Cert != CertAuto {
		t.Fatalf("draft cert = %q, want %q (R1 decides auto/le)", d.Cert, CertAuto)
	}
	if containsSecret(d) {
		t.Fatalf("draft %+v leaked an Ingress secretName or annotation", d)
	}
}

// ---------------------------------------------------------------------------
// AC4
// ---------------------------------------------------------------------------

// AC4: the private access choice keeps the R1 pairing: all VPN users is
// open/intentional with no roles, selected roles is role with at least one
// role, and an empty role list is never silently turned into open.
func TestPrivateDraftSupportsVPNOnlyAndSelectedRoles(t *testing.T) {
	base := Draft{Host: "app.example.test", Target: "https://10.0.0.10:443", Cert: CertAuto}

	t.Run("open clears roles and is complete", func(t *testing.T) {
		d, err := SetPrivateAccess(base, AccessChoiceOpen, []string{"developer"})
		if err != nil {
			t.Fatal(err)
		}
		if d.AccessChoice != AccessChoiceOpen || len(d.Roles) != 0 || !d.Complete() {
			t.Fatalf("draft = %+v, want open/intentional with no roles", d)
		}
	})

	t.Run("role keeps at least one role", func(t *testing.T) {
		d, err := SetPrivateAccess(base, AccessChoiceRole, []string{"developer"})
		if err != nil {
			t.Fatal(err)
		}
		if d.AccessChoice != AccessChoiceRole || !slices.Equal(d.Roles, []string{"developer"}) || !d.Complete() {
			t.Fatalf("draft = %+v, want role with the selected role", d)
		}
	})

	t.Run("role with an empty list is not turned into open", func(t *testing.T) {
		d, err := SetPrivateAccess(base, AccessChoiceRole, nil)
		if err != nil {
			t.Fatal(err)
		}
		if d.AccessChoice != AccessChoiceRole {
			t.Fatalf("access choice = %q, want role (never inferred open)", d.AccessChoice)
		}
		if d.Complete() {
			t.Fatal("role with no roles must not be complete")
		}
	})

	t.Run("roles are de-duplicated and sorted", func(t *testing.T) {
		d, err := SetPrivateAccess(base, AccessChoiceRole, []string{"devops", "developer", "devops", " "})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(d.Roles, []string{"developer", "devops"}) {
			t.Fatalf("roles = %v, want [developer devops]", d.Roles)
		}
	})

	t.Run("unknown choice is refused", func(t *testing.T) {
		if _, err := SetPrivateAccess(base, "", nil); err == nil {
			t.Fatal("empty access choice must be refused")
		}
	})
}

// ---------------------------------------------------------------------------
// AC5
// ---------------------------------------------------------------------------

// AC5: a managed host whose route is missing or different in a complete read is
// reported as an observation, leaving the site, its roles and its access
// preference unchanged; an incomplete read never infers absence.
func TestManagedSiteMissingRouteIsPreserved(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}
	// A complete read that has no route for the managed host.
	empty := InterpretRoutes(Inventory{IngressClasses: classes}, p)
	managed := []ManagedSite{{ID: 5, Hosts: []string{"app.example.test"},
		AccessChoice: AccessChoiceRole, Roles: []string{"developer"}}}

	t.Run("complete read with no route", func(t *testing.T) {
		out := BuildDrafts(DraftInputs{Report: empty, Profile: p, Managed: managed, Complete: true})
		obs, ok := managedByID(out.Managed, 5)
		if !ok || obs.Status != ManagedNoRoute {
			t.Fatalf("managed = %+v, want no_route", out.Managed)
		}
		if obs.AccessChoice != AccessChoiceRole || !slices.Equal(obs.Roles, []string{"developer"}) {
			t.Fatalf("managed = %+v, access preference must be preserved", obs)
		}
		if _, ok := draftByHost(out.Drafts, "app.example.test"); ok {
			t.Fatalf("drafts = %+v, a missing route must not create a draft", out.Drafts)
		}
	})

	t.Run("incomplete read infers nothing", func(t *testing.T) {
		out := BuildDrafts(DraftInputs{Report: empty, Profile: p, Managed: managed, Complete: false})
		obs, ok := managedByID(out.Managed, 5)
		if !ok || obs.Status != ManagedUnknown {
			t.Fatalf("managed = %+v, want unknown on an incomplete read", out.Managed)
		}
	})

	t.Run("changed route is a difference, not a change", func(t *testing.T) {
		ing := internalIngress("app", "web", "uid-app", "app.example.test", routePath("/", "Prefix", "newapp", 80))
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
		old := Route{Namespace: "web", Ingress: "app", UID: "uid-app", Host: "app.example.test",
			Path: "/", PathType: PathPrefix, Backend: Backend{Service: "oldapp", PortNumber: 80},
			Listener: p.Internal[0], Basis: BasisDeclaredProfile}
		managed := []ManagedSite{{ID: 5, Hosts: []string{"app.example.test"}, RouteKeys: []string{routeKey(old)}}}
		out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Managed: managed, Complete: true})
		obs, ok := managedByID(out.Managed, 5)
		if !ok || obs.Status != ManagedChanged {
			t.Fatalf("managed = %+v, want changed", out.Managed)
		}
		if _, ok := draftByHost(out.Drafts, "app.example.test"); ok {
			t.Fatalf("drafts = %+v, must not propose an apply for a managed host", out.Drafts)
		}
	})
}

// ---------------------------------------------------------------------------
// AC6
// ---------------------------------------------------------------------------

// AC6: every real route conflict asks for review, and the first profile never
// reads a controller winner, so the target stays unknown and the site
// unchanged.
func TestRouteConflictAlwaysRequestsReview(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	ing := internalIngress("app", "web", "uid-app", "app.example.test",
		routePath("/a", "Prefix", "svc1", 80),
		routePath("/a/b", "Prefix", "svc2", 80))
	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
	if len(rep.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want one", rep.Conflicts)
	}

	out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
	if len(out.Conflicts) != 1 || out.Conflicts[0].Default != nil {
		t.Fatalf("draft conflicts = %+v, want the conflict with no winner", out.Conflicts)
	}
	d, ok := draftByHost(out.Drafts, "app.example.test")
	if !ok || d.ReviewState != ReviewStateNeeded || d.ReviewReason != string(ReasonRouteConflict) {
		t.Fatalf("draft = %+v, want review needed for the conflict", d)
	}
	if d.Complete() {
		t.Fatal("a conflicting draft must not be complete")
	}

	// A conflicting host that is already applied must still surface the review
	// and must not change (or re-draft) the applied site.
	managed := []ManagedSite{{ID: 9, Hosts: []string{"app.example.test"}, AccessChoice: AccessChoiceOpen}}
	out2 := BuildDrafts(DraftInputs{Report: rep, Profile: p, Managed: managed, Complete: true})
	if len(out2.Conflicts) != 1 {
		t.Fatalf("draft conflicts = %+v, want the conflict even for a managed host", out2.Conflicts)
	}
	if _, ok := draftByHost(out2.Drafts, "app.example.test"); ok {
		t.Fatalf("drafts = %+v, must not re-draft a managed host", out2.Drafts)
	}
	obs, _ := managedByID(out2.Managed, 9)
	if obs.AccessChoice != AccessChoiceOpen {
		t.Fatalf("managed = %+v, must keep the applied access choice", obs)
	}
	// U-17: the managed mapping of a conflicting host is not "matched".
	if obs.Status != ManagedConflict {
		t.Fatalf("managed status = %q, want %q for a host in a route conflict", obs.Status, ManagedConflict)
	}
}

// AC6/AC7: with no proven controller route the conflict default stays unknown,
// every candidate is kept and the order of the evidence picks no winner.
func TestDraftConflictStaysUnknown(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	build := func(paths ...HTTPPath) DraftReport {
		ing := internalIngress("app", "web", "uid-app", "app.example.test", paths...)
		rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
		return BuildDrafts(DraftInputs{Report: rep, Profile: p, Complete: true})
	}

	first := routePath("/a", "Prefix", "svc1", 80)
	second := routePath("/a/b", "Prefix", "svc2", 80)

	out := build(first, second)
	d, ok := draftByHost(out.Drafts, "app.example.test")
	if !ok {
		t.Fatalf("drafts = %+v, want a review draft for the conflict host", out.Drafts)
	}
	if d.ReviewDefault != "" {
		t.Fatalf("review default = %q, want unknown (empty)", d.ReviewDefault)
	}
	if len(d.ReviewCandidates) != 2 {
		t.Fatalf("review candidates = %v, want both candidates", d.ReviewCandidates)
	}

	rev := build(second, first)
	dr, ok := draftByHost(rev.Drafts, "app.example.test")
	if !ok {
		t.Fatalf("drafts = %+v, want a review draft", rev.Drafts)
	}
	if !slices.Equal(d.ReviewCandidates, dr.ReviewCandidates) {
		t.Fatalf("candidate set changed with input order: %v vs %v", d.ReviewCandidates, dr.ReviewCandidates)
	}
}

// ---------------------------------------------------------------------------
// AC7
// ---------------------------------------------------------------------------

// AC7: several route observations of one host merge into one draft's provenance
// while the user's chosen fields are preserved, and different hosts that share
// a backend are never merged into one site.
func TestIngressDraft_HostIdentityPreservesChoices(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}

	a := internalIngress("app-a", "web", "uid-a", "app.example.test", routePath("/a", "Prefix", "app", 80))
	b := internalIngress("app-b", "web", "uid-b", "app.example.test", routePath("/b", "Prefix", "app", 80))
	// A different host to the same backend.
	c := internalIngress("other", "web", "uid-c", "other.example.test", routePath("/", "Prefix", "app", 80))

	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{a, b, c}, IngressClasses: classes}, p)

	existing := Draft{Host: "app.example.test", AccessChoice: AccessChoiceRole,
		Roles: []string{"developer"}, Note: "roller sonra", Target: "https://old:443", Cert: "le:old"}
	// An old route observation for the same host that must survive the merge.
	oldRoute := Route{Namespace: "web", Ingress: "app-old", UID: "uid-old", Host: "app.example.test",
		Path: "/old", PathType: PathPrefix, Backend: Backend{Service: "old", PortNumber: 80},
		Listener: p.Internal[0], Basis: BasisDeclaredProfile}
	existing.Routes = []Route{oldRoute}

	out := BuildDrafts(DraftInputs{Report: rep, Profile: p, Existing: []Draft{existing}, Complete: true})

	merged, ok := draftByHost(out.Drafts, "app.example.test")
	if !ok {
		t.Fatalf("drafts = %+v, want the merged host draft", out.Drafts)
	}
	if merged.AccessChoice != AccessChoiceRole || !slices.Equal(merged.Roles, []string{"developer"}) || merged.Note != "roller sonra" {
		t.Fatalf("draft = %+v, want the chosen access/roles/note preserved", merged)
	}
	if !draftHasRoute(merged, "app") || !draftHasRoute(merged, "old") {
		t.Fatalf("routes = %+v, want the new and old route evidence merged", merged.Routes)
	}

	// The common backend must not merge the two hosts.
	other, ok := draftByHost(out.Drafts, "other.example.test")
	if !ok {
		t.Fatalf("drafts = %+v, want a separate draft for the other host", out.Drafts)
	}
	if other.Host == merged.Host {
		t.Fatalf("hosts were merged: %+v", out.Drafts)
	}
}

// F5 L5: a system-template site (auth, hs, wg, tagcess) is not served by k8s routes, so a complete
// read without a route reports it as "system", not as a missing route. The control: an ordinary
// site with the same read is still no_route, and a system host that does have a route keeps the
// normal status.
func TestManagedSystemSiteIsNotNoRoute(t *testing.T) {
	p := traefikProfile()
	classes := []IngressClass{routeClass("traefik", p.Controller, false)}
	empty := InterpretRoutes(Inventory{IngressClasses: classes}, p)
	managed := []ManagedSite{
		{ID: 1, Hosts: []string{"hs.example.test"}, System: true},
		{ID: 2, Hosts: []string{"app.example.test"}},
	}
	out := BuildDrafts(DraftInputs{Report: empty, Profile: p, Managed: managed, Complete: true})
	if obs, _ := managedByID(out.Managed, 1); obs.Status != ManagedSystem {
		t.Errorf("system site status = %q, want %q", obs.Status, ManagedSystem)
	}
	if obs, _ := managedByID(out.Managed, 2); obs.Status != ManagedNoRoute {
		t.Errorf("control: ordinary site status = %q, want no_route", obs.Status)
	}

	ing := internalIngress("auth", "zitadel", "uid-auth", "hs.example.test", routePath("/", "Prefix", "zitadel", 8080))
	rep := InterpretRoutes(Inventory{Ingresses: []Ingress{ing}, IngressClasses: classes}, p)
	out = BuildDrafts(DraftInputs{Report: rep, Profile: p, Managed: managed[:1], Complete: true})
	if obs, _ := managedByID(out.Managed, 1); obs.Status != ManagedMatched {
		t.Errorf("system site with a route = %q, want matched", obs.Status)
	}
	if _, ok := draftByHost(out.Drafts, "hs.example.test"); ok {
		t.Error("a managed system host became a draft")
	}
}
