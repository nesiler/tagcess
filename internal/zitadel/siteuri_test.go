package zitadel

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

func cb(host string) string { return "https://" + host + "/oauth2/callback" }

func cbs(hosts ...string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, cb(h))
	}
	return out
}

// roleSite is a minimal role site: DesiredURIs only looks at kind, template and hosts.
func roleSite(hosts ...string) site.Site { return site.Site{Kind: site.KindRole, Hosts: hosts} }

type uriEnv struct {
	apps *fakeApps
	sync *URISync
	q    *db.Queries
}

// newURIEnv starts a fake Zitadel holding one oauth2-proxy app with the given URIs, a fresh
// SQLite store and a URISync over both. owned == nil leaves the ownership record absent (first
// import); a non-nil owned (possibly empty) is stored as the last written set O.
func newURIEnv(t *testing.T, current, owned []string) *uriEnv {
	t.Helper()
	apps := &fakeApps{apps: []*applicationv2.Application{
		oidcApp("app-1", testProject, "oauth2-proxy", current...),
	}}
	c := startAppFake(t, apps)
	st, err := store.Open(context.Background(), t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &uriEnv{apps: apps, sync: NewURISync(c, "app-1", st.Queries()), q: st.Queries()}
	if owned != nil {
		if err := e.sync.saveOwned(context.Background(), owned); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// current reads the fake app's live URI list.
func (e *uriEnv) current() []string {
	return e.apps.apps[0].GetOidcConfiguration().GetRedirectUris()
}

// owned reads the stored O; ok is false while no ownership record exists.
func (e *uriEnv) owned(t *testing.T) (uris []string, ok bool) {
	t.Helper()
	uris, ok, err := e.sync.loadOwned(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return uris, ok
}

func (e *uriEnv) openAlerts(t *testing.T) []db.Alert {
	t.Helper()
	rows, err := e.q.ListOpenAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func driftKinds(r URIResult) []string {
	var out []string
	for _, d := range r.Drift {
		out = append(out, d.Kind+" "+d.URI)
	}
	return out
}

func TestSiteURI_DesiredURIs(t *testing.T) {
	sites := []site.Site{
		roleSite("b.example.com", "a.example.com"),
		{Kind: site.KindOpen, OpenReason: site.OpenReasonIntentional, Hosts: []string{"open.example.com"}},
		{Kind: site.KindSystem, SystemTemplate: site.TemplateTagcess, Hosts: []string{"tagcess.example.com"}},
		{Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel, Hosts: []string{"auth.example.com"}},
		{Kind: site.KindSystem, SystemTemplate: site.TemplateHeadscale, Hosts: []string{"hs.example.com"}},
		roleSite("a.example.com"), // duplicate host: one URI
	}
	got, err := DesiredURIs(sites)
	if err != nil {
		t.Fatal(err)
	}
	want := cbs("a.example.com", "b.example.com", "tagcess.example.com")
	if !slices.Equal(got, want) {
		t.Fatalf("D = %v, want %v (role hosts and the tagcess template only, sorted, deduplicated)", got, want)
	}

	// Every user-controlled host is re-checked: nothing that is not a plain hostname may reach a URI.
	for _, bad := range []string{"", "*.example.com", "a.example.com/x", "a.example.com:8443", "a b.example.com",
		"A.EXAMPLE.COM", "a.example.com\nb", "a.example.com?x=1", "a.example.com#", "user@a.example.com", `a\.example.com`} {
		if _, err := DesiredURIs([]site.Site{roleSite("ok.example.com", bad)}); err == nil {
			t.Errorf("host %q was accepted into a redirect URI", bad)
		}
	}
}

func TestSiteURI_MergeOwned(t *testing.T) {
	tests := []struct {
		name                 string
		current, owned, want []string
		desired              []string
		wantChanged          bool
	}{
		{
			name:    "add: new URIs append sorted, foreign order kept",
			current: []string{cb("z"), cb("hs"), cb("a")}, owned: cbs("z", "a"), desired: cbs("z", "a", "n2", "n1"),
			want: []string{cb("z"), cb("hs"), cb("a"), cb("n1"), cb("n2")}, wantChanged: true,
		},
		{
			name:    "delete: owned URI no longer desired is removed, order of the rest kept",
			current: []string{cb("a"), cb("hs"), cb("b"), cb("c")}, owned: cbs("a", "b", "c"), desired: cbs("a", "c"),
			want: []string{cb("a"), cb("hs"), cb("c")}, wantChanged: true,
		},
		{
			name:    "foreign URI is never removed, even when not desired",
			current: []string{cb("hs"), "https://other.example.com/cb"}, owned: []string{}, desired: nil,
			want: []string{cb("hs"), "https://other.example.com/cb"}, wantChanged: false,
		},
		{
			name:    "add and delete together",
			current: []string{cb("hs"), cb("old")}, owned: cbs("old"), desired: cbs("new"),
			want: []string{cb("hs"), cb("new")}, wantChanged: true,
		},
		{
			name:    "already converged: no change",
			current: []string{cb("hs"), cb("a")}, owned: cbs("a"), desired: cbs("a"),
			want: []string{cb("hs"), cb("a")}, wantChanged: false,
		},
		{
			name:    "desired URI a human already added is not duplicated",
			current: []string{cb("a"), cb("hs")}, owned: []string{}, desired: cbs("a"),
			want: []string{cb("a"), cb("hs")}, wantChanged: false,
		},
		{
			name:    "owned URI missing from the list stays gone, desired one is re-added at the end",
			current: []string{cb("hs")}, owned: cbs("a"), desired: cbs("a"),
			want: []string{cb("hs"), cb("a")}, wantChanged: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cur := slices.Clone(tt.current)
			got, changed := mergeURIs(cur, tt.owned, tt.desired)
			if !slices.Equal(got, tt.want) || changed != tt.wantChanged {
				t.Fatalf("merge = %v changed=%v, want %v changed=%v", got, changed, tt.want, tt.wantChanged)
			}
			if !slices.Equal(cur, tt.current) {
				t.Fatalf("merge mutated its input: %v", cur)
			}
			// Property: every URI that is neither owned nor desired survives.
			for _, u := range tt.current {
				if !slices.Contains(tt.owned, u) && !slices.Contains(got, u) {
					t.Fatalf("foreign URI %q was dropped", u)
				}
			}
		})
	}
}

func TestSiteURI_WriteVerify(t *testing.T) {
	ctx := context.Background()
	t.Run("merged list is written with the four fields and O follows the verified result", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("a"), cb("hs"), cb("b")}, cbs("a", "b"))
		before := proto.Clone(e.apps.apps[0]).(*applicationv2.Application)

		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "c")})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{cb("a"), cb("hs"), cb("c")}
		if !slices.Equal(e.current(), want) || !res.Written {
			t.Fatalf("list = %v written=%v, want %v written", e.current(), res.Written, want)
		}
		if len(e.apps.updates) != 1 {
			t.Fatalf("%d writes, want 1", len(e.apps.updates))
		}
		got, was := e.apps.apps[0].GetOidcConfiguration(), before.GetOidcConfiguration()
		if !slices.Equal(got.GetResponseTypes(), was.GetResponseTypes()) || !slices.Equal(got.GetGrantTypes(), was.GetGrantTypes()) ||
			!proto.Equal(got.GetClockSkew(), was.GetClockSkew()) || !proto.Equal(got.GetLoginVersion(), was.GetLoginVersion()) {
			t.Fatalf("the four OIDC fields drifted: %v -> %v", was, got)
		}
		if o, _ := e.owned(t); !slices.Equal(o, cbs("a", "c")) {
			t.Fatalf("O = %v, want %v", o, cbs("a", "c"))
		}
		if n := len(e.openAlerts(t)); n != 0 {
			t.Fatalf("%d open alerts after a clean write", n)
		}
	})

	t.Run("a converged list is not written", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("hs"), cb("a")}, cbs("a"))
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a")})
		if err != nil {
			t.Fatal(err)
		}
		if res.Written || len(e.apps.updates) != 0 {
			t.Fatalf("written=%v updates=%d for a list that already matches", res.Written, len(e.apps.updates))
		}
	})

	t.Run("a lagging read-back that converges still updates O", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("a")}, cbs("a"))
		e.apps.lagGet = 3 // Sync's read and the client's pre-write read use two; the first read-back lags
		if _, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "b")}); err != nil {
			t.Fatalf("converging read-back: %v", err)
		}
		if o, _ := e.owned(t); !slices.Equal(o, cbs("a", "b")) {
			t.Fatalf("O = %v", o)
		}
	})
}

func TestSiteURI_FailSafe(t *testing.T) {
	ctx := context.Background()
	startO := cbs("a", "old")
	start := []string{cb("a"), cb("hs"), cb("old")}

	assertKept := func(t *testing.T, e *uriEnv, res URIResult, err error, kind string) {
		t.Helper()
		if err == nil {
			t.Fatal("a failed step must return an error")
		}
		if o, ok := e.owned(t); !ok || !slices.Equal(o, startO) {
			t.Fatalf("ownership record = %v (present=%v), want it kept as %v", o, ok, startO)
		}
		if !slices.Equal(e.current(), start) && kind != "write_failed" {
			t.Fatalf("live list changed to %v", e.current())
		}
		var found bool
		for _, d := range res.Drift {
			found = found || d.Kind == kind
		}
		if !found {
			t.Fatalf("drift %v lacks a %q warning", driftKinds(res), kind)
		}
		alerts := e.openAlerts(t)
		if len(alerts) != 1 || alerts[0].Kind != AlertURIDrift || alerts[0].Source != SourceOAuth2ProxyApp {
			t.Fatalf("alerts = %+v, want one open %s alert", alerts, AlertURIDrift)
		}
	}

	t.Run("read fails", func(t *testing.T) {
		e := newURIEnv(t, start, startO)
		e.apps.deniedGet = true
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a")})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("err = %v, want the permission error to survive", err)
		}
		assertKept(t, e, res, err, DriftReadFailed)
		if len(e.apps.updates) != 0 {
			t.Fatal("a failed read led to a write")
		}
	})

	t.Run("write fails", func(t *testing.T) {
		e := newURIEnv(t, start, startO)
		e.apps.deniedUpdate = true
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "new")})
		assertKept(t, e, res, err, DriftWriteFailed)
		if !slices.Equal(e.current(), start) {
			t.Fatalf("a denied write changed the list to %v", e.current())
		}
	})

	t.Run("verification fails", func(t *testing.T) {
		oldTries, oldWait := appReadBackTries, appReadBackWait
		appReadBackTries, appReadBackWait = 2, time.Millisecond
		defer func() { appReadBackTries, appReadBackWait = oldTries, oldWait }()
		e := newURIEnv(t, start, startO)
		e.apps.lagGet = 100 // every read-back still shows the old list
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "new")})
		assertKept(t, e, res, err, DriftWriteFailed)
	})

	t.Run("a bad site record stops before Zitadel is touched", func(t *testing.T) {
		e := newURIEnv(t, start, startO)
		e.apps.deniedGet = true // would be reported as a read failure if reached
		_, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "evil.example.com/x")})
		if err == nil || errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("err = %v, want the host validation error", err)
		}
		if len(e.apps.updates) != 0 {
			t.Fatal("a bad record reached Zitadel")
		}
		if o, _ := e.owned(t); !slices.Equal(o, startO) {
			t.Fatalf("O = %v", o)
		}
	})

	t.Run("a repeated failure keeps one alert, a clean run resolves it", func(t *testing.T) {
		e := newURIEnv(t, start, startO)
		e.apps.deniedGet = true
		for range 3 {
			_, _ = e.sync.Sync(ctx, []site.Site{roleSite("a")})
		}
		if n := len(e.openAlerts(t)); n != 1 {
			t.Fatalf("%d open alerts after three failures, want 1", n)
		}
		e.apps.deniedGet = false
		if _, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "old")}); err != nil {
			t.Fatal(err)
		}
		if n := len(e.openAlerts(t)); n != 0 {
			t.Fatalf("%d open alerts after a clean run, want 0", n)
		}
	})
}

func TestSiteURI_InitialOwnership(t *testing.T) {
	ctx := context.Background()
	foreignA, foreignB := cb("hs"), "https://console-added.example.com/cb"
	current := []string{cb("a"), foreignA, foreignB, cb("gone")}

	t.Run("O is current ∩ D and foreign URIs are listed untouched", func(t *testing.T) {
		e := newURIEnv(t, current, nil)
		if _, ok := e.owned(t); ok {
			t.Fatal("ownership record exists before the first import")
		}
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "c")})
		if err != nil {
			t.Fatal(err)
		}
		// cb("gone") is not in D, so it is foreign at import time and must survive.
		want := []string{cb("a"), foreignA, foreignB, cb("gone"), cb("c")}
		if !slices.Equal(e.current(), want) {
			t.Fatalf("list = %v, want %v", e.current(), want)
		}
		wantForeign := []string{foreignA, foreignB, cb("gone")}
		if !slices.Equal(res.Foreign, wantForeign) {
			t.Fatalf("foreign = %v, want %v", res.Foreign, wantForeign)
		}
		if o, ok := e.owned(t); !ok || !slices.Equal(o, cbs("a", "c")) {
			t.Fatalf("O = %v present=%v, want %v", o, ok, cbs("a", "c"))
		}
	})

	t.Run("a failed first write still records the import-time O", func(t *testing.T) {
		e := newURIEnv(t, current, nil)
		e.apps.deniedUpdate = true
		res, err := e.sync.Sync(ctx, []site.Site{roleSite("a", "c")})
		if err == nil {
			t.Fatal("expected the write error")
		}
		if o, ok := e.owned(t); !ok || !slices.Equal(o, cbs("a")) {
			t.Fatalf("O = %v present=%v, want [a] (current ∩ D)", o, ok)
		}
		if !slices.Equal(res.Foreign, []string{foreignA, foreignB, cb("gone")}) {
			t.Fatalf("foreign = %v", res.Foreign)
		}
	})

	t.Run("a failed first read records nothing", func(t *testing.T) {
		e := newURIEnv(t, current, nil)
		e.apps.deniedGet = true
		if _, err := e.sync.Sync(ctx, []site.Site{roleSite("a")}); err == nil {
			t.Fatal("expected the read error")
		}
		if _, ok := e.owned(t); ok {
			t.Fatal("an unproven import wrote an ownership record")
		}
	})
}

func TestSiteURI_PeriodicDrift(t *testing.T) {
	ctx := context.Background()

	t.Run("clean list", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("hs"), cb("a")}, cbs("a"))
		res, err := e.sync.CheckDrift(ctx, []site.Site{roleSite("a")})
		if err != nil || len(res.Drift) != 0 {
			t.Fatalf("drift = %v err = %v, want none", driftKinds(res), err)
		}
		if !slices.Equal(res.Foreign, []string{cb("hs")}) {
			t.Fatalf("foreign = %v", res.Foreign)
		}
	})

	t.Run("missing, removed-owned and stale-owned are reported and nothing is written", func(t *testing.T) {
		// a: owned and desired but removed by hand; b: desired, never written; old: owned, no longer
		// desired, still in the list; hs: foreign.
		e := newURIEnv(t, []string{cb("hs"), cb("old")}, cbs("a", "old"))
		res, err := e.sync.CheckDrift(ctx, []site.Site{roleSite("a", "b")})
		if err != nil {
			t.Fatal(err)
		}
		got := driftKinds(res)
		want := []string{DriftOwnedRemoved + " " + cb("a"), DriftMissing + " " + cb("b"), DriftStaleOwned + " " + cb("old")}
		if !slices.Equal(got, want) {
			t.Fatalf("drift = %v, want %v", got, want)
		}
		if len(e.apps.updates) != 0 {
			t.Fatal("the periodic check wrote to Zitadel")
		}
		if o, _ := e.owned(t); !slices.Equal(o, cbs("a", "old")) {
			t.Fatalf("the periodic check changed O to %v", o)
		}
		if n := len(e.openAlerts(t)); n != 1 {
			t.Fatalf("%d open alerts, want 1 drift alert", n)
		}
	})

	t.Run("a read failure is an error, an alert and never a write", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("a")}, cbs("a"))
		e.apps.deniedGet = true
		res, err := e.sync.CheckDrift(ctx, []site.Site{roleSite("a", "b")})
		if err == nil {
			t.Fatal("expected the read error")
		}
		if got := driftKinds(res); len(got) != 1 || !strings.HasPrefix(got[0], DriftReadFailed) {
			t.Fatalf("drift = %v, want one %s", got, DriftReadFailed)
		}
		if len(e.apps.updates) != 0 {
			t.Fatal("a failed read led to a write")
		}
		if n := len(e.openAlerts(t)); n != 1 {
			t.Fatalf("%d open alerts, want 1", n)
		}
	})

	t.Run("a repaired list resolves the alert", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("hs")}, cbs("a"))
		if res, _ := e.sync.CheckDrift(ctx, []site.Site{roleSite("a")}); len(res.Drift) == 0 {
			t.Fatal("expected drift")
		}
		if _, err := e.sync.Sync(ctx, []site.Site{roleSite("a")}); err != nil {
			t.Fatal(err)
		}
		if res, err := e.sync.CheckDrift(ctx, []site.Site{roleSite("a")}); err != nil || len(res.Drift) != 0 {
			t.Fatalf("drift = %v err = %v after the repair", driftKinds(res), err)
		}
		if n := len(e.openAlerts(t)); n != 0 {
			t.Fatalf("%d open alerts after the repair", n)
		}
	})

	t.Run("no ownership record yet: only the desired subset is checked", func(t *testing.T) {
		e := newURIEnv(t, []string{cb("hs")}, nil)
		res, err := e.sync.CheckDrift(ctx, []site.Site{roleSite("a")})
		if err != nil {
			t.Fatal(err)
		}
		if got := driftKinds(res); !slices.Equal(got, []string{DriftMissing + " " + cb("a")}) {
			t.Fatalf("drift = %v", got)
		}
	})
}

// A URISync built by app name finds the app on first use, not at construction: an unreachable
// Zitadel at startup must not take tagcess down (F1-021 AC4: Zitadel down changes nothing, the
// interface keeps running). Until the app is found every run is a failed read — a warning, no write
// — and once it is there the same sync works.
func TestURISync_ResolvesTheAppLazily(t *testing.T) {
	ctx := context.Background()
	apps := &fakeApps{}
	c := startAppFake(t, apps)
	st, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sync := NewNamedURISync(c, "oauth2-proxy", st.Queries())

	res, err := sync.Sync(ctx, []site.Site{roleSite("a.example.com")})
	if err == nil || res.Written || len(res.Drift) != 1 || res.Drift[0].Kind != DriftReadFailed {
		t.Fatalf("Sync with no app = (%+v, %v), want a failed read and no write", res, err)
	}
	if alerts, _ := st.Queries().ListOpenAlerts(ctx); len(alerts) != 1 || alerts[0].Kind != AlertURIDrift {
		t.Fatalf("open alerts = %+v, want the drift alert", alerts)
	}

	apps.apps = []*applicationv2.Application{oidcApp("app-1", testProject, "oauth2-proxy", "http://localhost:8080/oauth2/callback")}
	res, err = sync.Sync(ctx, []site.Site{roleSite("a.example.com")})
	if err != nil || !res.Written {
		t.Fatalf("Sync once the app exists = (%+v, %v), want a write", res, err)
	}
	got := apps.apps[0].GetOidcConfiguration().GetRedirectUris()
	if !slices.Contains(got, cb("a.example.com")) || !slices.Contains(got, "http://localhost:8080/oauth2/callback") {
		t.Errorf("redirect URIs = %v, want the new callback next to the foreign one", got)
	}
}

// J1: with a post-logout URI configured, Sync registers it next to the redirect URIs (additive); without
// one it leaves the list alone (positive control: same setup, no option, nothing registered).
func TestURISync_RegistersPostLogoutURI(t *testing.T) {
	for _, tc := range []struct {
		name string
		uri  string
		want []string
	}{
		{"with uri", "https://t.example.com/", []string{"https://t.example.com/"}},
		{"without uri", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			apps := &fakeApps{apps: []*applicationv2.Application{oidcApp("app-1", testProject, "oauth2-proxy", "http://localhost:8080/oauth2/callback")}}
			c := startAppFake(t, apps)
			st, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			sync := NewNamedURISync(c, "oauth2-proxy", st.Queries()).WithPostLogoutURI(tc.uri)
			if _, err := sync.Sync(ctx, []site.Site{roleSite("a.example.com")}); err != nil {
				t.Fatal(err)
			}
			got := apps.apps[0].GetOidcConfiguration().GetPostLogoutRedirectUris()
			if !slices.Equal(got, tc.want) {
				t.Errorf("post-logout uris = %v, want %v", got, tc.want)
			}
		})
	}
}

// F5 L2: OwnedURIs exposes O read-only: absent before the first record, the written set after a
// Sync, and it never calls Zitadel.
func TestURISync_OwnedURIs(t *testing.T) {
	ctx := context.Background()
	e := newURIEnv(t, nil, nil)
	if uris, ok, err := e.sync.OwnedURIs(ctx); err != nil || ok || len(uris) != 0 {
		t.Fatalf("before any record: %v %v %v", uris, ok, err)
	}
	if _, err := e.sync.Sync(ctx, []site.Site{roleSite("b.example", "a.example")}); err != nil {
		t.Fatal(err)
	}
	uris, ok, err := e.sync.OwnedURIs(ctx)
	want := []string{"https://a.example/oauth2/callback", "https://b.example/oauth2/callback"}
	if err != nil || !ok || !slices.Equal(uris, want) {
		t.Errorf("after Sync: %v %v %v, want %v", uris, ok, err, want)
	}
}
