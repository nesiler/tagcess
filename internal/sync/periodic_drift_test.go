package sync

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// F2-011 AC6: the periodic Y-02 loop also runs the F2-010 redirect URI drift check, and what it
// finds is shown (the drift alert itself is raised by that check; the run reports it as an error
// the scheduler logs). Only the periodic trigger runs it.

type driftURIs struct {
	runs int
	res  zitadel.URIResult
	err  error
}

func (d *driftURIs) Sync(context.Context, []site.Site) (zitadel.URIResult, error) {
	return zitadel.URIResult{}, errors.New("not used")
}

func (d *driftURIs) CheckDrift(context.Context, []site.Site) (zitadel.URIResult, error) {
	d.runs++
	return d.res, d.err
}

func (d *driftURIs) OwnedURIs(context.Context) ([]string, bool, error) { return nil, false, nil }

type noRoles struct{}

func (noRoles) ListRoles(context.Context) ([]string, error) { return []string{"devops"}, nil }

// stubCaddy and stubDNS satisfy the artifact surfaces the drift check never touches.
type stubCaddy struct{}

func (stubCaddy) Current(context.Context) (string, error)           { return "", errUnused }
func (stubCaddy) Live(context.Context) ([]byte, error)              { return nil, errUnused }
func (stubCaddy) Apply(context.Context, []site.Site, string) error  { return errUnused }
func (stubCaddy) AdaptJSON(context.Context, string) ([]byte, error) { return nil, errUnused }

type stubDNS struct{}

func (stubDNS) Current(context.Context) (string, bool, error) { return "", false, errUnused }
func (stubDNS) Apply(context.Context, []dns.Record) ([]dns.Mismatch, error) {
	return nil, errUnused
}
func (stubDNS) Restore(context.Context, string) error { return errUnused }

var errUnused = errors.New("unused in this test")

func newDriftReconciler(t *testing.T, uris *driftURIs) *Reconciler {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	v, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.com"}, AllowedTargets: []string{"100.64.0.5"},
	}, noRoles{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	sites, err := site.New(s.DB(), s.Queries(), v)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}
	sp, err := change.NewSite(change.SiteConfig{
		Queries: s.Queries(), Audit: audit.New(s.Queries()), DryRun: s,
		Sites: sites, Caddy: stubCaddy{}, DNS: stubDNS{}, URIs: uris,
		Settings: func(context.Context) (change.SiteSettings, error) { return change.SiteSettings{}, nil },
	})
	if err != nil {
		t.Fatalf("NewSite: %v", err)
	}

	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "dev"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive},
	}
	hs := newFakeHeadscale(`{"acls":[],"groups":{"group:dev":[]}}`)
	hs.users = []headscale.User{{ID: 11, ProviderID: issuer + "/1"}} // F3-031: holders need a Headscale user
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: change.New(hs, s.Queries(), audit.New(s.Queries()), s),
		Queries: s.Queries(), DryRun: s, Issuer: issuer,
		PeriodicCheck: sp.CheckURIDrift,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	setDryRun(t, s, false)
	return r
}

func TestSiteChange_PeriodicURIDrift(t *testing.T) {
	ctx := context.Background()

	t.Run("periodic run triggers the check and shows the drift", func(t *testing.T) {
		uris := &driftURIs{res: zitadel.URIResult{Drift: []zitadel.URIDrift{
			{Kind: zitadel.DriftOwnedRemoved, URI: "https://git.example.com/oauth2/callback"},
		}}}
		r := newDriftReconciler(t, uris)
		res, err := r.Run(ctx, TriggerPeriodic)
		if uris.runs != 1 {
			t.Fatalf("drift checks = %d, want 1", uris.runs)
		}
		if err == nil || !strings.Contains(err.Error(), "owned_removed https://git.example.com/oauth2/callback") {
			t.Errorf("Run error = %v, want the drift named", err)
		}
		// The drift never stops the reconcile itself.
		if !res.Change.Applied {
			t.Errorf("reconcile result = %+v, want it applied despite the drift", res)
		}
	})

	t.Run("a clean list is not an error", func(t *testing.T) {
		uris := &driftURIs{}
		r := newDriftReconciler(t, uris)
		if _, err := r.Run(ctx, TriggerPeriodic); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if uris.runs != 1 {
			t.Errorf("drift checks = %d, want 1", uris.runs)
		}
	})

	t.Run("an unreadable list is reported", func(t *testing.T) {
		uris := &driftURIs{err: errors.New("zitadel down")}
		r := newDriftReconciler(t, uris)
		if _, err := r.Run(ctx, TriggerPeriodic); err == nil || !strings.Contains(err.Error(), "zitadel down") {
			t.Errorf("Run error = %v, want the read failure", err)
		}
	})

	t.Run("webhook and manual runs do not run it", func(t *testing.T) {
		for _, trig := range []string{TriggerWebhook, TriggerManual} {
			uris := &driftURIs{}
			r := newDriftReconciler(t, uris)
			if _, err := r.Run(ctx, trig); err != nil {
				t.Fatalf("Run(%s): %v", trig, err)
			}
			if uris.runs != 0 {
				t.Errorf("%s run did %d drift checks, want 0", trig, uris.runs)
			}
		}
	})
}
