package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The real adapters satisfy the read-only interfaces: the drift check can only read through them.
var (
	_ PolicySource = (*headscale.Client)(nil)
	_ CaddyReader  = (*change.CaddyFile)(nil)
	_ DNSReader    = (*change.DNSFile)(nil)
	_ URIReader    = (*ZitadelURIs)(nil)
	_ SiteRecords  = (*site.Store)(nil)
)

const (
	appliedPolicy = "// applied\n{\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}]}\n"
	// samePolicyFormatted has the same meaning as appliedPolicy: only comments and spacing differ.
	samePolicyFormatted = "{\n  // reformatted\n  \"acls\": [{\"dst\": [\"*:*\"], \"src\": [\"*\"], \"action\": \"accept\"}],\n}\n"
	otherPolicy         = "{\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}, {\"action\": \"accept\", \"src\": [\"x\"], \"dst\": [\"*:*\"]}]}\n"
)

type fakePolicy struct {
	text  string
	err   error
	calls int
}

func (f *fakePolicy) GetPolicy(context.Context) (headscale.Policy, error) {
	f.calls++
	if f.err != nil {
		return headscale.Policy{}, f.err
	}
	return headscale.Policy{Text: f.text}, nil
}

type fakeSites struct {
	sites   []site.Site
	pending bool
	err     error
}

func (f *fakeSites) ListSites(context.Context) ([]site.Site, error) { return f.sites, f.err }
func (f *fakeSites) FirstImportPending(context.Context) (bool, error) {
	return f.pending, f.err
}

type fakeCaddy struct {
	disk, live           string // the Caddyfile on disk and the Caddyfile the live config came from
	diskErr, liveErr     error
	adaptErr             error
	diskCalls, liveCalls int
	rawLive              []byte // overrides the live config when set
}

func (f *fakeCaddy) Current(context.Context) (string, error) {
	f.diskCalls++
	return f.disk, f.diskErr
}

func (f *fakeCaddy) Live(context.Context) ([]byte, error) {
	f.liveCalls++
	if f.liveErr != nil {
		return nil, f.liveErr
	}
	if f.rawLive != nil {
		return f.rawLive, nil
	}
	return adapt(f.live), nil
}

func (f *fakeCaddy) AdaptJSON(_ context.Context, caddyfile string) ([]byte, error) {
	if f.adaptErr != nil {
		return nil, f.adaptErr
	}
	return adapt(caddyfile), nil
}

// adapt is a deterministic stand-in for Caddy's adapter: the JSON carries the Caddyfile text.
func adapt(caddyfile string) []byte {
	b, _ := json.Marshal(map[string]any{"adapted": caddyfile, "apps": map[string]any{}})
	return b
}

type fakeDNS struct {
	content string
	exists  bool
	err     error
	calls   int
}

func (f *fakeDNS) Current(context.Context) (string, bool, error) {
	f.calls++
	return f.content, f.exists, f.err
}

type fakeURIs struct {
	live       []string
	owned      []string
	haveOwned  bool
	liveErr    error
	ownedErr   error
	liveCalls  int
	ownedCalls int
}

func (f *fakeURIs) Redirects(context.Context) ([]string, error) {
	f.liveCalls++
	return f.live, f.liveErr
}

func (f *fakeURIs) Owned(context.Context) ([]string, bool, error) {
	f.ownedCalls++
	return f.owned, f.haveOwned, f.ownedErr
}

// driftHarness is a complete, matching world: every source equals the applied baseline until a
// test changes one of them.
type driftHarness struct {
	t      *testing.T
	svc    *Service
	st     *store.Store
	clock  *fakeClock
	drift  *Drift
	repo   *policyrev.Repo
	policy *fakePolicy
	sites  *fakeSites
	caddy  *fakeCaddy
	dns    *fakeDNS
	uris   *fakeURIs
}

func driftSites() []site.Site {
	return []site.Site{{
		ID: 1, Hosts: []string{"app.example.com"}, Kind: site.KindRole, Roles: []string{"devops"},
		TargetRoles: []string{}, Cert: "le:example", TargetKind: site.TargetK8s, MagicDNS: true,
		APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}}
}

func newDriftHarness(t *testing.T) *driftHarness { return newDriftHarnessWith(t, true) }

// newDriftHarnessWith builds the matching world; withPolicy false leaves it without an applied
// policy revision (no policy baseline).
func newDriftHarnessWith(t *testing.T, withPolicy bool) *driftHarness {
	t.Helper()
	svc, st, _, _ := openService(t)
	clock := newFakeClock(testBaseTime)
	svc.clock = clock.now

	h := &driftHarness{t: t, svc: svc, st: st, clock: clock, repo: policyrev.New(st.Queries())}
	h.sites = &fakeSites{sites: driftSites()}
	cfg := change.SiteSettings{
		Caddy: render.CaddyConfig{ACMEEmail: "ops@example.com", S06Open: true},
		DNS:   render.DNSConfig{AValue: "100.64.0.4"},
	}
	caddyfile, err := render.RenderCaddyfile(h.sites.sites, cfg.Caddy)
	if err != nil {
		t.Fatalf("render caddyfile: %v", err)
	}
	records, err := render.RenderDNSRecords(h.sites.sites, cfg.ManualDNS, cfg.DNS)
	if err != nil {
		t.Fatalf("render dns: %v", err)
	}
	dnsBody, err := dns.Marshal(records)
	if err != nil {
		t.Fatalf("marshal dns: %v", err)
	}
	desired, err := zitadel.DesiredURIs(h.sites.sites)
	if err != nil {
		t.Fatalf("desired uris: %v", err)
	}

	h.policy = &fakePolicy{text: appliedPolicy}
	h.caddy = &fakeCaddy{disk: caddyfile, live: caddyfile}
	h.dns = &fakeDNS{content: dnsBody, exists: true}
	h.uris = &fakeURIs{live: append([]string{}, desired...), owned: desired, haveOwned: true}
	if withPolicy {
		h.applyPolicy(appliedPolicy)
	}

	d, err := NewDrift(svc, DriftConfig{
		Policy: h.policy, Baseline: NewPolicyBaseline(st.Queries()), Sites: h.sites,
		Settings: func(context.Context) (change.SiteSettings, error) { return cfg, nil },
		Caddy:    h.caddy, DNS: h.dns, URIs: h.uris,
	})
	if err != nil {
		t.Fatalf("NewDrift: %v", err)
	}
	h.drift = d
	return h
}

// applyPolicy records raw as an applied revision (the baseline).
func (h *driftHarness) applyPolicy(raw string) policyrev.Revision {
	h.t.Helper()
	ctx := context.Background()
	rev, err := h.repo.Add(ctx, policyrev.NewRevision{Raw: raw, Source: policyrev.SourceUI, Actor: "dev@example.com"})
	if err != nil {
		h.t.Fatalf("add revision: %v", err)
	}
	if err := h.repo.Finish(ctx, rev.ID, policyrev.StatusApplied, "ok"); err != nil {
		h.t.Fatalf("finish revision: %v", err)
	}
	return rev
}

func (h *driftHarness) check() map[string]DriftFinding {
	h.t.Helper()
	found, err := h.drift.Check(context.Background())
	if err != nil {
		h.t.Fatalf("Check: %v", err)
	}
	out := map[string]DriftFinding{}
	for _, f := range found {
		out[f.Subject] = f
	}
	return out
}

func (h *driftHarness) openDrift(subject string) (Alert, bool) {
	h.t.Helper()
	a, err := h.svc.Get(context.Background(), KindDrift, subject, SourceDrift)
	if errors.Is(err, ErrNotFound) {
		return Alert{}, false
	}
	if err != nil {
		h.t.Fatalf("Get drift %s: %v", subject, err)
	}
	return a, true
}

func (h *driftHarness) openStale(subject string) (Alert, bool) {
	h.t.Helper()
	a, err := h.svc.Get(context.Background(), KindSourceStale, subject, SourceDrift)
	if errors.Is(err, ErrNotFound) {
		return Alert{}, false
	}
	if err != nil {
		h.t.Fatalf("Get stale %s: %v", subject, err)
	}
	return a, true
}

func (h *driftHarness) openLegacy(kind, source string) {
	h.t.Helper()
	if _, err := h.st.Queries().InsertAlert(context.Background(), db.InsertAlertParams{
		Kind: kind, Source: source, FirstSeenAt: stamp(h.clock.now()), LastSeenAt: stamp(h.clock.now()),
	}); err != nil {
		h.t.Fatalf("InsertAlert %s: %v", kind, err)
	}
}

// legacyOpen lists the open legacy (empty subject) alert kinds.
func (h *driftHarness) legacyOpen() map[string]bool {
	h.t.Helper()
	rows, err := h.st.Queries().ListOpenAlerts(context.Background())
	if err != nil {
		h.t.Fatalf("ListOpenAlerts: %v", err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.Subject == "" {
			out[r.Kind] = true
		}
	}
	return out
}

func requireStatus(t *testing.T, got map[string]DriftFinding, subject string, want DriftStatus) {
	t.Helper()
	f, ok := got[subject]
	if !ok {
		t.Fatalf("no finding for %s in %v", subject, got)
	}
	if f.Status != want {
		t.Fatalf("%s status = %s (%s), want %s", subject, f.Status, f.Evidence, want)
	}
}

var driftSubjects = []string{SubjectPolicy, SubjectCaddyFile, SubjectCaddyLive, SubjectDNS, SubjectURIs}

// AC1: a complete read that differs from the applied baseline raises drift for that source only;
// a foreign URI is not an owned drift; a formatting-only policy change is not a difference.
func TestAlertDriftRequiresCompleteOwnedBaseline(t *testing.T) {
	h := newDriftHarness(t)
	desired, _ := zitadel.DesiredURIs(h.sites.sites)

	t.Run("everything matching opens nothing", func(t *testing.T) {
		got := h.check()
		for _, s := range driftSubjects {
			requireStatus(t, got, s, DriftMatch)
			if _, open := h.openDrift(s); open {
				t.Fatalf("%s: drift alert open on a matching source", s)
			}
		}
		if open, _ := h.svc.ListOpen(context.Background()); len(open) != 0 {
			t.Fatalf("ListOpen = %+v, want none", open)
		}
	})

	t.Run("foreign URIs and policy formatting are not drift", func(t *testing.T) {
		h.uris.live = append(append([]string{}, desired...), "https://somebody-else.example/callback")
		h.policy.text = samePolicyFormatted
		got := h.check()
		requireStatus(t, got, SubjectURIs, DriftMatch)
		requireStatus(t, got, SubjectPolicy, DriftMatch)
		h.uris.live = append([]string{}, desired...)
		h.policy.text = appliedPolicy
	})

	cases := []struct {
		subject string
		mutate  func()
		restore func()
	}{
		{SubjectPolicy, func() { h.policy.text = otherPolicy }, func() { h.policy.text = appliedPolicy }},
		{SubjectCaddyFile, func() { h.caddy.disk += "\nextra.example { respond 200 }\n" }, func() {
			h.caddy.disk = h.caddy.live
		}},
		{SubjectCaddyLive, func() { h.caddy.live += "\nextra.example { respond 200 }\n" }, func() {
			h.caddy.live = h.caddy.disk
		}},
		{SubjectDNS, func() { h.dns.content += "extra\n" }, func() { h.dns.content = strings.TrimSuffix(h.dns.content, "extra\n") }},
		{SubjectDNS + " file missing", func() { h.dns.exists, h.dns.content = false, "" }, func() {
			h.dns.exists = true
			rec, _ := render.RenderDNSRecords(h.sites.sites, nil, render.DNSConfig{AValue: "100.64.0.4"})
			h.dns.content, _ = dns.Marshal(rec)
		}},
		{SubjectURIs + " desired missing", func() { h.uris.live = nil }, func() { h.uris.live = append([]string{}, desired...) }},
		{SubjectURIs + " stale owned", func() {
			h.uris.owned = append(append([]string{}, desired...), "https://gone.example.com/oauth2/callback")
			h.uris.live = append(append([]string{}, desired...), "https://gone.example.com/oauth2/callback")
		}, func() { h.uris.owned = desired; h.uris.live = append([]string{}, desired...) }},
	}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			tc.mutate()
			subject, _, _ := strings.Cut(tc.subject, " ")
			got := h.check()
			for _, s := range driftSubjects {
				want := DriftMatch
				if s == subject {
					want = DriftDiffers
				}
				requireStatus(t, got, s, want)
			}
			a, open := h.openDrift(subject)
			if !open || a.Severity != SeverityCritical || a.Evidence == "" || a.Freshness != FreshnessFresh {
				t.Fatalf("drift alert for %s = %+v open=%v, want an open critical fresh alert with a summary", subject, a, open)
			}
			if a.Source != SourceDrift {
				t.Fatalf("source = %q, want %q", a.Source, SourceDrift)
			}
			// A repeated check keeps one alert (dedup by key).
			before := a.ID
			h.clock.advance(1)
			h.check()
			if again, _ := h.openDrift(subject); again.ID != before {
				t.Fatalf("repeat check opened a second alert: %d vs %d", again.ID, before)
			}
			tc.restore()
			requireStatus(t, h.check(), subject, DriftMatch)
			if _, open := h.openDrift(subject); open {
				t.Fatalf("%s: drift alert stayed open after the source matched again", subject)
			}
		})
	}
}

// AC2: an unreadable source, a missing baseline or a pending first import is shown as
// read/freshness uncertainty, never as a difference and never as a recovery.
func TestAlertDriftUnreadableSourceIsNotDifferenceOrRecovery(t *testing.T) {
	t.Run("unreadable source keeps the drift alert and raises freshness", func(t *testing.T) {
		h := newDriftHarness(t)
		h.policy.text = otherPolicy
		requireStatus(t, h.check(), SubjectPolicy, DriftDiffers)
		raised, _ := h.openDrift(SubjectPolicy)

		h.policy.err = errors.New("rpc: connection refused")
		h.dns.err = errors.New("permission denied")
		got := h.check()
		requireStatus(t, got, SubjectPolicy, DriftUncertain)
		requireStatus(t, got, SubjectDNS, DriftUncertain)

		kept, open := h.openDrift(SubjectPolicy)
		if !open || kept.ID != raised.ID || kept.Resolved {
			t.Fatalf("drift alert after an unreadable source = %+v open=%v, want the same open alert", kept, open)
		}
		if kept.Freshness != FreshnessStale {
			t.Fatalf("drift freshness = %q, want stale", kept.Freshness)
		}
		if _, open := h.openStale(SubjectPolicy); !open {
			t.Fatal("no freshness alert for the unreadable policy")
		}
		if _, open := h.openDrift(SubjectDNS); open {
			t.Fatal("an unreadable DNS file was reported as drift")
		}
		if _, open := h.openStale(SubjectDNS); !open {
			t.Fatal("no freshness alert for the unreadable DNS file")
		}

		// The source comes back and matches: the drift and its freshness alert close.
		h.policy.err, h.dns.err, h.policy.text = nil, nil, appliedPolicy
		got = h.check()
		requireStatus(t, got, SubjectPolicy, DriftMatch)
		if _, open := h.openDrift(SubjectPolicy); open {
			t.Fatal("drift alert stayed open after the policy matched")
		}
		if _, open := h.openStale(SubjectPolicy); open {
			t.Fatal("freshness alert stayed open after the policy was read again")
		}
	})

	t.Run("a live config that cannot be compared is uncertain", func(t *testing.T) {
		h := newDriftHarness(t)
		h.caddy.rawLive = []byte("not json")
		requireStatus(t, h.check(), SubjectCaddyLive, DriftUncertain)
		h.caddy.rawLive = nil
		h.caddy.adaptErr = errors.New("adapt failed")
		requireStatus(t, h.check(), SubjectCaddyLive, DriftUncertain)
		h.caddy.adaptErr = nil
		h.caddy.liveErr = errors.New("admin api down")
		got := h.check()
		requireStatus(t, got, SubjectCaddyLive, DriftUncertain)
		requireStatus(t, got, SubjectCaddyFile, DriftMatch)
		if _, open := h.openDrift(SubjectCaddyLive); open {
			t.Fatal("unreadable live config reported as drift")
		}
	})

	t.Run("no baseline is uncertain, raises no drift alert and shows as unknown", func(t *testing.T) {
		// No applied revision, no ownership record.
		h2 := newDriftHarnessWith(t, false)
		h2.uris.haveOwned = false
		h2.policy.text = otherPolicy
		h2.uris.live = nil
		got := h2.check()
		requireStatus(t, got, SubjectPolicy, DriftUncertain)
		requireStatus(t, got, SubjectURIs, DriftUncertain)
		if h2.policy.calls != 0 || h2.uris.liveCalls != 0 {
			t.Fatalf("read a source without a baseline: policy=%d uris=%d", h2.policy.calls, h2.uris.liveCalls)
		}
		// Round review A-M3 (replaces the old "writes nothing" assertion, which let an artifact that
		// was never compared read as drift-free): no drift alert, but a freshness alert per artifact.
		if _, open := h2.openDrift(SubjectPolicy); open {
			t.Fatal("a missing baseline was reported as drift")
		}
		for _, s := range []string{SubjectPolicy, SubjectURIs} {
			a, open := h2.openStale(s)
			if !open || a.Evidence == "" {
				t.Fatalf("no freshness alert with a fixed reason for %s without a baseline", s)
			}
		}
	})

	t.Run("a policy apply in flight is uncertain", func(t *testing.T) {
		h := newDriftHarness(t)
		if _, err := h.repo.Add(context.Background(), policyrev.NewRevision{Raw: otherPolicy, Source: policyrev.SourceUI, Actor: "dev@example.com"}); err != nil {
			t.Fatalf("add pending revision: %v", err)
		}
		h.policy.text = otherPolicy
		requireStatus(t, h.check(), SubjectPolicy, DriftUncertain)
		if _, open := h.openDrift(SubjectPolicy); open {
			t.Fatal("an in-flight apply was reported as drift")
		}
	})

	t.Run("pending first import is uncertain for every source", func(t *testing.T) {
		h := newDriftHarness(t)
		h.policy.text = otherPolicy
		requireStatus(t, h.check(), SubjectPolicy, DriftDiffers)
		h.sites.pending = true
		h.dns.content = "different"
		h.caddy.diskCalls, h.dns.calls = 0, 0
		got := h.check()
		for _, s := range driftSubjects {
			requireStatus(t, got, s, DriftUncertain)
		}
		if a, open := h.openDrift(SubjectPolicy); !open || a.Resolved {
			t.Fatal("a pending first import resolved an existing drift alert")
		}
		if h.caddy.diskCalls != 0 || h.dns.calls != 0 {
			t.Fatalf("artifacts were read while the first import is pending: disk=%d dns=%d", h.caddy.diskCalls, h.dns.calls)
		}
		// F5 A2 (developer decision 2026-10-05): a pending first import is ONE "kurulum bekliyor"
		// state shown by the dashboard (Pending), not five freshness alerts.
		if !h.drift.Pending() {
			t.Fatal("Pending() = false while the first import is pending")
		}
		for _, s := range driftSubjects {
			if _, open := h.openStale(s); open {
				t.Fatalf("a freshness alert was raised for %s while the first import is pending", s)
			}
		}
	})

	t.Run("finished first import clears the pending state and compares again", func(t *testing.T) {
		h := newDriftHarness(t)
		h.sites.pending = true
		h.check()
		if !h.drift.Pending() {
			t.Fatal("Pending() = false while the first import is pending")
		}
		h.sites.pending = false
		got := h.check()
		if h.drift.Pending() {
			t.Fatal("Pending() = true after the first import finished")
		}
		requireStatus(t, got, SubjectDNS, DriftMatch)
	})

	t.Run("the hold hook skips the comparison and records nothing", func(t *testing.T) {
		h := newDriftHarness(t)
		h.policy.text = otherPolicy
		held := true
		h.drift.cfg.Hold = func(context.Context) (bool, error) { return held, nil }
		h.policy.calls = 0
		got := h.check()
		for _, s := range driftSubjects {
			requireStatus(t, got, s, DriftUncertain)
		}
		if h.policy.calls != 0 {
			t.Fatalf("the policy was read while an apply is held: %d", h.policy.calls)
		}
		if open, _ := h.svc.ListOpen(context.Background()); len(open) != 0 {
			t.Fatalf("alerts = %+v, want none while held", open)
		}
		if !h.drift.Held() {
			t.Fatal("Held() = false after a held check")
		}
		held = false
		requireStatus(t, h.check(), SubjectPolicy, DriftDiffers)
		if h.drift.Held() {
			t.Fatal("Held() = true after a compared check")
		}
	})

	t.Run("unreadable site records fail the check and are visible as uncertain", func(t *testing.T) {
		h := newDriftHarness(t)
		h.sites.err = errors.New("db locked")
		if _, err := h.drift.Check(context.Background()); err == nil {
			t.Fatal("Check succeeded with unreadable site records")
		}
		for _, s := range driftSubjects {
			if _, open := h.openStale(s); !open {
				t.Fatalf("no freshness alert for %s while the site records are unreadable", s)
			}
		}
	})
}

// AC3: a successful, matching source resolves only its own monitor alarm; other subjects' drift
// and the legacy F1/F2/F3 alarms are neither copied nor resolved.
func TestAlertDriftPreservesOtherSubjectsAndLegacyOwners(t *testing.T) {
	h := newDriftHarness(t)
	h.policy.text = otherPolicy
	h.dns.content += "extra\n"
	h.openLegacy(change.AlertPolicyMismatch, "headscale")
	h.openLegacy(change.AlertSiteDrift, "7")
	h.openLegacy(zitadel.AlertURIDrift, zitadel.SourceOAuth2ProxyApp)
	h.openLegacy("reconcile_read_failed", "zitadel")

	got := h.check()
	requireStatus(t, got, SubjectPolicy, DriftDiffers)
	requireStatus(t, got, SubjectDNS, DriftDiffers)
	// The legacy policy alarm already represents the policy problem: no monitor copy.
	if _, open := h.openDrift(SubjectPolicy); open {
		t.Fatal("a monitor copy of the legacy policy alarm was opened")
	}
	if !got[SubjectPolicy].LegacyOwned {
		t.Fatalf("policy finding = %+v, want it marked as owned by a legacy alarm", got[SubjectPolicy])
	}
	// The DNS drift is covered by the legacy site_drift alarm as well.
	if _, open := h.openDrift(SubjectDNS); open {
		t.Fatal("a monitor copy of the legacy site alarm was opened")
	}

	// Remove the legacy owners' reach for DNS: resolve only that legacy kind, then DNS drifts alone.
	if _, err := h.st.Queries().ResolveAlertKind(context.Background(), db.ResolveAlertKindParams{
		ResolvedAt: stampNull(h.clock.now()), Kind: change.AlertSiteDrift,
	}); err != nil {
		t.Fatalf("resolve legacy site_drift: %v", err)
	}
	h.check()
	dnsAlert, open := h.openDrift(SubjectDNS)
	if !open {
		t.Fatal("DNS drift not raised once no legacy alarm owns it")
	}
	h.uris.live = nil
	h.check()
	uriAlert, uriOpen := h.openDrift(SubjectURIs)
	if uriOpen {
		t.Fatalf("monitor copy of legacy URI alarm opened: %+v", uriAlert)
	}

	// Policy matches again: only the policy subject is resolved by this run, and a legacy
	// alarm is not resolved by a matching source.
	h.policy.text = appliedPolicy
	h.dns.content = strings.TrimSuffix(h.dns.content, "extra\n") + "extra\n"
	got = h.check()
	requireStatus(t, got, SubjectPolicy, DriftMatch)
	if still, open := h.openDrift(SubjectDNS); !open || still.ID != dnsAlert.ID {
		t.Fatalf("DNS drift alert = %+v open=%v, want it untouched by the policy match", still, open)
	}
	legacy := h.legacyOpen()
	for _, kind := range []string{change.AlertPolicyMismatch, zitadel.AlertURIDrift, "reconcile_read_failed"} {
		if !legacy[kind] {
			t.Fatalf("legacy alarm %s was resolved by the drift check; open = %v", kind, legacy)
		}
	}

	// A matching source resolves its own drift alert but nobody else's.
	h.dns.content = strings.TrimSuffix(h.dns.content, "extra\n")
	requireStatus(t, h.check(), SubjectDNS, DriftMatch)
	if _, open := h.openDrift(SubjectDNS); open {
		t.Fatal("DNS drift alert stayed open after DNS matched")
	}
	legacy = h.legacyOpen()
	if !legacy[change.AlertPolicyMismatch] || !legacy[zitadel.AlertURIDrift] {
		t.Fatalf("legacy alarms after the matches = %v, want them still open", legacy)
	}
}

// AC4: the check reads each source once through read-only interfaces, writes nothing but monitor
// alerts, and never puts secrets, bodies or raw errors into evidence.
func TestAlertDriftIsReadOnlyAndSanitizesEvidence(t *testing.T) {
	const secret = "s3cr3t-token-VALUE"
	h := newDriftHarness(t)
	before := tableCounts(t, h.st)

	// Differences whose raw content carries a secret.
	h.policy.text = otherPolicy + "// authkey " + secret + "\n"
	h.caddy.disk += "\nbasicauth { admin " + secret + " }\n"
	h.dns.content += secret + "\n"
	h.uris.live = []string{"https://x.example/cb?token=" + secret}
	got := h.check()
	for _, s := range []string{SubjectPolicy, SubjectCaddyFile, SubjectDNS, SubjectURIs} {
		requireStatus(t, got, s, DriftDiffers)
	}
	if h.policy.calls != 1 || h.caddy.diskCalls != 1 || h.caddy.liveCalls != 1 || h.dns.calls != 1 || h.uris.liveCalls != 1 {
		t.Fatalf("reads per check: policy=%d disk=%d live=%d dns=%d uris=%d, want one each",
			h.policy.calls, h.caddy.diskCalls, h.caddy.liveCalls, h.dns.calls, h.uris.liveCalls)
	}

	// Read failures whose errors carry a secret.
	h.policy.err = fmt.Errorf("GET https://user:%s@hs.example/policy: Authorization: Bearer %s", secret, secret)
	h.caddy.diskErr = errors.New("open /etc/caddy/Caddyfile: " + secret)
	h.caddy.liveErr = errors.New("body: " + secret)
	h.dns.err = errors.New("header X-Api-Key: " + secret)
	h.uris.liveErr = errors.New("token " + secret)
	got = h.check()

	after := tableCounts(t, h.st)
	for table, n := range before {
		if table != "alerts" && after[table] != n {
			t.Fatalf("table %s changed from %d to %d rows; the drift check may only write alerts", table, n, after[table])
		}
	}

	rows, err := h.st.Queries().ListOpenAlerts(context.Background())
	if err != nil {
		t.Fatalf("ListOpenAlerts: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no alerts raised")
	}
	for _, r := range rows {
		if strings.Contains(r.EvidenceSummary, secret) || strings.Contains(r.EvidenceSummary, "Bearer") || len(r.EvidenceSummary) > maxEvidence {
			t.Fatalf("alert %s/%s evidence %q leaks or is unbounded", r.Kind, r.Subject, r.EvidenceSummary)
		}
	}
	for _, f := range got {
		if strings.Contains(f.Evidence, secret) {
			t.Fatalf("finding %s evidence %q leaks the secret", f.Subject, f.Evidence)
		}
	}
	if len(got) != len(driftSubjects) {
		t.Fatalf("findings = %d, want %d", len(got), len(driftSubjects))
	}
}

func stampNull(t time.Time) sql.NullString {
	return sql.NullString{String: stamp(t), Valid: true}
}

// M2: a local read that fails before any artifact is compared is uncertainty, never silence.
func TestAlertDriftUnreadableLocalStateIsRecordedUncertain(t *testing.T) {
	cases := map[string]func(h *driftHarness){
		"first import state": func(h *driftHarness) { h.sites.err = errors.New("db locked") },
		"hold state": func(h *driftHarness) {
			h.drift.cfg.Hold = func(context.Context) (bool, error) { return true, errors.New("maintenance down") }
		},
		"render settings": func(h *driftHarness) {
			h.drift.cfg.Settings = func(context.Context) (change.SiteSettings, error) {
				return change.SiteSettings{}, errors.New("settings down")
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newDriftHarness(t)
			setup(h)
			if _, err := h.drift.Check(context.Background()); err == nil {
				t.Fatal("Check returned no error for an unreadable local state")
			}
			for _, s := range driftSubjects {
				a, open := h.openStale(s)
				if !open {
					t.Fatalf("no freshness alert for %s", s)
				}
				if strings.Contains(a.Evidence, "down") || strings.Contains(a.Evidence, "locked") {
					t.Fatalf("evidence echoes the raw error: %q", a.Evidence)
				}
			}
		})
	}
	t.Run("positive control: good sources leave no freshness alert", func(t *testing.T) {
		h := newDriftHarness(t)
		h.check()
		for _, s := range driftSubjects {
			if _, open := h.openStale(s); open {
				t.Fatalf("freshness alert for %s with good sources", s)
			}
		}
	})
}

// J2: the Caddy drift evidence names the likely cause (a newer template) and the fix (resync); the DNS
// drift, which a template cannot cause, does not carry the hint (positive control).
func TestAlertDriftCaddyEvidenceNamesTemplateCause(t *testing.T) {
	h := newDriftHarness(t)
	h.caddy.disk += "\n# older template\n"
	h.caddy.live += "\nextra.example { respond 200 }\n"
	h.dns.content += "extra\n"
	got := h.check()
	for _, s := range []string{SubjectCaddyFile, SubjectCaddyLive} {
		f := got[s]
		if f.Status != DriftDiffers || !strings.Contains(f.Evidence, "şablon güncellendi") || !strings.Contains(f.Evidence, "/sites") || !strings.Contains(f.Evidence, "Kayıtlardan yeniden apply et") {
			t.Errorf("%s evidence lacks the template hint: %+v", s, f)
		}
	}
	if f := got[SubjectDNS]; f.Status != DriftDiffers || strings.Contains(f.Evidence, "şablon") {
		t.Errorf("dns evidence = %+v, want a plain difference", f)
	}
}
