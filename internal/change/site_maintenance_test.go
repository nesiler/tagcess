package change

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
)

// The F3b-017 acceptance tests: while the durable Headscale maintenance flag is open, the site
// pipeline refuses every change that would write the MagicDNS extra-records file, before the first
// external write. A change that leaves the DNS records alone still runs, and an unreadable flag
// fails closed.

// intoMaintenance drives the harness's store into the active maintenance state, through the same
// F3b-013 service the pipeline reads.
func intoMaintenance(t *testing.T, h *siteHarness) {
	t.Helper()
	svc := maintenance.New(h.st.Queries())
	if _, err := svc.Start(context.Background(), "req-1", "devops@example.com"); err != nil {
		t.Fatalf("maintenance.Start: %v", err)
	}
}

// AC1: a manual record save is refused with "bakım sürüyor" and the DNS file is not touched.
func TestChange_MaintenanceRefusesManualDNS(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	intoMaintenance(t, h)
	before := h.dns.body()
	h.calls.reset()

	res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
	if err != nil {
		t.Fatalf("Submit error = %v, want a blocked result", err)
	}
	if res.Status != StatusBlocked || res.Applied {
		t.Fatalf("Submit = %+v, want blocked", res.Result)
	}
	if got := h.callLog().get(); len(got) != 0 {
		t.Errorf("external steps = %v, want none while in maintenance", got)
	}
	if h.dns.body() != before {
		t.Errorf("the dns file was written during maintenance")
	}
	if got := harnessManual(t, h); len(got) != 0 {
		t.Errorf("a refused manual change stored %+v", got)
	}
	rows := h.changes()
	if len(rows) != 1 || !strings.Contains(rows[0].Error, "bakım sürüyor") {
		t.Errorf("change rows = %+v, want one row naming the maintenance", rows)
	}
}

// AC2: a site change that would change the DNS records is refused before Caddy, Zitadel or DNS.
func TestChange_MaintenanceRefusesDNSSiteChange(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	intoMaintenance(t, h)
	before := h.dns.body()
	h.calls.reset()

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit error = %v, want a blocked result", err)
	}
	if res.Status != StatusBlocked || res.Applied {
		t.Fatalf("Submit = %+v, want blocked", res.Result)
	}
	if got := h.callLog().get(); len(got) != 0 {
		t.Errorf("external steps = %v, want none while in maintenance", got)
	}
	if h.hasHost(wikiHost) {
		t.Errorf("the blocked change created %s", wikiHost)
	}
	if h.dns.body() != before {
		t.Errorf("the dns file was written during maintenance")
	}
	if got := auditByName(h.audits(), "site.apply_start"); len(got) != 0 {
		t.Errorf("intent audits = %d, want none before the first write", len(got))
	}
	rows := h.changes()
	if len(rows) != 1 || !strings.Contains(rows[0].Error, "bakım sürüyor") {
		t.Errorf("change rows = %+v, want one row naming the maintenance", rows)
	}
}

// A resync still runs the DNS step when the rendered file equals the one on disk, and the step
// rewrites the file, so in maintenance it is refused like any other DNS write.
func TestChange_MaintenanceRefusesConvergedResync(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusApplied {
		t.Fatalf("resync baseline: %v (%s)", err, res.Status)
	}
	intoMaintenance(t, h)
	before := h.dns.body()
	h.calls.reset()

	res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("Submit error = %v, want a blocked result", err)
	}
	if res.Plan.Diff.DNS != "" {
		t.Fatalf("the resync is not converged: dns diff %q", res.Plan.Diff.DNS)
	}
	if res.Status != StatusBlocked || res.Applied {
		t.Fatalf("Submit = %+v, want blocked", res.Result)
	}
	if got := h.callLog().get(); len(got) != 0 {
		t.Errorf("external steps = %v, want none while in maintenance", got)
	}
	if h.dns.body() != before {
		t.Errorf("the dns file was written during maintenance")
	}
}

// AC3: a site change that leaves the DNS records alone still applies.
func TestChange_MaintenanceAllowsNonDNSSiteChange(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	intoMaintenance(t, h)
	h.calls.reset()

	edit := roleSiteRecord("git", "devops", "developer")
	res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: h.siteID(gitHost), Site: edit})
	if err != nil || !res.Applied {
		t.Fatalf("Submit = %+v, %v, want applied", res.Result, err)
	}
	if res.Plan.Diff.DNS != "" {
		t.Fatalf("the change unexpectedly writes DNS: %q", res.Plan.Diff.DNS)
	}
	if got := h.callLog().get(); !equalStrings(got, []string{"caddy"}) {
		t.Errorf("external steps = %v, want caddy only", got)
	}
}

// AC4: an unreadable maintenance state refuses the DNS-producing change (fail safe).
func TestChange_MaintenanceDNSUnreadableFailsClosed(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	// A maintenance gate over a closed database stands in for an unreadable state: the pipeline
	// must refuse rather than assume "off".
	dead, err := store.Open(ctx, filepath.Join(t.TempDir(), "maintenance.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	h.maint = maintenance.New(dead.Queries())
	if err := dead.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h.build()
	before := h.dns.body()
	h.calls.reset()

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit error = %v, want a blocked result", err)
	}
	if res.Status != StatusBlocked || res.Applied {
		t.Fatalf("Submit = %+v, want blocked", res.Result)
	}
	if got := h.callLog().get(); len(got) != 0 {
		t.Errorf("external steps = %v, want none", got)
	}
	if h.hasHost(wikiHost) {
		t.Errorf("the blocked change created %s", wikiHost)
	}
	if h.dns.body() != before {
		t.Errorf("the dns file was written")
	}
	rows := h.changes()
	if len(rows) != 1 || !strings.Contains(rows[0].Error, "bakım sürüyor") {
		t.Errorf("change rows = %+v, want one row naming the maintenance", rows)
	}
}
