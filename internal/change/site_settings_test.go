package change

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

// F2-015 (S-06, ADR 0010 m.5): the WireGuard key is a render input the interface changes through
// the site change pipeline. PreviewSettings shows the diff the new key state would produce before
// anything is stored; the approval stores the value and applies a resync, whose rendered
// Caddyfile is the access matrix: role and open sites answer 403 outside the tailnet, the @api
// exemption still passes from every source.

// apiRoleSite is a role site with an API exemption (the @api branch is the exemption under test).
func apiRoleSite(name string) site.Site {
	s := roleSiteRecord(name)
	s.APIRules = []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "X-Api"}}
	return s
}

// PreviewSettings plans the key flip read-only: the diff is exactly the Caddyfile swap and
// nothing is written.
func TestSiteSettings_PreviewSettingsPlansReadOnly(t *testing.T) {
	h := newSiteHarness(t)
	if _, err := h.sites.CreateSite(context.Background(), apiRoleSite("apix")); err != nil {
		t.Fatalf("seed api site: %v", err)
	}
	// Bring the disk artifacts in line with the records, so the preview below shows exactly the
	// key flip and nothing else.
	if res, err := h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusApplied {
		t.Fatalf("resync baseline: %v (%s)", err, res.Status)
	}
	h.calls.reset()

	closed := h.settings
	closed.Caddy.S06Open = false
	pl, err := h.sp.PreviewSettings(context.Background(), closed)
	if err != nil {
		t.Fatalf("PreviewSettings: %v", err)
	}
	if pl.Diff.Caddy == "" {
		t.Error("the key flip produced no Caddyfile diff")
	}
	// A resync's Zitadel diff is against O (F5 L2); the DNS diff is against the real file and
	// stays empty. Only the Caddyfile actually changes.
	if pl.Diff.DNS != "" {
		t.Errorf("the key flip touched the DNS file: %+v", pl.Diff)
	}
	if pl.Op != SiteResync {
		t.Errorf("op = %q, want resync", pl.Op)
	}
	if len(h.calls.get()) != 0 {
		t.Errorf("the preview wrote to an artifact: %v", h.calls.get())
	}

	// The same settings as the live ones change nothing on disk.
	same, err := h.sp.PreviewSettings(context.Background(), h.settings)
	if err != nil {
		t.Fatalf("PreviewSettings same: %v", err)
	}
	if same.Diff.Caddy != "" || same.Diff.DNS != "" {
		t.Errorf("an unchanged key produced a disk diff: %+v", same.Diff)
	}
}

// AC1: closing the key applies a Caddyfile in which role and open sites answer 403 outside the
// tailnet while the @api exemption keeps passing from every source; opening flips back.
func TestSiteSettings_TailnetGate(t *testing.T) {
	h := newSiteHarness(t)
	if _, err := h.sites.CreateSite(context.Background(), apiRoleSite("apix")); err != nil {
		t.Fatalf("seed api site: %v", err)
	}
	if _, err := h.sites.CreateSite(context.Background(), roleSiteRecord("plain")); err != nil {
		t.Fatalf("seed plain site: %v", err)
	}
	// Align the disk with the records before flipping the key.
	if res, err := h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusApplied {
		t.Fatalf("resync baseline: %v (%s)", err, res.Status)
	}

	// Close: the resync applies the closed-key matrix.
	closed := h.settings
	closed.Caddy.S06Open = false
	pl, err := h.sp.PreviewSettings(context.Background(), closed)
	if err != nil {
		t.Fatalf("preview closed: %v", err)
	}
	if pl.Diff.Caddy == "" {
		t.Fatal("no diff to approve")
	}

	h.settings = closed
	res, err := h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("submit closed: %v", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("status = %s (%s)", res.Status, h.changeError(t, res.ChangeID))
	}
	applied := h.caddy.appliedText(t)
	for _, want := range []string{
		// The closed tail: every role and open site answers 403 outside the tailnet.
		"handle {\n\t\trespond 403\n\t}",
		// The @api exemption keeps its own branch with no source restriction.
		"handle @api {\n\t\timport k8s\n\t}",
	} {
		if !strings.Contains(applied, want) {
			t.Errorf("the closed-key Caddyfile lacks %q:\n%s", want, applied)
		}
	}
	// The api matcher carries no remote_ip: the exemption answers from every source.
	for _, line := range strings.Split(applied, "\n") {
		if strings.Contains(line, "@api ") && strings.Contains(line, "remote_ip") {
			t.Errorf("the @api matcher is source-restricted: %s", line)
		}
	}
	if strings.Count(applied, "respond 403") < 3 {
		t.Errorf("expected a 403 tail per user site, got %d:\n%s", strings.Count(applied, "respond 403"), applied)
	}

	// Reopen: the open-key matrix returns.
	open := h.settings
	open.Caddy.S06Open = true
	h.settings = open
	res, err = h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("submit open: %v", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("status = %s", res.Status)
	}
	applied = h.caddy.appliedText(t)
	if !strings.Contains(applied, "handle {\n\t\timport k8s\n\t}") {
		t.Errorf("the open tail did not return:\n%s", applied)
	}
	// Only the tagcess system block keeps its own S-06-independent 403 tail (S-05.2); the user
	// sites answer through the open snippet again.
	if n := strings.Count(applied, "respond 403"); n != 1 {
		t.Errorf("user site tails did not reopen: %d sites still answer 403:\n%s", n-1, applied)
	}
}

// appliedText returns the Caddyfile text the last successful apply left on disk.
func (f *fakeCaddy) appliedText(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disk
}

// changeError reads the recorded error of a change row for failure messages.
func (h *siteHarness) changeError(t *testing.T, id int64) string {
	t.Helper()
	row, err := h.st.Queries().GetChange(context.Background(), id)
	if err != nil {
		return err.Error()
	}
	return row.Error
}

// F5 L2: a resync's Zitadel diff is against O, the set tagcess last wrote, not against nothing.
// Right after a successful resync nothing differs, so the preview shows no Zitadel change.
func TestSiteResync_ZitadelDiffAgainstOwned(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	if _, err := h.sites.CreateSite(ctx, roleSiteRecord("books", "developer")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Control: no O stored yet, so every desired callback is an addition.
	pl, err := h.sp.Preview(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !strings.Contains(pl.Diff.Zitadel, "+https://books.example.com/oauth2/callback") {
		t.Fatalf("control: no addition without O:\n%s", pl.Diff.Zitadel)
	}
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusApplied {
		t.Fatalf("resync: %v (%s)", err, res.Status)
	}
	pl, err = h.sp.Preview(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("preview after resync: %v", err)
	}
	if pl.Diff.Zitadel != "" {
		t.Errorf("Zitadel diff after a resync = %q, want none", pl.Diff.Zitadel)
	}
	// Positive control: O lacking one callback shows exactly that one as an addition.
	h.uris.mu.Lock()
	h.uris.owned = slices.DeleteFunc(slices.Clone(h.uris.owned), func(u string) bool { return strings.Contains(u, "books.") })
	h.uris.mu.Unlock()
	pl, err = h.sp.Preview(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("preview with partial O: %v", err)
	}
	if !strings.Contains(pl.Diff.Zitadel, "+https://books.example.com/oauth2/callback") {
		t.Errorf("partial O diff = %q, want the books callback added", pl.Diff.Zitadel)
	}
}

// F5 L3: an applied change (a resync here) calls the after-apply hook once, so the monitoring loops
// re-measure drift right away; a dry run or a refused request does not.
func TestSitePipeline_OnAppliedAfterApplyOnly(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	calls := 0
	h.onApplied = func() { calls++ }
	h.build()

	h.dry.mu.Lock()
	h.dry.on = true
	h.dry.mu.Unlock()
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusDryRun {
		t.Fatalf("dry run: %v (%s)", err, res.Status)
	}
	if calls != 0 {
		t.Errorf("hook called %d times on a dry run", calls)
	}
	h.dry.mu.Lock()
	h.dry.on = false
	h.dry.mu.Unlock()

	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync}); err != nil || res.Status != StatusApplied {
		t.Fatalf("resync: %v (%s)", err, res.Status)
	}
	if calls != 1 {
		t.Errorf("hook called %d times after one apply, want 1", calls)
	}
	// A failed Caddy step is not an apply.
	h.caddy.mu.Lock()
	h.caddy.applyErr = errors.New("caddy down")
	h.caddy.mu.Unlock()
	if res, _ := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync}); res.Status == StatusApplied {
		t.Fatalf("control: resync applied with a failing caddy")
	}
	if calls != 1 {
		t.Errorf("hook called %d times after a failed apply, want still 1", calls)
	}
}
