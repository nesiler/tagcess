package change

import (
	"context"
	"fmt"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/gitlog"
)

// The F2-022 acceptance tests: the first import keeps today's non-site DNS records (H-06) as the
// stored manual set, every later DNS render merges them back, and a record that cannot be kept
// faithfully blocks the import before anything is written.

var (
	manualLegacy = dns.Record{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"}
	manualV6     = dns.Record{Name: "v6.example.com", Type: dns.TypeAAAA, Value: "fd7a:115c:a1e0::9"}
)

// withTodaysManualDNS makes today's DNS file carry the given records next to the site-derived ones.
func withTodaysManualDNS(t *testing.T, h *importHarness, extra ...dns.Record) {
	t.Helper()
	recs, err := dns.Unmarshal([]byte(h.dns.content))
	if err != nil {
		t.Fatalf("parse today's file: %v", err)
	}
	recs = append(recs, extra...)
	body, err := dns.Marshal(recs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	h.dns.content, h.dns.exists = body, true
}

func fileRecords(t *testing.T, h *importHarness) []dns.Record {
	t.Helper()
	recs, err := dns.Unmarshal([]byte(h.dns.content))
	if err != nil {
		t.Fatalf("parse the dns file: %v", err)
	}
	return recs
}

func hasRecord(recs []dns.Record, want dns.Record) bool {
	for _, r := range recs {
		if r == want {
			return true
		}
	}
	return false
}

func storedManual(t *testing.T, h *importHarness) []dns.Record {
	t.Helper()
	got, err := h.sites.ManualDNS(context.Background())
	if err != nil {
		t.Fatalf("ManualDNS: %v", err)
	}
	return got
}

// AC1: the approved first import stores the non-site records of today's file as site.manual_dns and
// writes them back with the generated records; the site-derived ones are not copied.
func TestFirstImport_PersistsManualDNS(t *testing.T) {
	ctx := context.Background()

	t.Run("stores and keeps them", func(t *testing.T) {
		h := newImportHarness(t)
		withTodaysManualDNS(t, h, manualLegacy, manualV6)
		before := len(fileRecords(t, h))
		res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || !res.Applied {
			t.Fatalf("FirstImport = %+v, %v, want applied", res.Result, err)
		}
		if got, want := storedManual(t, h), []dns.Record{manualLegacy, manualV6}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
		file := fileRecords(t, h)
		for _, r := range []dns.Record{manualLegacy, manualV6} {
			if !hasRecord(file, r) {
				t.Errorf("the written dns file lost %+v", r)
			}
		}
		// Today's site-derived records plus the tagcess site and the manual ones; none twice.
		if len(file) < before {
			t.Errorf("the dns file shrank from %d to %d records", before, len(file))
		}
		seen := map[string]bool{}
		for _, r := range file {
			if k := r.Name + "/" + r.Type; seen[k] {
				t.Errorf("record %s appears twice", k)
			} else {
				seen[k] = true
			}
		}
	})

	t.Run("a file with only site records stores an empty set", func(t *testing.T) {
		h := newImportHarness(t)
		if res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts); err != nil || !res.Applied {
			t.Fatalf("FirstImport = %+v, %v, want applied", res.Result, err)
		}
		if got := storedManual(t, h); len(got) != 0 {
			t.Errorf("stored manual records = %+v, want none", got)
		}
	})

	t.Run("a retry after a partial import keeps the same set", func(t *testing.T) {
		h := newImportHarness(t)
		withTodaysManualDNS(t, h, manualLegacy)
		h.caddy.applyErr = errBoom
		res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || res.Applied {
			t.Fatalf("first run = %+v, %v, want it stopped at caddy", res.Result, err)
		}
		// DNS was written before Caddy failed: the retry reads its own output and must not
		// mistake the generated records for manual ones.
		h.caddy.applyErr = nil
		res, err = h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || !res.Applied {
			t.Fatalf("retry = %+v, %v, want applied", res.Result, err)
		}
		if got, want := storedManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
	})

	t.Run("a missing file after a failed attempt keeps the stored set", func(t *testing.T) {
		h := newImportHarness(t)
		withTodaysManualDNS(t, h, manualLegacy)
		h.caddy.applyErr = errBoom
		res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || res.Applied {
			t.Fatalf("first run = %+v, %v, want it stopped at caddy", res.Result, err)
		}
		if got, want := storedManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Fatalf("after the failed run stored manual records = %+v, want %+v", got, want)
		}
		// The DNS file disappears out of band between the failed attempt and the retry.
		h.dns.content, h.dns.exists = "", false
		h.caddy.applyErr = nil
		res, err = h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || !res.Applied {
			t.Fatalf("retry = %+v, %v, want applied", res.Result, err)
		}
		if got, want := storedManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
		if file := fileRecords(t, h); !hasRecord(file, manualLegacy) {
			t.Errorf("the written dns file lost %+v", manualLegacy)
		}
	})

	t.Run("a completed import is not re-read", func(t *testing.T) {
		h := newImportHarness(t)
		withTodaysManualDNS(t, h, manualLegacy)
		if res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts); err != nil || !res.Applied {
			t.Fatalf("FirstImport = %+v, %v, want applied", res.Result, err)
		}
		// Someone drops a record by hand afterwards; a second FirstImport must not re-import.
		h.dns.content = "[]\n"
		again, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err != nil || again.Status != StatusNoChange {
			t.Fatalf("second FirstImport = %+v, %v, want no_change", again.Result, err)
		}
		if got, want := storedManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
	})
}

// AC2: after the import, a site change and a resync render the manual records back into the file.
func TestSiteChange_KeepsManualDNS(t *testing.T) {
	ctx := context.Background()
	h := newImportHarness(t)
	withTodaysManualDNS(t, h, manualLegacy, manualV6)
	if res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts); err != nil || !res.Applied {
		t.Fatalf("FirstImport = %+v, %v, want applied", res.Result, err)
	}

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil || !res.Applied {
		t.Fatalf("add = %+v, %v, want applied", res.Result, err)
	}
	file := fileRecords(t, h)
	for _, r := range []dns.Record{manualLegacy, manualV6} {
		if !hasRecord(file, r) {
			t.Errorf("the add dropped the manual record %+v", r)
		}
	}
	if strings.Contains(res.Plan.Diff.DNS, "-") && strings.Contains(res.Plan.Diff.DNS, manualLegacy.Name) {
		t.Errorf("the dns diff removes a manual record:\n%s", res.Plan.Diff.DNS)
	}

	// A resync previews no manual-record change and keeps the records in the file.
	plan, err := h.sp.PreviewSettings(ctx, mustSettings(t, h))
	if err != nil {
		t.Fatalf("PreviewSettings: %v", err)
	}
	if plan.Diff.DNS != "" {
		t.Errorf("a resync after the import wants to change the dns file:\n%s", plan.Diff.DNS)
	}
	res, err = h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil || !res.Applied {
		t.Fatalf("resync = %+v, %v, want applied", res.Result, err)
	}
	file = fileRecords(t, h)
	for _, r := range []dns.Record{manualLegacy, manualV6} {
		if !hasRecord(file, r) {
			t.Errorf("the resync dropped the manual record %+v", r)
		}
	}
}

func mustSettings(t *testing.T, h *importHarness) SiteSettings {
	t.Helper()
	set, err := h.sp.settings(context.Background())
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	return set
}

// The F3-008 acceptance tests: the manual records are editable from the interface through the
// site pipeline's manual_dns operation. The request carries the full new manual set; the pipeline
// re-renders the DNS file, skips the Caddy/Zitadel steps when nothing changes for them, and goes
// through the same drift gate, audit and history as every site change.

// harnessManual reads the stored manual set of a plain site harness.
func harnessManual(t *testing.T, h *siteHarness) []dns.Record {
	t.Helper()
	got, err := h.sites.ManualDNS(context.Background())
	if err != nil {
		t.Fatalf("ManualDNS: %v", err)
	}
	return got
}

// manualReq builds a manual_dns request over a plain site harness.
func manualReq(recs ...dns.Record) SiteRequest {
	return SiteRequest{Actor: siteActor, Op: SiteManualDNS, ManualDNS: recs}
}

// AC2 (ApplyThroughPipeline): an add, an edit and a delete of a manual record go through the
// pipeline: the DNS file and the stored set are updated atomically, the Caddy and Zitadel steps
// are skipped because nothing changes for them, and the site records never move.
func TestManualDNS_ApplyThroughPipeline(t *testing.T) {
	ctx := context.Background()

	t.Run("adds a record through the dns step only", func(t *testing.T) {
		h := newSiteHarness(t)
		h.calls.reset()
		res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
		if err != nil || !res.Applied {
			t.Fatalf("Submit = %+v, %v, want applied", res.Result, err)
		}
		if got, want := harnessManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
		file := fileRecords(t, h.importHarnessView())
		if !hasRecord(file, manualLegacy) {
			t.Errorf("the dns file lost %+v:\n%s", manualLegacy, h.dns.body())
		}
		if got := h.callLog().get(); !equalStrings(got, []string{"dns"}) {
			t.Errorf("steps = %v, want only dns (caddy and zitadel unchanged)", got)
		}
		if !h.hasHost("git.example.com") {
			t.Error("the manual change moved the site records")
		}
	})

	t.Run("edits a record", func(t *testing.T) {
		h := newSiteHarness(t)
		if res, err := h.sp.Submit(ctx, manualReq(manualLegacy)); err != nil || !res.Applied {
			t.Fatalf("add = %+v, %v, want applied", res.Result, err)
		}
		edited := manualLegacy
		edited.Value = "100.64.0.8"
		h.calls.reset()
		res, err := h.sp.Submit(ctx, manualReq(edited))
		if err != nil || !res.Applied {
			t.Fatalf("edit = %+v, %v, want applied", res.Result, err)
		}
		if got, want := harnessManual(t, h), []dns.Record{edited}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
		file := fileRecords(t, h.importHarnessView())
		if hasRecord(file, manualLegacy) || !hasRecord(file, edited) {
			t.Errorf("the dns file did not follow the edit:\n%s", h.dns.body())
		}
		if got := h.callLog().get(); !equalStrings(got, []string{"dns"}) {
			t.Errorf("steps = %v, want only dns", got)
		}
	})

	t.Run("deletes a record", func(t *testing.T) {
		h := newSiteHarness(t)
		if res, err := h.sp.Submit(ctx, manualReq(manualLegacy, manualV6)); err != nil || !res.Applied {
			t.Fatalf("add = %+v, %v, want applied", res.Result, err)
		}
		h.calls.reset()
		res, err := h.sp.Submit(ctx, manualReq(manualV6))
		if err != nil || !res.Applied {
			t.Fatalf("delete = %+v, %v, want applied", res.Result, err)
		}
		if got, want := harnessManual(t, h), []dns.Record{manualV6}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
		file := fileRecords(t, h.importHarnessView())
		if hasRecord(file, manualLegacy) {
			t.Errorf("the dns file kept the deleted record:\n%s", h.dns.body())
		}
		if got := h.callLog().get(); !equalStrings(got, []string{"dns"}) {
			t.Errorf("steps = %v, want only dns", got)
		}
	})

	t.Run("an unchanged set writes no artifact", func(t *testing.T) {
		h := newSiteHarness(t)
		if res, err := h.sp.Submit(ctx, manualReq(manualLegacy)); err != nil || !res.Applied {
			t.Fatalf("add = %+v, %v, want applied", res.Result, err)
		}
		h.calls.reset()
		res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
		if err != nil || !res.Applied {
			t.Fatalf("no-op = %+v, %v, want applied", res.Result, err)
		}
		if got := h.callLog().get(); len(got) != 0 {
			t.Errorf("steps = %v, want none for an unchanged set", got)
		}
		if got, want := harnessManual(t, h), []dns.Record{manualLegacy}; !reflect.DeepEqual(got, want) {
			t.Errorf("stored manual records = %+v, want %+v", got, want)
		}
	})
}

// importHarnessView exposes the fake surfaces of a plain site harness to the file helpers, which
// were written against the import harness.
func (h *siteHarness) importHarnessView() *importHarness {
	return &importHarness{siteHarness: h}
}

// AC2 (ApplyAuditedAndCommitted): an applied manual record change writes one change row, the audit
// trail with the dns diff and a history revision carrying the new dns file.
func TestManualDNS_ApplyAuditedAndCommitted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	h := newSiteHarness(t)
	dir := t.TempDir()
	log, err := gitlog.New(gitlog.Config{
		Dir: dir, Auditor: audit.New(h.st.Queries()), Alerter: NewGitAlerter(h.st.Queries()),
		OnRetried: NewRevisionBinder(h.sites),
	})
	if err != nil {
		t.Fatalf("gitlog.New: %v", err)
	}
	h.git = log
	h.build()

	res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
	if err != nil || !res.Applied || res.Revision == "" {
		t.Fatalf("Submit = %+v, %v, want applied with a revision", res.Result, err)
	}
	rows := h.changes()
	if len(rows) != 1 || rows[0].Status != StatusApplied {
		t.Fatalf("change rows = %+v, want one applied row", rows)
	}
	if !strings.Contains(rows[0].Before, "manual_dns") {
		t.Errorf("change summary = %q, want the manual_dns operation", rows[0].Before)
	}
	applied := auditByName(h.audits(), "site.apply")
	if len(applied) != 1 {
		t.Fatalf("site.apply audits = %d, want 1", len(applied))
	}
	if d, ok := diffField(applied[0].Diff, "dns"); !ok || d.After == "" {
		t.Errorf("the audit trail lacks the dns diff: %+v", applied[0].Diff)
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "show", res.Revision+":"+GitFileMagicDNS).CombinedOutput()
	if err != nil {
		t.Fatalf("git show: %v: %s", err, out)
	}
	got, err := dns.Unmarshal(out)
	if err != nil {
		t.Fatalf("history dns file: %v", err)
	}
	if !hasRecord(got, manualLegacy) {
		t.Errorf("the history dns file lost %+v:\n%s", manualLegacy, out)
	}
}

// AC3: an invalid record, a collision with a site host, two values for one name and type, an
// exact duplicate and an oversized set are refused before anything is written.
func TestManualDNS_Validation(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		set  []dns.Record
		want []string
	}{
		{
			name: "a name that is not a hostname",
			set:  []dns.Record{{Name: "Bad Name", Type: dns.TypeA, Value: "100.64.0.9"}},
			want: []string{"Bad Name"},
		},
		{
			name: "a value that is not an IP",
			set:  []dns.Record{{Name: "old-db.example.com", Type: dns.TypeA, Value: "not-an-ip"}},
			want: []string{"not-an-ip"},
		},
		{
			name: "an A record with an IPv6 value",
			set:  []dns.Record{{Name: "old-db.example.com", Type: dns.TypeA, Value: "fd7a:115c:a1e0::9"}},
			want: []string{"not an IPv4"},
		},
		{
			name: "a site host with a different value",
			set:  []dns.Record{{Name: "git.example.com", Type: dns.TypeA, Value: "10.9.9.9"}},
			want: []string{"git.example.com", "site"},
		},
		{
			name: "a site host with the vpn value",
			set:  []dns.Record{{Name: "git.example.com", Type: dns.TypeA, Value: "100.64.0.4"}},
			want: []string{"git.example.com", "site"},
		},
		{
			name: "two values for one name and type",
			set: []dns.Record{
				{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"},
				{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.8"},
			},
			want: []string{"old-db.example.com"},
		},
		{
			name: "an exact duplicate",
			set: []dns.Record{
				{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"},
				{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"},
			},
			want: []string{"duplicate"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSiteHarness(t)
			_, err := h.sp.Preview(ctx, manualReq(tc.set...))
			if err == nil {
				t.Fatal("Preview = nil error, want a refusal")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not show %q", err, w)
				}
			}
			if _, err := h.sp.Submit(ctx, manualReq(tc.set...)); err == nil {
				t.Fatal("Submit = nil error, want a refusal")
			}
			// Nothing was written: no artifact step, no change row, no file or setting change.
			if got := h.callLog().get(); len(got) != 0 {
				t.Errorf("steps = %v, want none", got)
			}
			if rows := h.changes(); len(rows) != 0 {
				t.Errorf("change rows = %+v, want none", rows)
			}
			if got := harnessManual(t, h); len(got) != 0 {
				t.Errorf("stored manual records = %+v, want none", got)
			}
		})
	}

	t.Run("more than the record cap", func(t *testing.T) {
		h := newSiteHarness(t)
		set := make([]dns.Record, 0, MaxManualDNSRecords+1)
		for i := 0; len(set) <= MaxManualDNSRecords; i++ {
			set = append(set, dns.Record{
				Name: fmt.Sprintf("rec-%d.example.com", i), Type: dns.TypeA, Value: "100.64.0.9",
			})
		}
		if _, err := h.sp.Submit(ctx, manualReq(set...)); err == nil {
			t.Fatal("Submit = nil error, want the cap refusal")
		}
		if got := harnessManual(t, h); len(got) != 0 {
			t.Errorf("stored manual records = %d, want none", len(got))
		}
	})
}

// AC4: a drifted or unreadable DNS file blocks the change before anything is written; the drift
// alert is raised and the operator's way out is a resync.
func TestManualDNS_BlockedOnDrift(t *testing.T) {
	ctx := context.Background()

	t.Run("a drifted file blocks", func(t *testing.T) {
		h := newSiteHarness(t)
		recs, err := dns.Unmarshal([]byte(h.dns.body()))
		if err != nil {
			t.Fatalf("parse the dns file: %v", err)
		}
		recs = append(recs, dns.Record{Name: "foreign.example.com", Type: dns.TypeA, Value: "100.64.0.7"})
		body, err := dns.Marshal(recs)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		h.dns.content, h.dns.exists = body, true

		res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
		if err != nil {
			t.Fatalf("Submit error = %v, want a blocked result", err)
		}
		if res.Status != StatusBlocked || res.Applied {
			t.Fatalf("Submit = %+v, want blocked", res.Result)
		}
		if rows := h.changes(); len(rows) != 1 || !strings.Contains(rows[0].Error, "DNS dosyası kayıtlardan farklı") {
			t.Fatalf("change rows = %+v, want one row with the drift reason", rows)
		}
		if !slices.Contains(h.alerts(), AlertSiteDrift) {
			t.Errorf("alerts = %v, want %s", h.alerts(), AlertSiteDrift)
		}
		if got := harnessManual(t, h); len(got) != 0 {
			t.Errorf("a blocked change stored %+v", got)
		}
		if file := fileRecords(t, h.importHarnessView()); hasRecord(file, manualLegacy) {
			t.Errorf("a blocked change wrote the dns file:\n%s", h.dns.body())
		}
	})

	t.Run("an unreadable file blocks", func(t *testing.T) {
		h := newSiteHarness(t)
		h.dns.readErr = errBoom
		res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
		if err != nil {
			t.Fatalf("Submit error = %v, want a blocked result", err)
		}
		if res.Status != StatusBlocked || res.Applied {
			t.Fatalf("Submit = %+v, want blocked", res.Result)
		}
		if got := harnessManual(t, h); len(got) != 0 {
			t.Errorf("a blocked change stored %+v", got)
		}
	})
}

// AC5: a resolver mismatch warns, keeps the file and raises the unverified alert (ADR 0013 m.5).
func TestManualDNS_ResolverMismatchWarns(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	h.dns.mismatches = []dns.Mismatch{{Name: manualLegacy.Name, Type: manualLegacy.Type, Want: manualLegacy.Value}}

	res, err := h.sp.Submit(ctx, manualReq(manualLegacy))
	if err != nil || !res.Applied {
		t.Fatalf("Submit = %+v, %v, want applied", res.Result, err)
	}
	if file := fileRecords(t, h.importHarnessView()); !hasRecord(file, manualLegacy) {
		t.Errorf("the dns file did not keep the record:\n%s", h.dns.body())
	}
	if !slices.Contains(h.alerts(), AlertSiteDNSUnverified) {
		t.Errorf("alerts = %v, want %s", h.alerts(), AlertSiteDNSUnverified)
	}
	warns := auditByName(h.audits(), "site.dns_unverified")
	if len(warns) != 1 {
		t.Fatalf("site.dns_unverified audits = %d, want 1", len(warns))
	}
	if _, ok := diffField(warns[0].Diff, "dns"); !ok {
		t.Errorf("the warning does not carry the dns field: %+v", warns[0].Diff)
	}
	for _, c := range warns[0].Diff {
		if c.Field == "dns" && !strings.Contains(c.After, manualLegacy.Name) {
			t.Errorf("the warning does not name the record: %q", c.After)
		}
	}
}

// AC3: a manual record that collides with a site host, an invalid record or an unreadable file
// blocks the first import before any artifact is written, and nothing is stored.
func TestFirstImport_ManualDNSConflict(t *testing.T) {
	ctx := context.Background()

	blocked := func(t *testing.T, h *importHarness, wantInErr ...string) {
		t.Helper()
		before := h.dns.content
		res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
		if err == nil {
			t.Fatalf("FirstImport = %+v, want an error", res.Result)
		}
		for _, w := range wantInErr {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not show %q", err, w)
			}
		}
		wantCalls(t, h)
		if h.dns.content != before {
			t.Errorf("the dns file changed")
		}
		if got := storedManual(t, h); len(got) != 0 {
			t.Errorf("a blocked import stored %+v", got)
		}
		if done, _ := h.sites.FirstImportDone(ctx); done {
			t.Errorf("the gate was closed by a blocked import")
		}
	}

	t.Run("a different value for a site host", func(t *testing.T) {
		h := newImportHarness(t)
		recs := fileRecords(t, h)
		recs[0].Value = "10.9.9.9"
		body, err := dns.Marshal(recs)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		h.dns.content = body
		blocked(t, h, recs[0].Name, "10.9.9.9")
	})

	t.Run("an invalid record", func(t *testing.T) {
		h := newImportHarness(t)
		h.dns.content = `[{"name":"Bad Name","type":"A","value":"100.64.0.9"}]`
		blocked(t, h, "Bad Name")
	})

	t.Run("a corrupt file", func(t *testing.T) {
		h := newImportHarness(t)
		h.dns.content = "{not json"
		blocked(t, h)
	})

	t.Run("two values for one manual name", func(t *testing.T) {
		h := newImportHarness(t)
		other := manualLegacy
		other.Value = "100.64.0.8"
		withTodaysManualDNS(t, h, manualLegacy, other)
		blocked(t, h, manualLegacy.Name)
	})

	t.Run("an unreadable file", func(t *testing.T) {
		h := newImportHarness(t)
		h.dns.readErr = errBoom
		blocked(t, h)
	})
}
