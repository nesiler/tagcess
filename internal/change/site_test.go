package change

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The F2-011 acceptance tests: a site change is previewed as one three-artifact diff, applied in
// the safe order (add: DNS → Caddy → Zitadel, delete: Zitadel → Caddy → DNS), and every failure
// keeps the last known-good state instead of guessing (rule 7).

const wikiHost = "wiki.example.com"
const gitHost = "git.example.com"

// callLogger is satisfied by siteHarness and, through embedding, by importHarness.
type callLogger interface{ callLog() *siteCalls }

func wantCalls(t *testing.T, h callLogger, want ...string) {
	t.Helper()
	got := h.callLog().get()
	if !equalStrings(got, want) {
		t.Errorf("artifact writes = %v, want %v", got, want)
	}
}

func wantAlerts(t *testing.T, h *siteHarness, want ...string) {
	t.Helper()
	got := h.alerts()
	if !equalStrings(got, want) {
		t.Errorf("open alerts = %v, want %v", got, want)
	}
}

// AC1: a requested site change shows the diff of all three artifacts and the actor in ONE change
// record and ONE audit trail; the preview itself writes nothing.
func TestSiteChange_PreviewAudit(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)

	plan, err := h.sp.Preview(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !strings.Contains(plan.Diff.Caddy, "+") || !strings.Contains(plan.Diff.Caddy, wikiHost) {
		t.Errorf("caddy diff = %q, want added lines naming %s", plan.Diff.Caddy, wikiHost)
	}
	if !strings.Contains(plan.Diff.DNS, wikiHost) {
		t.Errorf("dns diff = %q, want the new record", plan.Diff.DNS)
	}
	if !strings.Contains(plan.Diff.Zitadel, "+https://"+wikiHost+"/oauth2/callback") {
		t.Errorf("zitadel diff = %q, want the added callback URI", plan.Diff.Zitadel)
	}
	wantCalls(t, h)
	if len(h.changes()) != 0 || len(h.audits()) != 0 || h.hasHost(wikiHost) {
		t.Fatalf("preview wrote something: changes=%d audits=%d host=%v", len(h.changes()), len(h.audits()), h.hasHost(wikiHost))
	}

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied || res.Status != StatusApplied {
		t.Fatalf("result = %+v, want applied", res.Result)
	}
	if res.Plan.Diff != plan.Diff {
		t.Errorf("submitted diff differs from the previewed one:\n%+v\n%+v", res.Plan.Diff, plan.Diff)
	}

	rows := h.changes()
	if len(rows) != 1 {
		t.Fatalf("change rows = %d, want exactly one for the site change", len(rows))
	}
	if rows[0].Actor != siteActor || rows[0].Status != StatusApplied {
		t.Errorf("change row = %+v, want actor %s, applied", rows[0], siteActor)
	}
	var stored struct{ Caddy, DNS, Zitadel string }
	if err := json.Unmarshal([]byte(rows[0].After), &stored); err != nil {
		t.Fatalf("after_summary is not the diff document: %v\n%s", err, rows[0].After)
	}
	if stored.Caddy == "" || stored.DNS == "" || stored.Zitadel == "" {
		t.Errorf("after_summary = %+v, want all three artifact diffs", stored)
	}

	final := auditByName(h.audits(), "site.apply")
	if len(final) != 1 {
		t.Fatalf("site.apply audit events = %d, want one", len(final))
	}
	if final[0].Actor != siteActor || final[0].Result != StatusApplied {
		t.Errorf("audit = %+v, want actor %s and result applied", final[0], siteActor)
	}
	for _, f := range []string{"caddy", "dns", "zitadel"} {
		c, ok := diffField(final[0].Diff, f)
		if !ok || c.After == "" {
			t.Errorf("audit diff has no %q entry: %+v", f, final[0].Diff)
		}
	}
	start := auditByName(h.audits(), "site.apply_start")
	if len(start) != 1 || start[0].Actor != siteActor {
		t.Errorf("site.apply_start events = %+v, want one with the actor (the intent is recorded before the first write)", start)
	}
}

// A change that leaves an artifact unchanged does not write it: the pipeline writes only what the
// diff says.
func TestSiteChange_OnlyChangedArtifactsAreWritten(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)

	edit := roleSiteRecord("git", "devops", "developer")
	res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: h.siteID(gitHost), Site: edit})
	if err != nil || !res.Applied {
		t.Fatalf("Submit: %+v, %v", res, err)
	}
	wantCalls(t, h, "caddy")
	if res.Plan.Diff.DNS != "" || res.Plan.Diff.Zitadel != "" {
		t.Errorf("diff = %+v, want only a caddy diff for a role change", res.Plan.Diff)
	}

	// A note-only edit changes no artifact: the record is committed, nothing external is written.
	h.calls.reset()
	note := roleSiteRecord("git", "devops", "developer")
	note.Note = "wiki"
	res, err = h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: h.siteID(gitHost), Site: note})
	if err != nil || !res.Applied {
		t.Fatalf("Submit note: %+v, %v", res, err)
	}
	wantCalls(t, h)
	got, err := h.sites.GetSite(ctx, h.siteID(gitHost))
	if err != nil || got.Note != "wiki" {
		t.Errorf("stored note = %q (%v), want it committed", got.Note, err)
	}
}

// AC2: a new site is applied DNS → Caddy → Zitadel. Every step's failure either rolls the applied
// steps back (only when that provably narrows access) or alerts.
func TestSiteChange_AddOrderAndFailures(t *testing.T) {
	cleanZitadelFailure := zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: zitadel.DriftReadFailed, Detail: "boom"}}}
	tests := []struct {
		name      string
		setup     func(h *siteHarness)
		calls     []string
		status    string
		added     bool
		alerts    []string
		wantErr   bool
		dnsBack   bool // the DNS file is back to its previous content
		caddyBack bool // the Caddyfile on disk is back to its previous content
	}{
		{
			name:   "all steps succeed",
			calls:  []string{"dns", "caddy", "zitadel"},
			status: StatusApplied, added: true,
		},
		{
			name:  "dns write fails: nothing else runs",
			setup: func(h *siteHarness) { h.dns.applyErr = errBoom },
			calls: []string{"dns"}, status: StatusFailed,
			dnsBack: true, caddyBack: true,
		},
		{
			name: "dns resolver mismatch warns and continues",
			setup: func(h *siteHarness) {
				h.dns.mismatches = []dns.Mismatch{{Name: wikiHost, Type: "A", Want: "100.64.0.4"}}
			},
			calls: []string{"dns", "caddy", "zitadel"}, status: StatusApplied, added: true,
			alerts: []string{AlertSiteDNSUnverified},
		},
		{
			name:  "caddy refuses: dns is restored",
			setup: func(h *siteHarness) { h.caddy.applyErr = errBoom },
			calls: []string{"dns", "caddy", "dns-restore"}, status: StatusRolledBack,
			dnsBack: true, caddyBack: true,
		},
		{
			name: "caddy refuses and the dns restore fails: alert",
			setup: func(h *siteHarness) {
				h.caddy.applyErr = errBoom
				h.dns.restoreErr = errBoom
			},
			calls: []string{"dns", "caddy", "dns-restore"}, status: StatusFailed,
			alerts: []string{AlertSiteRollbackFailed}, caddyBack: true,
		},
		{
			name:  "caddy file write fails but the previous config is back: dns restored, alert",
			setup: func(h *siteHarness) { h.caddy.fileWrite = &caddy.FileWriteError{WriteErr: errBoom, Restored: true} },
			calls: []string{"dns", "caddy", "dns-restore"}, status: StatusRolledBack,
			alerts: []string{AlertSiteCaddyFile}, dnsBack: true, caddyBack: true,
		},
		{
			name:  "caddy file write fails and the target stays live: nothing is rolled back",
			setup: func(h *siteHarness) { h.caddy.fileWrite = &caddy.FileWriteError{WriteErr: errBoom} },
			calls: []string{"dns", "caddy"}, status: StatusFailed,
			alerts: []string{AlertSiteCaddyFile}, caddyBack: true,
		},
		{
			name:  "zitadel cannot read: caddy and dns are rolled back in reverse order",
			setup: func(h *siteHarness) { h.uris.syncErr = errBoom; h.uris.syncRes = cleanZitadelFailure },
			calls: []string{"dns", "caddy", "zitadel", "caddy-restore", "dns-restore"}, status: StatusRolledBack,
			dnsBack: true, caddyBack: true,
		},
		{
			name: "zitadel cannot read and the caddy restore fails: stop, alert, dns stays",
			setup: func(h *siteHarness) {
				h.uris.syncErr = errBoom
				h.uris.syncRes = cleanZitadelFailure
				h.caddy.restoreErr = errBoom
			},
			calls: []string{"dns", "caddy", "zitadel", "caddy-restore"}, status: StatusFailed,
			alerts: []string{AlertSiteRollbackFailed},
		},
		{
			name: "zitadel wrote but could not store its ownership set: applied with a bookkeeping alert",
			setup: func(h *siteHarness) {
				h.uris.syncErr = errBoom
				h.uris.syncRes = zitadel.URIResult{Written: true, Drift: []zitadel.URIDrift{{Kind: zitadel.DriftOwnedNotSaved}}}
			},
			calls: []string{"dns", "caddy", "zitadel"}, status: StatusApplied, added: true,
			alerts: []string{AlertSiteBookkeepingFailed}, wantErr: true,
		},
		{
			// F2-011 review LOW 1: the write was verified and the owned set stored; only the drift
			// alert could not be resolved. The state is the target: DNS and Caddy stay.
			name: "zitadel wrote and verified but the alert resolve failed: applied, nothing rolled back",
			setup: func(h *siteHarness) {
				h.uris.syncErr = errBoom
				h.uris.syncRes = zitadel.URIResult{Written: true}
			},
			calls: []string{"dns", "caddy", "zitadel"}, status: StatusApplied, added: true,
			alerts: []string{AlertSiteBookkeepingFailed}, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			h := newSiteHarness(t)
			prevDNS, prevDisk := h.dns.body(), h.caddy.initial
			if tt.setup != nil {
				tt.setup(h)
			}

			res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Submit error = %v, want error: %v", err, tt.wantErr)
			}
			if res.Status != tt.status {
				t.Errorf("status = %q, want %q", res.Status, tt.status)
			}
			wantCalls(t, h, tt.calls...)
			wantAlerts(t, h, tt.alerts...)
			if got := h.hasHost(wikiHost); got != tt.added {
				t.Errorf("site stored = %v, want %v (the record is committed only after every artifact is applied)", got, tt.added)
			}
			if tt.dnsBack && h.dns.body() != prevDNS {
				t.Errorf("dns file was not restored")
			}
			if !tt.dnsBack && !tt.added && h.dns.body() == prevDNS {
				t.Errorf("dns file was restored, want it kept")
			}
			if disk, _ := h.caddy.state(); tt.caddyBack && disk != prevDisk {
				t.Errorf("caddyfile on disk changed")
			}
			rows := h.changes()
			if len(rows) != 1 {
				t.Fatalf("change rows = %d, want 1", len(rows))
			}
			if rows[0].Status != tt.status || rows[0].Actor != siteActor {
				t.Errorf("change row = %+v, want status %s and the actor", rows[0], tt.status)
			}
		})
	}
}

// F2-006 hand-over: a resolver mismatch is a warning that keeps the file; it is on the audit trail
// and raises an alert.
func TestSiteChange_DNSMismatchIsAudited(t *testing.T) {
	h := newSiteHarness(t)
	h.dns.mismatches = []dns.Mismatch{{Name: wikiHost, Type: "A", Want: "100.64.0.4", Have: "10.0.0.1"}}
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || !res.Applied {
		t.Fatalf("Submit: %+v, %v", res, err)
	}
	evs := auditByName(h.audits(), "site.dns_unverified")
	if len(evs) != 1 {
		t.Fatalf("site.dns_unverified events = %d, want 1", len(evs))
	}
	if evs[0].Actor != siteActor || !strings.Contains(evs[0].Diff[0].After, wikiHost) {
		t.Errorf("event = %+v, want the actor and the mismatched name", evs[0])
	}
}

// AC3: a site is deleted Zitadel → Caddy → DNS. A failure never re-opens what an earlier step
// closed: no rollback in the delete direction, only an alert.
func TestSiteChange_DeleteOrderAndFailures(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(h *siteHarness)
		calls   []string
		status  string
		deleted bool
		alerts  []string
	}{
		{
			name:  "all steps succeed",
			calls: []string{"zitadel", "caddy", "dns"}, status: StatusApplied, deleted: true,
		},
		{
			name:  "zitadel cannot read: nothing was changed, nothing else runs",
			setup: func(h *siteHarness) { h.uris.syncErr = errBoom; h.uris.syncRes = driftOf(zitadel.DriftReadFailed) },
			calls: []string{"zitadel"}, status: StatusFailed,
		},
		{
			name:  "zitadel write unknown: alert, nothing else runs",
			setup: func(h *siteHarness) { h.uris.syncErr = errBoom; h.uris.syncRes = driftOf(zitadel.DriftWriteFailed) },
			calls: []string{"zitadel"}, status: StatusFailed, alerts: []string{AlertSiteUnverified},
		},
		{
			name:  "caddy refuses: the callbacks are NOT restored, alert",
			setup: func(h *siteHarness) { h.caddy.applyErr = errBoom },
			calls: []string{"zitadel", "caddy"}, status: StatusFailed, alerts: []string{AlertSitePartial},
		},
		{
			name:  "caddy outcome unknown: alert, no dns step",
			setup: func(h *siteHarness) { h.caddy.applyErr = errBoom; h.caddy.liveMovesOnError = true },
			calls: []string{"zitadel", "caddy"}, status: StatusFailed, alerts: []string{AlertSiteUnverified},
		},
		{
			name:  "caddy file write fails: alert, no dns step",
			setup: func(h *siteHarness) { h.caddy.fileWrite = &caddy.FileWriteError{WriteErr: errBoom} },
			calls: []string{"zitadel", "caddy"}, status: StatusFailed, alerts: []string{AlertSiteCaddyFile},
		},
		{
			name:  "dns write fails: nothing is rolled back, alert",
			setup: func(h *siteHarness) { h.dns.applyErr = errBoom },
			calls: []string{"zitadel", "caddy", "dns"}, status: StatusFailed, alerts: []string{AlertSitePartial},
		},
		{
			name:  "dns resolver mismatch warns",
			setup: func(h *siteHarness) { h.dns.mismatches = []dns.Mismatch{{Name: "x.example.com", Type: "A"}} },
			calls: []string{"zitadel", "caddy", "dns"}, status: StatusApplied, deleted: true,
			alerts: []string{AlertSiteDNSUnverified},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSiteHarness(t)
			prevDisk := h.caddy.initial
			if tt.setup != nil {
				tt.setup(h)
			}
			res, err := h.sp.Submit(context.Background(), h.deleteReq(gitHost))
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if res.Status != tt.status {
				t.Errorf("status = %q, want %q", res.Status, tt.status)
			}
			wantCalls(t, h, tt.calls...)
			wantAlerts(t, h, tt.alerts...)
			if got := !h.hasHost(gitHost); got != tt.deleted {
				t.Errorf("site deleted = %v, want %v", got, tt.deleted)
			}
			if !tt.deleted {
				if disk, _ := h.caddy.state(); tt.status == StatusFailed && len(tt.calls) < 2 && disk != prevDisk {
					t.Errorf("caddyfile changed although the caddy step never ran")
				}
			}
			if tt.deleted {
				disk, _ := h.caddy.state()
				if strings.Contains(disk, gitHost) || strings.Contains(h.dns.body(), gitHost) {
					t.Errorf("the deleted host is still in an artifact")
				}
			}
		})
	}
}

func driftOf(kind string) zitadel.URIResult {
	return zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: kind, Detail: "boom"}}}
}

// A system site cannot be deleted whatever the request says: the store lock refuses before any
// external system is touched (S-05).
func TestSiteChange_SystemSiteDeleteRefused(t *testing.T) {
	h := newSiteHarness(t)
	_, err := h.sp.Submit(context.Background(), h.deleteReq("auth.example.com"))
	if !errors.Is(err, site.ErrSystemLocked) {
		t.Fatalf("err = %v, want ErrSystemLocked", err)
	}
	wantCalls(t, h)
	if len(h.changes()) != 0 {
		t.Errorf("a refused request created a change row")
	}
}

// AC4: when the outcome of a write is unknown the live state is kept and a critical alert is
// raised; nothing is rolled back blindly.
func TestSiteChange_UncertainWrite(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *siteHarness)
		calls []string
	}{
		{
			name:  "caddy errored but the config moved",
			setup: func(h *siteHarness) { h.caddy.applyErr = errBoom; h.caddy.liveMovesOnError = true },
			calls: []string{"dns", "caddy"},
		},
		{
			name:  "caddy errored and the running config cannot be read back",
			setup: func(h *siteHarness) { h.caddy.applyErr = errBoom; h.caddy.liveErrAfterApply = errBoom },
			calls: []string{"dns", "caddy"},
		},
		{
			name:  "zitadel write could not be verified",
			setup: func(h *siteHarness) { h.uris.syncErr = errBoom; h.uris.syncRes = driftOf(zitadel.DriftWriteFailed) },
			calls: []string{"dns", "caddy", "zitadel"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSiteHarness(t)
			prevDNS := h.dns.body()
			tt.setup(h)
			_, liveBefore := h.caddy.state()

			res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if res.Status != StatusFailed || res.Applied {
				t.Errorf("result = %+v, want failed and not applied", res.Result)
			}
			wantCalls(t, h, tt.calls...)
			wantAlerts(t, h, AlertSiteUnverified)
			if h.hasHost(wikiHost) {
				t.Errorf("the record was committed although the artifacts are unverified")
			}
			if h.dns.body() == prevDNS {
				t.Errorf("the dns step was rolled back blindly")
			}
			if _, live := h.caddy.state(); live == "live:"+h.caddy.initial && liveBefore != live {
				t.Errorf("the live caddy config was rolled back blindly")
			}
			final := auditByName(h.audits(), "site.apply_failed")
			if len(final) != 1 || final[0].Actor != siteActor {
				t.Errorf("site.apply_failed events = %+v, want one with the actor", final)
			}
		})
	}
}

// AC5: an unreadable system or a drift stops the pipeline before the first write; the last
// known-good state stays and an alert is raised.
func TestSiteChange_ReadFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *siteHarness)
	}{
		{"caddyfile on disk unreadable", func(h *siteHarness) { h.caddy.diskErr = errBoom }},
		{"caddy admin API unreadable", func(h *siteHarness) { h.caddy.liveErr = errBoom }},
		{"dns file unreadable", func(h *siteHarness) { h.dns.readErr = errBoom }},
		{"zitadel unreadable", func(h *siteHarness) { h.uris.driftErr = errBoom }},
		{"zitadel drift", func(h *siteHarness) {
			h.uris.driftRes = zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: zitadel.DriftMissing, URI: "https://x/oauth2/callback"}}}
		}},
		{"caddyfile drift", func(h *siteHarness) { h.caddy.disk += "# edited by hand\n" }},
		{"dns file drift", func(h *siteHarness) { h.dns.content = "[]\n" }},
		{"dns file missing", func(h *siteHarness) { h.dns.content, h.dns.exists = "", false }},
		{"settings unreadable", func(h *siteHarness) { h.settingsErr = errBoom }},
		{"s06 key closed but the file was rendered open", func(h *siteHarness) { h.settings.Caddy.S06Open = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSiteHarness(t)
			tt.setup(h)
			disk, live := h.caddy.state()
			dnsBody := h.dns.body()

			res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if res.Status != StatusBlocked || res.Applied {
				t.Errorf("result = %+v, want blocked", res.Result)
			}
			wantCalls(t, h)
			wantAlerts(t, h, AlertSiteDrift)
			if h.hasHost(wikiHost) {
				t.Errorf("the record was committed")
			}
			if d, l := h.caddy.state(); d != disk || l != live || h.dns.body() != dnsBody {
				t.Errorf("an artifact changed although the pipeline was blocked")
			}
			rows := h.changes()
			if len(rows) != 1 || rows[0].Status != StatusFailed || rows[0].Error == "" {
				t.Errorf("change rows = %+v, want one failed row with the reason", rows)
			}
			if len(auditByName(h.audits(), "site.blocked")) != 1 {
				t.Errorf("no site.blocked audit event")
			}
		})
	}
}

// A role list that cannot be read stops the change before any artifact is rendered or written
// (S-02.3 and F2-003 AC3 through the pipeline).
func TestSiteChange_RoleReadFailure(t *testing.T) {
	h := newSiteHarness(t)
	h.roles.setErr(errBoom)
	_, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err == nil {
		t.Fatal("a change was accepted while the role list was unreadable")
	}
	wantCalls(t, h)
	if h.hasHost(wikiHost) {
		t.Errorf("the record was committed")
	}
}

// Fail closed on records that cannot be written safely: every user-controlled field is refused
// before anything external runs, and a stored record that no longer renders blocks the pipeline.
func TestSiteChange_UnsafeRecordsFailClosed(t *testing.T) {
	mutations := map[string]func(s *site.Site){
		"host with a newline":     func(s *site.Site) { s.Hosts = []string{"wiki.example.com\nimport evil"} },
		"host with a brace":       func(s *site.Site) { s.Hosts = []string{"wiki.example.com {"} },
		"host outside the domain": func(s *site.Site) { s.Hosts = []string{"wiki.evil.test"} },
		"header value newline": func(s *site.Site) {
			s.Headers = []site.Header{{Name: "X-A", Value: "a\n}\nevil.test {"}}
		},
		"header name operator": func(s *site.Site) { s.Headers = []site.Header{{Name: "-Server", Value: "x"}} },
		"redirect target newline": func(s *site.Site) {
			s.Redirects = []site.Redirect{{Source: "/a", Target: "/b\nrespond 200", Code: 301}}
		},
		"api regex that does not compile": func(s *site.Site) {
			s.APIRules = []site.APIRule{{Type: site.APIRulePathRegex, Value: "(?"}}
		},
		// The regex sits in a single-quoted CEL literal inside backticks: a single quote or a
		// backtick would end it (a double quote is inert there).
		"api regex that closes the CEL string": func(s *site.Site) {
			s.APIRules = []site.APIRule{{Type: site.APIRulePathRegex, Value: `^/a' || true || '`}}
		},
		"api regex with a backtick": func(s *site.Site) {
			s.APIRules = []site.APIRule{{Type: site.APIRulePathRegex, Value: "^/a`b"}}
		},
		"role with a space":   func(s *site.Site) { s.Roles = []string{"dev ops"} },
		"cert path traversal": func(s *site.Site) { s.Cert = "le:../../etc" },
		"unlisted url target": func(s *site.Site) {
			s.TargetKind, s.TargetURL = site.TargetURL, "http://169.254.169.254:80"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newSiteHarness(t)
			s := roleSiteRecord("wiki")
			mutate(&s)
			if _, err := h.sp.Submit(context.Background(), addReq(s)); err == nil {
				t.Fatal("an unsafe record was accepted")
			}
			wantCalls(t, h)
			if len(h.changes()) != 0 {
				t.Errorf("a refused record created a change row")
			}
		})
	}

	t.Run("stored record that no longer renders", func(t *testing.T) {
		h := newSiteHarness(t)
		// Bypass the service layer the way a damaged database would.
		if _, err := h.st.DB().ExecContext(context.Background(),
			`UPDATE site_hosts SET hostname = 'git.example.com {' WHERE hostname = ?`, gitHost); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Status != StatusBlocked {
			t.Errorf("status = %q, want blocked", res.Status)
		}
		wantCalls(t, h)
		wantAlerts(t, h, AlertSiteDrift)
	})

	t.Run("dns records that disagree", func(t *testing.T) {
		h := newSiteHarness(t)
		h.settings.ManualDNS = []dns.Record{{Name: wikiHost, Type: dns.TypeA, Value: "10.9.9.9"}}
		if _, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki"))); err == nil {
			t.Fatal("a conflicting dns record set was accepted")
		}
		wantCalls(t, h)
	})
}

// A stored set that lacks a locked system site is blocked before the first write: applying it would
// take the UI or the login offline (S-05, F2-008 hand-over).
func TestSiteChange_MissingSystemSiteBlocks(t *testing.T) {
	h := newSiteHarness(t)
	if _, err := h.st.DB().ExecContext(context.Background(),
		`DELETE FROM sites WHERE system_template = 'tagcess'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	// Keep the artifacts equal to the (broken) stored set, so the only problem is the missing record.
	broken, err := h.sites.ListSites(context.Background())
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	text, err := render.RenderCaddyfile(broken, h.settings.Caddy)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	h.caddy.disk = text
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusBlocked {
		t.Errorf("status = %q, want blocked", res.Status)
	}
	wantCalls(t, h)
	wantAlerts(t, h, AlertSiteDrift)
}

// Update orders like an add and never rolls back: a rollback of an edit could widen access.
func TestSiteChange_UpdateFailuresKeepState(t *testing.T) {
	rename := roleSiteRecord("git2")
	t.Run("rename runs dns, caddy, zitadel", func(t *testing.T) {
		h := newSiteHarness(t)
		res, err := h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: h.siteID(gitHost), Site: rename})
		if err != nil || !res.Applied {
			t.Fatalf("Submit: %+v, %v", res, err)
		}
		wantCalls(t, h, "dns", "caddy", "zitadel")
		if !h.hasHost("git2.example.com") || h.hasHost(gitHost) {
			t.Errorf("hosts = %v, want the renamed host only", h.hosts())
		}
	})
	t.Run("caddy refusal after the dns step keeps the dns file and alerts", func(t *testing.T) {
		h := newSiteHarness(t)
		prevDNS := h.dns.body()
		h.caddy.applyErr = errBoom
		res, err := h.sp.Submit(context.Background(), SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: h.siteID(gitHost), Site: rename})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Status != StatusFailed {
			t.Errorf("status = %q, want failed", res.Status)
		}
		wantCalls(t, h, "dns", "caddy")
		wantAlerts(t, h, AlertSitePartial)
		if h.dns.body() == prevDNS || !h.hasHost(gitHost) {
			t.Errorf("update was rolled back or committed: hosts=%v", h.hosts())
		}
	})
}

// The first import carries the seed: load, parity gate before the first apply, the gate is
// closed only after the first apply succeeded (F2-007 hand-over).
func TestSiteChange_FirstImport(t *testing.T) {
	t.Run("applies and closes the gate", func(t *testing.T) {
		h := newImportHarness(t)
		res, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil {
			t.Fatalf("FirstImport: %v", err)
		}
		if !res.Applied {
			t.Fatalf("result = %+v, want applied", res.Result)
		}
		wantCalls(t, h, "dns", "caddy", "zitadel")
		if pending, err := h.sites.FirstImportPending(context.Background()); err != nil || pending {
			t.Errorf("first import pending = %v (%v), want the gate closed", pending, err)
		}
		if disk, _ := h.caddy.state(); disk == h.caddy.initial {
			t.Errorf("the generated Caddyfile was not written")
		}
		// A second run has nothing left to do.
		h.calls.reset()
		again, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil || again.Status != StatusNoChange {
			t.Errorf("second FirstImport = %+v, %v, want no_change", again.Result, err)
		}
		wantCalls(t, h)
	})

	t.Run("parity mismatch blocks the first apply", func(t *testing.T) {
		h := newImportHarness(t)
		h.caddy.adapted = map[string]string{h.caddy.initial: `{"apps":{"http":{"different":true}}}`}
		res, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil {
			t.Fatalf("FirstImport: %v", err)
		}
		if res.Status != StatusBlocked {
			t.Errorf("status = %q, want blocked", res.Status)
		}
		wantCalls(t, h)
		if pending, _ := h.sites.FirstImportPending(context.Background()); !pending {
			t.Errorf("the gate was closed by a blocked import")
		}
	})

	t.Run("an adapter failure blocks it too", func(t *testing.T) {
		h := newImportHarness(t)
		h.caddy.adaptErr = errBoom
		res, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil || res.Status != StatusBlocked {
			t.Fatalf("FirstImport = %+v, %v, want blocked", res.Result, err)
		}
		wantCalls(t, h)
	})

	t.Run("a failed apply keeps the gate open", func(t *testing.T) {
		h := newImportHarness(t)
		h.caddy.applyErr = errBoom
		res, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil {
			t.Fatalf("FirstImport: %v", err)
		}
		if res.Applied {
			t.Fatalf("result = %+v, want not applied", res.Result)
		}
		if pending, _ := h.sites.FirstImportPending(context.Background()); !pending {
			t.Errorf("the gate was closed although the first apply failed")
		}
	})

	t.Run("a retry after a partial first import is not held against its own output", func(t *testing.T) {
		h := newImportHarness(t)
		h.uris.syncErr = errBoom
		h.uris.syncRes = driftOf(zitadel.DriftReadFailed)
		res, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil || res.Applied {
			t.Fatalf("first run = %+v, %v, want it stopped at zitadel", res.Result, err)
		}
		wantCalls(t, h, "dns", "caddy", "zitadel")
		// Caddy now runs the generated file, which carries the tagcess block today's file never had:
		// the adapted JSON no longer matches today's, so only "disk == target" can let the retry through.
		written, _ := h.caddy.state()
		h.caddy.adapted = map[string]string{written: `{"apps":{"http":{"different":true}}}`}
		h.uris.syncErr, h.uris.syncRes = nil, zitadel.URIResult{}

		h.calls.reset()
		res, err = h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
		if err != nil || !res.Applied {
			t.Fatalf("retry = %+v, %v, want applied", res.Result, err)
		}
		if pending, _ := h.sites.FirstImportPending(context.Background()); pending {
			t.Errorf("the gate stayed open after the retry succeeded")
		}
	})

	t.Run("ordinary edits are refused until the first import passed", func(t *testing.T) {
		h := newImportHarness(t)
		h.caddy.adapted = map[string]string{h.caddy.initial: `{"apps":{"http":{"different":true}}}`}
		if _, err := h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts); err != nil {
			t.Fatalf("FirstImport: %v", err)
		}
		res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if res.Status != StatusBlocked {
			t.Errorf("status = %q, want blocked while the first import is pending", res.Status)
		}
		wantCalls(t, h)
	})
}

// Applies are serialized under the writer lock: two requests never write at the same time, and
// the second plans from the first's committed state.
func TestSiteChange_SerializedApply(t *testing.T) {
	h := newSiteHarness(t)
	h.caddy.applyBlock = make(chan struct{})

	var wg sync.WaitGroup
	results := make([]SiteResult, 2)
	errs := make([]error, 2)
	run := func(i int, name string) {
		defer wg.Done()
		results[i], errs[i] = h.sp.Submit(context.Background(), addReq(roleSiteRecord(name)))
	}
	wg.Add(1)
	go run(0, "wiki")
	waitFor(t, func() bool { return len(h.calls.get()) >= 2 }) // first request is inside caddy.Apply
	wg.Add(1)
	go run(1, "blog")
	time.Sleep(100 * time.Millisecond)
	if got := h.calls.get(); len(got) != 2 {
		t.Fatalf("second request started writing while the first was applying: %v", got)
	}
	close(h.caddy.applyBlock)
	wg.Wait()

	for i := range results {
		if errs[i] != nil || !results[i].Applied {
			t.Fatalf("request %d = %+v, %v, want applied", i, results[i].Result, errs[i])
		}
	}
	if h.caddy.maxFlight != 1 {
		t.Errorf("max concurrent caddy applies = %d, want 1", h.caddy.maxFlight)
	}
	wantCalls(t, h, "dns", "caddy", "zitadel", "dns", "caddy", "zitadel")
	// The apply is handed the exact site set the target was rendered from (F2-008 hand-over).
	if len(h.uris.syncSites) != 2 || len(h.uris.syncSites[1]) != len(h.uris.syncSites[0])+1 {
		t.Errorf("zitadel sync site counts = %d/%d, want the second to see the first's site",
			len(h.uris.syncSites[0]), len(h.uris.syncSites[1]))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Dry run (Y-06) plans and records but writes nothing, not even the site record.
func TestSiteChange_DryRun(t *testing.T) {
	h := newSiteHarness(t)
	h.dry.set(true)
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != StatusDryRun || res.Applied {
		t.Errorf("result = %+v, want dry_run", res.Result)
	}
	if res.Plan.Diff.Caddy == "" {
		t.Errorf("a dry run still shows the diff")
	}
	wantCalls(t, h)
	if h.hasHost(wikiHost) || len(h.changes()) != 0 {
		t.Errorf("a dry run wrote a record")
	}
}

// With the S-06 key closed the new site is rendered with the closed snippets, from the same
// settings the drift check uses.
func TestSiteChange_S06ClosedRender(t *testing.T) {
	h := newSiteHarness(t)
	h.settings.Caddy.S06Open = false
	closed, err := render.RenderCaddyfile(h.before, h.settings.Caddy)
	if err != nil {
		t.Fatalf("render closed: %v", err)
	}
	h.caddy.disk, h.caddy.initial, h.caddy.live = closed, closed, "live:"+closed

	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || !res.Applied {
		t.Fatalf("Submit: %+v, %v", res, err)
	}
	after, err := h.sites.ListSites(context.Background())
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	want, err := render.RenderCaddyfile(after, h.settings.Caddy)
	if err != nil {
		t.Fatalf("render want: %v", err)
	}
	if disk, _ := h.caddy.state(); disk != want {
		t.Errorf("written Caddyfile is not the closed-key render of the new set")
	}
}

// A resync is the explicit "overwrite": it re-applies the stored records over drifted artifacts
// (the diff shows what is overwritten) instead of stopping at the drift.
func TestSiteChange_ResyncOverwritesDrift(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)
	h.caddy.disk += "# edited by hand\n"
	h.dns.content = "[]\n"

	res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteResync})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied {
		t.Fatalf("result = %+v, want applied", res.Result)
	}
	// The fake names an apply of the baseline text "caddy-restore": the target is the records' render.
	wantCalls(t, h, "dns", "caddy-restore", "zitadel")
	if !strings.Contains(res.Plan.Diff.Caddy, "-# edited by hand") {
		t.Errorf("caddy diff = %q, want the hand edit shown as removed", res.Plan.Diff.Caddy)
	}
	if disk, _ := h.caddy.state(); disk != h.caddy.initial {
		t.Errorf("the Caddyfile was not brought back to the records")
	}
}

// Actor is mandatory: an anonymous change never reaches an external system.
func TestSiteChange_ActorRequired(t *testing.T) {
	h := newSiteHarness(t)
	if _, err := h.sp.Submit(context.Background(), SiteRequest{Op: SiteAdd, Site: roleSiteRecord("wiki")}); err == nil {
		t.Fatal("a change without an actor was accepted")
	}
	wantCalls(t, h)
}

var _ = audit.Mask

// F5 I9: a completed first import records the policy baseline (once, with the importing actor); a
// blocked or repeated import does not, and a failing hook never fails the import.
func TestSiteChange_FirstImportRecordsPolicyBaseline(t *testing.T) {
	var calls []string
	run := func(h *importHarness) (SiteResult, error) {
		return h.sp.FirstImport(context.Background(), siteActor, h.seed, h.seedOpts)
	}
	t.Run("completed import", func(t *testing.T) {
		calls = nil
		h := newImportHarness(t)
		h.baseline = func(_ context.Context, actor string) error { calls = append(calls, actor); return nil }
		h.build()
		res, err := run(h)
		if err != nil || !res.Applied {
			t.Fatalf("FirstImport = %+v, %v, want applied", res.Result, err)
		}
		if len(calls) != 1 || calls[0] != siteActor {
			t.Fatalf("baseline calls = %v, want one call by %q", calls, siteActor)
		}
		if _, err := run(h); err != nil || len(calls) != 1 {
			t.Fatalf("second import: err=%v calls=%v, want no further baseline call", err, calls)
		}
	})
	t.Run("blocked import", func(t *testing.T) {
		calls = nil
		h := newImportHarness(t)
		h.baseline = func(_ context.Context, actor string) error { calls = append(calls, actor); return nil }
		h.build()
		h.caddy.adapted = map[string]string{h.caddy.initial: `{"apps":{"http":{"different":true}}}`}
		if _, err := run(h); err != nil {
			t.Fatalf("FirstImport: %v", err)
		}
		if len(calls) != 0 {
			t.Fatalf("baseline recorded for a blocked import: %v", calls)
		}
	})
	t.Run("failing hook", func(t *testing.T) {
		h := newImportHarness(t)
		h.baseline = func(context.Context, string) error { return errBoom }
		h.build()
		res, err := run(h)
		if err != nil || !res.Applied {
			t.Fatalf("a failing baseline hook failed the import: %+v, %v", res.Result, err)
		}
		if pending, _ := h.sites.FirstImportPending(context.Background()); pending {
			t.Error("the first import was not completed")
		}
	})
}
