package change

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Tests of F2-020 (A-03, ADR 0017): rolling back to an earlier site source snapshot is a new
// validated, approved and audited change that runs through the F2-011 pipeline.

// rollbackFixture is a wiki site with two applied versions: v1 holds roles v1Roles, v2 holds v2Roles.
type rollbackFixture struct {
	*siteHarness
	git    *fakeGit
	id     int64
	v1, v2 site.Version
}

func newRollbackFixture(t *testing.T, v1Roles, v2Roles []string) *rollbackFixture {
	t.Helper()
	ctx := context.Background()
	h, g := newGitSiteHarness(t)
	if res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki", v1Roles...))); err != nil || res.Status != StatusApplied {
		t.Fatalf("add = %+v, %v", res, err)
	}
	id := h.siteID(wikiHost)
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: id, Site: roleSiteRecord("wiki", v2Roles...)}); err != nil || res.Status != StatusApplied {
		t.Fatalf("update = %+v, %v", res, err)
	}
	list, err := h.sites.ListVersions(ctx, id)
	if err != nil || len(list) != 2 {
		t.Fatalf("versions = %+v, %v, want 2", list, err)
	}
	h.calls.reset()
	return &rollbackFixture{siteHarness: h, git: g, id: id, v1: list[1], v2: list[0]}
}

// narrowing: v1 = [devops], v2 = [devops developer]; widening is the other way round.
func narrowingFixture(t *testing.T) *rollbackFixture {
	return newRollbackFixture(t, []string{"devops"}, []string{"devops", "developer"})
}

func wideningFixture(t *testing.T) *rollbackFixture {
	return newRollbackFixture(t, []string{"devops", "developer"}, []string{"devops"})
}

func (f *rollbackFixture) wiki() site.Site {
	f.t.Helper()
	s, err := f.sites.GetSite(context.Background(), f.id)
	if err != nil {
		f.t.Fatalf("GetSite: %v", err)
	}
	return s
}

func (f *rollbackFixture) approval(p RollbackPreview, v site.Version) RollbackApproval {
	return RollbackApproval{Actor: siteActor, VersionID: v.ID, BaseHash: p.BaseHash}
}

func (f *rollbackFixture) noWrites() {
	f.t.Helper()
	if got := f.calls.get(); len(got) != 0 {
		f.t.Errorf("external writes = %v, want none", got)
	}
}

func changeCount(h *siteHarness) int { return len(h.changes()) }

// AC1: selecting a version shows a read-only preview: today's field validation, Caddy /adapt and the
// diff. Nothing is written, and the live base hash is recorded.
func TestArtifactRollback_PreviewReadOnly(t *testing.T) {
	ctx := context.Background()
	f := narrowingFixture(t)
	beforeSite := f.wiki()
	disk, live := f.caddy.state()
	dnsBody := f.dns.body()
	changes, audits := changeCount(f.siteHarness), len(f.audits())
	adapts := len(f.caddy.adaptTexts)

	p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
	if err != nil {
		t.Fatalf("PreviewRollback: %v", err)
	}
	f.noWrites()
	if got := len(f.caddy.adaptTexts) - adapts; got != 1 {
		t.Errorf("/adapt calls = %d, want 1 (the generated Caddyfile is checked)", got)
	}
	if last := f.caddy.adaptTexts[len(f.caddy.adaptTexts)-1]; !strings.Contains(last, wikiHost) {
		t.Errorf("/adapt got a Caddyfile without the site")
	}
	if p.Plan.Diff.Caddy == "" || !strings.Contains(p.Plan.Diff.Caddy, "developer") && !strings.Contains(p.Plan.Diff.Caddy, "devops") {
		t.Errorf("caddy diff = %q, want the role change", p.Plan.Diff.Caddy)
	}
	if p.Plan.Diff.Zitadel != "" || p.Plan.Diff.DNS != "" {
		t.Errorf("diff = %+v, want only the Caddyfile to change for a role edit", p.Plan.Diff)
	}
	if p.Op != SiteUpdate || p.Version.ID != f.v1.ID || p.NoChange || len(p.Widens) != 0 {
		t.Errorf("preview = %+v", p)
	}
	if len(p.BaseHash) != 64 {
		t.Errorf("base hash = %q, want a sha-256 hex digest", p.BaseHash)
	}
	again, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
	if err != nil || again.BaseHash != p.BaseHash {
		t.Errorf("second preview hash = %q (%v), want the same live base", again.BaseHash, err)
	}
	if d, l := f.caddy.state(); d != disk || l != live || f.dns.body() != dnsBody {
		t.Error("the preview changed a live artifact")
	}
	if !reflect.DeepEqual(f.wiki().Roles, beforeSite.Roles) {
		t.Error("the preview changed the stored site")
	}
	if changeCount(f.siteHarness) != changes {
		t.Error("the preview wrote a change row")
	}
	if len(f.audits()) != audits {
		t.Error("the preview wrote audit events of a change")
	}
	if len(f.git.requests()) != 2 {
		t.Errorf("history commits = %d, want only the two of the setup", len(f.git.requests()))
	}
}

// The preview is where a rollback is refused first: a snapshot that no longer validates, a Caddy
// that rejects the generated file, unreadable roles or a first import that is not finished.
func TestArtifactRollback_PreviewRefuses(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *rollbackFixture)
	}{
		{"role no longer exists", func(f *rollbackFixture) { f.roles.roles = []string{"devops"} }},
		{"roles unreadable", func(f *rollbackFixture) { f.roles.setErr(errBoom) }},
		{"caddy rejects the file", func(f *rollbackFixture) { f.caddy.adaptErr = errBoom }},
		{"caddyfile unreadable", func(f *rollbackFixture) { f.caddy.diskErr = errBoom }},
		{"settings unreadable", func(f *rollbackFixture) { f.settingsErr = errBoom }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// v1 = [devops developer] so "role no longer exists" bites on the rolled-back model.
			f := wideningFixture(t)
			tt.setup(f)
			p, err := f.sp.PreviewRollback(context.Background(), siteActor, f.v1.ID)
			if err == nil || p.BaseHash != "" {
				t.Fatalf("PreviewRollback = %+v, %v, want a refusal without a base hash", p, err)
			}
			f.noWrites()
		})
	}
}

func TestArtifactRollback_PreviewUnknownVersion(t *testing.T) {
	f := narrowingFixture(t)
	if _, err := f.sp.PreviewRollback(context.Background(), siteActor, 9999); !errors.Is(err, site.ErrNotFound) {
		t.Errorf("PreviewRollback(unknown) = %v, want site.ErrNotFound", err)
	}
	if _, err := f.sp.PreviewRollback(context.Background(), " ", f.v1.ID); err == nil {
		t.Error("PreviewRollback without an actor = nil error")
	}
}

// AC2: every applied change is a selectable version; the source model of the selected one is rebuilt
// exactly, also for a site that was deleted since (it comes back as a new site).
func TestArtifactRollback_SourceSnapshotSelectable(t *testing.T) {
	ctx := context.Background()
	f := narrowingFixture(t)
	wantV1 := roleSiteRecord("wiki", "devops")
	if got, want := f.v1.Site, wantV1; !reflect.DeepEqual(got, want) {
		t.Fatalf("v1 model:\n got %#v\nwant %#v", got, want)
	}
	// Every version reads back to exactly the model that was applied; each is selectable.
	for _, v := range []site.Version{f.v1, f.v2} {
		got, err := f.sites.GetVersion(ctx, v.ID)
		if err != nil || !reflect.DeepEqual(got.Site, v.Site) {
			t.Fatalf("GetVersion(%d) = %+v, %v", v.ID, got.Site, err)
		}
		if _, err := f.sp.PreviewRollback(ctx, siteActor, v.ID); err != nil && !errors.Is(err, ErrRollbackNoChange) {
			t.Errorf("version %d is not selectable: %v", v.ID, err)
		}
	}
	// A deleted site: its versions stay, and a version brings the exact model back as a new site.
	if res, err := f.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteDelete, ID: f.id}); err != nil || res.Status != StatusApplied {
		t.Fatalf("delete = %+v, %v", res, err)
	}
	if f.hasHost(wikiHost) {
		t.Fatal("wiki still exists")
	}
	p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
	if err != nil {
		t.Fatalf("preview of a deleted site's version: %v", err)
	}
	if p.Op != SiteAdd || len(p.Widens) == 0 {
		t.Errorf("preview = %+v, want an add that is flagged as opening access again", p)
	}
	res, err := f.sp.ApplyRollback(ctx, RollbackApproval{Actor: siteActor, VersionID: f.v1.ID, BaseHash: p.BaseHash, AcknowledgeWiden: true})
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("ApplyRollback = %+v, %v", res, err)
	}
	restored := f.sitesNamed(wikiHost)
	if restored.ID == f.id || restored.ID == 0 {
		t.Errorf("restored id = %d, want a new site (old id %d)", restored.ID, f.id)
	}
	restored.ID, restored.CreatedAt, restored.UpdatedAt = 0, time.Time{}, time.Time{}
	if !reflect.DeepEqual(restored, wantV1) {
		t.Errorf("restored model:\n got %#v\nwant %#v", restored, wantV1)
	}
}

func (f *rollbackFixture) sitesNamed(host string) site.Site {
	f.t.Helper()
	list, err := f.sites.ListSites(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	for _, s := range list {
		if slices.Contains(s.Hosts, host) {
			return s
		}
	}
	f.t.Fatalf("no site %s", host)
	return site.Site{}
}

// AC3: an approved rollback with an unchanged live base runs the F2-011 pipeline as ONE new change,
// records a new version bound to the change's revision, audits the selected version, and the next
// render keeps the rolled-back state.
func TestArtifactRollback_ApplyPersists(t *testing.T) {
	ctx := context.Background()
	f := narrowingFixture(t)
	p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	changes, commits := changeCount(f.siteHarness), len(f.git.requests())

	res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
	if err != nil || res.Status != StatusApplied || !res.Applied {
		t.Fatalf("ApplyRollback = %+v, %v, want applied", res, err)
	}
	// The existing pipeline ran: only the Caddyfile changes for a role edit.
	wantCalls(t, f.siteHarness, "caddy")
	if !slices.Equal(f.wiki().Roles, []string{"devops"}) {
		t.Errorf("stored roles = %v, want the rolled-back [devops]", f.wiki().Roles)
	}
	// Exactly one new change row, labelled as a rollback.
	rows := f.changes()
	if len(rows) != changes+1 {
		t.Fatalf("change rows = %d, want %d (one new change)", len(rows), changes+1)
	}
	last := rows[len(rows)-1]
	if last.Status != StatusApplied || last.Actor != siteActor || !strings.Contains(last.Before, "rollback to version") {
		t.Errorf("change row = %+v", last)
	}
	// A new version bound to this change's revision, pointing at the version it re-applied.
	list, err := f.sites.ListVersions(ctx, f.id)
	if err != nil || len(list) != 3 {
		t.Fatalf("versions = %+v, %v, want 3", list, err)
	}
	if list[0].RollbackOf != f.v1.ID || list[0].ChangeID != res.ChangeID || list[0].Revision == "" || list[0].Revision != res.Revision {
		t.Errorf("new version = %+v, want rollback_of %d, change %d and the change's revision %q",
			list[0], f.v1.ID, res.ChangeID, res.Revision)
	}
	if !reflect.DeepEqual(list[0].Site, f.v1.Site) {
		t.Errorf("new version model differs from the selected one")
	}
	if got := len(f.git.requests()); got != commits+1 {
		t.Errorf("history commits = %d, want one new", got-commits)
	}
	// Audit: who, which version, result.
	var found bool
	for _, e := range f.audits() {
		if e.Event != "site.rollback" {
			continue
		}
		found = true
		if e.Actor != siteActor || e.Result != StatusApplied {
			t.Errorf("rollback audit = %+v", e)
		}
		if c, ok := diffField(e.Diff, "version"); !ok || c.After != strconv.FormatInt(f.v1.ID, 10) {
			t.Errorf("rollback audit version = %+v, want the selected version %d", e.Diff, f.v1.ID)
		}
		if c, ok := diffField(e.Diff, "revision"); !ok || c.After != res.Revision {
			t.Errorf("rollback audit revision = %+v, want %q", c, res.Revision)
		}
	}
	if !found {
		t.Error("no site.rollback audit event")
	}
	if len(auditByName(f.audits(), "site.apply")) < 3 {
		t.Error("the pipeline's own apply event is missing")
	}

	// The next render keeps the rollback: the files equal the render of the stored records, and an
	// unrelated change passes the drift check and keeps the rolled-back site.
	cfg := f.settings
	sites, err := f.sites.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, err := render.RenderCaddyfile(sites, cfg.Caddy)
	if err != nil {
		t.Fatal(err)
	}
	if disk, _ := f.caddy.state(); disk != want {
		t.Error("the Caddyfile on disk differs from the render of the stored records")
	}
	f.calls.reset()
	next, err := f.sp.Submit(ctx, addReq(roleSiteRecord("blog")))
	if err != nil || next.Status != StatusApplied {
		t.Fatalf("next change = %+v, %v, want applied (no drift after a rollback)", next, err)
	}
	if !slices.Equal(f.wiki().Roles, []string{"devops"}) {
		t.Error("the next change undid the rollback")
	}
}

// A rollback to the state the site already has is not offered as a change.
func TestArtifactRollback_NoChange(t *testing.T) {
	ctx := context.Background()
	f := narrowingFixture(t)
	p, err := f.sp.PreviewRollback(ctx, siteActor, f.v2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.NoChange {
		t.Errorf("preview of the current version = %+v, want NoChange", p)
	}
	if _, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v2)); !errors.Is(err, ErrRollbackNoChange) {
		t.Errorf("ApplyRollback = %v, want ErrRollbackNoChange", err)
	}
	f.noWrites()
}

// AC4: a rollback that would break a system lock (S-05) is refused, and so is one that widens
// access without an explicit acknowledgement. S-06 is a global setting, not part of a snapshot: a
// rollback renders under the key as it is now.
func TestArtifactRollback_Locks(t *testing.T) {
	ctx := context.Background()

	t.Run("system site lock", func(t *testing.T) {
		f := narrowingFixture(t)
		cur, err := f.sites.GetSite(ctx, f.siteID("tagcess.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		doctored := cur
		doctored.Maintenance = true // a field the tagcess template does not open
		v, _, err := f.sites.RecordVersion(ctx, site.NewVersion{
			SiteID: cur.ID, ChangeID: 1, Op: site.VersionUpdate, Site: doctored, Actor: siteActor,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sp.PreviewRollback(ctx, siteActor, v.ID); !errors.Is(err, site.ErrSystemLocked) {
			t.Errorf("PreviewRollback = %v, want site.ErrSystemLocked", err)
		}
		if _, err := f.sp.ApplyRollback(ctx, RollbackApproval{Actor: siteActor, VersionID: v.ID, BaseHash: "x", AcknowledgeWiden: true}); err == nil {
			t.Error("ApplyRollback of a lock-breaking version = nil error")
		}
		f.noWrites()
	})

	t.Run("system site cannot be deleted by a tombstone", func(t *testing.T) {
		f := narrowingFixture(t)
		cur, err := f.sites.GetSite(ctx, f.siteID("auth.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		v, _, err := f.sites.RecordVersion(ctx, site.NewVersion{
			SiteID: cur.ID, ChangeID: 1, Op: site.VersionDelete, Deleted: true, Site: cur, Actor: siteActor,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sp.PreviewRollback(ctx, siteActor, v.ID); !errors.Is(err, site.ErrSystemLocked) {
			t.Errorf("PreviewRollback = %v, want site.ErrSystemLocked", err)
		}
		f.noWrites()
	})

	t.Run("S-06 closed stays closed", func(t *testing.T) {
		f := narrowingFixture(t)
		// The key is closed by now (an earlier change did it): the artifacts and the setting say so.
		f.settings.Caddy.S06Open = false
		sites, err := f.sites.ListSites(ctx)
		if err != nil {
			t.Fatal(err)
		}
		closed, err := render.RenderCaddyfile(sites, f.settings.Caddy)
		if err != nil {
			t.Fatal(err)
		}
		open, err := render.RenderCaddyfile(sites, render.CaddyConfig{ACMEEmail: f.settings.Caddy.ACMEEmail, S06Open: true})
		if err != nil || !strings.Contains(open, caddyTailOpenForTest) || strings.Contains(closed, caddyTailOpenForTest) {
			t.Fatalf("test precondition: the open tail marker must tell the two renders apart (%v)", err)
		}
		f.caddy.disk, f.caddy.live = closed, "live:"+closed
		p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
		if err != nil {
			t.Fatal(err)
		}
		res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
		if err != nil || res.Status != StatusApplied {
			t.Fatalf("ApplyRollback = %+v, %v", res, err)
		}
		disk, _ := f.caddy.state()
		if !strings.Contains(disk, "respond 403") || strings.Contains(disk, caddyTailOpenForTest) {
			t.Errorf("rolled-back Caddyfile does not keep the closed S-06 key")
		}
	})

	t.Run("widening needs an explicit acknowledgement", func(t *testing.T) {
		f := wideningFixture(t)
		p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Widens) == 0 || !strings.Contains(strings.Join(p.Widens, " "), "developer") {
			t.Fatalf("Widens = %v, want the added role named", p.Widens)
		}
		if _, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1)); !errors.Is(err, ErrRollbackWidens) {
			t.Fatalf("ApplyRollback without acknowledgement = %v, want ErrRollbackWidens", err)
		}
		f.noWrites()
		if !slices.Equal(f.wiki().Roles, []string{"devops"}) {
			t.Error("a refused rollback changed the site")
		}
		if ev := auditByName(f.audits(), "site.rollback_refused"); len(ev) != 1 || ev[0].Actor != siteActor {
			t.Errorf("refusal audit = %+v, want one event of the actor", ev)
		}
		ack := f.approval(p, f.v1)
		ack.AcknowledgeWiden = true
		if res, err := f.sp.ApplyRollback(ctx, ack); err != nil || res.Status != StatusApplied {
			t.Fatalf("acknowledged ApplyRollback = %+v, %v", res, err)
		}
		if !slices.Equal(f.wiki().Roles, []string{"devops", "developer"}) {
			t.Errorf("roles = %v after the acknowledged rollback", f.wiki().Roles)
		}
	})

	t.Run("incomplete reads stop the apply", func(t *testing.T) {
		f := narrowingFixture(t)
		p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.caddy.liveErr = errBoom // the running config cannot be read at approval time
		res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
		if err != nil && !errors.Is(err, ErrRollbackStale) {
			t.Fatalf("ApplyRollback error = %v", err)
		}
		if res.Status == StatusApplied {
			t.Errorf("rollback applied with an unreadable running config: %+v", res)
		}
		f.noWrites()
		if !slices.Equal(f.wiki().Roles, []string{"devops", "developer"}) {
			t.Error("the site changed although the reads were incomplete")
		}
	})

	t.Run("dry run writes nothing", func(t *testing.T) {
		f := narrowingFixture(t)
		p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.dry.set(true)
		res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
		if err != nil || res.Status != StatusDryRun {
			t.Fatalf("ApplyRollback = %+v, %v, want dry_run", res, err)
		}
		f.noWrites()
	})
}

const caddyTailOpenForTest = "\thandle {\n\t\timport k8s\n\t}\n}\n"

// AC5: when the live base changed between the preview and the approval, the apply stops.
func TestArtifactRollback_Stale(t *testing.T) {
	ctx := context.Background()
	for name, race := range map[string]func(f *rollbackFixture){
		"another change applied": func(f *rollbackFixture) {
			if res, err := f.sp.Submit(ctx, addReq(roleSiteRecord("blog"))); err != nil || res.Status != StatusApplied {
				f.t.Fatalf("racing change = %+v, %v", res, err)
			}
		},
		"caddyfile edited by hand": func(f *rollbackFixture) { f.caddy.disk += "# by hand\n" },
		"dns file changed":         func(f *rollbackFixture) { f.dns.content += " " },
		"s-06 key closed": func(f *rollbackFixture) {
			f.settings.Caddy.S06Open = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := narrowingFixture(t)
			p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
			if err != nil {
				t.Fatal(err)
			}
			race(f)
			f.calls.reset()
			changes := changeCount(f.siteHarness)

			res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
			if !errors.Is(err, ErrRollbackStale) {
				t.Fatalf("ApplyRollback = %+v, %v, want ErrRollbackStale", res, err)
			}
			f.noWrites()
			if changeCount(f.siteHarness) != changes {
				t.Error("a stale rollback wrote a change row")
			}
			if ev := auditByName(f.audits(), "site.rollback_refused"); len(ev) != 1 {
				t.Errorf("refusal audit events = %d, want 1", len(ev))
			}
		})
	}

	t.Run("missing or wrong hash", func(t *testing.T) {
		f := narrowingFixture(t)
		for _, hash := range []string{"", "deadbeef", strings.Repeat("0", 64)} {
			_, err := f.sp.ApplyRollback(ctx, RollbackApproval{Actor: siteActor, VersionID: f.v1.ID, BaseHash: hash})
			if !errors.Is(err, ErrRollbackStale) {
				t.Errorf("ApplyRollback(hash %q) = %v, want ErrRollbackStale", hash, err)
			}
		}
		f.noWrites()
	})
}

// A rollback whose apply fails leaves no version behind and is recorded as the failed change it is.
func TestArtifactRollback_ApplyFailure(t *testing.T) {
	ctx := context.Background()
	f := narrowingFixture(t)
	p, err := f.sp.PreviewRollback(ctx, siteActor, f.v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.uris.syncErr = errBoom
	f.uris.syncRes = zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: zitadel.DriftWriteFailed}}}
	f.caddy.applyErr = errBoom // a clean refusal: the running config does not move
	res, err := f.sp.ApplyRollback(ctx, f.approval(p, f.v1))
	if err != nil {
		t.Fatalf("ApplyRollback error = %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if list, _ := f.sites.ListVersions(ctx, f.id); len(list) != 2 {
		t.Errorf("versions = %d, want the two of the setup (a failed rollback is not a version)", len(list))
	}
	if !slices.Equal(f.wiki().Roles, []string{"devops", "developer"}) {
		t.Error("the site record moved although the apply failed")
	}
	if ev := auditByName(f.audits(), "site.rollback"); len(ev) != 1 || ev[0].Result != StatusFailed {
		t.Errorf("rollback audit = %+v, want one failed event", ev)
	}
}
