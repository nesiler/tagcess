package change

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Tests of the F2-019 wiring round (ADR 0016, A-02, A-03.4): the pipelines commit the verified final
// artifacts to the local history after the apply, never an uncertain one, and the revision is
// recorded with the durable site versions.

// fakeGit records what the pipelines hand to the history.
type fakeGit struct {
	mu      sync.Mutex
	reqs    []gitlog.CommitRequest
	err     error
	pending []gitlog.Retry
}

func (f *fakeGit) Commit(_ context.Context, req gitlog.CommitRequest) (gitlog.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return gitlog.Result{}, f.err
	}
	return gitlog.Result{Revision: revisionFor(len(f.reqs)), Committed: true}, nil
}

func (f *fakeGit) Pending(context.Context) ([]gitlog.Retry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pending), nil
}

func (f *fakeGit) requests() []gitlog.CommitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func revisionFor(n int) string { return strings.Repeat("a", 39) + string(rune('0'+n)) }

func fileContent(req gitlog.CommitRequest, name string) (string, bool) {
	for _, f := range req.Files {
		if f.Name == name {
			return string(f.Content), true
		}
	}
	return "", false
}

func newGitSiteHarness(t *testing.T) (*siteHarness, *fakeGit) {
	t.Helper()
	h := newSiteHarness(t)
	g := &fakeGit{}
	h.git = g
	h.build()
	return h, g
}

// A-02.1: after a verified apply the final artifacts are committed under the acting user and the
// revision comes back with the result and on the durable site version.
func TestSiteChange_GitCommitsVerifiedFinal(t *testing.T) {
	ctx := context.Background()
	h, g := newGitSiteHarness(t)

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("Submit = %+v, %v, want applied", res, err)
	}
	reqs := g.requests()
	if len(reqs) != 1 {
		t.Fatalf("commits = %d, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Actor != siteActor || req.AppliedAt.IsZero() || req.Uncertain {
		t.Errorf("commit request = %+v, want the actor, an apply time and a certain apply", req)
	}
	if req.Ref != GitRef(res.ChangeID) {
		t.Errorf("ref = %q, want %q", req.Ref, GitRef(res.ChangeID))
	}
	disk, _ := h.caddy.state()
	if got, ok := fileContent(req, GitFileCaddyfile); !ok || got != disk {
		t.Errorf("committed Caddyfile differs from the applied one (present=%v)", ok)
	}
	if got, ok := fileContent(req, GitFileMagicDNS); !ok || got != h.dns.body() {
		t.Errorf("committed MagicDNS file differs from the applied one (present=%v)", ok)
	}
	uris, ok := fileContent(req, GitFileRedirectURIs)
	if !ok || !strings.Contains(uris, "https://wiki.example.com/oauth2/callback") {
		t.Errorf("committed redirect URIs = %q, want the desired set", uris)
	}
	if len(req.Files) != 3 {
		t.Errorf("committed %d files, want only the three generated artifacts", len(req.Files))
	}
	if res.Revision != revisionFor(1) || res.GitFailed {
		t.Errorf("result revision = %q failed=%v, want the commit's revision", res.Revision, res.GitFailed)
	}
	versions, err := h.sites.ListVersions(ctx, h.siteID("wiki.example.com"))
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %+v, %v, want one", versions, err)
	}
	if versions[0].Revision != revisionFor(1) || versions[0].ChangeID != res.ChangeID {
		t.Errorf("version = %+v, want it bound to the change and its revision (A-03.4)", versions[0])
	}
}

// A-02.4: only a verified, applied change is committed. A failed, unknown, rolled back, blocked or
// dry-run request never reaches the history, and leaves no version behind.
func TestSiteChange_GitNoCommitWithoutVerifiedApply(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *siteHarness)
		want  string
	}{
		{"zitadel write unknown", func(h *siteHarness) {
			h.uris.syncErr = errBoom
			h.uris.syncRes = zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: zitadel.DriftWriteFailed}}}
		}, StatusFailed},
		{"caddy outcome unknown", func(h *siteHarness) {
			h.caddy.applyErr = errBoom
			h.caddy.liveMovesOnError = true
		}, StatusFailed},
		{"rolled back", func(h *siteHarness) {
			h.uris.syncErr = errBoom
			h.uris.syncRes = zitadel.URIResult{Drift: []zitadel.URIDrift{{Kind: zitadel.DriftReadFailed}}}
		}, StatusRolledBack},
		{"blocked by drift", func(h *siteHarness) { h.caddy.disk += "# edited by hand\n" }, StatusBlocked},
		{"dry run", func(h *siteHarness) { h.dry.set(true) }, StatusDryRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, g := newGitSiteHarness(t)
			tt.setup(h)
			res, _ := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
			if res.Status != tt.want {
				t.Fatalf("status = %q, want %q", res.Status, tt.want)
			}
			if n := len(g.requests()); n != 0 {
				t.Errorf("commits = %d, want none (never commit what is not verified)", n)
			}
			if res.Revision != "" {
				t.Errorf("revision = %q, want none", res.Revision)
			}
			list, err := h.sites.ListVersions(context.Background(), 99)
			if err != nil || len(list) != 0 {
				t.Errorf("versions = %v, %v, want none", list, err)
			}
		})
	}
}

// A-02.3: a commit that fails never fails the change: the verified live state stays, the result
// carries no revision and says so, and the version waits unbound for its late revision.
func TestSiteChange_GitFailureKeepsAppliedState(t *testing.T) {
	ctx := context.Background()
	h, g := newGitSiteHarness(t)
	g.err = errors.New("git: index locked")

	res, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil {
		t.Fatalf("Submit error = %v, want none (gitlog already audited, alerted and queued the intent)", err)
	}
	if res.Status != StatusApplied || !res.Applied {
		t.Fatalf("result = %+v, want applied", res)
	}
	if res.Revision != "" || !res.GitFailed {
		t.Errorf("revision = %q failed=%v, want no revision and the failure flagged", res.Revision, res.GitFailed)
	}
	if !h.hasHost("wiki.example.com") {
		t.Error("the site record is missing after a git failure")
	}
	versions, err := h.sites.ListVersions(ctx, h.siteID("wiki.example.com"))
	if err != nil || len(versions) != 1 || versions[0].Revision != "" {
		t.Errorf("versions = %+v, %v, want one without a revision", versions, err)
	}
}

// Without a configured history the pipeline works as before (F2-011) and claims no revision.
func TestSiteChange_NoGitConfigured(t *testing.T) {
	h := newSiteHarness(t)
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("Submit = %+v, %v", res, err)
	}
	if res.Revision != "" || res.GitFailed {
		t.Errorf("revision = %q failed=%v, want neither without a history", res.Revision, res.GitFailed)
	}
}

// A clean commit with an empty retry queue proves the history alerts gone; a queue that is not
// empty keeps them.
func TestSiteChange_GitResolvesAlertsOnlyWhenQueueEmpty(t *testing.T) {
	ctx := context.Background()
	h, g := newGitSiteHarness(t)
	raise := func() {
		for _, kind := range []string{gitlog.AlertGitFailed, gitlog.AlertGitSecret} {
			if err := h.sp.base.raiseAlert(ctx, 0, kind); err != nil {
				t.Fatal(err)
			}
		}
	}
	raise()
	g.pending = []gitlog.Retry{{ID: 1}}
	if _, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki"))); err != nil {
		t.Fatal(err)
	}
	if got := h.alerts(); !slices.Equal(got, []string{gitlog.AlertGitFailed, gitlog.AlertGitSecret}) {
		t.Errorf("alerts with a pending intent = %v, want both kept", got)
	}
	g.pending = nil
	if _, err := h.sp.Submit(ctx, addReq(roleSiteRecord("blog"))); err != nil {
		t.Fatal(err)
	}
	if got := h.alerts(); len(got) != 0 {
		t.Errorf("alerts after a clean commit with an empty queue = %v, want none", got)
	}
}

// A-03.4: every applied change leaves a durable version per site it touched: add, update, delete
// (a tombstone with the last model), and the first import for every site.
func TestSiteChange_RecordsVersions(t *testing.T) {
	ctx := context.Background()
	h := newSiteHarness(t)

	if _, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki"))); err != nil {
		t.Fatal(err)
	}
	id := h.siteID("wiki.example.com")
	upd := roleSiteRecord("wiki", "devops", "developer")
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteUpdate, ID: id, Site: upd}); err != nil || res.Status != StatusApplied {
		t.Fatalf("update = %+v, %v", res, err)
	}
	if res, err := h.sp.Submit(ctx, SiteRequest{Actor: siteActor, Op: SiteDelete, ID: id}); err != nil || res.Status != StatusApplied {
		t.Fatalf("delete = %+v, %v", res, err)
	}
	list, err := h.sites.ListVersions(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("versions = %d, want add, update and delete", len(list))
	}
	if list[2].Op != "add" || list[1].Op != "update" || list[0].Op != "delete" || !list[0].Deleted {
		t.Errorf("versions = %+v, want add < update < delete tombstone", list)
	}
	if !slices.Equal(list[1].Site.Roles, []string{"devops", "developer"}) {
		t.Errorf("update version roles = %v", list[1].Site.Roles)
	}
	if !slices.Equal(list[0].Site.Roles, []string{"devops", "developer"}) {
		t.Errorf("tombstone must keep the last source model, roles = %v", list[0].Site.Roles)
	}
	for _, v := range list {
		if v.Actor != siteActor || v.ChangeID == 0 {
			t.Errorf("version %+v lacks actor or change", v)
		}
	}
}

// A-03.4: the first import is the first version of every site, so the imported state is a rollback
// target; repeating the import records nothing new.
func TestSiteChange_FirstImportRecordsVersions(t *testing.T) {
	ctx := context.Background()
	h := newImportHarness(t)
	res, err := h.sp.FirstImport(ctx, siteActor, h.seed, h.seedOpts)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("FirstImport = %+v, %v", res, err)
	}
	all, err := h.sites.ListSites(ctx)
	if err != nil || len(all) == 0 {
		t.Fatalf("sites = %d, %v", len(all), err)
	}
	for _, s := range all {
		v, err := h.sites.ListVersions(ctx, s.ID)
		if err != nil || len(v) != 1 || v[0].Op != "resync" {
			t.Errorf("versions of %v = %+v, %v, want the one import version", s.Hosts, v, err)
		}
	}
}

// F2-019 AC1/AC3 end to end with the real gitlog: a commit that fails is queued, the change stays
// applied, and the next commit drains the queue first and binds the late revision to the version
// that waited for it (A-03.4).
func TestSiteChange_GitLateRevisionBindsVersion(t *testing.T) {
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

	first, err := h.sp.Submit(ctx, addReq(roleSiteRecord("wiki")))
	if err != nil || first.Revision == "" {
		t.Fatalf("first change = %+v, %v, want a real revision", first, err)
	}

	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := h.sp.Submit(ctx, addReq(roleSiteRecord("blog")))
	if err != nil {
		t.Fatalf("second change error = %v, want none: the apply is verified", err)
	}
	if second.Status != StatusApplied || second.Revision != "" || !second.GitFailed {
		t.Fatalf("second change = %+v, want applied without a revision", second)
	}
	blogID := h.siteID("blog.example.com")
	if v, _ := h.sites.ListVersions(ctx, blogID); len(v) != 1 || v[0].Revision != "" {
		t.Fatalf("blog version = %+v, want it unbound while the commit is queued", v)
	}
	if !slices.Contains(h.alerts(), gitlog.AlertGitFailed) {
		t.Errorf("alerts = %v, want %s", h.alerts(), gitlog.AlertGitFailed)
	}

	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	third, err := h.sp.Submit(ctx, addReq(roleSiteRecord("docs")))
	if err != nil || third.Revision == "" {
		t.Fatalf("third change = %+v, %v, want a real revision", third, err)
	}
	v, _ := h.sites.ListVersions(ctx, blogID)
	if len(v) != 1 || v[0].Revision == "" || v[0].Revision == third.Revision {
		t.Fatalf("blog version = %+v, want the late revision of its own commit", v)
	}
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "show", v[0].Revision+":"+GitFileCaddyfile).CombinedOutput()
	if err != nil {
		t.Fatalf("git show: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "blog.example.com") || strings.Contains(string(out), "docs.example.com") {
		t.Errorf("the bound revision does not hold the blog change's Caddyfile")
	}
	if len(h.alerts()) != 0 {
		t.Errorf("alerts after the queue drained = %v, want none", h.alerts())
	}
}

// F1 policy pipeline: the verified policy is committed under the acting user. A failed check, a
// mismatch or an unverified write is never committed; a verified policy whose node expiry failed
// still is (the policy is the final state).
func TestPolicyApply_GitCommitsVerifiedFinal(t *testing.T) {
	ctx := context.Background()
	p, hs, _ := newPipeline(t)
	g := &fakeGit{}
	p.WithGit(g)

	res, err := p.Submit(ctx, baseRequest())
	if err != nil || !res.Applied {
		t.Fatalf("Submit = %+v, %v", res, err)
	}
	reqs := g.requests()
	if len(reqs) != 1 {
		t.Fatalf("commits = %d, want 1", len(reqs))
	}
	if reqs[0].Actor != "dev@example.com" || reqs[0].AppliedAt.IsZero() || reqs[0].Uncertain {
		t.Errorf("commit request = %+v", reqs[0])
	}
	if got, ok := fileContent(reqs[0], GitFilePolicy); !ok || got != targetPolicy || len(reqs[0].Files) != 1 {
		t.Errorf("committed files = %+v, want only the verified policy", reqs[0].Files)
	}
	if res.Revision != revisionFor(1) {
		t.Errorf("revision = %q, want the commit's", res.Revision)
	}
	_ = hs
}

func TestPolicyApply_GitNeverCommitsUncertain(t *testing.T) {
	tests := []struct {
		name  string
		setup func(hs *fakeHeadscale)
	}{
		{"check refused", func(hs *fakeHeadscale) { hs.checkErr = errors.New("invalid") }},
		{"write refused", func(hs *fakeHeadscale) { hs.setErr = errors.New("down") }},
		{"readback mismatch", func(hs *fakeHeadscale) { hs.SetGetAfter(`{"acls":[],"groups":{}}`) }},
		{"readback fails", func(hs *fakeHeadscale) { hs.SetGetErrAfter(errors.New("down")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, hs, _ := newPipeline(t)
			g := &fakeGit{}
			p.WithGit(g)
			tt.setup(hs)
			res, _ := p.Submit(context.Background(), baseRequest())
			if res.Applied {
				t.Fatalf("result = %+v, want not applied", res)
			}
			if n := len(g.requests()); n != 0 {
				t.Errorf("commits = %d, want none for an unverified policy", n)
			}
		})
	}
}

func TestPolicyApply_GitCommitsVerifiedPolicyWhenExpireFails(t *testing.T) {
	p, hs, _ := newPipeline(t)
	g := &fakeGit{}
	p.WithGit(g)
	hs.SetExpireErr(8, errors.New("headscale down"))
	req := baseRequest()
	req.Expire = []uint64{7, 8}
	res, err := p.Submit(context.Background(), req)
	if err != nil || res.Applied {
		t.Fatalf("Submit = %+v, %v, want failed", res, err)
	}
	if len(g.requests()) != 1 || res.Revision != revisionFor(1) {
		t.Errorf("commits = %d, revision = %q, want the verified policy committed once", len(g.requests()), res.Revision)
	}
}

func TestPolicyApply_GitFailureKeepsApplied(t *testing.T) {
	p, _, _ := newPipeline(t)
	g := &fakeGit{err: errors.New("git down")}
	p.WithGit(g)
	res, err := p.Submit(context.Background(), baseRequest())
	if err != nil || !res.Applied {
		t.Fatalf("Submit = %+v, %v, want applied without error", res, err)
	}
	if res.Revision != "" || !res.GitFailed {
		t.Errorf("revision = %q failed=%v, want none and flagged", res.Revision, res.GitFailed)
	}
}

// The site and the policy pipeline hand different files to the same history repository.
func TestGitFileNames(t *testing.T) {
	names := []string{GitFileCaddyfile, GitFileMagicDNS, GitFileRedirectURIs, GitFilePolicy}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] || strings.ContainsAny(n, `/\`) {
			t.Errorf("bad artifact file name %q", n)
		}
		seen[n] = true
	}
}
