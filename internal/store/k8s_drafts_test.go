package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/store/db"
)

// openK8sDraftStore opens a migrated store at path. The caller closes it; reopening the same path
// is how the tests model a process restart (F4-009 AC1).
func openK8sDraftStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return s
}

// draftFixture is the full row of a draft: every column has a distinct value so a query that drops
// or overwrites a column is caught. assertRow checks all of them (the review fix for the update path).
type draftFixture struct {
	Cluster          string
	Host             string
	ProfileVersion   string
	SnapshotID       sql.NullInt64
	ObservedAt       string
	AccessChoice     string
	Roles            string
	Target           string
	Cert             string
	Note             string
	ReviewState      string
	ReviewReason     string
	ReviewCandidates string
	ReviewDefault    string
	CreatedAt        string
	UpdatedAt        string
}

func (f draftFixture) upsertParams() db.UpsertK8sDraftParams {
	return db.UpsertK8sDraftParams{
		Cluster: f.Cluster, Host: f.Host, ProfileVersion: f.ProfileVersion,
		SnapshotID: f.SnapshotID, ObservedAt: f.ObservedAt,
		AccessChoice: f.AccessChoice, Roles: f.Roles, Target: f.Target, Cert: f.Cert, Note: f.Note,
		ReviewState: f.ReviewState, ReviewReason: f.ReviewReason,
		ReviewCandidates: f.ReviewCandidates, ReviewDefault: f.ReviewDefault,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
}

// assertRow pins EVERY column of a draft row against the fixture.
func (f draftFixture) assertRow(t *testing.T, got db.K8sDraft) {
	t.Helper()
	if got.ID == 0 {
		t.Error("draft id was not assigned")
	}
	if got.Cluster != f.Cluster {
		t.Errorf("cluster = %q, want %q", got.Cluster, f.Cluster)
	}
	if got.Host != f.Host {
		t.Errorf("host = %q, want %q", got.Host, f.Host)
	}
	if got.ProfileVersion != f.ProfileVersion {
		t.Errorf("profile_version = %q, want %q", got.ProfileVersion, f.ProfileVersion)
	}
	if got.SnapshotID != f.SnapshotID {
		t.Errorf("snapshot_id = %+v, want %+v", got.SnapshotID, f.SnapshotID)
	}
	if got.ObservedAt != f.ObservedAt {
		t.Errorf("observed_at = %q, want %q", got.ObservedAt, f.ObservedAt)
	}
	if got.AccessChoice != f.AccessChoice {
		t.Errorf("access_choice = %q, want %q", got.AccessChoice, f.AccessChoice)
	}
	if got.Roles != f.Roles {
		t.Errorf("roles = %q, want %q", got.Roles, f.Roles)
	}
	if got.Target != f.Target {
		t.Errorf("target = %q, want %q", got.Target, f.Target)
	}
	if got.Cert != f.Cert {
		t.Errorf("cert = %q, want %q", got.Cert, f.Cert)
	}
	if got.Note != f.Note {
		t.Errorf("note = %q, want %q", got.Note, f.Note)
	}
	if got.ReviewState != f.ReviewState {
		t.Errorf("review_state = %q, want %q", got.ReviewState, f.ReviewState)
	}
	if got.ReviewReason != f.ReviewReason {
		t.Errorf("review_reason = %q, want %q", got.ReviewReason, f.ReviewReason)
	}
	if got.ReviewCandidates != f.ReviewCandidates {
		t.Errorf("review_candidates = %q, want %q", got.ReviewCandidates, f.ReviewCandidates)
	}
	if got.ReviewDefault != f.ReviewDefault {
		t.Errorf("review_default = %q, want %q", got.ReviewDefault, f.ReviewDefault)
	}
	if got.CreatedAt != f.CreatedAt {
		t.Errorf("created_at = %q, want %q", got.CreatedAt, f.CreatedAt)
	}
	if got.UpdatedAt != f.UpdatedAt {
		t.Errorf("updated_at = %q, want %q", got.UpdatedAt, f.UpdatedAt)
	}
}

// insertDraftSnapshot writes a successful read so a draft can reference a real snapshot_id.
func insertDraftSnapshot(t *testing.T, s *Store, observed string) db.K8sSnapshot {
	t.Helper()
	snap, err := s.Queries().InsertK8sSnapshot(context.Background(), db.InsertK8sSnapshotParams{
		Scope: "lab", ProfileVersion: "traefik-v1", ObservedAt: observed, Payload: `{"ingresses":[]}`,
	})
	if err != nil {
		t.Fatalf("InsertK8sSnapshot: %v", err)
	}
	return snap
}

// routeParams builds a fully specified route provenance row.
func routeParams(draftID int64, ns, name, uid, rv, path, pathType, svc, port, class, observed string) db.UpsertK8sDraftRouteParams {
	return db.UpsertK8sDraftRouteParams{
		DraftID: draftID, Namespace: ns, IngressName: name, IngressUid: uid, ResourceVersion: rv,
		Path: path, PathType: pathType, BackendService: svc, BackendPort: port, Class: class,
		ObservedAt: observed,
	}
}

// AC1: an incomplete proposal survives a process restart with the user's choices and the discovery
// provenance (snapshot/cluster/namespace/Ingress UID/resourceVersion/host/path/backend); saving it
// never applies a site.
func TestIncompleteDraftPersistsWithoutApplying(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sDraftStore(t, path)
	q := s.Queries()

	snap := insertDraftSnapshot(t, s, "2026-10-04T01:00:00.000Z")
	f := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v1",
		SnapshotID: sql.NullInt64{Int64: snap.ID, Valid: true}, ObservedAt: "2026-10-04T01:00:00.000Z",
		AccessChoice: "role", Roles: `["developer","devops"]`,
		Target: "https://100.64.0.5:443", Cert: "auto", Note: "roller eksik",
		ReviewState: "needed", ReviewReason: "route_conflict",
		ReviewCandidates: `["svc-a:80","svc-b:80"]`, ReviewDefault: "unknown",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}
	got, err := q.UpsertK8sDraft(ctx, f.upsertParams())
	if err != nil {
		t.Fatalf("UpsertK8sDraft: %v", err)
	}
	f.assertRow(t, got)

	for _, r := range []db.UpsertK8sDraftRouteParams{
		routeParams(got.ID, "ns-a", "ing", "uid-1", "7", "/", "Prefix", "svc-a", "80", "traefik", "2026-10-04T01:00:00.000Z"),
		routeParams(got.ID, "ns-a", "ing", "uid-1", "7", "/api", "Prefix", "svc-a", "80", "traefik", "2026-10-04T01:00:00.000Z"),
	} {
		if _, err := q.UpsertK8sDraftRoute(ctx, r); err != nil {
			t.Fatalf("UpsertK8sDraftRoute: %v", err)
		}
	}

	// Saving an incomplete proposal is not applying it: no applicable site record exists.
	var sites int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM sites`).Scan(&sites); err != nil {
		t.Fatalf("count sites: %v", err)
	}
	if sites != 0 {
		t.Fatalf("sites rows = %d, want 0: saving a draft must not apply a site", sites)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same database file: a restart keeps the choices and the provenance.
	s2 := openK8sDraftStore(t, path)
	t.Cleanup(func() { _ = s2.Close() })
	reopened, err := s2.Queries().GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft after reopen: %v", err)
	}
	f.assertRow(t, reopened)
	if reopened.ID != got.ID {
		t.Fatalf("reopened draft id = %d, want %d", reopened.ID, got.ID)
	}
	routes, err := s2.Queries().ListK8sDraftRoutes(ctx, got.ID)
	if err != nil {
		t.Fatalf("ListK8sDraftRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(routes))
	}
	wantPaths := map[string]string{"/": "svc-a", "/api": "svc-a"}
	for _, r := range routes {
		wantBackend, ok := wantPaths[r.Path]
		if !ok {
			t.Errorf("unexpected route path %q", r.Path)
			continue
		}
		if r.DraftID != got.ID || r.Namespace != "ns-a" || r.IngressName != "ing" || r.IngressUid != "uid-1" ||
			r.ResourceVersion != "7" || r.PathType != "Prefix" || r.BackendService != wantBackend ||
			r.BackendPort != "80" || r.Class != "traefik" || r.ObservedAt != "2026-10-04T01:00:00.000Z" {
			t.Errorf("route provenance = %+v, want the persisted discovery evidence", r)
		}
	}
}

// ListK8sDraftRoutes returns a deterministic order (namespace, ingress_uid, path, path_type) that
// does not depend on insert order.
func TestK8sDraftRoutes_ListOrder(t *testing.T) {
	ctx := context.Background()
	s := openK8sDraftStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	draft, err := q.UpsertK8sDraft(ctx, draftFixture{
		Cluster: "lab", Host: "app.example", ObservedAt: "t", AccessChoice: "role", Roles: `["developer"]`,
		Cert: "auto", CreatedAt: "t", UpdatedAt: "t",
	}.upsertParams())
	if err != nil {
		t.Fatalf("UpsertK8sDraft: %v", err)
	}
	// Insert in an order that is neither the sorted order nor its reverse.
	for _, r := range []struct{ ns, path string }{{"ns-a", "/z"}, {"ns-b", "/a"}, {"ns-a", "/a"}} {
		if _, err := q.UpsertK8sDraftRoute(ctx, routeParams(draft.ID, r.ns, "ing", "uid-"+r.ns, "1", r.path, "Prefix", "svc", "80", "traefik", "t")); err != nil {
			t.Fatalf("UpsertK8sDraftRoute(%s %s): %v", r.ns, r.path, err)
		}
	}
	routes, err := q.ListK8sDraftRoutes(ctx, draft.ID)
	if err != nil {
		t.Fatalf("ListK8sDraftRoutes: %v", err)
	}
	var got []string
	for _, r := range routes {
		got = append(got, r.Namespace+r.Path)
	}
	want := []string{"ns-a/a", "ns-a/z", "ns-b/a"}
	if !slices.Equal(got, want) {
		t.Errorf("route order = %v, want %v", got, want)
	}
}

// siteTables are the applicable-site tables the draft store must never touch (F4-009 AC2).
var siteTables = []string{"sites", "site_hosts", "site_api_rules", "site_redirects", "site_headers", "site_versions"}

// snapshotTables dumps every row of each table as a deterministic string. Row order is normalised so
// the before/after comparison reflects row content, not scan order.
func snapshotTables(t *testing.T, d *sql.DB, tables []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tbl := range tables {
		rows, err := d.QueryContext(context.Background(), "SELECT * FROM "+tbl)
		if err != nil {
			t.Fatalf("snapshot %s: %v", tbl, err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatalf("columns %s: %v", tbl, err)
		}
		var lines []string
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("scan %s: %v", tbl, err)
			}
			parts := make([]string, len(cols))
			for i, c := range cols {
				parts[i] = c + "=" + strconv.FormatBool(vals[i].Valid) + ":" + vals[i].String
			}
			lines = append(lines, strings.Join(parts, ","))
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("close %s: %v", tbl, err)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate %s: %v", tbl, err)
		}
		sort.Strings(lines)
		out[tbl] = strings.Join(lines, "\n")
	}
	return out
}

// seedSite writes one full applicable site record (site + hosts + api rule + redirect + header +
// version) so the draft mutations have a running application state to leave untouched.
func seedSite(t *testing.T, d *sql.DB, host string) int64 {
	t.Helper()
	ctx := context.Background()
	res, err := d.ExecContext(ctx,
		`INSERT INTO sites (kind, open_reason, cert, target_kind, target_url, roles, created_at, updated_at)
		 VALUES ('open', 'intentional', 'auto', 'k8s', 'https://100.64.0.5', '["developer"]', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("seed site: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("site id: %v", err)
	}
	stmts := []string{
		`INSERT INTO site_hosts (site_id, position, hostname) VALUES (?, 0, ?)`,
		`INSERT INTO site_api_rules (site_id, position, type, value) VALUES (?, 0, 'path_regex', '^/health$')`,
		`INSERT INTO site_redirects (site_id, position, source_path, target, code) VALUES (?, 0, '/old', '/new', 301)`,
		`INSERT INTO site_headers (site_id, position, name, value) VALUES (?, 0, 'X-Frame-Options', 'DENY')`,
		`INSERT INTO site_versions (site_id, change_id, op, deleted, hosts, snapshot, revision, actor, created_at)
		 VALUES (?, 0, 'add', 0, '["live.example"]', '{}', 'rev-1', 'devops', '2026-10-01T00:00:00Z')`,
	}
	for _, q := range stmts {
		if _, err := d.ExecContext(ctx, q, id, host); err != nil {
			t.Fatalf("seed site child (%s): %v", q, err)
		}
	}
	return id
}

// AC2: creating, updating and deleting a draft (and its routes) touches only draft rows; the
// applicable site record, its hosts/roles rules and its version history stay byte-for-byte equal.
func TestK8sDraftStore_MutationsDoNotTouchSites(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sDraftStore(t, path)
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()
	d := s.DB()

	seedSite(t, d, "live.example")
	before := snapshotTables(t, d, siteTables)

	f := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v1",
		ObservedAt:   "2026-10-04T01:00:00.000Z",
		AccessChoice: "open", Roles: `[]`, Target: "https://100.64.0.5:443", Cert: "auto",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}
	created, err := q.UpsertK8sDraft(ctx, f.upsertParams())
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	// Update path: same (cluster, host), new choices.
	f.AccessChoice = "role"
	f.Roles = `["developer"]`
	f.Note = "güncellendi"
	f.UpdatedAt = "2026-10-04T02:00:00.000Z"
	if _, err := q.UpsertK8sDraft(ctx, f.upsertParams()); err != nil {
		t.Fatalf("update draft: %v", err)
	}
	route, err := q.UpsertK8sDraftRoute(ctx, routeParams(created.ID, "ns-a", "ing", "uid-1", "7", "/", "Prefix", "svc-a", "80", "traefik", "t"))
	if err != nil {
		t.Fatalf("insert route: %v", err)
	}
	if route.DraftID != created.ID {
		t.Fatalf("route draft_id = %d, want %d", route.DraftID, created.ID)
	}

	// The mutations really happened (positive control for the comparison below).
	var drafts, routes int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM k8s_drafts`).Scan(&drafts); err != nil || drafts != 1 {
		t.Fatalf("drafts after create/update = %d (err %v), want 1", drafts, err)
	}
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM k8s_draft_routes`).Scan(&routes); err != nil || routes != 1 {
		t.Fatalf("routes after insert = %d (err %v), want 1", routes, err)
	}

	if n, err := q.DeleteK8sDraftRoutes(ctx, created.ID); err != nil || n != 1 {
		t.Fatalf("DeleteK8sDraftRoutes = %d (err %v), want 1", n, err)
	}
	if n, err := q.DeleteK8sDraft(ctx, db.DeleteK8sDraftParams{Cluster: "lab", Host: "app.example"}); err != nil || n != 1 {
		t.Fatalf("DeleteK8sDraft = %d (err %v), want 1", n, err)
	}

	after := snapshotTables(t, d, siteTables)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("draft mutations changed the applicable site state:\nbefore=%v\nafter=%v", before, after)
	}

	// Positive control: the snapshot comparison must be able to fail. Adding a running site row has
	// to show up as a difference, so the equality above is meaningful.
	seedSite(t, d, "second.example")
	mutated := snapshotTables(t, d, siteTables)
	if reflect.DeepEqual(after, mutated) {
		t.Error("positive control: site-table snapshot did not detect a newly applied site")
	}
}

// AC3: a failed draft transaction keeps the previous user choices and writes no partial new draft.
// It runs through the generated store queries inside a caller-owned transaction (the store's write
// surface) and relies on SQLite's rollback semantics for the all-or-nothing guarantee.
func TestK8sDraftStore_TransactionFailureKeepsChoices(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sDraftStore(t, path)
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	orig := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v1",
		ObservedAt:   "2026-10-04T01:00:00.000Z",
		AccessChoice: "role", Roles: `["developer"]`, Target: "https://100.64.0.5:443", Cert: "auto",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}
	created, err := q.UpsertK8sDraft(ctx, orig.upsertParams())
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if _, err := q.UpsertK8sDraftRoute(ctx, routeParams(created.ID, "ns-a", "ing", "uid-1", "7", "/", "Prefix", "svc-a", "80", "traefik", "t")); err != nil {
		t.Fatalf("insert route: %v", err)
	}

	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	tq := q.WithTx(tx)

	// First change the existing draft's choices in the transaction ...
	changed := orig
	changed.AccessChoice = "open"
	changed.Roles = `[]`
	changed.Target = ""
	changed.UpdatedAt = "2026-10-04T03:00:00.000Z"
	if _, err := tq.UpsertK8sDraft(ctx, changed.upsertParams()); err != nil {
		t.Fatalf("update draft in tx: %v", err)
	}
	// ... then a second, partial new draft fails on the empty-host CHECK, aborting the transaction.
	bad := orig
	bad.Host = ""
	bad.CreatedAt = "2026-10-04T03:00:00.000Z"
	bad.UpdatedAt = "2026-10-04T03:00:00.000Z"
	if _, err := tq.UpsertK8sDraft(ctx, bad.upsertParams()); err == nil {
		t.Fatal("expected the empty-host partial draft to be rejected")
	}
	// Positive control: the in-transaction update was applied before the rollback undoes it.
	if inTx, err := tq.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"}); err != nil || inTx.AccessChoice != "open" {
		t.Fatalf("in-tx draft = %+v (err %v), want the uncommitted access_choice open", inTx, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft after rollback: %v", err)
	}
	orig.assertRow(t, got)

	var drafts int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM k8s_drafts`).Scan(&drafts); err != nil || drafts != 1 {
		t.Errorf("drafts after failed tx = %d (err %v), want the single previous draft", drafts, err)
	}
	routes, err := q.ListK8sDraftRoutes(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListK8sDraftRoutes after rollback: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("routes after failed tx = %d, want the one previous route", len(routes))
	}
}

// Review fix (MEDIUM 1): the Upsert update path must write every column and never overwrite
// created_at. Re-read after the update and again after a reopen.
func TestK8sDraftStore_UpsertUpdatesEveryColumn(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sDraftStore(t, path)
	q := s.Queries()

	first := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v1",
		ObservedAt:   "2026-10-04T01:00:00.000Z",
		AccessChoice: "role", Roles: `["developer"]`, Target: "https://100.64.0.5:443", Cert: "auto",
		Note: "first", ReviewState: "needed", ReviewReason: "route_conflict",
		ReviewCandidates: `["svc-a:80"]`, ReviewDefault: "unknown",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}
	created, err := q.UpsertK8sDraft(ctx, first.upsertParams())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	snap := insertDraftSnapshot(t, s, "2026-10-04T02:00:00.000Z")
	second := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v2",
		SnapshotID: sql.NullInt64{Int64: snap.ID, Valid: true}, ObservedAt: "2026-10-04T02:00:00.000Z",
		AccessChoice: "open", Roles: `[]`, Target: "https://100.64.0.6:443", Cert: "cert-2", Note: "second",
		ReviewState: "resolved", ReviewReason: "ambiguous_class",
		ReviewCandidates: `["svc-b:80","svc-c:80"]`, ReviewDefault: "svc-b",
		// A caller-supplied created_at must be ignored on the update path.
		CreatedAt: "2099-01-01T00:00:00.000Z", UpdatedAt: "2026-10-04T02:00:00.000Z",
	}
	updated, err := q.UpsertK8sDraft(ctx, second.upsertParams())
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("update created a new draft id %d, want the existing %d", updated.ID, created.ID)
	}
	if updated.CreatedAt != first.CreatedAt {
		t.Errorf("created_at = %q, want the original %q", updated.CreatedAt, first.CreatedAt)
	}
	second.CreatedAt = first.CreatedAt
	second.assertRow(t, updated)

	// Re-read through the scoped getter.
	reread, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft: %v", err)
	}
	second.assertRow(t, reread)

	// Reopen: the update survives a restart, still with the original created_at.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2 := openK8sDraftStore(t, path)
	t.Cleanup(func() { _ = s2.Close() })
	reopened, err := s2.Queries().GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft after reopen: %v", err)
	}
	second.assertRow(t, reopened)
}

// Review fix (MEDIUM 2): every query is scoped. Two drafts share a host across clusters and two
// share a cluster; GetK8sDraft, ListK8sDraftRoutes, DeleteK8sDraft and DeleteK8sDraftRoutes must only
// ever touch their own row(s).
func TestK8sDraftStore_QueriesAreScoped(t *testing.T) {
	ctx := context.Background()
	s := openK8sDraftStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	mk := func(cluster, host, choice string) db.K8sDraft {
		t.Helper()
		got, err := q.UpsertK8sDraft(ctx, draftFixture{
			Cluster: cluster, Host: host, AccessChoice: choice,
			CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
		}.upsertParams())
		if err != nil {
			t.Fatalf("create %s/%s: %v", cluster, host, err)
		}
		return got
	}
	labApp := mk("lab", "app.example", "role")
	otherApp := mk("other", "app.example", "open")
	labOther := mk("lab", "other.example", "system")

	// Same route identity on every draft: only draft_id separates them.
	addRoute := func(draftID int64, backend string) {
		t.Helper()
		if _, err := q.UpsertK8sDraftRoute(ctx, routeParams(draftID, "ns-a", "ing", "uid-1", "7", "/", "Prefix", backend, "80", "traefik", "t")); err != nil {
			t.Fatalf("route for %d: %v", draftID, err)
		}
	}
	addRoute(labApp.ID, "app-lab")
	addRoute(otherApp.ID, "app-other")
	addRoute(labOther.ID, "other-lab")

	// GetK8sDraft is scoped by BOTH cluster and host: the same host in another cluster is a different
	// draft, and the scoped getter returns the right one.
	for _, tc := range []struct {
		cluster, host, choice string
		id                    int64
	}{
		{"lab", "app.example", "role", labApp.ID},
		{"other", "app.example", "open", otherApp.ID},
		{"lab", "other.example", "system", labOther.ID},
	} {
		got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: tc.cluster, Host: tc.host})
		if err != nil {
			t.Fatalf("GetK8sDraft(%s/%s): %v", tc.cluster, tc.host, err)
		}
		if got.ID != tc.id || got.AccessChoice != tc.choice {
			t.Errorf("GetK8sDraft(%s/%s) = id %d choice %q, want id %d choice %q", tc.cluster, tc.host, got.ID, got.AccessChoice, tc.id, tc.choice)
		}
	}

	// ListK8sDraftRoutes is scoped by draft_id even when the route key is identical.
	for _, tc := range []struct {
		id      int64
		backend string
	}{{labApp.ID, "app-lab"}, {otherApp.ID, "app-other"}, {labOther.ID, "other-lab"}} {
		routes, err := q.ListK8sDraftRoutes(ctx, tc.id)
		if err != nil {
			t.Fatalf("ListK8sDraftRoutes(%d): %v", tc.id, err)
		}
		if len(routes) != 1 || routes[0].BackendService != tc.backend || routes[0].DraftID != tc.id {
			t.Errorf("routes for draft %d = %+v, want exactly the %s route", tc.id, routes, tc.backend)
		}
	}

	// DeleteK8sDraftRoutes only removes the named draft's routes.
	if n, err := q.DeleteK8sDraftRoutes(ctx, labOther.ID); err != nil || n != 1 {
		t.Fatalf("DeleteK8sDraftRoutes(%d) = %d (err %v), want 1", labOther.ID, n, err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, labApp.ID); err != nil || len(routes) != 1 {
		t.Fatalf("lab/app routes after deleting lab/other routes = %d (err %v), want 1", len(routes), err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, otherApp.ID); err != nil || len(routes) != 1 {
		t.Fatalf("other/app routes after deleting lab/other routes = %d (err %v), want 1", len(routes), err)
	}

	// UpdateK8sDraftProvenance is scoped by (cluster, host) too: refreshing lab/app must not touch
	// the same host in another cluster.
	if _, err := q.UpdateK8sDraftProvenance(ctx, db.UpdateK8sDraftProvenanceParams{
		ProfileVersion: "traefik-v9", ObservedAt: "2026-10-04T09:00:00.000Z",
		UpdatedAt: "2026-10-04T09:00:00.000Z", Cluster: "lab", Host: "app.example",
	}); err != nil {
		t.Fatalf("UpdateK8sDraftProvenance(lab/app): %v", err)
	}
	if got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"}); err != nil || got.ProfileVersion != "traefik-v9" {
		t.Errorf("provenance was not refreshed for lab/app: %+v (err %v)", got, err)
	}
	if got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "other", Host: "app.example"}); err != nil || got.ProfileVersion != "" || got.ObservedAt != "" {
		t.Errorf("provenance update leaked to the same host in another cluster: %+v (err %v)", got, err)
	}
	if got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "other.example"}); err != nil || got.ProfileVersion != "" || got.ObservedAt != "" {
		t.Errorf("provenance update leaked to another host in the same cluster: %+v (err %v)", got, err)
	}

	// DeleteK8sDraft only deletes the exact (cluster, host) draft and cascades its routes.
	if n, err := q.DeleteK8sDraft(ctx, db.DeleteK8sDraftParams{Cluster: "lab", Host: "app.example"}); err != nil || n != 1 {
		t.Fatalf("DeleteK8sDraft(lab/app) = %d (err %v), want 1", n, err)
	}
	if _, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("deleted draft is still readable: err %v, want sql.ErrNoRows", err)
	}
	if got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "other", Host: "app.example"}); err != nil || got.ID != otherApp.ID {
		t.Errorf("same host in another cluster was deleted: %+v (err %v)", got, err)
	}
	if got, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "other.example"}); err != nil || got.ID != labOther.ID {
		t.Errorf("other host in the same cluster was deleted: %+v (err %v)", got, err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, labApp.ID); err != nil || len(routes) != 0 {
		t.Errorf("deleted draft left %d routes (err %v), want 0", len(routes), err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, otherApp.ID); err != nil || len(routes) != 1 {
		t.Errorf("surviving draft routes = %d (err %v), want 1", len(routes), err)
	}
	// Deleting the already-deleted draft affects nothing.
	if n, err := q.DeleteK8sDraft(ctx, db.DeleteK8sDraftParams{Cluster: "lab", Host: "app.example"}); err != nil || n != 0 {
		t.Errorf("second DeleteK8sDraft = %d (err %v), want 0", n, err)
	}
}

// Review fix (MEDIUM 3): re-observing one route refreshes its mutable fields (resourceVersion,
// backend, class, name, observed_at) instead of failing on the unique key, and the replace path
// (delete + reinsert) is available for a full refresh.
func TestK8sDraftStore_UpsertRouteRefreshes(t *testing.T) {
	ctx := context.Background()
	s := openK8sDraftStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	draft, err := q.UpsertK8sDraft(ctx, draftFixture{
		Cluster: "lab", Host: "app.example",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}.upsertParams())
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}

	if _, err := q.UpsertK8sDraftRoute(ctx, routeParams(draft.ID, "ns-a", "ing", "uid-1", "7", "/", "Prefix", "svc-a", "80", "traefik", "2026-10-04T01:00:00.000Z")); err != nil {
		t.Fatalf("first route upsert: %v", err)
	}
	refreshed, err := q.UpsertK8sDraftRoute(ctx, routeParams(draft.ID, "ns-a", "ing-renamed", "uid-1", "9", "/", "Prefix", "svc-b", "8080", "", "2026-10-04T02:00:00.000Z"))
	if err != nil {
		t.Fatalf("refreshing route upsert must not fail on the unique key: %v", err)
	}
	if refreshed.IngressUid != "uid-1" || refreshed.Path != "/" || refreshed.PathType != "Prefix" {
		t.Errorf("refresh changed the route identity: %+v", refreshed)
	}
	if refreshed.IngressName != "ing-renamed" || refreshed.ResourceVersion != "9" ||
		refreshed.BackendService != "svc-b" || refreshed.BackendPort != "8080" ||
		refreshed.Class != "" || refreshed.ObservedAt != "2026-10-04T02:00:00.000Z" {
		t.Errorf("refresh did not update the mutable fields: %+v", refreshed)
	}

	routes, err := q.ListK8sDraftRoutes(ctx, draft.ID)
	if err != nil {
		t.Fatalf("ListK8sDraftRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("routes after refresh = %d, want 1 (no duplicate)", len(routes))
	}
	if routes[0].ResourceVersion != "9" || routes[0].BackendService != "svc-b" {
		t.Errorf("stored route = %+v, want the refreshed observation", routes[0])
	}

	// Full refresh: delete the draft's routes and reinsert the current observation set.
	if n, err := q.DeleteK8sDraftRoutes(ctx, draft.ID); err != nil || n != 1 {
		t.Fatalf("DeleteK8sDraftRoutes = %d (err %v), want 1", n, err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, draft.ID); err != nil || len(routes) != 0 {
		t.Fatalf("routes after delete = %d (err %v), want 0", len(routes), err)
	}
	if _, err := q.UpsertK8sDraftRoute(ctx, routeParams(draft.ID, "ns-a", "ing-renamed", "uid-1", "9", "/", "Prefix", "svc-b", "8080", "", "2026-10-04T02:00:00.000Z")); err != nil {
		t.Fatalf("reinsert after delete: %v", err)
	}
	if routes, err := q.ListK8sDraftRoutes(ctx, draft.ID); err != nil || len(routes) != 1 {
		t.Fatalf("routes after reinsert = %d (err %v), want 1", len(routes), err)
	}
}

// Review fix (MEDIUM 4): refreshing discovery provenance must never overwrite the user's choices.
func TestK8sDraftStore_ProvenanceUpdateKeepsChoices(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)
	s := openK8sDraftStore(t, path)
	q := s.Queries()

	orig := draftFixture{
		Cluster: "lab", Host: "app.example", ProfileVersion: "traefik-v1",
		SnapshotID: sql.NullInt64{Int64: insertDraftSnapshot(t, s, "2026-10-04T01:00:00.000Z").ID, Valid: true}, ObservedAt: "2026-10-04T01:00:00.000Z",
		AccessChoice: "role", Roles: `["developer","devops"]`,
		Target: "https://100.64.0.5:443", Cert: "auto", Note: "kullanıcı notu",
		ReviewState: "needed", ReviewReason: "route_conflict",
		ReviewCandidates: `["svc-a:80","svc-b:80"]`, ReviewDefault: "unknown",
		CreatedAt: "2026-10-04T01:00:00.000Z", UpdatedAt: "2026-10-04T01:00:00.000Z",
	}
	created, err := q.UpsertK8sDraft(ctx, orig.upsertParams())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newSnap := insertDraftSnapshot(t, s, "2026-10-04T05:00:00.000Z")
	got, err := q.UpdateK8sDraftProvenance(ctx, db.UpdateK8sDraftProvenanceParams{
		ProfileVersion: "traefik-v2",
		SnapshotID:     sql.NullInt64{Int64: newSnap.ID, Valid: true},
		ObservedAt:     "2026-10-04T05:00:00.000Z",
		UpdatedAt:      "2026-10-04T05:00:00.000Z",
		Cluster:        "lab", Host: "app.example",
	})
	if err != nil {
		t.Fatalf("UpdateK8sDraftProvenance: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("provenance update id = %d, want %d", got.ID, created.ID)
	}
	if got.ProfileVersion != "traefik-v2" || got.SnapshotID.Int64 != newSnap.ID || !got.SnapshotID.Valid ||
		got.ObservedAt != "2026-10-04T05:00:00.000Z" || got.UpdatedAt != "2026-10-04T05:00:00.000Z" {
		t.Errorf("provenance not refreshed: %+v", got)
	}

	// Every user-owned column — including created_at — must survive unchanged.
	want := orig
	want.ProfileVersion = "traefik-v2"
	want.SnapshotID = sql.NullInt64{Int64: newSnap.ID, Valid: true}
	want.ObservedAt = "2026-10-04T05:00:00.000Z"
	want.UpdatedAt = "2026-10-04T05:00:00.000Z"
	want.assertRow(t, got)

	reread, err := q.GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft: %v", err)
	}
	want.assertRow(t, reread)

	// Reopen: the refreshed provenance and the kept choices both persist.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2 := openK8sDraftStore(t, path)
	t.Cleanup(func() { _ = s2.Close() })
	reopened, err := s2.Queries().GetK8sDraft(ctx, db.GetK8sDraftParams{Cluster: "lab", Host: "app.example"})
	if err != nil {
		t.Fatalf("GetK8sDraft after reopen: %v", err)
	}
	want.assertRow(t, reopened)
}
