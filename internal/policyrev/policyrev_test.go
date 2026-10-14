package policyrev

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

func openRepo(t *testing.T) (*Repo, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s.Queries()), s
}

func newRev(raw string) NewRevision {
	return NewRevision{Raw: raw, Source: SourceUI, Actor: "devops@example.com", Reason: "test"}
}

// AC2: the raw text is stored byte for byte, including comments, blanks, tabs, CRLF and trailing
// commas, and read back unchanged.
func TestPolicyRev_RoundTripBytes(t *testing.T) {
	ctx := context.Background()
	r, _ := openRepo(t)
	at := time.Date(2026, 10, 1, 8, 30, 15, 123_000_000, time.UTC)
	r.clock = func() time.Time { return at }

	raw := "// leading comment\r\n{\r\n\t/* block */ \"groups\": {\"group:a\": [\"x@example.com\",],},   \n\n\t\"acls\": [],\n}\n\n"
	rev, err := r.Add(ctx, NewRevision{
		BaseHash: "abc", Raw: raw, Source: SourceUI, Actor: "devops@example.com", Reason: "why",
		Validation: `{"stages":["syntax"],"validator":"v1"}`, ChangeID: 7, RollbackOf: 3,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if rev.ID == 0 || rev.ApplyStatus != StatusPending {
		t.Fatalf("Add = %+v, want an id and pending", rev)
	}
	got, err := r.Get(ctx, rev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Raw != raw {
		t.Errorf("raw changed:\n got %q\nwant %q", got.Raw, raw)
	}
	if got.RawHash != HashRaw(raw) {
		t.Errorf("raw_hash = %q, want sha256 of the exact bytes", got.RawHash)
	}
	if got.BaseHash != "abc" || got.Source != SourceUI || got.Actor != "devops@example.com" || got.Reason != "why" ||
		got.Validation != `{"stages":["syntax"],"validator":"v1"}` || got.ChangeID != 7 || got.RollbackOf != 3 {
		t.Errorf("stored fields = %+v", got)
	}
	if !got.CreatedAt.Equal(at) {
		t.Errorf("created_at = %v, want %v", got.CreatedAt, at)
	}
}

func TestPolicyRev_AddRejects(t *testing.T) {
	ctx := context.Background()
	r, _ := openRepo(t)
	tests := []struct {
		name string
		mut  func(*NewRevision)
		want error
	}{
		{"empty actor", func(n *NewRevision) { n.Actor = "  " }, ErrNoActor},
		{"unknown source", func(n *NewRevision) { n.Source = "cli" }, ErrInvalidSource},
		{"not hujson", func(n *NewRevision) { n.Raw = `{"acls": [` }, ErrInvalidRaw},
		{"not an object", func(n *NewRevision) { n.Raw = `[1]` }, ErrInvalidRaw},
		{"validation not json", func(n *NewRevision) { n.Validation = "ok" }, ErrInvalidValidation},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := newRev(`{"acls": []}`)
			tc.mut(&n)
			if _, err := r.Add(ctx, n); !errors.Is(err, tc.want) {
				t.Errorf("Add = %v, want %v", err, tc.want)
			}
		})
	}
	if got, err := r.List(ctx, 10); err != nil || len(got) != 0 {
		t.Errorf("List after rejected adds = %d rows (err %v), want 0", len(got), err)
	}
}

// AC3: comments, whitespace, key order and trailing commas do not change the canonical hash; a
// semantic change does.
func TestPolicyRev_CanonicalHash(t *testing.T) {
	base := `{"groups": {"group:a": ["x@example.com", "y@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	same := []struct{ name, doc string }{
		{"comments and blanks", "// c\n{\n  /* b */ \"groups\": {\"group:a\": [\"x@example.com\", \"y@example.com\"]},\n\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}] // t\n}\n"},
		{"trailing commas", `{"groups": {"group:a": ["x@example.com", "y@example.com",],}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"],},],}`},
		{"key order", `{"acls": [{"dst": ["*:*"], "src": ["*"], "action": "accept"}], "groups": {"group:a": ["x@example.com", "y@example.com"]}}`},
		{"compact", `{"groups":{"group:a":["x@example.com","y@example.com"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`},
	}
	want, err := CanonicalHash(base)
	if err != nil || want == "" {
		t.Fatalf("CanonicalHash(base) = %q, %v", want, err)
	}
	for _, tc := range same {
		t.Run("same/"+tc.name, func(t *testing.T) {
			got, err := CanonicalHash(tc.doc)
			if err != nil || got != want {
				t.Errorf("CanonicalHash = %q (err %v), want %q", got, err, want)
			}
			if HashRaw(tc.doc) == HashRaw(base) {
				t.Error("raw hash equal for different text")
			}
		})
	}
	different := []struct{ name, doc string }{
		{"member removed", `{"groups": {"group:a": ["x@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`},
		{"array order", `{"groups": {"group:a": ["y@example.com", "x@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`},
		{"value changed", `{"groups": {"group:a": ["x@example.com", "y@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}`},
		{"extra key", `{"groups": {"group:a": ["x@example.com", "y@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}], "hosts": {}}`},
		{"comment-looking string", `{"groups": {"group:a": ["x@example.com", "y@example.com"]}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"], "note": "// c"}]}`},
	}
	for _, tc := range different {
		t.Run("different/"+tc.name, func(t *testing.T) {
			got, err := CanonicalHash(tc.doc)
			if err != nil || got == want {
				t.Errorf("CanonicalHash = %q (err %v), want a different hash", got, err)
			}
		})
	}
	if _, err := CanonicalHash(`{"a":`); err == nil {
		t.Error("CanonicalHash of broken text returned no error")
	}
}

// AC4: Finish moves pending to a final state once; the content is never updated or deleted.
func TestPolicyRev_FinishOnce(t *testing.T) {
	ctx := context.Background()
	for _, status := range []Status{StatusApplied, StatusFailed, StatusUnknown, StatusDryRun} {
		t.Run(string(status), func(t *testing.T) {
			r, _ := openRepo(t)
			rev, err := r.Add(ctx, newRev(`{"acls": []}`))
			if err != nil {
				t.Fatalf("Add: %v", err)
			}
			if err := r.Finish(ctx, rev.ID, status, "detail"); err != nil {
				t.Fatalf("Finish: %v", err)
			}
			got, _ := r.Get(ctx, rev.ID)
			if got.ApplyStatus != status || got.ApplyDetail != "detail" {
				t.Errorf("after Finish = %q/%q, want %q/detail", got.ApplyStatus, got.ApplyDetail, status)
			}
			if err := r.Finish(ctx, rev.ID, StatusFailed, "again"); !errors.Is(err, ErrAlreadyFinished) {
				t.Errorf("second Finish = %v, want ErrAlreadyFinished", err)
			}
			if got2, _ := r.Get(ctx, rev.ID); got2 != got {
				t.Errorf("second Finish changed the row: %+v -> %+v", got, got2)
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		r, _ := openRepo(t)
		rev, _ := r.Add(ctx, newRev(`{"acls": []}`))
		if err := r.Finish(ctx, rev.ID, StatusPending, ""); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("Finish(pending) = %v, want ErrInvalidStatus", err)
		}
		if err := r.Finish(ctx, rev.ID, Status("bogus"), ""); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("Finish(bogus) = %v, want ErrInvalidStatus", err)
		}
		if err := r.Finish(ctx, 9999, StatusApplied, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("Finish(unknown id) = %v, want ErrNotFound", err)
		}
		if got, _ := r.Get(ctx, rev.ID); got.ApplyStatus != StatusPending {
			t.Errorf("rejected Finish left status %q, want pending", got.ApplyStatus)
		}
	})

	t.Run("the database refuses content updates and deletes", func(t *testing.T) {
		r, s := openRepo(t)
		rev, _ := r.Add(ctx, newRev(`{"acls": []}`))
		for _, q := range []string{
			`UPDATE policy_revisions SET raw = '{}' WHERE id = ?`,
			`UPDATE policy_revisions SET raw_hash = 'x' WHERE id = ?`,
			`UPDATE policy_revisions SET actor = 'x' WHERE id = ?`,
			`DELETE FROM policy_revisions WHERE id = ?`,
		} {
			if _, err := s.DB().ExecContext(ctx, q, rev.ID); err == nil {
				t.Errorf("%s succeeded, want an error", q)
			}
		}
		if err := r.Finish(ctx, rev.ID, StatusApplied, ""); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		if _, err := s.DB().ExecContext(ctx, `UPDATE policy_revisions SET apply_status = 'failed' WHERE id = ?`, rev.ID); err == nil {
			t.Error("a finished revision's status was changed by raw SQL, want an error")
		}
		if got, _ := r.Get(ctx, rev.ID); got.Raw != `{"acls": []}` || got.ApplyStatus != StatusApplied {
			t.Errorf("row changed: %+v", got)
		}
	})
}

var mutatingSQL = regexp.MustCompile(`(?is)\b(update\s+(?:main\.)?["` + "`" + `\[]?policy_revisions|delete\s+from\s+(?:main\.)?["` + "`" + `\[]?policy_revisions|replace\s+into\s+(?:main\.)?["` + "`" + `\[]?policy_revisions|insert\s+or\s+replace)`)

// AC4: the only UPDATE the SQL layer has sets apply_status/apply_detail on a pending row; there is
// no DELETE, REPLACE or content UPDATE in the queries or the package code.
func TestPolicyRev_NoMutatingQueries(t *testing.T) {
	var files []string
	for _, pattern := range []string{
		filepath.Join("..", "store", "queries", "policy_revisions.sql"),
		"*.go",
	} {
		m, err := filepath.Glob(pattern)
		if err != nil || len(m) == 0 {
			t.Fatalf("glob %s: %v (%d files)", pattern, err, len(m))
		}
		files = append(files, m...)
	}
	updates := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range strings.Split(stripSQLComments(string(body)), ";") {
			m := mutatingSQL.FindString(stmt)
			if m == "" {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(m), "update") {
				t.Errorf("%s: forbidden statement %q", f, m)
				continue
			}
			updates++
			low := strings.ToLower(stmt)
			set := low[strings.Index(low, "set"):]
			if i := strings.Index(set, "where"); i >= 0 {
				set = set[:i]
			}
			cols := regexp.MustCompile(`(\w+)\s*=`).FindAllStringSubmatch(set, -1)
			for _, c := range cols {
				if c[1] != "apply_status" && c[1] != "apply_detail" {
					t.Errorf("%s: UPDATE sets %s, only apply_status/apply_detail may change", f, c[1])
				}
			}
			if !strings.Contains(low, "apply_status = 'pending'") {
				t.Errorf("%s: UPDATE is not guarded by apply_status = 'pending'", f)
			}
		}
	}
	if updates != 1 {
		t.Errorf("found %d UPDATE statements on policy_revisions, want exactly the Finish transition", updates)
	}
}

func stripSQLComments(s string) string {
	return regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(s, "")
}

// AC5: a live policy that differs from the last applied revision gets one external baseline.
func TestPolicyRev_EnsureBaseline(t *testing.T) {
	ctx := context.Background()
	live := "// edited in Headscale directly\n{\"acls\": []}\n"

	t.Run("empty store gets one baseline", func(t *testing.T) {
		r, _ := openRepo(t)
		rev, added, err := r.EnsureBaseline(ctx, live, "tagcess")
		if err != nil || !added {
			t.Fatalf("EnsureBaseline = %+v, %v, %v; want added", rev, added, err)
		}
		if rev.Source != SourceExternal || rev.ApplyStatus != StatusApplied || rev.Raw != live || rev.RawHash != HashRaw(live) || rev.Actor != "tagcess" {
			t.Errorf("baseline = %+v", rev)
		}
		rev2, added, err := r.EnsureBaseline(ctx, live, "tagcess")
		if err != nil || added || rev2.ID != rev.ID {
			t.Errorf("second EnsureBaseline = %+v, %v, %v; want the same row, not added", rev2, added, err)
		}
		if got, _ := r.List(ctx, 10); len(got) != 1 {
			t.Errorf("revisions = %d, want 1", len(got))
		}
	})

	t.Run("matching live adds nothing", func(t *testing.T) {
		r, _ := openRepo(t)
		rev, _ := r.Add(ctx, newRev(live))
		if err := r.Finish(ctx, rev.ID, StatusApplied, ""); err != nil {
			t.Fatal(err)
		}
		got, added, err := r.EnsureBaseline(ctx, live, "tagcess")
		if err != nil || added || got.ID != rev.ID {
			t.Errorf("EnsureBaseline = %+v, %v, %v; want the applied row, not added", got, added, err)
		}
		if all, _ := r.List(ctx, 10); len(all) != 1 {
			t.Errorf("revisions = %d, want 1", len(all))
		}
	})

	t.Run("drift after an applied revision adds a baseline chained to it", func(t *testing.T) {
		r, _ := openRepo(t)
		first, _ := r.Add(ctx, newRev(`{"acls": []}`))
		_ = r.Finish(ctx, first.ID, StatusApplied, "")
		rev, added, err := r.EnsureBaseline(ctx, live, "tagcess")
		if err != nil || !added {
			t.Fatalf("EnsureBaseline = %+v, %v, %v; want added", rev, added, err)
		}
		if rev.ParentID != first.ID || rev.BaseHash != first.RawHash {
			t.Errorf("baseline parent/base = %d/%q, want %d/%q", rev.ParentID, rev.BaseHash, first.ID, first.RawHash)
		}
	})

	t.Run("a failed or dry-run later revision does not count as live", func(t *testing.T) {
		r, _ := openRepo(t)
		first, _ := r.Add(ctx, newRev(live))
		_ = r.Finish(ctx, first.ID, StatusApplied, "")
		for _, st := range []Status{StatusFailed, StatusDryRun} {
			next, _ := r.Add(ctx, newRev(`{"acls": [], "hosts": {}}`))
			_ = r.Finish(ctx, next.ID, st, "")
		}
		if _, added, err := r.EnsureBaseline(ctx, live, "tagcess"); err != nil || added {
			t.Errorf("EnsureBaseline = added %v, err %v; want no baseline", added, err)
		}
	})

	t.Run("rejects unusable input", func(t *testing.T) {
		r, _ := openRepo(t)
		if _, _, err := r.EnsureBaseline(ctx, `{"acls":`, "tagcess"); !errors.Is(err, ErrInvalidRaw) {
			t.Errorf("EnsureBaseline(broken) = %v, want ErrInvalidRaw", err)
		}
		if _, _, err := r.EnsureBaseline(ctx, live, ""); !errors.Is(err, ErrNoActor) {
			t.Errorf("EnsureBaseline(no actor) = %v, want ErrNoActor", err)
		}
	})
}

// AC6: the history lists newest first within a limit; an unknown id is ErrNotFound.
func TestPolicyRev_ListGet(t *testing.T) {
	ctx := context.Background()
	r, _ := openRepo(t)
	var ids []int64
	for _, raw := range []string{`{"acls": []}`, `{"hosts": {}}`, `{"groups": {}}`} {
		rev, err := r.Add(ctx, newRev(raw))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rev.ID)
	}
	got, err := r.List(ctx, 2)
	if err != nil || len(got) != 2 || got[0].ID != ids[2] || got[1].ID != ids[1] {
		t.Errorf("List(2) = %+v, %v; want ids %d, %d", got, err, ids[2], ids[1])
	}
	all, err := r.List(ctx, 50)
	if err != nil || len(all) != 3 || all[2].ID != ids[0] {
		t.Errorf("List(50) = %d rows, %v; want 3, oldest last", len(all), err)
	}
	if all[1].ParentID != ids[0] || all[0].ParentID != ids[1] || all[2].ParentID != 0 {
		t.Errorf("parent chain = %d,%d,%d", all[0].ParentID, all[1].ParentID, all[2].ParentID)
	}
	for _, limit := range []int{0, -1} {
		if _, err := r.List(ctx, limit); !errors.Is(err, ErrInvalidLimit) {
			t.Errorf("List(%d) = %v, want ErrInvalidLimit", limit, err)
		}
	}
	if _, err := r.Get(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := r.Get(ctx, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(0) = %v, want ErrNotFound", err)
	}
}
