package sync

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// fakeKeyRevoker is the KeyRevoker the reconcile tests plug in. It counts calls and can fail the
// listing or single keys.
type fakeKeyRevoker struct {
	mu        sync.Mutex
	keys      []admin.PreAuthKey
	listErr   error
	expireErr map[uint64]error
	listed    int
	expired   []uint64
}

func newFakeKeyRevoker(keys ...admin.PreAuthKey) *fakeKeyRevoker {
	return &fakeKeyRevoker{keys: keys, expireErr: map[uint64]error{}}
}

func (f *fakeKeyRevoker) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.keys), nil
}

func (f *fakeKeyRevoker) ExpirePreAuthKey(_ context.Context, k admin.PreAuthKey, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.expireErr[k.ID]; err != nil {
		return err
	}
	f.expired = append(f.expired, k.ID)
	// An expired key is no longer usable: a later listing shows it expired.
	for i := range f.keys {
		if f.keys[i].ID == k.ID {
			past := time.Now().Add(-time.Minute)
			f.keys[i].Expiration = &past
		}
	}
	return nil
}

func (f *fakeKeyRevoker) Expired() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]uint64(nil), f.expired...)
	slices.Sort(out)
	return out
}

func (f *fakeKeyRevoker) Listed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listed
}

func soon() *time.Time { t := time.Now().Add(time.Hour); return &t }
func past() *time.Time { t := time.Now().Add(-time.Hour); return &t }

// keyFixture builds a reconciler with four Headscale users (Zitadel 1..4): 1 and 2 keep the dev
// role, 3 has no grant at all (lost every role), 4 still has a grant but was deactivated.
func keyFixture(t *testing.T, keys ...admin.PreAuthKey) (*Reconciler, *fakeZitadelReader, *fakeHeadscale, *store.Store, *fakeKeyRevoker) {
	t.Helper()
	r, z, hs, s := newTestReconciler(t)
	z.grants = []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"}, {UserID: "4", Role: "dev"}}
	z.states = map[string]zitadel.UserState{
		"1": zitadel.UserActive, "2": zitadel.UserActive, "3": zitadel.UserActive, "4": zitadel.UserInactive,
	}
	hs.policy = `{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `"]}}`
	for i, id := range []string{"1", "2", "3", "4"} {
		hs.users = append(hs.users, headscale.User{ID: uint64(11 + i), ProviderID: issuer + "/" + id})
	}
	kr := newFakeKeyRevoker(keys...)
	r.keys = kr
	return r, z, hs, s, kr
}

// AC1: every usable personal key of a user who lost all roles or whose account closed is expired.
func TestReconcile_RevokesUnusedPersonalKeys(t *testing.T) {
	for _, tt := range []struct {
		name  string
		state zitadel.UserState
		grant bool
	}{
		{"no role left", zitadel.UserActive, false},
		{"deactivated", zitadel.UserInactive, true},
		{"locked", zitadel.UserLocked, true},
		{"removed", zitadel.UserDeleted, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, z, _, _, kr := keyFixture(t,
				admin.PreAuthKey{ID: 1, UserID: 13, Expiration: soon()},
				admin.PreAuthKey{ID: 2, UserID: 13, Reusable: true, Used: true, Expiration: soon()},
			)
			z.states["3"] = tt.state
			if tt.grant {
				z.grants = append(z.grants, zitadel.Grant{UserID: "3", Role: "dev"})
			}

			res, err := r.Run(context.Background(), "periodic")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := kr.Expired(); !reflect.DeepEqual(got, []uint64{1, 2}) {
				t.Fatalf("expired keys = %v, want [1 2]", got)
			}
			if len(res.RevokedKeys) != 2 || res.KeyErr != nil {
				t.Errorf("result keys = %+v err = %v, want 2 revoked and no error", res.RevokedKeys, res.KeyErr)
			}
		})
	}
}

// AC1: the revocation goes through the admin pipeline as system:sync and the audit row names the
// key id, never a secret.
func TestKeyRevoker_AuditsThroughExecutor(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	c := &fakeAdminKeys{keys: []admin.PreAuthKey{{ID: 5, UserID: 13, UserName: "u3", Expiration: soon()}}}
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(s.Queries()), Store: s.Queries()})
	kr := NewKeyRevoker(ex, c, SystemActor)

	keys, err := kr.ListPreAuthKeys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListPreAuthKeys = %v, %v", keys, err)
	}
	if err := kr.ExpirePreAuthKey(ctx, keys[0], "hiç rol kalmadı"); err != nil {
		t.Fatalf("ExpirePreAuthKey: %v", err)
	}
	if got := c.Expired(); !reflect.DeepEqual(got, []uint64{5}) {
		t.Fatalf("expired = %v, want [5]", got)
	}
	rows, err := s.DB().QueryContext(ctx, `SELECT actor, event, target, result, diff FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var results []string
	for rows.Next() {
		var actor, event, target, result, diff string
		if err := rows.Scan(&actor, &event, &target, &result, &diff); err != nil {
			t.Fatal(err)
		}
		if actor != SystemActor || event != "headscale.preauth.expire" || target != "preauth:5" {
			t.Errorf("audit row = %s %s %s, want system:sync headscale.preauth.expire preauth:5", actor, event, target)
		}
		if !strings.Contains(diff, "hiç rol kalmadı") {
			t.Errorf("audit diff %q lacks the reason", diff)
		}
		results = append(results, result)
	}
	if !reflect.DeepEqual(results, []string{"started", "applied"}) {
		t.Errorf("audit results = %v, want [started applied]", results)
	}
}

// fakeAdminKeys is the Headscale admin surface behind the executor: a key list that reflects an
// expiry, so the executor's read-back passes.
type fakeAdminKeys struct {
	mu      sync.Mutex
	keys    []admin.PreAuthKey
	expired []uint64
}

func (f *fakeAdminKeys) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys), nil
}

func (f *fakeAdminKeys) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expired = append(f.expired, id)
	for i := range f.keys {
		if f.keys[i].ID == id {
			p := time.Now().Add(-time.Second)
			f.keys[i].Expiration = &p
		}
	}
	return nil
}

func (f *fakeAdminKeys) ListNodes(context.Context) ([]admin.AdminNode, error) { return nil, nil }
func (f *fakeAdminKeys) ListApiKeys(context.Context) ([]admin.APIKey, error)  { return nil, nil }

func (f *fakeAdminKeys) Expired() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.expired)
}

// AC2: only the usable personal keys of role-less or closed users are touched.
func TestReconcile_KeyRevocationScope(t *testing.T) {
	r, z, hs, _, kr := keyFixture(t,
		admin.PreAuthKey{ID: 1, UserID: 11, Expiration: soon()},                                   // user with a role
		admin.PreAuthKey{ID: 2, UserID: 13, Tags: []string{"tag:vpn-server"}, Expiration: soon()}, // tagged
		admin.PreAuthKey{ID: 3, UserID: 13, Expiration: past()},                                   // already expired
		admin.PreAuthKey{ID: 4, UserID: 13, Used: true, Expiration: soon()},                       // used single-use
		admin.PreAuthKey{ID: 5, UserID: 99, Expiration: soon()},                                   // unknown Headscale user
		admin.PreAuthKey{ID: 6, UserID: 14, Used: true, Expiration: soon()},                       // used single-use, deactivated
		admin.PreAuthKey{ID: 7, UserID: 13, Expiration: soon()},                                   // the one to revoke
		admin.PreAuthKey{ID: 8, UserID: 13},                                                       // never expires: usable
		admin.PreAuthKey{ID: 9, UserID: 16, Expiration: soon()},                                   // user without a known state
	)
	hs.users = append(hs.users,
		headscale.User{ID: 16, ProviderID: issuer + "/6"},     // state not returned by Zitadel
		headscale.User{ID: 17, ProviderID: "https://other/7"}, // foreign issuer
	)
	kr.keys = append(kr.keys, admin.PreAuthKey{ID: 10, UserID: 17, Expiration: soon()})
	_ = z

	if _, err := r.Run(context.Background(), "periodic"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := kr.Expired(); !reflect.DeepEqual(got, []uint64{7, 8}) {
		t.Fatalf("expired keys = %v, want [7 8]", got)
	}
}

// AC3: dry run reports the keys and revokes none.
func TestReconcile_DryRunDoesNotRevokeKeys(t *testing.T) {
	r, _, _, s, kr := keyFixture(t, admin.PreAuthKey{ID: 1, UserID: 13, Expiration: soon()})
	setDryRun(t, s, true)

	res, err := r.Run(context.Background(), "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := kr.Expired(); len(got) != 0 {
		t.Fatalf("dry run expired keys %v", got)
	}
	if len(res.RevokedKeys) != 1 || res.RevokedKeys[0].KeyID != 1 {
		t.Errorf("dry run result keys = %+v, want the key reported", res.RevokedKeys)
	}
	if !slices.ContainsFunc(res.Plan.Warnings, func(w string) bool { return strings.Contains(w, "dry-run") && strings.Contains(w, "key") }) {
		t.Errorf("warnings = %v, want a dry-run key note", res.Plan.Warnings)
	}
}

// AC4: an incomplete or failed read revokes nothing, and does not even list keys.
func TestReconcile_IncompleteReadNoRevocation(t *testing.T) {
	for _, tt := range []struct {
		name string
		mut  func(*fakeZitadelReader, *fakeHeadscale)
	}{
		{"zitadel grants", func(z *fakeZitadelReader, _ *fakeHeadscale) { z.grantsErr = errors.New("boom") }},
		{"zitadel states", func(z *fakeZitadelReader, _ *fakeHeadscale) { z.statesErr = errors.New("boom") }},
		{"headscale", func(_ *fakeZitadelReader, hs *fakeHeadscale) { hs.nodesErr = errors.New("boom") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, z, hs, _, kr := keyFixture(t, admin.PreAuthKey{ID: 1, UserID: 13, Expiration: soon()})
			tt.mut(z, hs)
			if _, err := r.Run(context.Background(), "periodic"); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := kr.Expired(); len(got) != 0 {
				t.Fatalf("a failed read revoked keys %v", got)
			}
			if kr.Listed() != 0 {
				t.Errorf("a failed read still listed keys %d times", kr.Listed())
			}
		})
	}
}

// AC5: a failing key step raises a warning (alert), never stops the group and node steps, and the
// next reconcile retries and clears the alert.
func TestReconcile_KeyRevocationFailureRetried(t *testing.T) {
	for _, tt := range []struct {
		name string
		mut  func(*fakeKeyRevoker)
		heal func(*fakeKeyRevoker)
	}{
		{"list fails",
			func(kr *fakeKeyRevoker) { kr.listErr = errors.New("headscale down") },
			func(kr *fakeKeyRevoker) { kr.listErr = nil }},
		{"expire fails",
			func(kr *fakeKeyRevoker) { kr.expireErr[1] = errors.New("headscale down") },
			func(kr *fakeKeyRevoker) { delete(kr.expireErr, 1) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r, z, hs, s, kr := keyFixture(t,
				admin.PreAuthKey{ID: 1, UserID: 13, Expiration: soon()},
				admin.PreAuthKey{ID: 2, UserID: 13, Expiration: soon()},
			)
			// Group and node work for the same run: user 5 gets the role, user 3's node expires.
			// Enough other members keep the single node expiry under the approval threshold.
			// Users 5-9 are already members; user 10 is the group change.
			members := member("1") + `","` + member("2")
			for _, id := range []string{"5", "6", "7", "8", "9"} {
				z.grants = append(z.grants, zitadel.Grant{UserID: id, Role: "dev"})
				z.states[id] = zitadel.UserActive
				hs.users = append(hs.users, headscale.User{ID: 100 + uint64(id[0]), ProviderID: issuer + "/" + id})
				members += `","` + member(id)
			}
			z.grants = append(z.grants, zitadel.Grant{UserID: "10", Role: "dev"})
			z.states["10"] = zitadel.UserActive
			hs.policy = `{"acls":[],"groups":{"group:dev":["` + members + `"]}}`
			hs.nodes = []headscale.Node{{ID: 100, UserID: 13}}
			tt.mut(kr)

			res, err := r.Run(ctx, "periodic")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.KeyErr == nil {
				t.Fatal("KeyErr = nil, want the key step failure reported")
			}
			if len(hs.SetCalls()) != 1 || !slices.Equal(hs.Expired(), []uint64{100}) {
				t.Fatalf("group/node steps: set=%d expired=%v, want both applied", len(hs.SetCalls()), hs.Expired())
			}
			if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, AlertKeyRevokeFailed); n != 1 {
				t.Fatalf("open %s alerts = %d, want 1", AlertKeyRevokeFailed, n)
			}
			if tt.name == "expire fails" && !slices.Equal(kr.Expired(), []uint64{2}) {
				t.Fatalf("expired = %v, want the healthy key 2 still revoked", kr.Expired())
			}

			tt.heal(kr)
			if _, err := r.Run(ctx, "periodic"); err != nil {
				t.Fatalf("second Run: %v", err)
			}
			if !slices.Equal(kr.Expired(), []uint64{1, 2}) {
				t.Fatalf("after retry expired = %v, want [1 2]", kr.Expired())
			}
			if n := count(t, s, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, AlertKeyRevokeFailed); n != 0 {
				t.Errorf("open %s alerts after retry = %d, want 0", AlertKeyRevokeFailed, n)
			}
		})
	}
}

// AC7: the reconciler sees the key admin client only through KeyRevoker's two operations, so the
// narrow F1 client and its surface test stay as they were.
func TestReconciler_KeyRevokerIsNarrow(t *testing.T) {
	f, ok := reflect.TypeOf(ReconcilerConfig{}).FieldByName("Keys")
	if !ok {
		t.Fatal("ReconcilerConfig has no Keys field")
	}
	if f.Type != reflect.TypeOf((*KeyRevoker)(nil)).Elem() {
		t.Fatalf("Keys type = %v, want KeyRevoker", f.Type)
	}
	var got []string
	for i := 0; i < f.Type.NumMethod(); i++ {
		got = append(got, f.Type.Method(i).Name)
	}
	if want := []string{"ExpirePreAuthKey", "ListPreAuthKeys"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("KeyRevoker methods = %v, want %v", got, want)
	}
	// The reconciler's own reader stays the F1 client's read surface: no key methods leak into it.
	for _, m := range []string{"ListPreAuthKeys", "ExpirePreAuthKey"} {
		if _, ok := reflect.TypeOf((*HeadscaleReader)(nil)).Elem().MethodByName(m); ok {
			t.Errorf("HeadscaleReader exposes %s", m)
		}
	}
	// The wiring type of the real client compiles against the interface through the adapter.
	_ = NewKeyRevoker(nil, (*admin.AdminClient)(nil), SystemActor)
}

// F3b-016 AC2: key revocation narrows access, so it keeps running through the real admin executor
// with the maintenance gate wired while the maintenance is active; the same run holds the policy.
func TestReconcile_MaintenanceRevokesKeys(t *testing.T) {
	ctx := context.Background()
	f := newMaintFixture(t, filepath.Join(t.TempDir(), "tagcess.db"), maintenance.Active)
	f.z.states["3"] = zitadel.UserActive // user 3 holds no role at all
	f.hs.users = append(f.hs.users, headscale.User{ID: 13, ProviderID: issuer + "/3"})
	c := &fakeAdminKeys{keys: []admin.PreAuthKey{
		{ID: 5, UserID: 13, UserName: "u3", Expiration: soon()},
		{ID: 6, UserID: 11, UserName: "u1", Expiration: soon()}, // user 1 keeps the role
	}}
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(f.s.Queries()), Store: f.s.Queries(), Maintenance: f.maint})
	f.r.keys = NewKeyRevoker(ex, c, SystemActor)

	res, err := f.r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.KeyErr != nil || len(res.RevokedKeys) != 1 || res.RevokedKeys[0].KeyID != 5 {
		t.Fatalf("revoked = %+v, err = %v, want key 5 only", res.RevokedKeys, res.KeyErr)
	}
	if got := c.Expired(); !reflect.DeepEqual(got, []uint64{5}) {
		t.Fatalf("expired = %v, want [5]", got)
	}
	if n := count(t, f.s, `SELECT count(*) FROM audit_events WHERE event = 'headscale.preauth.expire' AND result = 'applied'`); n != 1 {
		t.Errorf("applied expire audit rows = %d, want 1", n)
	}
}
