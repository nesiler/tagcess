//go:build integration

// Integration test for F3-013 (AC8): a user without any role has a pre-auth key in a real
// database-mode Headscale (disposable hsstack fixture, no lab Zitadel needed: the Zitadel side is a
// fake); one reconcile expires the key through the admin pipeline. Run with
// `go test -tags=integration -count=1 -run TestReconcile_Integration_RevokesKey ./internal/sync/...`.
package sync

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

func TestReconcile_Integration_RevokesKey(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()

	// Headscale user "gone" (Zitadel 2) has no role left; "kept" (Zitadel 1) still has one.
	h.CreateUser(t, "kept")
	h.CreateUser(t, "gone")
	h.SetProviderID(t, "kept", issuer+"/1")
	h.SetProviderID(t, "gone", issuer+"/2")
	h.PreAuthKey(t, "kept", hsstack.PreAuthKeyOptions{Expiration: time.Hour})
	h.PreAuthKey(t, "gone", hsstack.PreAuthKeyOptions{Expiration: time.Hour})
	h.PreAuthKey(t, "gone", hsstack.PreAuthKeyOptions{Reusable: true, Expiration: time.Hour})

	hs, err := headscale.New(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	ac, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ac.Close() })
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	setDryRun(t, s, false)

	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "baseline"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
	}
	aud := audit.New(s.Queries())
	ex := hsadmin.New(hsadmin.Config{Reader: ac, Audit: aud, Store: s.Queries()})
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel: z, Headscale: hs, Pipeline: change.New(hs, s.Queries(), aud, s), Queries: s.Queries(),
		DryRun: s, Issuer: issuer, Keys: NewKeyRevoker(ex, ac, SystemActor),
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(ctx, "manual")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.KeyErr != nil || len(res.RevokedKeys) != 2 {
		t.Fatalf("revoked = %+v, err = %v, want the two keys of the role-less user", res.RevokedKeys, res.KeyErr)
	}

	keys, err := ac.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var usable, total int
	for _, k := range keys {
		total++
		if usableKey(k, time.Now()) {
			usable++
			if k.UserName != "kept" {
				t.Errorf("key %d of %q is still usable", k.ID, k.UserName)
			}
		}
	}
	if total != 3 || usable != 1 {
		t.Fatalf("keys: total %d usable %d, want 3 and 1 (the kept user's)", total, usable)
	}
	if n := count(t, s, `SELECT count(*) FROM audit_events WHERE actor = ? AND event = 'headscale.preauth.expire' AND result = 'applied'`, SystemActor); n != 2 {
		t.Errorf("applied audit rows = %d, want 2", n)
	}
}
