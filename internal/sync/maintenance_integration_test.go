//go:build integration

// Integration test for F3b-016 (AC6): with the maintenance active, a reconcile after a role loss
// expires the node in a real database-mode Headscale (disposable hsstack fixture, Zitadel is a fake)
// and leaves the policy as it was. Run with
// `go test -tags=integration -count=1 -run TestReconcile_Integration_MaintenanceExpireOnly ./internal/sync/...`.
package sync

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

func TestReconcile_Integration_MaintenanceExpireOnly(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()

	// "kept" (Zitadel 1) and "gone" (Zitadel 2) hold the dev role and sit in group:dev; "gone" owns a node.
	h.CreateUser(t, "kept")
	h.CreateUser(t, "gone")
	h.SetProviderID(t, "kept", issuer+"/1")
	h.SetProviderID(t, "gone", issuer+"/2")
	nodeID := h.NewNode(t, "gone", "laptop", "")
	hs := h.Client()
	seed := `{"acls":[],"groups":{"group:dev":["` + member("1") + `","` + member("2") + `"]}}`
	if _, err := hs.SetPolicy(ctx, seed); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	setDryRun(t, s, false)
	maint := maintenance.New(s.Queries())
	if _, err := maint.Start(ctx, "req-1", "devops"); err != nil {
		t.Fatal(err)
	}

	// User 2 lost the role; user 1 keeps it.
	z := &fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "1", Role: "dev"}},
		states: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
	}
	before, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReconciler(ReconcilerConfig{
		Zitadel: z, Headscale: hs, Queries: s.Queries(), DryRun: s, Issuer: issuer,
		Pipeline:    change.New(hs, s.Queries(), audit.New(s.Queries()), s).WithMaintenance(maint),
		Settings:    Settings{MaxRemovedPercent: 100, MaxRemovedUsers: 10},
		Maintenance: maint,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(ctx, "periodic")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != change.StatusHeld || !res.Change.PolicyHeld {
		t.Fatalf("result = %+v (reason %q), want held", res.Change, res.Plan.Reason)
	}
	if exp := h.NodeExpiry(t, nodeID); exp == nil || exp.After(time.Now()) {
		t.Fatalf("node expiry = %v, want it expired", exp)
	}
	after, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Text != before.Text {
		t.Fatalf("policy changed during maintenance:\nbefore %s\nafter  %s", before.Text, after.Text)
	}
	if st, err := maint.Get(ctx); err != nil || !st.PendingReconcile {
		t.Fatalf("maintenance = %+v, %v, want the pending reconcile marked", st, err)
	}
}
