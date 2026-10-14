//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// TestReopen_Integration_HeadscaleExpiry (F3-021 AC9) reopens an expired personal node against the
// real Headscale v0.29.4 in the disposable hsstack fixture and shows the expiry moved to the
// chosen future instant. There is no Zitadel in the fixture: the eligibility check is a stub, the
// Headscale side is real.
func TestReopen_Integration_HeadscaleExpiry(t *testing.T) {
	ctx := context.Background()
	h := hsstack.Start(t)
	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Queries().UpsertSetting(ctx, db.UpsertSettingParams{
		Key: hsadmin.ProtectedTagsKey, Value: `["tag:server"]`, UpdatedAt: "2026-10-01T00:00:00.000Z",
	}); err != nil {
		t.Fatal(err)
	}
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(st.Queries()), Store: st.Queries()})

	h.CreateUser(t, "carol")
	laptop := h.NewNode(t, "carol", "laptop", "")
	// Expire the node so the reopen has an expired personal device to work on.
	if _, err := c.ExpireNode(ctx, laptop, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("ExpireNode: %v", err)
	}
	if exp := h.NodeExpiry(t, laptop); exp == nil || !exp.Before(time.Now()) {
		t.Fatalf("precondition: expiry = %v, want past", exp)
	}

	elig := func(context.Context, headscale.User) (vpnuser.Eligibility, error) {
		return vpnuser.Eligibility{UserID: "u-carol", State: 1, Roles: []string{"vpn-user"}}, nil
	}
	svc, err := NewDeviceReopenService(c, h.Client(), elig, ex, reopenTriggerStub{})
	if err != nil {
		t.Fatal(err)
	}
	csrf := testCSRF(t)
	handler, err := NewDeviceReopenHandler(svc, csrf)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	chain := RequireDevops(csrf.Protect(mux))

	// The guarded apply: version from a fresh read, future expiry, explicit confirm.
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var node admin.AdminNode
	for _, n := range nodes {
		if n.ID == laptop {
			node = n
		}
	}
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Minute)
	fields := url.Values{
		"expected":       {hsadmin.NodeVersion(node)},
		"current_expiry": {node.Expiry.UTC().Format(time.RFC3339)},
		"expiry":         {future.Format("2006-01-02T15:04")},
		"confirm":        {"evet"},
		"current_name":   {node.GivenName},
	}
	fields.Set(CSRFParam, csrf.Token())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/headscale/devices/"+uintText(laptop)+"/reopen/apply",
		strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reopen = %d:\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Apply edildi") {
		t.Fatalf("result screen lacks the applied status:\n%s", rec.Body.String())
	}
	exp := h.NodeExpiry(t, laptop)
	if exp == nil || exp.Sub(future).Abs() > time.Minute {
		t.Fatalf("Headscale expiry = %v, want ~%s", exp, future)
	}
}

type reopenTriggerStub struct{}

func (reopenTriggerStub) RequestManual() {}
