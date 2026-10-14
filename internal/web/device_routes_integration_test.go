//go:build integration

package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// AC9 (F3-015): against a real DB-mode Headscale, a route-advertising node is approved and
// revoked through the UI handler, and Headscale's approved set matches afterwards. The fixture
// node announces routes through the hostinfo SQLite patch (see hsstack.SetNodeRoutableIPs).
func TestRoutes_Integration_ApproveRevoke(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()

	const userName, nodeName = "devops", "route-node"
	h.CreateUser(t, userName)
	id := h.NewNode(t, userName, nodeName, "")
	const subnet = "10.77.0.0/24"
	h.SetNodeRoutableIPs(t, nodeName, []string{subnet})

	adminHS, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	t.Cleanup(func() { _ = adminHS.Close() })
	narrow, err := headscale.New(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("narrow client: %v", err)
	}
	t.Cleanup(func() { _ = narrow.Close() })

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	q := st.Queries()
	exec := hsadmin.New(hsadmin.Config{Reader: adminHS, Audit: audit.New(q), Store: q})

	csrfKey, err := web.LoadOrCreateCSRFKey(filepath.Join(t.TempDir(), "csrf-key"))
	if err != nil {
		t.Fatalf("csrf key: %v", err)
	}
	csrf, err := web.NewCSRF(csrfKey)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	handler, err := web.NewDeviceRoutesHandler(web.DeviceRoutesHandlerConfig{
		Reader:   adminHS,
		Writer:   adminHS,
		Policy:   narrow,
		Executor: exec,
		DryRun:   staticDryRun{},
		CSRF:     csrf,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	chain := web.RequireDevops(csrf.Protect(mux))

	node := func() admin.AdminNode {
		t.Helper()
		nodes, err := adminHS.ListNodes(ctx)
		if err != nil {
			t.Fatalf("ListNodes: %v", err)
		}
		i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == id })
		if i < 0 {
			t.Fatalf("node %d not found", id)
		}
		return nodes[i]
	}

	first := node()
	if !slices.Contains(first.AvailableRoutes, subnet) {
		t.Fatalf("fixture node advertises %v, want %q", first.AvailableRoutes, subnet)
	}

	post := func(t *testing.T, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost,
			"/headscale/devices/"+strconv.FormatUint(id, 10)+"/routes", strings.NewReader(form.Encode()))
		req.Header.Set("X-Auth-Request-User", "devops-user")
		req.Header.Set("X-Auth-Request-Email", "devops@example.com")
		req.Header.Set("X-Auth-Request-Groups", "devops")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrf.Token())
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}

	// Approve the advertised route.
	rec := post(t, url.Values{"version": {hsadmin.NodeVersion(first)}, "route": {subnet}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	approved := node().ApprovedRoutes
	if !slices.Equal(approved, []string{subnet}) {
		t.Errorf("approved in Headscale = %v, want [%s]", approved, subnet)
	}

	// Revoke everything.
	rec = post(t, url.Values{"version": {hsadmin.NodeVersion(node())}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if got := node().ApprovedRoutes; len(got) != 0 {
		t.Errorf("approved after revoke = %v, want empty", got)
	}

	// The audit trail recorded the two operations.
	events, err := audit.New(q).List(ctx, audit.Filter{Event: "headscale.node.routes", Limit: 10})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("audit events = %d, want 4 (started+applied twice)", len(events))
	}
}

type staticDryRun struct{}

func (staticDryRun) DryRun(context.Context) (bool, error) { return false, nil }
