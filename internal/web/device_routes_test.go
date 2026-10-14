package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// mustQueries opens a throwaway store; the F3 handler tests run the real executor and audit
// logger over it.
func mustQueries(t *testing.T) *db.Queries {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.Queries()
}

// Harness of the device routes screen (F3-015, H-01): GET /headscale/devices/{id}/routes renders
// the advertised/approved/active sets with the approval checkboxes, POST applies the desired full
// set through the real F3-009 executor over a fake admin client. The fake mutates its node like
// Headscale would, so the executor's read-back verification runs for real.

// routesCall is one SetApprovedRoutes call the fake recorded.
type routesCall struct {
	id     uint64
	routes []string
}

// fakeRoutesAdmin is the fake admin surface: the hsadmin.Reader view plus SetApprovedRoutes.
type fakeRoutesAdmin struct {
	mu          sync.Mutex
	nodes       []admin.AdminNode
	preAuthKeys []admin.PreAuthKey
	apiKeys     []admin.APIKey
	listErr     error
	setErr      error
	calls       []routesCall
	expireCalls []uint64
	deleteCalls []uint64
}

func (f *fakeRoutesAdmin) ListNodes(context.Context) ([]admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.nodes), f.listErr
}

func (f *fakeRoutesAdmin) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.preAuthKeys), nil
}

func (f *fakeRoutesAdmin) ListApiKeys(context.Context) ([]admin.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.apiKeys), f.listErr
}

// SetApprovedRoutes records the call and applies it to the stored node, like Headscale's full-set
// replace would.
func (f *fakeRoutesAdmin) SetApprovedRoutes(_ context.Context, id uint64, routes []string) (admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, routesCall{id: id, routes: slices.Clone(routes)})
	if f.setErr != nil {
		return admin.AdminNode{}, f.setErr
	}
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes[i].ApprovedRoutes = slices.Clone(routes)
			return f.nodes[i], nil
		}
	}
	return admin.AdminNode{}, errors.New("headscale/admin: node not found")
}

// node returns a copy of the stored node with the given id.
func (f *fakeRoutesAdmin) node(id uint64) admin.AdminNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.ID == id {
			return n
		}
	}
	return admin.AdminNode{}
}

// mutate changes a stored node in place, simulating another actor's write between render and post.
func (f *fakeRoutesAdmin) mutate(id uint64, fn func(*admin.AdminNode)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			fn(&f.nodes[i])
		}
	}
}

// apiKeyCopy returns a copy of the stored API key with the given id.
func (f *fakeRoutesAdmin) apiKeyCopy(id uint64) admin.APIKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.apiKeys {
		if k.ID == id {
			return k
		}
	}
	return admin.APIKey{}
}

// setListErr makes every list read fail (fail-safe tests).
func (f *fakeRoutesAdmin) setListErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listErr = err
}

// fakePolicyReader is a fixed policy read for the autoApprovers display.
type fakePolicyReader struct {
	text string
	err  error
}

func (f *fakePolicyReader) GetPolicy(context.Context) (headscale.Policy, error) {
	if f.err != nil {
		return headscale.Policy{}, f.err
	}
	return headscale.Policy{Text: f.text}, nil
}

type routesHarness struct {
	hs      *fakeRoutesAdmin
	pol     *fakePolicyReader
	dry     *fakeDryRunReader
	csrf    *CSRF
	exec    *hsadmin.Executor
	auditor *audit.Logger
	chain   http.Handler
}

func newRoutesHarness(t *testing.T, nodes []admin.AdminNode, policyText string, policyErr error) *routesHarness {
	t.Helper()
	q := mustQueries(t)
	h := &routesHarness{
		hs:      &fakeRoutesAdmin{nodes: nodes},
		pol:     &fakePolicyReader{text: policyText, err: policyErr},
		dry:     &fakeDryRunReader{},
		csrf:    testCSRF(t),
		auditor: audit.New(q),
	}
	exec := hsadmin.New(hsadmin.Config{Reader: h.hs, Audit: h.auditor, Store: q})
	h.exec = exec
	handler, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{
		Reader:   h.hs,
		Writer:   h.hs,
		Policy:   h.pol,
		Executor: exec,
		DryRun:   h.dry,
		CSRF:     h.csrf,
	})
	if err != nil {
		t.Fatalf("NewDeviceRoutesHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *routesHarness) get(t *testing.T, target, groups string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, strings.NewReader(""))
	if groups != "" {
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, "devops@example.com")
		req.Header.Set(headerGroups, groups)
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// postForm sends a form post as a devops actor with the CSRF header.
func (h *routesHarness) postForm(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", h.csrf.Token())
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// routesEvents lists the route audit events, newest first.
func (h *routesHarness) routesEvents(t *testing.T) []audit.Event {
	t.Helper()
	events, err := h.auditor.List(context.Background(), audit.Filter{Event: "headscale.node.routes", Limit: 20})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

// routeNode is the standard fixture: two advertised subnet routes, one approved and active.
func routeNode(id uint64) admin.AdminNode {
	return admin.AdminNode{
		ID: id, GivenName: "srv-routes", UserName: "alice",
		IPs: []string{"100.64.0.30"}, CreatedAt: deviceMade,
		AvailableRoutes: []string{"10.0.0.0/24", "10.0.1.0/24"},
		ApprovedRoutes:  []string{"10.0.0.0/24"},
		SubnetRoutes:    []string{"10.0.0.0/24"},
	}
}

// versionOfNode is the Expected version the page would have rendered for the node's current state.
func versionOfNode(t *testing.T, h *routesHarness, id uint64) string {
	t.Helper()
	return hsadmin.NodeVersion(h.hs.node(id))
}

// AC1: approving an advertised route sends the full approved set (the current approvals plus the
// new route) to SetApprovedRoutes and the read-back confirms it; the page then shows the new set.
func TestRoutes_ApproveAddsToFullSet(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(7)}, "", nil)

	page := h.get(t, "/headscale/devices/7/routes", "devops")
	if page.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", page.Code)
	}
	if body := page.Body.String(); !strings.Contains(body, `name="version"`) {
		t.Fatalf("page lacks the version field:\n%s", body)
	}

	form := url.Values{"version": {versionOfNode(t, h, 7)}, "route": {"10.0.0.0/24", "10.0.1.0/24"}}
	rec := h.postForm(t, "/headscale/devices/7/routes", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/headscale/devices/7/routes" {
		t.Errorf("Location = %q, want /headscale/devices/7/routes", loc)
	}
	if len(h.hs.calls) != 1 {
		t.Fatalf("SetApprovedRoutes calls = %d, want 1", len(h.hs.calls))
	}
	call := h.hs.calls[0]
	if call.id != 7 {
		t.Errorf("call id = %d, want 7", call.id)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24"}
	slices.Sort(call.routes)
	if !slices.Equal(call.routes, want) {
		t.Errorf("routes = %v, want the full set %v", call.routes, want)
	}

	after := h.get(t, "/headscale/devices/7/routes", "devops")
	if got := "10.0.0.0/24, 10.0.1.0/24"; !strings.Contains(after.Body.String(), got) {
		t.Errorf("approved set after approval lacks %q:\n%s", got, after.Body.String())
	}
}

// AC2: revoking sends the full set without the revoked route; revoking the last one sends the
// empty set.
func TestRoutes_RevokeAndRevokeAll(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(8)}, "", nil)

	// Keep only the first route.
	form := url.Values{"version": {versionOfNode(t, h, 8)}, "route": {"10.0.0.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/8/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if len(h.hs.calls) != 1 || !slices.Equal(h.hs.calls[0].routes, []string{"10.0.0.0/24"}) {
		t.Fatalf("calls = %+v, want one call with [10.0.0.0/24]", h.hs.calls)
	}

	// Revoke the rest: an empty set is a legal full-set write.
	form = url.Values{"version": {versionOfNode(t, h, 8)}}
	if rec := h.postForm(t, "/headscale/devices/8/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke-all post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if len(h.hs.calls) != 2 {
		t.Fatalf("calls = %d, want 2 (the second RPC must have run)", len(h.hs.calls))
	}
	if len(h.hs.calls[1].routes) != 0 {
		t.Errorf("revoke-all routes = %v, want the empty set", h.hs.calls[1].routes)
	}
}

// AC3: the exit node is one row; approving it sends the IPv4 and IPv6 /0 pair together and the
// read-back confirms both.
func TestRoutes_ExitNodePair(t *testing.T) {
	node := routeNode(9)
	node.AvailableRoutes = []string{"10.9.0.0/16", "0.0.0.0/0"}
	node.ApprovedRoutes = nil
	node.SubnetRoutes = nil
	h := newRoutesHarness(t, []admin.AdminNode{node}, "", nil)

	page := h.get(t, "/headscale/devices/9/routes", "devops")
	if page.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", page.Code)
	}
	if body := page.Body.String(); !strings.Contains(body, "exit node") {
		t.Fatalf("page lacks the exit node row:\n%s", body)
	}

	form := url.Values{"version": {versionOfNode(t, h, 9)}, "route": {"10.9.0.0/16", "exit"}}
	rec := h.postForm(t, "/headscale/devices/9/routes", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if len(h.hs.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(h.hs.calls))
	}
	got := slices.Clone(h.hs.calls[0].routes)
	slices.Sort(got)
	want := []string{"0.0.0.0/0", "10.9.0.0/16", "::/0"}
	if !slices.Equal(got, want) {
		t.Errorf("routes = %v, want the /0 pair with the subnet route %v", got, want)
	}
	if h.hs.node(9).ApprovedRoutes == nil || len(h.hs.node(9).ApprovedRoutes) != 3 {
		t.Errorf("stored approvals = %v, want the pair applied", h.hs.node(9).ApprovedRoutes)
	}
}

// AC4: a route the node does not advertise is refused without an RPC; so is an exit request from
// a node that advertises no /0.
func TestRoutes_UnadvertisedRejected(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(10)}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 10)}, "route": {"192.168.5.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/10/routes", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("unadvertised post = %d, want 400", rec.Code)
	}
	if len(h.hs.calls) != 0 {
		t.Errorf("calls = %d, want 0 (no RPC)", len(h.hs.calls))
	}

	node := routeNode(10)
	node.AvailableRoutes = []string{"10.0.0.0/24"}
	h2 := newRoutesHarness(t, []admin.AdminNode{node}, "", nil)
	form = url.Values{"version": {versionOfNode(t, h2, 10)}, "route": {"exit"}}
	if rec := h2.postForm(t, "/headscale/devices/10/routes", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("exit post on non-exit node = %d, want 400", rec.Code)
	}
	if len(h2.hs.calls) != 0 {
		t.Errorf("calls = %d, want 0 (no RPC)", len(h2.hs.calls))
	}
}

// A non-canonical prefix never matches an advertised route (Headscale keeps canonical forms), so
// it is refused without an RPC.
func TestRoutes_NonCanonicalPrefixRejected(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(12)}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 12)}, "route": {"10.0.0.5/24"}}
	if rec := h.postForm(t, "/headscale/devices/12/routes", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical post = %d, want 400", rec.Code)
	}
	if len(h.hs.calls) != 0 {
		t.Errorf("calls = %d, want 0 (no RPC)", len(h.hs.calls))
	}
}

// An approval Headscale still holds for a route the node no longer advertises has no checkbox; a
// change to another route must keep it, not revoke it silently.
func TestRoutes_KeepsApprovedButUnadvertised(t *testing.T) {
	node := routeNode(13)
	node.AvailableRoutes = []string{"10.0.0.0/24", "10.0.1.0/24"}
	node.ApprovedRoutes = []string{"10.0.0.0/24", "172.16.0.0/16"}
	h := newRoutesHarness(t, []admin.AdminNode{node}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 13)}, "route": {"10.0.0.0/24", "10.0.1.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/13/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if len(h.hs.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(h.hs.calls))
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "172.16.0.0/16"}
	got := slices.Clone(h.hs.calls[0].routes)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("routes = %v, want the unadvertised approval kept: %v", got, want)
	}
}

// A lone approved /0 on a node that stopped advertising exit is kept as well.
func TestRoutes_KeepsApprovedExitWhenNotAdvertised(t *testing.T) {
	node := routeNode(14)
	node.AvailableRoutes = []string{"10.0.0.0/24", "10.0.1.0/24"}
	node.ApprovedRoutes = []string{"0.0.0.0/0", "::/0"}
	h := newRoutesHarness(t, []admin.AdminNode{node}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 14)}, "route": {"10.0.0.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/14/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	got := slices.Clone(h.hs.calls[0].routes)
	slices.Sort(got)
	if want := []string{"0.0.0.0/0", "10.0.0.0/24", "::/0"}; !slices.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
}

// AC5: a form posted after the node changed is a 409 and nothing is applied.
func TestRoutes_StaleDiffRejected(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(11)}, "", nil)
	stale := versionOfNode(t, h, 11)

	// Another actor writes the node after the page was rendered (expiry changes the version).
	newExpiry := time.Date(2099, 6, 1, 0, 0, 0, 0, time.UTC)
	h.hs.mutate(11, func(n *admin.AdminNode) {
		n.Expiry = &newExpiry
		n.ApprovedRoutes = []string{"10.0.0.0/24", "10.0.1.0/24"}
	})

	form := url.Values{"version": {stale}, "route": {"10.0.0.0/24", "10.0.1.0/24"}}
	rec := h.postForm(t, "/headscale/devices/11/routes", form)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale post = %d, want 409", rec.Code)
	}
	if len(h.hs.calls) != 0 {
		t.Errorf("calls = %d, want 0 (stale diff must not be applied)", len(h.hs.calls))
	}
	if got := h.hs.node(11).ApprovedRoutes; !slices.Equal(got, []string{"10.0.0.0/24", "10.0.1.0/24"}) {
		t.Errorf("approvals = %v, want the other actor's set untouched", got)
	}
}

// AC6: the page shows the advertised, approved and active sets separately, carries the
// "approval is not access" note, and shows the autoApprovers match from policy; an unreadable
// policy shows a warning instead of blocking the page.
func TestRoutes_ShowsAdvertisedApprovedActiveAndAutoApprovers(t *testing.T) {
	const policy = `{
		"autoApprovers": {
			"routes": {"10.0.0.0/24": ["tag:server"]},
			"exitNode": ["tag:server"]
		}
	}`
	node := routeNode(6)
	node.AvailableRoutes = []string{"10.0.0.0/24", "10.0.1.0/24", "0.0.0.0/0"}
	h := newRoutesHarness(t, []admin.AdminNode{node}, policy, nil)

	page := h.get(t, "/headscale/devices/6/routes", "devops")
	if page.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		"İlan edilen", "Onaylı", "Aktif",
		"erişim garantisi değildir",
		"exit node", "0.0.0.0/0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The approver identity appears exactly twice: the matching subnet row and the exit row.
	if n := strings.Count(body, "tag:server"); n != 2 {
		t.Errorf("autoApprovers match shown %d times, want 2:\n%s", n, body)
	}

	h2 := newRoutesHarness(t, []admin.AdminNode{node}, "", errors.New("headscale: GetPolicy: down"))
	page = h2.get(t, "/headscale/devices/6/routes", "devops")
	if page.Code != http.StatusOK {
		t.Fatalf("page with unreadable policy = %d, want 200", page.Code)
	}
	if body := page.Body.String(); !strings.Contains(body, "autoApprovers") || !strings.Contains(body, "okunamadı") {
		t.Errorf("page lacks the policy warning:\n%s", body)
	}
}

// AC7: route approval on a server-tagged node is free: the protected-tag rule does not block it.
func TestRoutes_ServerNodeAllowed(t *testing.T) {
	node := routeNode(12)
	node.Tags = []string{"tag:vpn-server"}
	h := newRoutesHarness(t, []admin.AdminNode{node}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 12)}, "route": {"10.0.0.0/24", "10.0.1.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/12/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303 (server node must not be blocked)", rec.Code, rec.Body.String())
	}
	if len(h.hs.calls) != 1 {
		t.Errorf("calls = %d, want 1", len(h.hs.calls))
	}
}

// AC8: the audit trail holds the node id, the approved set before/after and the active primary
// set separately, with the result.
func TestRoutes_AuditBeforeAfter(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(13)}, "", nil)

	form := url.Values{"version": {versionOfNode(t, h, 13)}, "route": {"10.0.0.0/24", "10.0.1.0/24"}}
	if rec := h.postForm(t, "/headscale/devices/13/routes", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("post = %d (%s), want 303", rec.Code, rec.Body.String())
	}

	events := h.routesEvents(t)
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want 2 (started + applied)", len(events))
	}
	results := []string{events[0].Result, events[1].Result}
	if !slices.Equal(results, []string{string(hsadmin.StatusApplied), string(hsadmin.StatusStarted)}) {
		t.Errorf("results = %v, want [applied started] (newest first)", results)
	}
	for _, e := range events {
		if e.Actor != "devops@example.com" {
			t.Errorf("actor = %q, want devops@example.com", e.Actor)
		}
		if e.Target != "node:13" {
			t.Errorf("target = %q, want node:13", e.Target)
		}
	}
	applied := events[0]
	var approved, active bool
	for _, c := range applied.Diff {
		switch c.Field {
		case "approved_routes":
			approved = true
			if !strings.Contains(c.Before, "10.0.0.0/24") || strings.Contains(c.Before, "10.0.1.0/24") {
				t.Errorf("approved before = %q, want the old set only", c.Before)
			}
			if !strings.Contains(c.After, "10.0.0.0/24") || !strings.Contains(c.After, "10.0.1.0/24") {
				t.Errorf("approved after = %q, want the full new set", c.After)
			}
		case "active_routes":
			active = true
			if !strings.Contains(c.After, "10.0.0.0/24") {
				t.Errorf("active set = %q, want the active primary route", c.After)
			}
		}
	}
	if !approved || !active {
		t.Errorf("diff lacks fields (approved_routes=%v, active_routes=%v): %+v", approved, active, applied.Diff)
	}
}

// The routes screen sits behind the devops middleware and CSRF: no identity or a foreign group is
// 403, a post without the token is 403, and unknown ids are 404.
func TestRoutes_GuardRails(t *testing.T) {
	h := newRoutesHarness(t, []admin.AdminNode{routeNode(14)}, "", nil)

	if rec := h.get(t, "/headscale/devices/14/routes", ""); rec.Code != http.StatusForbidden {
		t.Errorf("no identity = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/headscale/devices/14/routes", "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/headscale/devices/99/routes", "devops"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	form := url.Values{"version": {versionOfNode(t, h, 14)}, "route": {"10.0.0.0/24"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/headscale/devices/14/routes", strings.NewReader(form.Encode()))
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("post without CSRF token = %d, want 403", rec.Code)
	}

	// A malformed version cannot come from this page; refuse it before any read-back decision.
	h2 := newRoutesHarness(t, []admin.AdminNode{routeNode(14)}, "", nil)
	if rec := h2.postForm(t, "/headscale/devices/14/routes", url.Values{"route": {"10.0.0.0/24"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("post without version = %d, want 400", rec.Code)
	}
}

// NewDeviceRoutesHandler refuses an incomplete wiring.
func TestRoutesWiring(t *testing.T) {
	hs := &fakeRoutesAdmin{}
	exec := hsadmin.New(hsadmin.Config{Reader: hs, Audit: audit.New(mustQueries(t)), Store: mustQueries(t)})
	if _, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{}); err == nil {
		t.Error("accepted an empty config")
	}
	if _, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{Writer: hs, Executor: exec, DryRun: &fakeDryRunReader{}, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing reader")
	}
	if _, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{Reader: hs, Executor: exec, DryRun: &fakeDryRunReader{}, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing writer")
	}
	if _, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{Reader: hs, Writer: hs, DryRun: &fakeDryRunReader{}, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing executor")
	}
	if _, err := NewDeviceRoutesHandler(DeviceRoutesHandlerConfig{Reader: hs, Writer: hs, Executor: exec, DryRun: &fakeDryRunReader{}}); err == nil {
		t.Error("accepted a missing CSRF signer")
	}
}
