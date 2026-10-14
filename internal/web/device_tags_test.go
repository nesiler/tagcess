package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
)

// Harness of the device tag screens (F3-016, H-01/H-05): /headscale/devices/{id}/tags changes a
// tagged node's tag set, and turns a personal device into a tagged one in two steps. The tests
// drive the production handler with the real hsadmin.Executor over a fake Headscale that behaves
// like SetTags does on v0.29.4 (replaces the set, moves the node to the tagged-devices user, leaves
// the expiry alone).

const tagsTestPolicy = `{
  // tags a device may carry
  "tagOwners": {
    "tag:web": ["group:devops"],
    "tag:db": ["group:devops"],
    "tag:k8s": ["group:devops"],
    "tag:vpn-server": ["group:devops"],
  },
}`

// taggedDevicesUserID is the id of Headscale's built-in tagged-devices user, observed in the integration test.
const taggedDevicesUserID = 2147455555

var tagsTestExpiry = time.Date(2099, 3, 4, 5, 6, 0, 0, time.UTC)

// fakeTagHS is the Headscale side: node list, policy, and the one write the tag screens use.
type fakeTagHS struct {
	mu        sync.Mutex
	nodes     []admin.AdminNode
	listErr   error
	policy    string
	policyErr error
	setCalls  [][]string
	setErr    error
}

func (f *fakeTagHS) ListNodes(context.Context) ([]admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.nodes), nil
}

func (f *fakeTagHS) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) { return nil, nil }
func (f *fakeTagHS) ListApiKeys(context.Context) ([]admin.APIKey, error)         { return nil, nil }

func (f *fakeTagHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return headscale.Policy{Text: f.policy}, f.policyErr
}

func (f *fakeTagHS) SetTags(_ context.Context, id uint64, tags []string) (admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls = append(f.setCalls, slices.Clone(tags))
	if f.setErr != nil {
		return admin.AdminNode{}, f.setErr
	}
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes[i].Tags = slices.Clone(tags)
			// Observed on Headscale v0.29.4 (F3-016 integration test): the node moves to the
			// built-in "tagged-devices" user; the expiry is left alone.
			f.nodes[i].UserID, f.nodes[i].UserName = taggedDevicesUserID, "tagged-devices"
			return f.nodes[i], nil
		}
	}
	return admin.AdminNode{}, errors.New("no such node")
}

func (f *fakeTagHS) rpcs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.setCalls)
}

func (f *fakeTagHS) node(id uint64) admin.AdminNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.ID == id {
			return n
		}
	}
	return admin.AdminNode{}
}

func (f *fakeTagHS) mutate(id uint64, fn func(*admin.AdminNode)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			fn(&f.nodes[i])
		}
	}
}

type tagsHarness struct {
	hs    *fakeTagHS
	audit *audit.Logger
	csrf  *CSRF
	chain http.Handler
}

// Node ids of the fixture: 1 personal, 2 tagged (tag:web), 3 protected server, 4 personal.
func newTagsHarness(t *testing.T) *tagsHarness {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hs := &fakeTagHS{
		policy: tagsTestPolicy,
		nodes: []admin.AdminNode{
			{ID: 1, GivenName: "alice-laptop", UserID: 10, UserName: "alice", Expiry: &tagsTestExpiry},
			{ID: 2, GivenName: "build-box", UserID: 11, UserName: "ops", Tags: []string{"tag:web"}},
			{ID: 3, GivenName: "gw", UserID: 11, UserName: "ops", Tags: []string{"tag:vpn-server"}},
			{ID: 4, GivenName: "bob-phone", UserID: 12, UserName: "bob"},
		},
	}
	auditor := audit.New(s.Queries())
	ex := hsadmin.New(hsadmin.Config{
		Reader: hs, Audit: auditor, Store: s.Queries(),
		Log: slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
	})
	h := &tagsHarness{hs: hs, audit: auditor, csrf: testCSRF(t)}
	handler, err := NewDeviceTagsHandler(DeviceTagsConfig{
		Nodes: hs, Policy: hs, Setter: hs, Executor: ex, DryRun: &fakeDryRunReader{}, CSRF: h.csrf,
	})
	if err != nil {
		t.Fatalf("NewDeviceTagsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *tagsHarness) do(method, target string, form url.Values, groups string) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		form.Set(CSRFParam, h.csrf.Token())
		body = form.Encode()
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if groups != "" {
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, "devops@example.com")
		req.Header.Set(headerGroups, groups)
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *tagsHarness) get(id uint64) *httptest.ResponseRecorder {
	return h.do(http.MethodGet, tagsURL(id), nil, "devops")
}

func (h *tagsHarness) post(id uint64, form url.Values) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, tagsURL(id), form, "devops")
}

func tagsURL(id uint64) string { return "/headscale/devices/" + strconv.FormatUint(id, 10) + "/tags" }

// form builds the POST body of a node as the page would have rendered it: the node's current
// version plus the chosen tags.
func (h *tagsHarness) form(id uint64, tags ...string) url.Values {
	v := url.Values{}
	v.Set("version", hsadmin.NodeVersion(h.hs.node(id)))
	for _, tag := range tags {
		v.Add("tag", tag)
	}
	return v
}

func (h *tagsHarness) events(t *testing.T) []audit.Event {
	t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(evs) // oldest first
	return evs
}

func diffField(d audit.Diff, field string) (audit.Change, bool) {
	for _, c := range d {
		if c.Field == field {
			return c, true
		}
	}
	return audit.Change{}, false
}

// AC1: the options are the policy's tagOwners keys (minus protected server tags), nothing else;
// the tags the node carries are pre-checked, and there is no way to type a tag.
func TestTags_OffersPolicyTags(t *testing.T) {
	h := newTagsHarness(t)
	rec := h.get(2)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`value="tag:web"`, `value="tag:db"`, "kişisel cihaza dönüş yok"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	for _, not := range []string{`value="tag:k8s"`, `value="tag:vpn-server"`, `type="text"`} {
		if strings.Contains(body, not) {
			t.Errorf("page contains %q", not)
		}
	}
	if !strings.Contains(body, `value="tag:web" checked`) {
		t.Errorf("current tag tag:web is not pre-checked:\n%s", body)
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, a page view must not write", h.hs.rpcs())
	}
}

// AC2: a tagged node's set changes through SetTags with the full new set, verified by read-back.
func TestTags_ChangeTaggedNode(t *testing.T) {
	h := newTagsHarness(t)
	rec := h.post(2, h.form(2, "tag:web", "tag:db"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if len(h.hs.setCalls) != 1 || !slices.Equal(h.hs.setCalls[0], []string{"tag:db", "tag:web"}) {
		t.Fatalf("SetTags calls = %v, want one call with the full sorted set", h.hs.setCalls)
	}
	if got := h.hs.node(2).Tags; !slices.Equal(got, []string{"tag:db", "tag:web"}) {
		t.Errorf("node tags = %v", got)
	}
	evs := h.events(t)
	if len(evs) != 2 || evs[1].Result != "applied" || evs[1].Event != "headscale.node.tags" {
		t.Errorf("audit = %+v, want started + applied headscale.node.tags", evs)
	}
	if evs[0].Actor != "devops@example.com" {
		t.Errorf("actor = %q", evs[0].Actor)
	}

	t.Run("duplicates collapse", func(t *testing.T) {
		h := newTagsHarness(t)
		if rec := h.post(2, h.form(2, "tag:db", "tag:db")); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if !slices.Equal(h.hs.setCalls[0], []string{"tag:db"}) {
			t.Errorf("SetTags = %v, want [tag:db]", h.hs.setCalls[0])
		}
	})
}

// AC3: an empty set is refused without an RPC and the reason is on the page.
func TestTags_EmptyRejected(t *testing.T) {
	h := newTagsHarness(t)
	for _, id := range []uint64{1, 2} {
		rec := h.post(id, h.form(id))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("node %d: status = %d, want 400", id, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "kişisel cihaza dönüş yok") {
			t.Errorf("node %d: reason missing: %s", id, rec.Body)
		}
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, want 0", h.hs.rpcs())
	}
}

// AC4b: a protected server tag is neither offered nor assignable, not even in the personal →
// tagged conversion's last step.
func TestTags_ProtectedTagCannotBeAssigned(t *testing.T) {
	h := newTagsHarness(t)
	for _, id := range []uint64{1, 2} {
		if body := h.get(id).Body.String(); strings.Contains(body, "tag:k8s") || strings.Contains(body, "tag:vpn-server") {
			t.Errorf("node %d page offers a protected tag", id)
		}
		for _, tag := range []string{"tag:k8s", "tag:vpn-server"} {
			f := h.form(id, tag)
			f.Set("step", "convert")
			f.Set("confirm_name", h.hs.node(id).GivenName)
			f.Set("confirm", "on")
			if rec := h.post(id, f); rec.Code != http.StatusForbidden {
				t.Errorf("node %d %s: status = %d, want 403", id, tag, rec.Code)
			}
		}
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, want 0", h.hs.rpcs())
	}
}

// AC4: a tag the policy does not know, or with a bad shape, is refused without an RPC.
func TestTags_UnknownTagRejected(t *testing.T) {
	h := newTagsHarness(t)
	for _, tag := range []string{"tag:nope", "tag:WEB", "tag:", "web", "tag:-x", "tag:a b", "tag:" + strings.Repeat("a", 64), "group:devops"} {
		if rec := h.post(2, h.form(2, "tag:web", tag)); rec.Code != http.StatusBadRequest {
			t.Errorf("tag %q: status = %d, want 400", tag, rec.Code)
		}
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, want 0", h.hs.rpcs())
	}
}

// AC5: personal → tagged needs the warning page, then the device name and the checkbox; a single
// POST, a wrong name or a missing box never converts.
func TestTags_PersonalToTaggedNeedsExtraApproval(t *testing.T) {
	h := newTagsHarness(t)

	// Step 1: the warning page.
	rec := h.get(1)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rec.Code)
	}
	for _, want := range []string{"geri alınamaz", "rol kaybında expire edilmez", "ownership", "expire"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("warning page lacks %q", want)
		}
	}

	// A direct one-step POST (even with the name and box) only shows step 2.
	f := h.form(1, "tag:web")
	f.Set("confirm_name", "alice-laptop")
	f.Set("confirm", "on")
	rec = h.post(1, f)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="confirm_name"`) {
		t.Fatalf("step-1 POST: status %d, want the confirmation page", rec.Code)
	}
	if h.hs.rpcs() != 0 {
		t.Fatalf("a step-1 POST wrote: rpcs = %d", h.hs.rpcs())
	}

	// Step 2 with a wrong name, a missing name or a missing box is refused.
	for name, mutate := range map[string]func(url.Values){
		"wrong name":  func(v url.Values) { v.Set("confirm_name", "bob-phone"); v.Set("confirm", "on") },
		"empty name":  func(v url.Values) { v.Set("confirm", "on") },
		"no checkbox": func(v url.Values) { v.Set("confirm_name", "alice-laptop") },
	} {
		f := h.form(1, "tag:web")
		f.Set("step", "convert")
		mutate(f)
		if rec := h.post(1, f); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if h.hs.rpcs() != 0 {
		t.Fatalf("a refused step 2 wrote: rpcs = %d", h.hs.rpcs())
	}

	// Step 2 with the name and the box converts.
	f = h.form(1, "tag:web")
	f.Set("step", "convert")
	f.Set("confirm_name", "alice-laptop")
	f.Set("confirm", "on")
	if rec := h.post(1, f); rec.Code != http.StatusOK {
		t.Fatalf("convert status = %d: %s", rec.Code, rec.Body)
	}
	if h.hs.rpcs() != 1 || !slices.Equal(h.hs.node(1).Tags, []string{"tag:web"}) {
		t.Errorf("rpcs = %d, tags = %v", h.hs.rpcs(), h.hs.node(1).Tags)
	}
}

// AC6: the audit row says what changed: ownership kind, UserID, the tag diff and the expiry read
// back after the change.
func TestTags_AuditOwnershipAndExpiry(t *testing.T) {
	h := newTagsHarness(t)
	f := h.form(1, "tag:web")
	f.Set("step", "convert")
	f.Set("confirm_name", "alice-laptop")
	f.Set("confirm", "on")
	rec := h.post(1, f)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), tagsTestExpiry.Format(deviceTimeLayout)) {
		t.Errorf("result page does not show the read-back expiry")
	}
	evs := h.events(t)
	if len(evs) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(evs))
	}
	want := map[string][2]string{
		"ownership":          {"personal", "tagged"},
		"user_id":            {"10", ""},
		"tags":               {"", "tag:web"},
		"tags_added":         {"", "tag:web"},
		"observed.ownership": {"personal", "tagged"},
		"observed.user_id":   {"10", strconv.FormatUint(taggedDevicesUserID, 10)},
		"observed.expiry":    {tagsTestExpiry.UTC().Format(time.RFC3339), tagsTestExpiry.UTC().Format(time.RFC3339)},
	}
	for field, ba := range want {
		c, ok := diffField(evs[1].Diff, field)
		if !ok {
			t.Errorf("applied row lacks %q: %+v", field, evs[1].Diff)
			continue
		}
		if c.Before != ba[0] || c.After != ba[1] {
			t.Errorf("%s = %q → %q, want %q → %q", field, c.Before, c.After, ba[0], ba[1])
		}
	}
	if _, ok := diffField(evs[0].Diff, "observed.expiry"); ok {
		t.Errorf("the started row carries a read-back fact")
	}

	t.Run("tag change records the removed tag", func(t *testing.T) {
		h := newTagsHarness(t)
		if rec := h.post(2, h.form(2, "tag:db")); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		evs := h.events(t)
		if c, _ := diffField(evs[1].Diff, "tags_removed"); c.Before != "tag:web" {
			t.Errorf("tags_removed = %+v", c)
		}
		if c, _ := diffField(evs[1].Diff, "ownership"); c.Before != "tagged" || c.After != "tagged" {
			t.Errorf("ownership = %+v", c)
		}
	})
}

// AC7: a protected server node shows no tag form and refuses a direct POST.
func TestTags_ProtectedBlocked(t *testing.T) {
	h := newTagsHarness(t)
	rec := h.get(3)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<form") || strings.Contains(body, `name="tag"`) {
		t.Errorf("a protected node page offers a tag form:\n%s", body)
	}
	if !strings.Contains(body, "korumalı") {
		t.Errorf("page does not say the node is protected")
	}
	if rec := h.post(3, h.form(3, "tag:web")); rec.Code != http.StatusForbidden {
		t.Errorf("POST status = %d, want 403", rec.Code)
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, want 0", h.hs.rpcs())
	}
}

// AC8: a form older than the node's current state is a conflict, in both steps.
func TestTags_Stale(t *testing.T) {
	h := newTagsHarness(t)
	f := h.form(2, "tag:db")
	h.hs.mutate(2, func(n *admin.AdminNode) { n.Tags = []string{"tag:web", "tag:db"} })
	if rec := h.post(2, f); rec.Code != http.StatusConflict {
		t.Errorf("tagged: status = %d, want 409", rec.Code)
	}

	f = h.form(1, "tag:web")
	f.Set("step", "convert")
	f.Set("confirm_name", "alice-laptop")
	f.Set("confirm", "on")
	h.hs.mutate(1, func(n *admin.AdminNode) { n.GivenName = "alice-renamed" })
	if rec := h.post(1, f); rec.Code != http.StatusConflict {
		t.Errorf("personal: status = %d, want 409", rec.Code)
	}
	if h.hs.rpcs() != 0 {
		t.Errorf("rpcs = %d, want 0", h.hs.rpcs())
	}
}

// Fail safe (rule 7): when Headscale or the policy cannot be read, nothing is offered or written.
func TestTags_UnreadableFailsSafe(t *testing.T) {
	t.Run("policy", func(t *testing.T) {
		h := newTagsHarness(t)
		f := h.form(2, "tag:db")
		h.hs.mu.Lock()
		h.hs.policyErr = errors.New("policy down")
		h.hs.mu.Unlock()
		if rec := h.post(2, f); rec.Code < 500 {
			t.Errorf("POST status = %d, want 5xx", rec.Code)
		}
		if body := h.get(2).Body.String(); strings.Contains(body, `name="tag"`) {
			t.Errorf("page offers tags without a readable policy")
		}
		if h.hs.rpcs() != 0 {
			t.Errorf("rpcs = %d", h.hs.rpcs())
		}
	})
	t.Run("malformed policy", func(t *testing.T) {
		h := newTagsHarness(t)
		h.hs.policy = `{"tagOwners": [`
		if rec := h.post(2, h.form(2, "tag:db")); rec.Code < 500 || h.hs.rpcs() != 0 {
			t.Errorf("status = %d, rpcs = %d", rec.Code, h.hs.rpcs())
		}
	})
	t.Run("nodes", func(t *testing.T) {
		h := newTagsHarness(t)
		f := h.form(2, "tag:db")
		h.hs.mu.Lock()
		h.hs.listErr = errors.New("headscale down")
		h.hs.mu.Unlock()
		if rec := h.post(2, f); rec.Code < 500 || h.hs.rpcs() != 0 {
			t.Errorf("status = %d, rpcs = %d", rec.Code, h.hs.rpcs())
		}
	})
}

// Routing and access: unknown or malformed ids are 404, a non-devops identity 403 and a POST
// without the CSRF token 403.
func TestTags_Access(t *testing.T) {
	h := newTagsHarness(t)
	if rec := h.get(99); rec.Code != http.StatusNotFound {
		t.Errorf("unknown node: status = %d, want 404", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/headscale/devices/x/tags", nil, "devops"); rec.Code != http.StatusNotFound {
		t.Errorf("malformed id: status = %d, want 404", rec.Code)
	}
	if rec := h.do(http.MethodGet, tagsURL(2), nil, "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("viewer: status = %d, want 403", rec.Code)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tagsURL(2),
		strings.NewReader(h.form(2, "tag:db").Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(headerUser, "u")
	req.Header.Set(headerEmail, "u@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || h.hs.rpcs() != 0 {
		t.Errorf("no CSRF token: status = %d, rpcs = %d", rec.Code, h.hs.rpcs())
	}
}

// The RPC failing leaves the node alone and the page says so (no blind retry, one RPC).
func TestTags_RPCFailureReported(t *testing.T) {
	h := newTagsHarness(t)
	h.hs.setErr = errors.New("boom")
	rec := h.post(2, h.form(2, "tag:db"))
	if rec.Code < 500 {
		t.Errorf("status = %d, want 5xx", rec.Code)
	}
	if h.hs.rpcs() != 1 {
		t.Errorf("rpcs = %d, want exactly 1", h.hs.rpcs())
	}
	if got := h.hs.node(2).Tags; !slices.Equal(got, []string{"tag:web"}) {
		t.Errorf("node tags = %v, want unchanged", got)
	}
}
