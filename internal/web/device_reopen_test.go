package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The personal-device reopen (F3-021): an expired personal device is reopened only when a fresh
// Zitadel read proves the owner eligible, under the writer lock, with an explicit confirm step.
// The tests drive the production service over the same fakes the device actions use.

const testIssuer = "https://auth.example.com"

// fakeHSUsers is the fixed Headscale user read (F1 surface) for the owner lookup.
type fakeHSUsers struct {
	users []headscale.User
	err   error
}

func (f *fakeHSUsers) ListUsers(context.Context) ([]headscale.User, error) {
	return f.users, f.err
}

// fakeEligibility answers the resolver's question. Setting err makes every later read fail, so a
// verdict proved before a role loss cannot be reused by a later step.
type fakeEligibility struct {
	mu       sync.Mutex
	calls    int
	err      error
	evidence vpnuser.Eligibility
}

func (f *fakeEligibility) check(context.Context, headscale.User) (vpnuser.Eligibility, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return vpnuser.Eligibility{}, f.err
	}
	return f.evidence, nil
}

func (f *fakeEligibility) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type reopenTrigger struct {
	mu    sync.Mutex
	fired int
}

func (f *reopenTrigger) RequestManual() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fired++
}

func (f *reopenTrigger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

var (
	// expiredPersonalNode is carol's laptop whose expiry passed (Y-04 or the time itself).
	expiredPersonalNode = adminNodeAt(31, "old-laptop", 10, "carol", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	// expiredTaggedNode is a tagged (non-protected) node: reopen is personal-only.
	expiredTaggedNode = func() admin.AdminNode {
		n := adminNodeAt(32, "old-node", 11, "ops", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
		n.Tags = []string{"tag:lab"}
		return n
	}()
	ownerUsers = []headscale.User{{ID: 10, Name: "carol", ProviderID: testIssuer + "/u10"}}
)

// adminNodeAt is a fixture node with a fixed expiry.
func adminNodeAt(id uint64, name string, userID uint64, user string, expiry time.Time) admin.AdminNode {
	return admin.AdminNode{
		ID: id, Name: name + ".tailnet", GivenName: name, UserID: userID, UserName: user,
		IPs:       []string{"100.64.0.30"},
		Expiry:    &expiry,
		CreatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}

// reopenNodeVersion stamps a fake node's shown state.
func reopenNodeVersion(t *testing.T, hs *fakeDeviceAdmin, id uint64) string {
	t.Helper()
	n, ok := hs.node(id)
	if !ok {
		t.Fatalf("node %d missing", id)
	}
	return hsadmin.NodeVersion(n)
}

type reopenHarness struct {
	t       *testing.T
	hs      *fakeDeviceAdmin
	elig    *fakeEligibility
	trig    *reopenTrigger
	handler *DeviceReopenHandler
	audit   *audit.Logger
	csrf    *CSRF
	chain   http.Handler
}

func newReopenHarness(t *testing.T, nodes []admin.AdminNode, users []headscale.User) *reopenHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hs := &fakeDeviceAdmin{nodes: nodes}
	auditLog := audit.New(st.Queries())
	ex := hsadmin.New(hsadmin.Config{Reader: hs, Audit: auditLog, Store: st.Queries()})
	elig := &fakeEligibility{
		evidence: vpnuser.Eligibility{UserID: "u10", State: zitadel.UserActive, Roles: []string{"vpn-user"}},
	}
	trig := &reopenTrigger{}
	svc, err := NewDeviceReopenService(hs, &fakeHSUsers{users: users}, elig.check, ex, trig)
	if err != nil {
		t.Fatalf("NewDeviceReopenService: %v", err)
	}
	csrf := testCSRF(t)
	handler, err := NewDeviceReopenHandler(svc, csrf)
	if err != nil {
		t.Fatalf("NewDeviceReopenHandler: %v", err)
	}
	h := &reopenHarness{t: t, hs: hs, elig: elig, trig: trig, handler: handler, audit: auditLog, csrf: csrf}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(csrf.Protect(mux))
	return h
}

// get issues a GET as devops.
func (h *reopenHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	return h.do(req)
}

// post issues a form POST as devops with the fields plus a valid CSRF token.
func (h *reopenHarness) post(target string, fields url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	if fields == nil {
		fields = url.Values{}
	}
	fields.Set(CSRFParam, h.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(req)
}

func (h *reopenHarness) do(req *http.Request) *httptest.ResponseRecorder {
	h.t.Helper()
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *reopenHarness) versionOf(id uint64) string { return reopenNodeVersion(h.t, h.hs, id) }

func (h *reopenHarness) results() []string {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for i := len(evs) - 1; i >= 0; i-- {
		out = append(out, evs[i].Result)
	}
	return out
}

// AC1: an eligible user's device is reopened with a future expiry, the read-back verifies it, the
// audit carries the eligibility proof (no secrets) and a reconcile is requested.
func TestReopen_EligibleUser(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
	future := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Minute)
	rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
		"expected":       {h.versionOf(31)},
		"current_expiry": {expiredPersonalNode.Expiry.Format(time.RFC3339)},
		"expiry":         {future.Format("2006-01-02T15:04")},
		"confirm":        {"evet"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("reopen = %d:\n%s", rec.Code, rec.Body.String())
	}
	n, _ := h.hs.node(31)
	if n.Expiry == nil || !n.Expiry.After(time.Now()) {
		t.Fatalf("expiry = %v, want a future instant", n.Expiry)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Apply edildi") {
		t.Errorf("result screen lacks the applied status:\n%s", body)
	}
	if !strings.Contains(body, "reconcile") {
		t.Errorf("result screen does not mention the triggered reconcile:\n%s", body)
	}
	if h.trig.count() != 1 {
		t.Errorf("RequestManual calls = %d, want 1", h.trig.count())
	}
	evs := h.auditEvents(t)
	if len(evs) != 2 || evs[0].Result != "started" || evs[1].Result != "applied" {
		t.Fatalf("audit results = %v", h.results())
	}
	for _, e := range evs {
		if e.Event != "headscale.node.reopen" || e.Target != "node:31" || e.Actor != "devops@example.com" {
			t.Errorf("event = %+v", e)
		}
		if !auditHas(e.Diff, "zitadel_kullanıcı", "u10") ||
			!auditHas(e.Diff, "hesap_durumu", "active") ||
			!auditHas(e.Diff, "roller", "vpn-user") {
			t.Errorf("entry %s lacks the eligibility evidence: %+v", e.Result, e.Diff)
		}
		if strings.Contains(diffText(e.Diff), "secret") {
			t.Errorf("audit diff carries a secret-looking value: %+v", e.Diff)
		}
	}
}

// AC2: a roleless, inactive or unreadable owner is refused before any RPC, with the reason shown.
func TestReopen_IneligibleRefused(t *testing.T) {
	t.Run("roleless", func(t *testing.T) {
		h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
		h.elig.err = errors.New("zitadel kullanıcısı u10 vpn projesinde rolü yok")
		rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
			"expected": {h.versionOf(31)},
			"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
			"confirm":  {"evet"},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("roleless reopen = %d, want 409:\n%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "rolü yok") {
			t.Errorf("result screen lacks the reason:\n%s", rec.Body.String())
		}
		if got := h.hs.rpcCount(); got != 0 {
			t.Errorf("rpcs = %d, want 0", got)
		}
		if got := h.results(); len(got) != 1 || got[0] != "blocked" {
			t.Errorf("audit = %v, want [blocked]", got)
		}
	})
	t.Run("zitadel unreadable", func(t *testing.T) {
		h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
		h.elig.err = errors.New("zitadel okunamadı: down")
		rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
			"expected": {h.versionOf(31)},
			"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
			"confirm":  {"evet"},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("unreadable Zitadel reopen = %d, want 409", rec.Code)
		}
		if got := h.hs.rpcCount(); got != 0 {
			t.Errorf("rpcs = %d, want 0", got)
		}
	})
	t.Run("unknown owner", func(t *testing.T) {
		h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, nil)
		rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
			"expected": {h.versionOf(31)},
			"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
			"confirm":  {"evet"},
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("unknown owner reopen = %d, want 409", rec.Code)
		}
		if got := h.hs.rpcCount(); got != 0 {
			t.Errorf("rpcs = %d, want 0", got)
		}
	})
}

// AC3: a tagged device gets no reopen action and the direct POSTs are refused (personal-only).
func TestReopen_PersonalOnly(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredTaggedNode}, ownerUsers)

	// The check page is refused (the action is not offered for a tagged device).
	rec := h.get("/headscale/devices/32/reopen")
	if rec.Code != http.StatusConflict {
		t.Fatalf("tagged check = %d, want 409", rec.Code)
	}
	// The apply is refused without any write RPC.
	rec = h.post("/headscale/devices/32/reopen/apply", url.Values{
		"expected": {h.versionOf(32)},
		"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
		"confirm":  {"evet"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("tagged reopen = %d, want 409", rec.Code)
	}
	n, _ := h.hs.node(32)
	if !n.Expiry.Equal(expiredTaggedNode.Expiry.UTC()) {
		t.Fatalf("tagged node expiry changed: %v", n.Expiry)
	}

	// The detail page draws no reopen form for the tagged node.
	dh := newDeviceActionsHarness(t, expiredTaggedNode)
	body := dh.detail(32)
	if strings.Contains(body, "/reopen") {
		t.Errorf("detail page offers reopen for a tagged device:\n%s", body)
	}
	// ...and draws it for an expired personal device.
	dh2 := newDeviceActionsHarness(t, expiredPersonalNode)
	body = dh2.detail(31)
	if !strings.Contains(body, "/headscale/devices/31/reopen") {
		t.Errorf("detail page lacks the reopen action for an expired personal device:\n%s", body)
	}
}

// AC4: the apply without the confirm step is refused; the check page shows the eligibility result.
func TestReopen_NeedsExplicitConfirm(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)

	// One-step POST: refused without an RPC.
	rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
		"expected": {h.versionOf(31)},
		"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed reopen = %d, want 400", rec.Code)
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Fatalf("rpcs = %d, want 0", got)
	}

	// The check page shows the verdict, the roles and the confirm form.
	rec = h.get("/headscale/devices/31/reopen")
	if rec.Code != http.StatusOK {
		t.Fatalf("check page = %d:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"u10", "active", "vpn-user", `name="expiry"`, `name="confirm"`, "evet"} {
		if !strings.Contains(body, want) {
			t.Errorf("check page lacks %q:\n%s", want, body)
		}
	}
	if h.hs.rpcCount() != 0 {
		t.Errorf("check page caused RPCs: %d", h.hs.rpcCount())
	}

	// An ineligible owner shows the reason instead of the form.
	h.elig.err = errors.New("zitadel kullanıcısı u10 vpn projesinde rolü yok")
	rec = h.get("/headscale/devices/31/reopen")
	if rec.Code != http.StatusOK {
		t.Fatalf("ineligible check page = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rolü yok") || strings.Contains(rec.Body.String(), `name="confirm"`) {
		t.Errorf("ineligible check page does not show only the reason:\n%s", rec.Body.String())
	}
}

// AC5: the eligibility proof used at apply time is read under the writer lock, fresh: a verdict
// from the confirm step is never reused, and a role loss between the two steps is seen.
func TestReopen_EligibilityUnderLock(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)

	// The confirm step's read passes.
	rec := h.get("/headscale/devices/31/reopen")
	if rec.Code != http.StatusOK {
		t.Fatalf("check page = %d", rec.Code)
	}
	// The roles are revoked after the confirm page was rendered.
	h.elig.mu.Lock()
	h.elig.err = errors.New("zitadel kullanıcısı u10 vpn projesinde rolü yok")
	h.elig.mu.Unlock()

	rec = h.post("/headscale/devices/31/reopen/apply", url.Values{
		"expected": {h.versionOf(31)},
		"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
		"confirm":  {"evet"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("reopen after role loss = %d, want 409:\n%s", rec.Code, rec.Body.String())
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Errorf("rpcs = %d, want 0", got)
	}
	if got := h.elig.count(); got != 2 {
		t.Errorf("eligibility reads = %d, want 2 (the apply re-read, it did not reuse the verdict)", got)
	}
}

// AC6 (happy path already covered in AC1): a failed reopen never triggers a reconcile.
func TestReopen_FailureDoesNotTriggerReconcile(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
	h.elig.err = errors.New("zitadel kullanıcısı u10 aktif değil (durum: USER_STATE_INACTIVE)")
	rec := h.post("/headscale/devices/31/reopen/apply", url.Values{
		"expected": {h.versionOf(31)},
		"expiry":   {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")},
		"confirm":  {"evet"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("reopen = %d, want 409", rec.Code)
	}
	if h.trig.count() != 0 {
		t.Errorf("RequestManual calls = %d, want 0", h.trig.count())
	}
}

func (h *reopenHarness) auditEvents(t *testing.T) []audit.Event {
	t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// oldest first
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs
}

func auditHas(d audit.Diff, field, after string) bool {
	for _, c := range d {
		if c.Field == field && c.After == after {
			return true
		}
	}
	return false
}

func diffText(d audit.Diff) string {
	var sb strings.Builder
	for _, c := range d {
		sb.WriteString(c.Field + "=" + c.Before + "->" + c.After + "\n")
	}
	return sb.String()
}
