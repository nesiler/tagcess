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
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The device actions (F3-014, H-01 write side): rename, expire now, set or disable the expiry and
// the two-step delete, every one through the F3-009 executor. The tests drive the production
// service over a fake admin client the way a real Headscale would behave (the RPC mutates the
// node; the read-back sees the mutation).

// fakeDeviceAdmin is the write-capable admin surface. The RPC methods mutate the node list like
// the real v0.29.4 server does.
type fakeDeviceAdmin struct {
	mu      sync.Mutex
	nodes   []admin.AdminNode
	listErr error
	rpcs    int
	// setListErrAfterRPC makes the read after the first RPC fail, so the outcome turns unknown.
	setListErrAfterRPC bool
}

func (f *fakeDeviceAdmin) ListNodes(context.Context) ([]admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]admin.AdminNode(nil), f.nodes...), nil
}

func (f *fakeDeviceAdmin) ListApiKeys(context.Context) ([]admin.APIKey, error) {
	return nil, errors.New("not used by the device actions")
}

func (f *fakeDeviceAdmin) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) {
	return nil, errors.New("not used by the device actions")
}

func (f *fakeDeviceAdmin) find(id uint64) *admin.AdminNode {
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			return &f.nodes[i]
		}
	}
	return nil
}

func (f *fakeDeviceAdmin) RenameNode(_ context.Context, id uint64, newName string) (admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rpcs++
	if f.setListErrAfterRPC {
		f.listErr = errors.New("read-back unavailable")
	}
	if n := f.find(id); n != nil {
		n.GivenName = newName
		return *n, nil
	}
	return admin.AdminNode{}, errors.New("node not found")
}

func (f *fakeDeviceAdmin) DeleteNode(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rpcs++
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes = append(f.nodes[:i], f.nodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

func (f *fakeDeviceAdmin) ExpireNode(_ context.Context, id uint64, expiry time.Time) (admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rpcs++
	if n := f.find(id); n != nil {
		e := expiry
		n.Expiry = &e
		return *n, nil
	}
	return admin.AdminNode{}, errors.New("node not found")
}

func (f *fakeDeviceAdmin) EnableNode(_ context.Context, id uint64) (admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rpcs++
	if n := f.find(id); n != nil {
		n.Expiry = nil
		return *n, nil
	}
	return admin.AdminNode{}, errors.New("node not found")
}

func (f *fakeDeviceAdmin) setListErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listErr = err
}

func (f *fakeDeviceAdmin) rpcCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rpcs
}

func (f *fakeDeviceAdmin) node(id uint64) (admin.AdminNode, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.find(id); n != nil {
		return *n, true
	}
	return admin.AdminNode{}, false
}

// deviceActionExpiry is a fixed future instant for the fixtures.
var deviceActionExpiry = time.Date(2099, 3, 4, 5, 6, 0, 0, time.UTC).Truncate(time.Second)

type deviceActionsHarness struct {
	t       *testing.T
	hs      *fakeDeviceAdmin
	csrf    *CSRF
	svc     *DeviceActionsService
	handler *DeviceActionsHandler
	audit   *audit.Logger
	store   *store.Store
	maint   *maintenance.Service
	chain   http.Handler
}

func newDeviceActionsHarness(t *testing.T, nodes ...admin.AdminNode) *deviceActionsHarness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hs := &fakeDeviceAdmin{nodes: nodes}
	auditLog := audit.New(st.Queries())
	maint := maintenance.New(st.Queries())
	ex := hsadmin.New(hsadmin.Config{Reader: hs, Audit: auditLog, Store: st.Queries(), Maintenance: maint})
	svc, err := NewDeviceActionsService(hs, ex)
	if err != nil {
		t.Fatalf("NewDeviceActionsService: %v", err)
	}
	csrf := testCSRF(t)
	handler, err := NewDeviceActionsHandler(svc, csrf)
	if err != nil {
		t.Fatalf("NewDeviceActionsHandler: %v", err)
	}
	h := &deviceActionsHarness{t: t, maint: maint, hs: hs, csrf: csrf, svc: svc, handler: handler, audit: auditLog, store: st}
	mux := http.NewServeMux()
	handler.Register(mux)
	devices, err := NewDevicesHandler(DevicesHandlerConfig{
		Reader:  mustDevicesService(t, hs),
		DryRun:  &fakeDryRunReader{},
		CSRF:    csrf,
		Actions: svc,
	})
	if err != nil {
		t.Fatalf("NewDevicesHandler: %v", err)
	}
	devices.Register(mux)
	h.chain = RequireDevops(csrf.Protect(mux))
	return h
}

func mustDevicesService(t *testing.T, hs *fakeDeviceAdmin) *DevicesService {
	t.Helper()
	svc, err := NewDevicesService(hs)
	if err != nil {
		t.Fatalf("NewDevicesService: %v", err)
	}
	return svc
}

// setProtected writes the protected tag list into the settings store.
func (h *deviceActionsHarness) setProtected(tags string) {
	h.t.Helper()
	if err := h.store.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: hsadmin.ProtectedTagsKey, Value: tags, UpdatedAt: "2026-10-01T00:00:00.000Z",
	}); err != nil {
		h.t.Fatal(err)
	}
}

// post issues a form POST as devops with the given fields plus a valid CSRF token.
func (h *deviceActionsHarness) post(target string, fields url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	if fields == nil {
		fields = url.Values{}
	}
	fields.Set(CSRFParam, h.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

// detail returns the detail page body for id.
func (h *deviceActionsHarness) detail(id uint64) string {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/headscale/devices/"+uintText(id), nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("detail page = %d", rec.Code)
	}
	return rec.Body.String()
}

func uintText(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// versionOf returns the node's current version stamp for form fields.
func (h *deviceActionsHarness) versionOf(id uint64) string {
	h.t.Helper()
	n, ok := h.hs.node(id)
	if !ok {
		h.t.Fatalf("node %d missing", id)
	}
	return hsadmin.NodeVersion(n)
}

func (h *deviceActionsHarness) events() []audit.Event {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs
}

func hasDiff(e audit.Event, field, before, after string) bool {
	for _, c := range e.Diff {
		if c.Field == field && c.Before == before && c.After == after {
			return true
		}
	}
	return false
}

var (
	personalNode = admin.AdminNode{
		ID: 11, Name: "laptop.tailnet", GivenName: "laptop", UserID: 10, UserName: "carol",
		IPs: []string{"100.64.0.10"}, CreatedAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
	}
	protectedNode = admin.AdminNode{
		ID: 22, Name: "gw.tailnet", GivenName: "gw", UserID: 11, UserName: "ops",
		Tags: []string{"tag:vpn-server"}, IPs: []string{"100.64.0.20"}, CreatedAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
	}
)

// AC1: a valid rename calls RenameNode, verifies the new name by read-back and writes the
// before/after to the audit log.
func TestDeviceAction_Rename(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	form := url.Values{
		"expected":     {h.versionOf(11)},
		"current_name": {"laptop"},
		"name":         {"laptop-2"},
	}
	rec := h.post("/headscale/devices/11/rename", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename = %d, want 200:\n%s", rec.Code, rec.Body.String())
	}
	if n, _ := h.hs.node(11); n.GivenName != "laptop-2" {
		t.Fatalf("node name = %q, want laptop-2", n.GivenName)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Apply edildi") {
		t.Errorf("result screen lacks the applied status:\n%s", body)
	}
	evs := h.events()
	if len(evs) != 2 || evs[0].Result != "started" || evs[1].Result != "applied" {
		t.Fatalf("audit results = %v", h.results(t))
	}
	for _, e := range evs {
		if e.Actor != "devops@example.com" || e.Event != "headscale.node.rename" || e.Target != "node:11" {
			t.Errorf("event = %+v", e)
		}
	}
	if !hasDiff(evs[0], "given_name", "laptop", "laptop-2") || !hasDiff(evs[1], "given_name", "laptop", "laptop-2") {
		t.Errorf("audit diff lacks the name before/after: %+v", evs)
	}
}

func (h *deviceActionsHarness) results(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range h.events() {
		out = append(out, e.Result)
	}
	return out
}

// AC1: an invalid name is refused without any RPC. The rule is the Headscale given-name regex
// ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$: single characters are valid, uppercase, spaces, empty,
// hyphen edges and over-long names are not.
func TestDeviceAction_RenameValidation(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	for _, name := range []string{"", "Laptop", "with space", "-leading", "trailing-", "ab-", strings.Repeat("a", 64)} {
		form := url.Values{
			"expected":     {h.versionOf(11)},
			"current_name": {"laptop"},
			"name":         {name},
		}
		rec := h.post("/headscale/devices/11/rename", form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("rename %q = %d, want 400", name, rec.Code)
		}
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Errorf("rpcs = %d, want 0", got)
	}
	if len(h.events()) != 0 {
		t.Errorf("validation refusals wrote audit rows: %v", h.results(t))
	}
}

// AC2: "şimdi expire et" expires the node and the read-back sees a past expiry.
func TestDeviceAction_ExpireNow(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	before := time.Now().Add(-time.Second)
	form := url.Values{
		"expected":       {h.versionOf(11)},
		"current_expiry": {""},
	}
	rec := h.post("/headscale/devices/11/expire", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("expire = %d:\n%s", rec.Code, rec.Body.String())
	}
	n, _ := h.hs.node(11)
	if n.Expiry == nil || n.Expiry.Before(before) {
		t.Fatalf("expiry = %v, want a past instant set by the action", n.Expiry)
	}
	if !strings.Contains(rec.Body.String(), "Apply edildi") {
		t.Errorf("result screen lacks the applied status:\n%s", rec.Body.String())
	}
	if got := h.results(t); len(got) != 2 || got[0] != "started" || got[1] != "applied" {
		t.Errorf("audit = %v", got)
	}
}

// AC3: a future expiry is set and verified; a past or unparseable one is refused without an RPC.
func TestDeviceAction_SetExpiry(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	future := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Minute).Format("2006-01-02T15:04")
	rec := h.post("/headscale/devices/11/expiry", url.Values{
		"expected":       {h.versionOf(11)},
		"current_expiry": {""},
		"expiry":         {future},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("set expiry = %d:\n%s", rec.Code, rec.Body.String())
	}
	n, _ := h.hs.node(11)
	if n.Expiry == nil || n.Expiry.Before(time.Now()) {
		t.Fatalf("expiry = %v, want a future instant", n.Expiry)
	}

	for _, bad := range []string{"2020-01-01T00:00", "not-a-date", ""} {
		rec := h.post("/headscale/devices/11/expiry", url.Values{
			"expected":       {h.versionOf(11)},
			"current_expiry": {""},
			"expiry":         {bad},
		})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("bad expiry %q = %d, want 400", bad, rec.Code)
		}
	}
	if got := h.hs.rpcCount(); got != 1 {
		t.Errorf("rpcs = %d, want 1 (only the valid expiry)", got)
	}
}

// AC4: disabling the expiry clears it, verified by read-back.
func TestDeviceAction_DisableExpiry(t *testing.T) {
	node := personalNode
	node.Expiry = &deviceActionExpiry
	h := newDeviceActionsHarness(t, node)
	rec := h.post("/headscale/devices/11/expiry/disable", url.Values{
		"expected":       {h.versionOf(11)},
		"current_expiry": {deviceActionExpiry.Format(time.RFC3339)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable expiry = %d:\n%s", rec.Code, rec.Body.String())
	}
	n, _ := h.hs.node(11)
	if n.Expiry != nil {
		t.Fatalf("expiry = %v, want none", n.Expiry)
	}
	if !strings.Contains(rec.Body.String(), "Apply edildi") {
		t.Errorf("result screen lacks the applied status:\n%s", rec.Body.String())
	}
}

// F3-021 bypass: an expired personal device may only be reopened through the confirm page and the
// fresh eligibility read. The two expiry actions refuse it (409, RPC=0) and the detail page does
// not draw their forms; a tagged expired node and a live personal node keep them.
func TestDeviceAction_ExpiredPersonalNodeNeedsReopen(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	node := personalNode
	node.Expiry = &past
	h := newDeviceActionsHarness(t, node)

	body := h.detail(11)
	for _, unwanted := range []string{`action="/headscale/devices/11/expiry"`, `action="/headscale/devices/11/expiry/disable"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("expired personal device draws %s:\n%s", unwanted, body)
		}
	}
	if !strings.Contains(body, "/headscale/devices/11/reopen") {
		t.Errorf("expired personal device lacks the reopen link:\n%s", body)
	}

	future := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04")
	for _, tt := range []struct {
		path   string
		fields url.Values
	}{
		{"/headscale/devices/11/expiry", url.Values{"expiry": {future}, "expected": {h.versionOf(11)}}},
		{"/headscale/devices/11/expiry/disable", url.Values{"expected": {h.versionOf(11)}}},
	} {
		rec := h.post(tt.path, tt.fields)
		if rec.Code != http.StatusConflict {
			t.Errorf("POST %s on expired personal node = %d, want 409", tt.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Yeniden aç") {
			t.Errorf("POST %s refusal does not point to reopen:\n%s", tt.path, rec.Body.String())
		}
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Errorf("rpcs = %d, want 0", got)
	}
	if n, _ := h.hs.node(11); n.Expiry == nil || !n.Expiry.Equal(past) {
		t.Errorf("expiry changed to %v", n.Expiry)
	}

	// A tagged node with a past expiry is not a personal device: the expiry actions stay.
	tagged := personalNode
	tagged.ID = 33
	tagged.Tags = []string{"tag:other"}
	tagged.Expiry = &past
	h2 := newDeviceActionsHarness(t, tagged)
	if body := h2.detail(33); !strings.Contains(body, `action="/headscale/devices/33/expiry"`) {
		t.Errorf("tagged expired node lacks the expiry form:\n%s", body)
	}
	if rec := h2.post("/headscale/devices/33/expiry/disable", url.Values{"expected": {h2.versionOf(33)}}); rec.Code != http.StatusOK {
		t.Errorf("disable expiry on tagged expired node = %d, want 200", rec.Code)
	}
}

// The audit "before" values come from the executor's fresh node, not from the form's hidden fields.
func TestDeviceAction_AuditBeforeFromFreshNode(t *testing.T) {
	node := personalNode
	node.Expiry = &deviceActionExpiry
	h := newDeviceActionsHarness(t, node)
	rec := h.post("/headscale/devices/11/rename", url.Values{
		"expected":     {h.versionOf(11)},
		"current_name": {"forged-name"},
		"name":         {"laptop-2"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("rename = %d", rec.Code)
	}
	rec = h.post("/headscale/devices/11/expire", url.Values{
		"expected":       {h.versionOf(11)},
		"current_expiry": {"forged-expiry"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expire = %d", rec.Code)
	}
	var sawName, sawExpiry bool
	for _, e := range h.events() {
		sawName = sawName || hasDiff(e, "given_name", "laptop", "laptop-2")
		sawExpiry = sawExpiry || hasDiff(e, "expiry", deviceActionExpiry.Format(time.RFC3339), "şimdi")
		for _, c := range e.Diff {
			if strings.HasPrefix(c.Before, "forged") {
				t.Errorf("audit trusts a client field: %+v", c)
			}
		}
	}
	if !sawName || !sawExpiry {
		t.Errorf("audit lacks the fresh before values (name=%v expiry=%v): %v", sawName, sawExpiry, h.events())
	}
}

// AC5: the delete needs the confirm page first; a direct POST is refused, a confirmed one deletes
// and the device drops from the list.
func TestDeviceAction_DeleteNeedsConfirm(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)

	// The confirm page renders and carries the confirm form.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/headscale/devices/11/delete", nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm page = %d", rec.Code)
	}
	page := rec.Body.String()
	for _, want := range []string{"Silme onayı", "laptop", `name="confirm"`, "evet"} {
		if !strings.Contains(page, want) {
			t.Errorf("confirm page lacks %q:\n%s", want, page)
		}
	}

	// A direct POST without the confirmation field is refused before any RPC.
	rec = h.post("/headscale/devices/11/delete", url.Values{
		"expected":     {h.versionOf(11)},
		"current_name": {"laptop"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed delete = %d, want 400", rec.Code)
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Fatalf("rpcs = %d, want 0", got)
	}
	if _, ok := h.hs.node(11); !ok {
		t.Fatal("node vanished without an RPC")
	}

	// The confirmed POST deletes the node and the list no longer shows it.
	rec = h.post("/headscale/devices/11/delete", url.Values{
		"expected":     {h.versionOf(11)},
		"current_name": {"laptop"},
		"confirm":      {"evet"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed delete = %d:\n%s", rec.Code, rec.Body.String())
	}
	if _, ok := h.hs.node(11); ok {
		t.Fatal("node still present after a confirmed delete")
	}
	if list := h.listBody(t); strings.Contains(list, "laptop") {
		t.Errorf("list still shows the deleted device:\n%s", list)
	}
	if got := h.results(t); len(got) != 2 || got[0] != "started" || got[1] != "applied" {
		t.Errorf("audit = %v", got)
	}
}

func (h *deviceActionsHarness) listBody(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/headscale/devices", nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	return rec.Body.String()
}

// AC6: on a protected node the destructive buttons are not drawn, the server badge is shown,
// rename stays available, and the direct destructive POSTs are refused without an RPC.
func TestDeviceAction_ProtectedNode(t *testing.T) {
	h := newDeviceActionsHarness(t, protectedNode)
	h.setProtected(`["tag:vpn-server"]`)

	body := h.detail(22)
	for _, unwanted := range []string{`action="/headscale/devices/22/delete"`, `action="/headscale/devices/22/expire"`, `action="/headscale/devices/22/expiry"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("detail page draws a destructive form %s on a protected node:\n%s", unwanted, body)
		}
	}
	if !strings.Contains(body, "korumalı sunucu") {
		t.Errorf("detail page lacks the server badge:\n%s", body)
	}
	if !strings.Contains(body, `action="/headscale/devices/22/rename"`) {
		t.Errorf("detail page lacks the rename form on a protected node:\n%s", body)
	}

	// The direct destructive POSTs are refused with no RPC. The forms' own field validation passes
	// (confirm word, valid future expiry) so the refusal is the executor's server-node protection.
	future := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04")
	for _, tt := range []struct {
		path   string
		fields url.Values
	}{
		{"/headscale/devices/22/delete", url.Values{"confirm": {"evet"}, "expected": {h.versionOf(22)}}},
		{"/headscale/devices/22/expire", url.Values{"expected": {h.versionOf(22)}}},
		{"/headscale/devices/22/expiry", url.Values{"expiry": {future}, "expected": {h.versionOf(22)}}},
		{"/headscale/devices/22/expiry/disable", url.Values{"expected": {h.versionOf(22)}}},
	} {
		rec := h.post(tt.path, tt.fields)
		if rec.Code != http.StatusConflict {
			t.Errorf("POST %s on protected node = %d, want 409", tt.path, rec.Code)
		}
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Errorf("rpcs = %d, want 0", got)
	}

	// Rename on the protected node still works.
	rec := h.post("/headscale/devices/22/rename", url.Values{
		"expected":     {h.versionOf(22)},
		"current_name": {"gw"},
		"name":         {"gw-2"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("rename on protected node = %d:\n%s", rec.Code, rec.Body.String())
	}
	if n, _ := h.hs.node(22); n.GivenName != "gw-2" {
		t.Fatalf("protected node name = %q", n.GivenName)
	}
}

// AC6b: an untagged node is never protected, even when the protected list cannot be read.
func TestDeviceAction_ProtectedListUnreadable(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	if err := h.store.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: hsadmin.ProtectedTagsKey, Value: "not-json", UpdatedAt: "2026-10-01T00:00:00.000Z",
	}); err != nil {
		t.Fatal(err)
	}
	body := h.detail(11)
	if strings.Contains(body, `action="/headscale/devices/11/delete"`) {
		t.Errorf("unreadable protected list drew destructive forms:\n%s", body)
	}
	if !strings.Contains(body, "korumalı") {
		t.Errorf("unreadable protected list shows no warning:\n%s", body)
	}
	// An untagged node may still be renamed.
	rec := h.post("/headscale/devices/11/rename", url.Values{
		"expected":     {h.versionOf(11)},
		"current_name": {"laptop"},
		"name":         {"laptop-9"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("rename with unreadable list = %d:\n%s", rec.Code, rec.Body.String())
	}
}

// AC7: a form whose version no longer matches the live node is answered 409 and nothing is
// applied.
func TestDeviceAction_Stale(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	old := h.versionOf(11)
	h.hs.mu.Lock()
	h.hs.find(11).Tags = []string{"tag:other"} // the node changed after the page was rendered
	h.hs.mu.Unlock()

	rec := h.post("/headscale/devices/11/rename", url.Values{
		"expected":     {old},
		"current_name": {"laptop"},
		"name":         {"laptop-2"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale rename = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bayat") {
		t.Errorf("result screen lacks the stale status:\n%s", rec.Body.String())
	}
	if got := h.hs.rpcCount(); got != 0 {
		t.Errorf("rpcs = %d, want 0", got)
	}
}

// AC8: the audit carries actor, target, the allowed before/after and the result, and the result
// screen names failed and unknown outcomes explicitly.
func TestDeviceAction_AuditAndResult(t *testing.T) {
	t.Run("failed", func(t *testing.T) {
		h := newDeviceActionsHarness(t, personalNode)
		h.hs.setListErr(errors.New("headscale down")) // the executor's fresh read fails
		rec := h.post("/headscale/devices/11/rename", url.Values{
			"expected":     {h.versionOf(11)},
			"current_name": {"laptop"},
			"name":         {"laptop-2"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("failed rename = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Başarısız") {
			t.Errorf("result screen lacks the failed status:\n%s", rec.Body.String())
		}
		if got := h.results(t); len(got) != 1 || got[0] != "failed" {
			t.Errorf("audit = %v, want [failed]", got)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		h := newDeviceActionsHarness(t, personalNode)
		h.hs.setListErrAfterRPC = true
		rec := h.post("/headscale/devices/11/rename", url.Values{
			"expected":     {h.versionOf(11)},
			"current_name": {"laptop"},
			"name":         {"laptop-2"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("unknown rename = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Sonuç bilinmiyor") {
			t.Errorf("result screen lacks the unknown status:\n%s", rec.Body.String())
		}
		if got := h.results(t); len(got) != 2 || got[0] != "started" || got[1] != "unknown" {
			t.Errorf("audit = %v, want [started unknown]", got)
		}
	})
}

// F3b-014 AC2: while the Headscale maintenance is open, an expiry change that extends or removes
// the expiry is refused (409, no RPC, audited as blocked); one that shortens it, an expire-now and
// a rename still run.
func TestDeviceActions_ExpiryWidens(t *testing.T) {
	cur := deviceActionExpiry
	later := cur.Add(48 * time.Hour)
	earlier := cur.Add(-48 * time.Hour)
	if !earlier.After(time.Now()) {
		t.Fatal("fixture: the shortened expiry must still be in the future")
	}
	withExpiry := func(exp *time.Time) admin.AdminNode {
		n := personalNode
		n.Expiry = exp
		return n
	}
	cases := []struct {
		name    string
		node    admin.AdminNode
		path    string
		form    func(h *deviceActionsHarness) url.Values
		allowed bool
	}{
		{"extend", withExpiry(&cur), "/headscale/devices/11/expiry", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}, "expiry": {later.Format(time.RFC3339)}}
		}, false},
		{"set when none", withExpiry(nil), "/headscale/devices/11/expiry", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}, "expiry": {later.Format(time.RFC3339)}}
		}, false},
		{"disable", withExpiry(&cur), "/headscale/devices/11/expiry/disable", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}}
		}, false},
		{"shorten", withExpiry(&cur), "/headscale/devices/11/expiry", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}, "expiry": {earlier.Format(time.RFC3339)}}
		}, true},
		{"expire now", withExpiry(&cur), "/headscale/devices/11/expire", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}}
		}, true},
		{"rename", withExpiry(&cur), "/headscale/devices/11/rename", func(h *deviceActionsHarness) url.Values {
			return url.Values{"expected": {h.versionOf(11)}, "name": {"laptop-2"}}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDeviceActionsHarness(t, tc.node)
			if _, err := h.maint.Start(context.Background(), "req-1", "devops@example.com"); err != nil {
				t.Fatal(err)
			}
			rec := h.post(tc.path, tc.form(h))
			if tc.allowed {
				if rec.Code != http.StatusOK || h.hs.rpcCount() != 1 {
					t.Fatalf("%s = %d, rpcs %d; want 200 and 1 RPC:\n%s", tc.name, rec.Code, h.hs.rpcCount(), rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusConflict || h.hs.rpcCount() != 0 {
				t.Fatalf("%s = %d, rpcs %d; want 409 and no RPC:\n%s", tc.name, rec.Code, h.hs.rpcCount(), rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "bakım sürüyor") {
				t.Errorf("result screen lacks the maintenance reason:\n%s", rec.Body.String())
			}
			if got := h.results(t); len(got) != 1 || got[0] != "blocked" {
				t.Errorf("audit results = %v, want [blocked]", got)
			}
		})
	}

	t.Run("off allows extending", func(t *testing.T) {
		h := newDeviceActionsHarness(t, withExpiry(&cur))
		rec := h.post("/headscale/devices/11/expiry", url.Values{"expected": {h.versionOf(11)}, "expiry": {later.Format(time.RFC3339)}})
		if rec.Code != http.StatusOK || h.hs.rpcCount() != 1 {
			t.Fatalf("extend while off = %d, rpcs %d", rec.Code, h.hs.rpcCount())
		}
	})
}

// M2 (F5 live findings): the detail page links to the route approval screen next to the route
// table, so H-01 route approval is discoverable.
func TestDeviceDetail_LinksRoutesPage(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	body := h.detail(personalNode.ID)
	if !strings.Contains(body, `href="/headscale/devices/11/routes"`) {
		t.Fatalf("detail page has no link to the routes page:\n%s", body)
	}
}
