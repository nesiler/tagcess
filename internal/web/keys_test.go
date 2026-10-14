package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	"github.com/nesiler/tagcess/internal/store/db"
)

// Harness of the pre-auth key screens (F3-017, H-03/H-05): the list, the confirmed expire and
// delete, and the tagged key creation. The tests drive the production KeysService and the real
// hsadmin executor over a fake Headscale, so the whole chain from form to audit is covered.

const (
	keysActor  = "devops@example.com"
	keysSecret = "hskey-auth-abcdef-SECRETVALUE0123456789"
	keysPolicy = `{"tagOwners": {"tag:web": ["group:devops"], "tag:printer": ["group:devops"], "tag:vpn-server": ["group:devops"]}}`
)

// fakeKeyHS is the live Headscale the key screens read and write. It satisfies the executor's
// Reader, the key admin surface and the policy read.
type fakeKeyHS struct {
	mu     sync.Mutex
	keys   []admin.PreAuthKey
	nodes  []admin.AdminNode
	nextID uint64
	policy string

	policyErr  error
	listErr    error
	createErr  error // the create RPC fails and nothing is created
	createLost bool  // the key is created but the RPC reports an error (lost response)
	noopExpire bool  // the expire RPC answers ok and changes nothing
	creates    int
	expires    int
	deletes    int
	lastCreate admin.PreAuthKeyOptions
	lastUser   uint64
}

func newFakeKeyHS() *fakeKeyHS {
	return &fakeKeyHS{nextID: 100, policy: keysPolicy}
}

func (f *fakeKeyHS) ListNodes(context.Context) ([]admin.AdminNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]admin.AdminNode(nil), f.nodes...), nil
}

func (f *fakeKeyHS) ListApiKeys(context.Context) ([]admin.APIKey, error) { return nil, nil }

func (f *fakeKeyHS) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]admin.PreAuthKey(nil), f.keys...), nil
}

func (f *fakeKeyHS) CreatePreAuthKey(_ context.Context, userID uint64, opts admin.PreAuthKeyOptions) (admin.PreAuthKey, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	f.lastCreate = opts
	f.lastUser = userID
	if f.createErr != nil {
		return admin.PreAuthKey{}, "", f.createErr
	}
	f.nextID++
	exp := opts.Expiration
	k := admin.PreAuthKey{
		ID: f.nextID, UserID: userID, Reusable: opts.Reusable, Ephemeral: opts.Ephemeral,
		Expiration: &exp, CreatedAt: time.Now(), Tags: opts.Tags,
	}
	f.keys = append(f.keys, k)
	if f.createLost {
		return admin.PreAuthKey{}, "", errors.New("rpc error: connection reset")
	}
	return k, keysSecret, nil
}

func (f *fakeKeyHS) ExpirePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expires++
	if f.noopExpire {
		return nil
	}
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Expiration = &past
		}
	}
	return nil
}

func (f *fakeKeyHS) DeletePreAuthKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys = append(f.keys[:i], f.keys[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeKeyHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policyErr != nil {
		return headscale.Policy{}, f.policyErr
	}
	return headscale.Policy{Text: f.policy}, nil
}

func (f *fakeKeyHS) key(id uint64) (admin.PreAuthKey, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k.ID == id {
			return k, true
		}
	}
	return admin.PreAuthKey{}, false
}

type keysHarness struct {
	t      *testing.T
	hs     *fakeKeyHS
	store  *store.Store
	dbDir  string
	audit  *audit.Logger
	logBuf *bytes.Buffer
	csrf   *CSRF
	svc    *KeysService
	chain  http.Handler
	now    time.Time
}

func newKeysHarness(t *testing.T) *keysHarness {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(context.Background(), filepath.Join(dir, "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h := &keysHarness{
		t: t, hs: newFakeKeyHS(), store: s, dbDir: dir, audit: audit.New(s.Queries()),
		logBuf: &bytes.Buffer{}, csrf: testCSRF(t),
		now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
	ex := hsadmin.New(hsadmin.Config{
		Reader: h.hs, Audit: h.audit, Store: s.Queries(),
		Log: slog.New(slog.NewTextHandler(h.logBuf, nil)),
	})
	h.svc, err = NewKeysService(KeysServiceConfig{Admin: h.hs, Policy: h.hs, Exec: ex, Now: func() time.Time { return h.now }})
	if err != nil {
		t.Fatalf("NewKeysService: %v", err)
	}
	handler, err := NewKeysHandler(KeysHandlerConfig{Service: h.svc, DryRun: &fakeDryRunReader{}, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewKeysHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *keysHarness) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		form.Set(CSRFParam, h.csrf.Token())
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, keysActor)
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *keysHarness) get(target string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(http.MethodGet, target, nil)
}

func (h *keysHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(http.MethodPost, target, form)
}

// createTagKey posts the tagged key form.
func (h *keysHarness) createTagKey(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.post("/headscale/keys/preauth/create", form)
}

func (h *keysHarness) events() []audit.Event {
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

func (h *keysHarness) setProtected(raw string) {
	h.t.Helper()
	err := h.store.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: hsadmin.ProtectedTagsKey, Value: raw, UpdatedAt: "2026-10-01T00:00:00.000Z",
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

// addKey puts a key straight into the fake, as if created earlier.
func (h *keysHarness) addKey(k admin.PreAuthKey) {
	h.hs.mu.Lock()
	defer h.hs.mu.Unlock()
	h.hs.keys = append(h.hs.keys, k)
}

func tagForm(tags ...string) url.Values {
	v := url.Values{}
	for _, t := range tags {
		v.Add("tags", t)
	}
	return v
}

// hiddenValue reads a hidden form field the way a browser would submit it back.
func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no hidden field %q in %s", name, body)
	}
	rest := body[i+len(marker):]
	return strings.ReplaceAll(rest[:strings.Index(rest, `"`)], "&#34;", `"`)
}

// AC1: the list shows id, owner/tags, reusable/ephemeral, used, expiry, creation and a status
// (active / used / expired); no response carries a key value, not even a legacy plaintext one.
func TestKeysPage_ListsNoSecret(t *testing.T) {
	h := newKeysHarness(t)
	future := time.Date(2099, 1, 2, 3, 4, 0, 0, time.UTC)
	past := time.Date(2020, 5, 6, 7, 8, 0, 0, time.UTC)
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	h.addKey(admin.PreAuthKey{ID: 1, UserID: 7, UserName: "alice", Used: false, Expiration: &future, CreatedAt: created})
	h.addKey(admin.PreAuthKey{ID: 2, UserID: 7, UserName: "alice", Used: true, Expiration: &future, CreatedAt: created})
	h.addKey(admin.PreAuthKey{ID: 3, UserName: "", Reusable: true, Ephemeral: true, Expiration: &future, CreatedAt: created, Tags: []string{"tag:printer"}})
	h.addKey(admin.PreAuthKey{ID: 4, UserID: 8, UserName: "bob", Expiration: &past, CreatedAt: created})
	// A key created through the screen: its value must not come back on any later page.
	rec := h.createTagKey(tagForm("tag:web"))
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body)
	}

	for _, path := range []string{"/headscale/keys", "/headscale/keys/preauth"} {
		rec := h.get(path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, keysSecret) || strings.Contains(body, "hskey-auth") {
			t.Fatalf("GET %s carries a key value", path)
		}
		for _, want := range []string{
			"alice", "bob", "tag:printer", "tag:web",
			"aktif", "kullanıldı", "süresi doldu",
			"2099-01-02 03:04", "2020-05-06 07:08", "2026-09-01 08:00",
			"yeniden kullanılabilir", "geçici",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
		for _, id := range []string{"1", "2", "3"} {
			if !strings.Contains(body, "/headscale/keys/preauth/"+id+"/expire") {
				t.Errorf("GET %s lacks the expire link of key %s", path, id)
			}
		}
		if strings.Contains(body, "/headscale/keys/preauth/4/expire") {
			t.Errorf("GET %s offers to expire an already expired key", path)
		}
		if !strings.Contains(body, "/headscale/keys/preauth/4/delete") {
			t.Errorf("GET %s lacks the delete link of the expired key", path)
		}
	}

	t.Run("headscale unreadable shows the reason and no rows", func(t *testing.T) {
		h.hs.mu.Lock()
		h.hs.listErr = errors.New("socket closed")
		h.hs.mu.Unlock()
		rec := h.get("/headscale/keys")
		body := rec.Body.String()
		if !strings.Contains(body, "socket closed") || strings.Contains(body, "alice") {
			t.Errorf("body = %s", body)
		}
	})
}

// AC2: expiring asks for a confirmation, calls ExpirePreAuthKey and trusts only the read-back; an
// RPC that answers ok but changes nothing is not reported as done; a key that is not there is a
// refusal, with no RPC.
func TestPreAuth_ExpireVerifiesReadBack(t *testing.T) {
	future := time.Date(2099, 1, 2, 3, 4, 0, 0, time.UTC)
	newH := func(t *testing.T) *keysHarness {
		h := newKeysHarness(t)
		h.addKey(admin.PreAuthKey{ID: 5, UserID: 7, UserName: "alice", Expiration: &future, CreatedAt: h.now})
		return h
	}

	t.Run("applied", func(t *testing.T) {
		h := newH(t)
		confirm := h.get("/headscale/keys/preauth/5/expire")
		if confirm.Code != http.StatusOK || !strings.Contains(confirm.Body.String(), "geri alınamaz") {
			t.Fatalf("confirm page = %d %s", confirm.Code, confirm.Body)
		}
		if h.hs.expires != 0 {
			t.Fatal("the confirm page expired the key")
		}
		rec := h.post("/headscale/keys/preauth/5/expire", url.Values{"version": {hiddenValue(t, confirm.Body.String(), "version")}})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "süresi doldu") {
			t.Fatalf("expire = %d %s", rec.Code, rec.Body)
		}
		k, _ := h.hs.key(5)
		if k.Expiration == nil || !k.Expiration.Before(time.Now()) {
			t.Errorf("key not expired: %+v", k)
		}
	})

	t.Run("rpc ok but unchanged is not success", func(t *testing.T) {
		h := newH(t)
		h.hs.noopExpire = true
		confirm := h.get("/headscale/keys/preauth/5/expire")
		rec := h.post("/headscale/keys/preauth/5/expire", url.Values{"version": {hiddenValue(t, confirm.Body.String(), "version")}})
		body := rec.Body.String()
		if rec.Code == http.StatusOK || !strings.Contains(body, "doğrulanamadı") {
			t.Fatalf("noop expire reported as success: %d %s", rec.Code, body)
		}
	})

	t.Run("missing id", func(t *testing.T) {
		h := newH(t)
		rec := h.post("/headscale/keys/preauth/99/expire", url.Values{"version": {"x"}})
		if rec.Code == http.StatusOK || h.hs.expires != 0 {
			t.Fatalf("missing key: status %d, expires %d", rec.Code, h.hs.expires)
		}
		if strings.Contains(rec.Body.String(), "süresi doldu") {
			t.Errorf("success text for a missing key: %s", rec.Body)
		}
		if rec := h.get("/headscale/keys/preauth/99/expire"); rec.Code != http.StatusNotFound {
			t.Errorf("confirm for a missing key = %d, want 404", rec.Code)
		}
	})

	t.Run("changed since confirm", func(t *testing.T) {
		h := newH(t)
		confirm := h.get("/headscale/keys/preauth/5/expire")
		version := hiddenValue(t, confirm.Body.String(), "version")
		later := future.Add(time.Hour)
		h.hs.mu.Lock()
		h.hs.keys[0].Expiration = &later
		h.hs.mu.Unlock()
		rec := h.post("/headscale/keys/preauth/5/expire", url.Values{"version": {version}})
		if rec.Code == http.StatusOK || h.hs.expires != 0 {
			t.Fatalf("stale expire went through: %d, expires %d", rec.Code, h.hs.expires)
		}
	})
}

// AC3: delete shows a confirmation that says it cannot be undone and that devices stay; only the
// POST after it deletes. (The real-Headscale half is TestPreAuth_Integration_DeleteKeepsNodes.)
func TestPreAuth_DeleteNeedsConfirm(t *testing.T) {
	h := newKeysHarness(t)
	future := time.Date(2099, 1, 2, 3, 4, 0, 0, time.UTC)
	h.addKey(admin.PreAuthKey{ID: 5, UserID: 7, UserName: "alice", Expiration: &future, CreatedAt: h.now})
	h.hs.nodes = []admin.AdminNode{{ID: 1, GivenName: "laptop", UserID: 7}}

	confirm := h.get("/headscale/keys/preauth/5/delete")
	body := confirm.Body.String()
	if confirm.Code != http.StatusOK || !strings.Contains(body, "geri alınamaz") || !strings.Contains(body, "node'lar silinmez") {
		t.Fatalf("confirm page = %d %s", confirm.Code, body)
	}
	if _, ok := h.hs.key(5); !ok || h.hs.deletes != 0 {
		t.Fatal("the confirm page deleted the key")
	}

	rec := h.post("/headscale/keys/preauth/5/delete", url.Values{"version": {hiddenValue(t, body, "version")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, ok := h.hs.key(5); ok {
		t.Error("key still there after delete")
	}
	if nodes, _ := h.hs.ListNodes(context.Background()); len(nodes) != 1 {
		t.Errorf("nodes = %d, want the device untouched", len(nodes))
	}

	t.Run("a POST without the confirm token is forbidden", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/headscale/keys/preauth/5/delete", strings.NewReader("version=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, keysActor)
		req.Header.Set(headerGroups, "devops")
		rec := httptest.NewRecorder()
		h.chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}

// AC4: tags come from the policy's tagOwners only; an empty set, a tag the policy does not have and
// a protected server tag are refused without an RPC.
func TestTagKey_TagsFromPolicyOnly(t *testing.T) {
	h := newKeysHarness(t)

	for name, form := range map[string]url.Values{
		"empty":       tagForm(),
		"not in tags": tagForm("tag:ghost"),
		"one unknown": tagForm("tag:web", "tag:ghost"),
		"no prefix":   tagForm("web"),
	} {
		rec := h.createTagKey(form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", name, rec.Code, rec.Body)
		}
		if h.hs.creates != 0 {
			t.Fatalf("%s: %d create RPCs, want 0", name, h.hs.creates)
		}
	}

	rec := h.createTagKey(tagForm("tag:web", "tag:printer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid tags = %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(h.hs.lastCreate.Tags, ","); got != "tag:printer,tag:web" {
		t.Errorf("tags sent = %q, want the sorted set", got)
	}
	if h.hs.lastUser != 0 {
		t.Errorf("user = %d, a shared-device key has no owner", h.hs.lastUser)
	}

	t.Run("policy unreadable", func(t *testing.T) {
		h := newKeysHarness(t)
		h.hs.policyErr = errors.New("headscale down")
		rec := h.createTagKey(tagForm("tag:web"))
		if rec.Code == http.StatusOK || h.hs.creates != 0 {
			t.Fatalf("created without a policy: %d, creates %d", rec.Code, h.hs.creates)
		}
		if page := h.get("/headscale/keys"); !strings.Contains(page.Body.String(), "headscale down") {
			t.Errorf("page does not say why: %s", page.Body)
		}
	})

	t.Run("the form offers the policy tags only", func(t *testing.T) {
		body := h.get("/headscale/keys").Body.String()
		for _, want := range []string{`value="tag:web"`, `value="tag:printer"`} {
			if !strings.Contains(body, want) {
				t.Errorf("form lacks %s", want)
			}
		}
	})
}

// AC4: a tag in headscale.protected_tags (default tag:vpn-server, tag:k8s) cannot be chosen, even
// though the policy has it; it is not offered and a forced POST is refused without an RPC. An
// unreadable protected list fails closed.
func TestTagKey_ProtectedTagRefused(t *testing.T) {
	h := newKeysHarness(t)
	rec := h.createTagKey(tagForm("tag:vpn-server"))
	if rec.Code != http.StatusBadRequest || h.hs.creates != 0 {
		t.Fatalf("protected tag: %d, creates %d: %s", rec.Code, h.hs.creates, rec.Body)
	}
	rec = h.createTagKey(tagForm("tag:web", "tag:vpn-server"))
	if rec.Code != http.StatusBadRequest || h.hs.creates != 0 {
		t.Fatalf("mixed with a protected tag: %d, creates %d", rec.Code, h.hs.creates)
	}
	if body := h.get("/headscale/keys").Body.String(); strings.Contains(body, `value="tag:vpn-server"`) {
		t.Error("the form offers a protected tag")
	}

	t.Run("custom list", func(t *testing.T) {
		h := newKeysHarness(t)
		h.setProtected(`["tag:printer"]`)
		if rec := h.createTagKey(tagForm("tag:printer")); rec.Code != http.StatusBadRequest || h.hs.creates != 0 {
			t.Fatalf("custom protected tag: %d, creates %d", rec.Code, h.hs.creates)
		}
		if rec := h.createTagKey(tagForm("tag:vpn-server")); rec.Code != http.StatusOK {
			t.Fatalf("a tag no longer protected: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("corrupt list fails closed", func(t *testing.T) {
		h := newKeysHarness(t)
		h.setProtected(`not json`)
		if rec := h.createTagKey(tagForm("tag:web")); rec.Code == http.StatusOK || h.hs.creates != 0 {
			t.Fatalf("created with an unreadable protected list: %d, creates %d", rec.Code, h.hs.creates)
		}
	})
}

// AC5: no expiry means one hour from now, always sent as an explicit time; more than 30 days, a
// past or a malformed value is refused without an RPC.
func TestTagKey_ExpiryDefaultsAndCap(t *testing.T) {
	h := newKeysHarness(t)

	rec := h.createTagKey(tagForm("tag:web"))
	if rec.Code != http.StatusOK {
		t.Fatalf("default expiry = %d %s", rec.Code, rec.Body)
	}
	if got, want := h.hs.lastCreate.Expiration, h.now.Add(time.Hour); !got.Equal(want) {
		t.Errorf("default expiration = %v, want %v", got, want)
	}

	for _, tc := range []struct {
		in   string
		want time.Duration // 0: refused
	}{
		{"30m", 30 * time.Minute},
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"720h", 30 * 24 * time.Hour},
		{"31d", 0},
		{"1y", 0},
		{"5w", 0},
		{"721h", 0},
		{"-1h", 0},
		{"0", 0},
		{"0s", 0},
		{"soon", 0},
		{"1x", 0},
	} {
		before := h.hs.creates
		form := tagForm("tag:web")
		form.Set("expires_in", tc.in)
		rec := h.createTagKey(form)
		if tc.want == 0 {
			if rec.Code != http.StatusBadRequest || h.hs.creates != before {
				t.Errorf("%q: status %d, creates %d; want refused without an RPC", tc.in, rec.Code, h.hs.creates-before)
			}
			continue
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%q: status %d: %s", tc.in, rec.Code, rec.Body)
			continue
		}
		if got := h.hs.lastCreate.Expiration; !got.Equal(h.now.Add(tc.want)) {
			t.Errorf("%q: expiration = %v, want now+%v", tc.in, got, tc.want)
		}
	}
}

// AC6: the value shows up in the one create response, with Cache-Control: no-store, and nowhere
// afterwards.
func TestTagKey_SecretShownOnce(t *testing.T) {
	h := newKeysHarness(t)
	rec := h.createTagKey(tagForm("tag:web"))
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), keysSecret) {
		t.Error("the create response does not show the key value")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	for _, path := range []string{"/headscale/keys", "/headscale/keys/preauth"} {
		if body := h.get(path).Body.String(); strings.Contains(body, keysSecret) {
			t.Errorf("GET %s shows the key value again", path)
		}
	}
}

// AC6: the value is in no audit row, no log line and no byte of the database.
func TestTagKey_SecretNotLogged(t *testing.T) {
	h := newKeysHarness(t)
	rec := h.createTagKey(tagForm("tag:web"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), keysSecret) {
		t.Fatalf("create = %d", rec.Code)
	}
	// An RPC error text that quotes the secret must not leak either.
	h.hs.createErr = errors.New("rpc failed for " + keysSecret)
	_ = h.createTagKey(tagForm("tag:printer"))

	if strings.Contains(h.logBuf.String(), keysSecret) {
		t.Errorf("log carries the key value:\n%s", h.logBuf)
	}
	for _, e := range h.events() {
		if raw := fmt.Sprintf("%+v", e); strings.Contains(raw, keysSecret) {
			t.Errorf("audit row carries the key value: %s", raw)
		}
	}
	// Close the store so the WAL is checkpointed, then scan every file of the data directory.
	_ = h.store.Close()
	entries, err := os.ReadDir(h.dbDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		b, err := os.ReadFile(filepath.Join(h.dbDir, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(keysSecret)) || bytes.Contains(b, []byte("SECRETVALUE")) {
			t.Errorf("%s carries the key value", ent.Name())
		}
	}
}

// AC7: a failing create RPC, or one whose answer is lost, is never retried; the page says the
// outcome is unknown and warns that trying again may make a second key.
func TestTagKey_UnknownOutcome(t *testing.T) {
	for name, set := range map[string]func(*fakeKeyHS){
		"rpc error":     func(f *fakeKeyHS) { f.createErr = errors.New("deadline exceeded") },
		"response lost": func(f *fakeKeyHS) { f.createLost = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := newKeysHarness(t)
			set(h.hs)
			rec := h.createTagKey(tagForm("tag:web"))
			body := rec.Body.String()
			if rec.Code == http.StatusOK {
				t.Errorf("status = 200 for an unknown outcome")
			}
			if !strings.Contains(body, "sonuç belirsiz: listeyi kontrol edin; yeniden denemek ikinci bir key üretebilir") {
				t.Errorf("body lacks the unknown-outcome text: %s", body)
			}
			if h.hs.creates != 1 {
				t.Errorf("create RPCs = %d, want exactly 1 (no blind retry)", h.hs.creates)
			}
			if strings.Contains(body, keysSecret) {
				t.Error("an unknown outcome shows a key value")
			}
			if got := h.events(); got[len(got)-1].Result != "unknown" {
				t.Errorf("audit result = %q, want unknown", got[len(got)-1].Result)
			}
		})
	}
}

// AC9: every operation leaves a started and a result row with the actor, the key id, the tag set,
// the flags, the expiry and no secret.
func TestPreAuth_Audit(t *testing.T) {
	h := newKeysHarness(t)
	form := tagForm("tag:web", "tag:printer")
	form.Set("reusable", "1")
	form.Set("expires_in", "2h")
	if rec := h.createTagKey(form); rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id := strconv.FormatUint(h.hs.nextID, 10)

	evs := h.events()
	if len(evs) != 2 || evs[0].Result != "started" || evs[1].Result != "applied" {
		t.Fatalf("create audit = %+v", evs)
	}
	last := evs[1]
	if last.Actor != keysActor || last.Event != "headscale.preauth.create" {
		t.Errorf("event = %+v", last)
	}
	fields := map[string]string{}
	for _, c := range last.Diff {
		fields[c.Field] = c.After
	}
	for field, want := range map[string]string{
		"id":         id,
		"tags":       "tag:printer,tag:web",
		"reusable":   "true",
		"ephemeral":  "false",
		"expiration": h.now.Add(2 * time.Hour).UTC().Format(time.RFC3339),
	} {
		if fields[field] != want {
			t.Errorf("audit %s = %q, want %q (diff %+v)", field, fields[field], want, last.Diff)
		}
	}
	if raw := fmt.Sprintf("%+v", evs); strings.Contains(raw, keysSecret) {
		t.Errorf("audit carries the key value")
	}

	// Expire and delete: the key id is the target; the actor and the result are recorded.
	confirm := h.get("/headscale/keys/preauth/" + id + "/expire")
	h.post("/headscale/keys/preauth/"+id+"/expire", url.Values{"version": {hiddenValue(t, confirm.Body.String(), "version")}})
	confirm = h.get("/headscale/keys/preauth/" + id + "/delete")
	h.post("/headscale/keys/preauth/"+id+"/delete", url.Values{"version": {hiddenValue(t, confirm.Body.String(), "version")}})

	var got []string
	for _, e := range h.events()[2:] {
		if e.Actor != keysActor || e.Target != "preauth:"+id {
			t.Errorf("event = %+v", e)
		}
		got = append(got, e.Event+"/"+e.Result)
	}
	want := "headscale.preauth.expire/started headscale.preauth.expire/applied headscale.preauth.delete/started headscale.preauth.delete/applied"
	if strings.Join(got, " ") != want {
		t.Errorf("audit = %v", got)
	}
}

// F5 E4: expired keys are folded into their own section; active keys stay in the main table.
func TestKeysPage_ExpiredKeysAreFolded(t *testing.T) {
	h := newKeysHarness(t)
	future := time.Date(2099, 1, 2, 3, 4, 0, 0, time.UTC)
	past := time.Date(2020, 5, 6, 7, 8, 0, 0, time.UTC)
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	h.addKey(admin.PreAuthKey{ID: 1, UserID: 7, UserName: "alice", Expiration: &future, CreatedAt: created})
	h.addKey(admin.PreAuthKey{ID: 4, UserID: 8, UserName: "bob", Expiration: &past, CreatedAt: created})
	body := h.get("/headscale/keys").Body.String()
	i := strings.Index(body, `data-expired-keys="true"`)
	if i < 0 {
		t.Fatal("no folded expired section")
	}
	folded, active := body[i:], body[:i]
	if !strings.Contains(folded, "/headscale/keys/preauth/4/delete") || strings.Contains(folded, "/preauth/1/") {
		t.Errorf("the folded section must hold only the expired key")
	}
	if !strings.Contains(active, "/headscale/keys/preauth/1/expire") || strings.Contains(active, "/preauth/4/") {
		t.Errorf("the main table must hold only the active key")
	}

	// Positive control: no expired key, no folded section.
	h2 := newKeysHarness(t)
	h2.addKey(admin.PreAuthKey{ID: 1, UserID: 7, UserName: "alice", Expiration: &future, CreatedAt: created})
	if strings.Contains(h2.get("/headscale/keys").Body.String(), "data-expired-keys") {
		t.Error("an empty expired section is rendered")
	}
}
