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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Harness of the personal pre-auth key screen (F3-022, H-03): the real PersonalKeyService, vpnuser
// resolver and hsadmin executor over a fake Headscale and a fake Zitadel. The Headscale fake and
// the request helpers are the F3-017 ones (keys_test.go).

const personalIssuer = "https://auth.example.com"

// fakeKeyZitadel is the Zitadel read surface. It records the order of its reads against the key
// creation and whether the writer lock was held at the time of each read while recording.
type fakeKeyZitadel struct {
	mu     sync.Mutex
	grants []zitadel.Grant
	states map[string]zitadel.UserState
	gerr   error
	serr   error

	hs        *fakeKeyHS
	recording bool
	reads     int
	lockHeld  []bool
}

func (z *fakeKeyZitadel) ListGrants(context.Context) ([]zitadel.Grant, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.noteRead()
	return z.grants, z.gerr
}

func (z *fakeKeyZitadel) UserStates(_ context.Context, ids []string) (map[string]zitadel.UserState, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.noteRead()
	if z.serr != nil {
		return nil, z.serr
	}
	out := map[string]zitadel.UserState{}
	for _, id := range ids {
		if st, ok := z.states[id]; ok {
			out[id] = st
		} else {
			out[id] = zitadel.UserDeleted
		}
	}
	return out, nil
}

func (z *fakeKeyZitadel) noteRead() {
	if !z.recording {
		return
	}
	z.reads++
	z.lockHeld = append(z.lockHeld, writerLockHeld())
}

// writerLockHeld reports whether another goroutine currently holds the process-wide writer lock:
// a second acquirer must wait.
func writerLockHeld() bool {
	got := make(chan struct{})
	go func() { _ = change.WithWriterLock(func() error { close(got); return nil }) }()
	select {
	case <-got:
		return false
	case <-time.After(50 * time.Millisecond):
		return true
	}
}

type fakePersonalUsers struct {
	users []headscale.User
	err   error
}

func (f *fakePersonalUsers) ListUsers(context.Context) ([]headscale.User, error) {
	return f.users, f.err
}

type personalHarness struct {
	*keysHarness
	z     *fakeKeyZitadel
	users *fakePersonalUsers
}

// Fixed users: 1 alice is eligible; 2 has no role; 3 is locked; 4 is deleted in Zitadel; 5 has a
// provider identifier of another issuer; 6 is eligible too.
func newPersonalHarness(t *testing.T) *personalHarness {
	t.Helper()
	kh := newKeysHarness(t)
	ph := &personalHarness{
		keysHarness: kh,
		z: &fakeKeyZitadel{
			hs: kh.hs,
			grants: []zitadel.Grant{
				{UserID: "z1", Role: "vpn-user"}, {UserID: "z3", Role: "vpn-user"},
				{UserID: "z4", Role: "vpn-user"}, {UserID: "z6", Role: "vpn-admin"},
			},
			states: map[string]zitadel.UserState{
				"z1": zitadel.UserActive, "z2": zitadel.UserActive, "z3": zitadel.UserLocked, "z6": zitadel.UserActive,
			},
		},
		users: &fakePersonalUsers{users: []headscale.User{
			{ID: 1, Name: "alice", Email: "alice@example.com", ProviderID: personalIssuer + "/z1"},
			{ID: 2, Name: "norole", ProviderID: personalIssuer + "/z2"},
			{ID: 3, Name: "locked", ProviderID: personalIssuer + "/z3"},
			{ID: 4, Name: "gone", ProviderID: personalIssuer + "/z4"},
			{ID: 5, Name: "stranger", ProviderID: "https://other.example.com/z5"},
			{ID: 6, Name: "frank", ProviderID: personalIssuer + "/z6"},
		}},
	}
	resolver, err := vpnuser.NewResolver(ph.z, personalIssuer)
	if err != nil {
		t.Fatal(err)
	}
	ex := hsadmin.New(hsadmin.Config{
		Reader: kh.hs, Audit: kh.audit, Store: kh.store.Queries(),
		Log: slog.New(slog.NewTextHandler(kh.logBuf, nil)),
	})
	svc, err := NewPersonalKeyService(PersonalKeyServiceConfig{
		Admin: kh.hs, Users: ph.users, Resolver: resolver, Exec: ex, Issuer: personalIssuer,
		Now: func() time.Time { return kh.now },
	})
	if err != nil {
		t.Fatalf("NewPersonalKeyService: %v", err)
	}
	handler, err := NewPersonalKeyHandler(PersonalKeyHandlerConfig{Service: svc, DryRun: &fakeDryRunReader{}, CSRF: kh.csrf})
	if err != nil {
		t.Fatalf("NewPersonalKeyHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	kh.chain = RequireDevops(kh.csrf.Protect(mux))
	return ph
}

func personalForm(user string, kv ...string) url.Values {
	v := url.Values{"user": {user}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func (h *personalHarness) create(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.post("/headscale/keys/personal", form)
}

// AC1: an eligible user gets a one-time, untagged key bound to them with an explicit expiry (one
// hour by default); the value shows once, with no-store. The page offers eligible users only.
func TestPersonalKey_CreateEligible(t *testing.T) {
	h := newPersonalHarness(t)

	page := h.get("/headscale/keys/personal")
	body := page.Body.String()
	if page.Code != http.StatusOK {
		t.Fatalf("page = %d", page.Code)
	}
	for _, id := range []string{"1", "6"} {
		if !strings.Contains(body, `<option value="`+id+`"`) {
			t.Errorf("the form does not offer eligible user %s", id)
		}
	}
	for _, id := range []string{"2", "3", "4", "5"} {
		if strings.Contains(body, `<option value="`+id+`"`) {
			t.Errorf("the form offers ineligible user %s", id)
		}
	}

	rec := h.create(personalForm("1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), keysSecret) {
		t.Error("the create response does not show the key value")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if h.hs.lastUser != 1 {
		t.Errorf("key made for user %d, want 1", h.hs.lastUser)
	}
	o := h.hs.lastCreate
	if o.Reusable || o.Ephemeral || len(o.Tags) != 0 {
		t.Errorf("options = %+v, want one-time and untagged", o)
	}
	if !o.Expiration.Equal(h.now.Add(time.Hour)) {
		t.Errorf("expiration = %v, want now+1h", o.Expiration)
	}
	for _, path := range []string{"/headscale/keys/personal", "/headscale/keys"} {
		if strings.Contains(h.get(path).Body.String(), keysSecret) {
			t.Errorf("GET %s shows the key value again", path)
		}
	}
}

// AC2: a user without a role, locked, deleted, not matched, not found, or whose Zitadel read fails
// is refused without an RPC, with the reason on the page.
func TestPersonalKey_IneligibleRefused(t *testing.T) {
	cases := []struct {
		name   string
		user   string
		setup  func(*personalHarness)
		reason string
	}{
		{"no role", "2", nil, "rolü yok"},
		{"locked", "3", nil, "aktif değil"},
		{"deleted", "4", nil, "aktif değil"},
		{"unmatched", "5", nil, "eşleşmedi"},
		{"unknown headscale user", "99", nil, "bulunamadı"},
		{"not a number", "abc", nil, "Geçersiz"},
		{"missing", "", nil, "Geçersiz"},
		{"grants unreadable", "1", func(h *personalHarness) { h.z.gerr = errors.New("zitadel down") }, "zitadel okunamadı"},
		{"states unreadable", "1", func(h *personalHarness) { h.z.serr = errors.New("zitadel down") }, "zitadel okunamadı"},
		{"headscale users unreadable", "1", func(h *personalHarness) { h.users.err = errors.New("hs down") }, "okunamadı"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPersonalHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			rec := h.create(personalForm(tc.user))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.reason) {
				t.Errorf("the page does not say why (%q): %s", tc.reason, rec.Body)
			}
			if h.hs.creates != 0 {
				t.Errorf("%d create RPCs, want 0", h.hs.creates)
			}
			if strings.Contains(rec.Body.String(), keysSecret) {
				t.Error("a refusal shows a key value")
			}
		})
	}
}

// AC3 (changed 2026-10-06 item 8): a personal key has no 30-day maximum (server keys are made this
// way); a past or malformed expiry is still refused without an RPC, none means one hour, and the
// expiry is always an explicit future instant (Headscale stores an omitted one as already expired).
func TestPersonalKey_ExpiryCap(t *testing.T) {
	h := newPersonalHarness(t)
	for _, tc := range []struct {
		in   string
		want time.Duration // 0: refused
	}{
		{"", time.Hour},
		{"15m", 15 * time.Minute},
		{"30d", 30 * 24 * time.Hour},
		{"31d", 31 * 24 * time.Hour},
		{"721h", 721 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"1y", 365 * 24 * time.Hour},
		{"10y", 3650 * 24 * time.Hour},
		{"101y", 0},
		{"-2h", 0},
		{"-2d", 0},
		{"0", 0},
		{"0d", 0},
		{"tomorrow", 0},
		{"xd", 0},
		{"1ms", 0},
		{"59s", 0},
		{"1m", time.Minute},
	} {
		before := h.hs.creates
		rec := h.create(personalForm("1", "expires_in", tc.in))
		if tc.want == 0 {
			if rec.Code != http.StatusBadRequest || h.hs.creates != before {
				t.Errorf("%q: status %d, creates %d; want refused without an RPC", tc.in, rec.Code, h.hs.creates-before)
			}
			continue
		}
		if rec.Code != http.StatusOK || !h.hs.lastCreate.Expiration.Equal(h.now.Add(tc.want)) {
			t.Errorf("%q: status %d, expiration %v, want now+%v", tc.in, rec.Code, h.hs.lastCreate.Expiration, tc.want)
		}
	}
}

// AC4: a reusable, ephemeral or tag field in the request is refused, however it is set.
func TestPersonalKey_SingleUseOnly(t *testing.T) {
	h := newPersonalHarness(t)
	for _, kv := range [][]string{
		{"reusable", "1"}, {"reusable", ""}, {"reusable", "0"},
		{"ephemeral", "1"}, {"ephemeral", ""},
		{"tags", "tag:web"}, {"tags", ""},
	} {
		rec := h.create(personalForm("1", kv...))
		if rec.Code != http.StatusBadRequest || h.hs.creates != 0 {
			t.Errorf("%v: status %d, creates %d; want refused without an RPC", kv, rec.Code, h.hs.creates)
		}
	}
	if rec := h.create(personalForm("1")); rec.Code != http.StatusOK {
		t.Errorf("a plain request = %d", rec.Code)
	}
}

// AC5: the form and the result pages say that the key bypasses the OIDC sign-in conditions.
func TestPersonalKey_ShowsBypassWarning(t *testing.T) {
	const warning = "OIDC giriş şartlarını baypas eder"
	h := newPersonalHarness(t)
	if body := h.get("/headscale/keys/personal").Body.String(); !strings.Contains(body, warning) {
		t.Errorf("the form lacks the bypass warning")
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"created": h.create(personalForm("1")),
		"refused": h.create(personalForm("2")),
	} {
		if !strings.Contains(rec.Body.String(), warning) {
			t.Errorf("the %s page lacks the bypass warning", name)
		}
	}
	h.hs.createErr = errors.New("rpc down")
	if rec := h.create(personalForm("1")); !strings.Contains(rec.Body.String(), warning) {
		t.Errorf("the unknown-outcome page lacks the bypass warning")
	}
}

// AC6: the value is in no audit row, no log line and no byte of the database; the audit row carries
// the actor, the Headscale user, the Zitadel user id, the expiry and the key id.
func TestPersonalKey_SecretNotLogged(t *testing.T) {
	h := newPersonalHarness(t)
	rec := h.create(personalForm("1", "expires_in", "2h"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), keysSecret) {
		t.Fatalf("create = %d", rec.Code)
	}
	h.hs.createErr = errors.New("rpc failed for " + keysSecret)
	_ = h.create(personalForm("6"))

	evs := h.events()
	var applied bool
	for _, e := range evs {
		if raw := fmt.Sprintf("%+v", e); strings.Contains(raw, keysSecret) {
			t.Errorf("audit row carries the key value: %s", raw)
		}
		if e.Event != "headscale.preauth.create" || e.Result != "applied" {
			continue
		}
		applied = true
		fields := map[string]string{}
		for _, c := range e.Diff {
			fields[c.Field] = c.After
		}
		for field, want := range map[string]string{
			"headscale_user": "alice (1)",
			"zitadel_user":   "z1",
			"expiration":     h.now.Add(2 * time.Hour).UTC().Format(time.RFC3339),
			"id":             fmt.Sprint(h.hs.nextID),
			"reusable":       "false",
			"ephemeral":      "false",
		} {
			if fields[field] != want {
				t.Errorf("audit %s = %q, want %q (diff %+v)", field, fields[field], want, e.Diff)
			}
		}
		if e.Actor != keysActor {
			t.Errorf("actor = %q", e.Actor)
		}
	}
	if !applied {
		t.Fatalf("no applied create row in %+v", evs)
	}
	if strings.Contains(h.logBuf.String(), keysSecret) {
		t.Errorf("log carries the key value:\n%s", h.logBuf)
	}
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
		if bytes.Contains(b, []byte("SECRETVALUE")) {
			t.Errorf("%s carries the key value", ent.Name())
		}
	}
}

// AC7: a failing create RPC, or a lost answer, is not retried; the page says the outcome is
// unknown.
func TestPersonalKey_UnknownOutcome(t *testing.T) {
	for name, set := range map[string]func(*fakeKeyHS){
		"rpc error":     func(f *fakeKeyHS) { f.createErr = errors.New("deadline exceeded") },
		"response lost": func(f *fakeKeyHS) { f.createLost = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := newPersonalHarness(t)
			set(h.hs)
			rec := h.create(personalForm("1"))
			body := rec.Body.String()
			if rec.Code == http.StatusOK || !strings.Contains(body, "sonuç belirsiz") {
				t.Errorf("status %d, body lacks the unknown-outcome text: %s", rec.Code, body)
			}
			if h.hs.creates != 1 {
				t.Errorf("create RPCs = %d, want exactly 1", h.hs.creates)
			}
			if strings.Contains(body, keysSecret) {
				t.Error("an unknown outcome shows a key value")
			}
		})
	}
}

// AC8: the eligibility read and the key creation happen under the same writer lock: every Zitadel
// read of the request was made while the lock was held, and the RPC came after the last of them.
func TestPersonalKey_EligibilityUnderLock(t *testing.T) {
	h := newPersonalHarness(t)
	h.z.recording = true
	rec := h.create(personalForm("1"))
	h.z.recording = false
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if h.z.reads == 0 {
		t.Fatal("the request did not read Zitadel")
	}
	for i, held := range h.z.lockHeld {
		if !held {
			t.Errorf("Zitadel read %d ran outside the writer lock", i)
		}
	}

	// The check is not served from an earlier read: a role lost between the page and the POST
	// stops the key.
	h.z.grants = nil
	if rec := h.create(personalForm("1")); rec.Code != http.StatusBadRequest {
		t.Errorf("after the role was removed: %d, want 400", rec.Code)
	}
	if h.hs.creates != 1 {
		t.Errorf("creates = %d, want 1", h.hs.creates)
	}
}
