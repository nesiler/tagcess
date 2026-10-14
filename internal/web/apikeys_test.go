package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
)

// Harness of the API keys screen (F3-018, H-03): GET /headscale/keys/api lists the keys, the
// expire and delete actions run through the real F3-009 executor over the shared fake admin
// client. There is no create route, form or action (R2 karar 7); the fake implements the same
// narrow surface.

// apiKeysHarness reuses the F3-015 harness plumbing (store, executor, CSRF, middleware chain).
func newAPIKeysHarness(t *testing.T, keys []admin.APIKey) *routesHarness {
	t.Helper()
	h := newRoutesHarness(t, nil, "", nil)
	h.hs.mu.Lock()
	h.hs.apiKeys = keys
	h.hs.mu.Unlock()

	handler, err := NewAPIKeysHandler(APIKeysHandlerConfig{
		Reader:   h.hs,
		Writer:   h.hs,
		Executor: h.exec,
		DryRun:   h.dry,
		CSRF:     h.csrf,
	})
	if err != nil {
		t.Fatalf("NewAPIKeysHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

// apiKey fixtures: a fresh key without expiry, an expired key and a used key.
var (
	keyExpiryFar  = time.Date(2126, 1, 2, 3, 4, 0, 0, time.UTC)
	keyExpiryPast = time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	keySeen       = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	keyMade       = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
)

func apiKey(id uint64, prefix string) admin.APIKey {
	return admin.APIKey{ID: id, Prefix: prefix, CreatedAt: keyMade}
}

// ExpireApiKey records the id-only call and marks the key expired, like Headscale would.
func (f *fakeRoutesAdmin) ExpireApiKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireCalls = append(f.expireCalls, id)
	past := time.Now().Add(-time.Second)
	for i := range f.apiKeys {
		if f.apiKeys[i].ID == id {
			f.apiKeys[i].Expiration = &past
			return nil
		}
	}
	return errors.New("headscale/admin: ExpireApiKey: key not found")
}

// DeleteApiKey records the id-only call and removes the key, like Headscale would.
func (f *fakeRoutesAdmin) DeleteApiKey(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, id)
	for i := range f.apiKeys {
		if f.apiKeys[i].ID == id {
			f.apiKeys = slices.Delete(f.apiKeys, i, i+1)
			return nil
		}
	}
	return errors.New("headscale/admin: DeleteApiKey: key not found")
}

// apiKeyEvent lists one API key audit event type, newest first.
func (h *routesHarness) apiKeyEvent(t *testing.T, event string) []audit.Event {
	t.Helper()
	events, err := h.auditor.List(context.Background(), audit.Filter{Event: event, Limit: 20})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

// AC1: the page shows, per key, the id, prefix, creation, expiration, last seen and state
// (never used / expired / no expiry); no full key value can appear because the DTO carries none.
func TestAPIKeysPage_List(t *testing.T) {
	far := keyExpiryFar
	past := keyExpiryPast
	seen := keySeen
	h := newAPIKeysHarness(t, []admin.APIKey{
		{ID: 3, Prefix: "aaaa1111", Expiration: &past, CreatedAt: keyMade, LastSeen: &seen},
		{ID: 1, Prefix: "bbbb2222", CreatedAt: keyMade},
		{ID: 2, Prefix: "cccc3333", Expiration: &far, CreatedAt: keyMade, LastSeen: &seen},
	})

	rec := h.get(t, "/headscale/keys/api", "devops")
	if rec.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"aaaa1111", "bbbb2222", "cccc3333",
		keyMade.Format(deviceTimeLayout),
		keyExpiryFar.Format(deviceTimeLayout),
		keySeen.Format(deviceTimeLayout),
		"hiç kullanılmamış",
		"süresi dolmuş",
		"süresiz",
		"tam yönetici",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// AC2: there is no create action, form or route.
func TestAPIKeys_NoCreateRoute(t *testing.T) {
	h := newAPIKeysHarness(t, []admin.APIKey{apiKey(1, "bbbb2222")})

	for _, target := range []string{"/headscale/keys/api/new", "/headscale/keys/api/create"} {
		if rec := h.get(t, target, "devops"); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
	body := h.get(t, "/headscale/keys/api", "devops").Body.String()
	if strings.Contains(body, ">Oluştur<") || strings.Contains(body, `action="/headscale/keys/api/create"`) {
		t.Errorf("page offers a create action:\n%s", body)
	}
}

// AC3: expiring calls ExpireApiKey with the id only and the read-back confirms the expiration is
// in the past.
func TestAPIKeys_ExpireByIDOnly(t *testing.T) {
	h := newAPIKeysHarness(t, []admin.APIKey{apiKey(5, "dddd4444")})

	form := url.Values{"version": {hsadmin.APIKeyVersion(h.hs.apiKeyCopy(5))}}
	rec := h.postForm(t, "/headscale/keys/api/5/expire", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expire = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if !slices.Equal(h.hs.expireCalls, []uint64{5}) {
		t.Errorf("expire calls = %v, want [5] (id only)", h.hs.expireCalls)
	}
	if h.hs.deleteCalls != nil {
		t.Errorf("delete calls = %v, want none", h.hs.deleteCalls)
	}
	key := h.hs.apiKeyCopy(5)
	if key.Expiration == nil || !key.Expiration.Before(time.Now()) {
		t.Errorf("expiration = %v, want a past instant", key.Expiration)
	}
}

// AC4: delete asks for the irreversible confirmation; an unconfirmed post is refused and the
// confirmed post removes the key from the list.
func TestAPIKeys_DeleteNeedsConfirm(t *testing.T) {
	h := newAPIKeysHarness(t, []admin.APIKey{apiKey(6, "eeee5555")})

	// The confirm page warns that the action cannot be undone.
	page := h.get(t, "/headscale/keys/api/6/delete", "devops")
	if page.Code != http.StatusOK {
		t.Fatalf("confirm page = %d, want 200", page.Code)
	}
	if body := page.Body.String(); !strings.Contains(body, "geri alınamaz") {
		t.Fatalf("confirm page lacks the irreversible warning:\n%s", body)
	}

	// Without confirm=1 the post is refused before anything runs.
	form := url.Values{"version": {hsadmin.APIKeyVersion(h.hs.apiKeyCopy(6))}}
	if rec := h.postForm(t, "/headscale/keys/api/6/delete", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed delete = %d, want 400", rec.Code)
	}
	if len(h.hs.deleteCalls) != 0 {
		t.Fatalf("delete calls = %d, want 0", len(h.hs.deleteCalls))
	}

	// The confirmed post deletes; the read-back sees the key gone.
	form.Set("confirm", "1")
	if rec := h.postForm(t, "/headscale/keys/api/6/delete", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirmed delete = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	if !slices.Equal(h.hs.deleteCalls, []uint64{6}) {
		t.Errorf("delete calls = %v, want [6]", h.hs.deleteCalls)
	}
	body := h.get(t, "/headscale/keys/api", "devops").Body.String()
	if strings.Contains(body, "eeee5555") {
		t.Errorf("deleted key still listed:\n%s", body)
	}
	if page := h.get(t, "/headscale/keys/api/6/delete", "devops"); page.Code != http.StatusNotFound {
		t.Errorf("confirm page for deleted key = %d, want 404", page.Code)
	}
}

// AC5: the audit trail holds the actor, the key id and prefix and the result; no secret value is
// written because the surface never sees one.
func TestAPIKeys_Audit(t *testing.T) {
	h := newAPIKeysHarness(t, []admin.APIKey{apiKey(7, "ffff6666")})

	form := url.Values{"version": {hsadmin.APIKeyVersion(h.hs.apiKeyCopy(7))}}
	if rec := h.postForm(t, "/headscale/keys/api/7/expire", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("expire = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	form = url.Values{"version": {hsadmin.APIKeyVersion(h.hs.apiKeyCopy(7))}, "confirm": {"1"}}
	if rec := h.postForm(t, "/headscale/keys/api/7/delete", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d (%s), want 303", rec.Code, rec.Body.String())
	}

	for _, event := range []string{"headscale.apikey.expire", "headscale.apikey.delete"} {
		events := h.apiKeyEvent(t, event)
		if len(events) != 2 {
			t.Fatalf("%s events = %d, want 2 (started + applied)", event, len(events))
		}
		for _, e := range events {
			if e.Actor != "devops@example.com" {
				t.Errorf("%s actor = %q, want devops@example.com", event, e.Actor)
			}
			if e.Target != "apikey:7" {
				t.Errorf("%s target = %q, want apikey:7", event, e.Target)
			}
			var keyField bool
			for _, c := range e.Diff {
				if c.Field == "api_key" {
					keyField = true
					if !strings.Contains(c.After, "7") || !strings.Contains(c.After, "ffff6666") {
						t.Errorf("%s api_key field = %q, want id and prefix", event, c.After)
					}
				}
			}
			if !keyField {
				t.Errorf("%s diff lacks the api_key field: %+v", event, e.Diff)
			}
		}
	}
}

// Guard rails: unknown keys are 404, a missing version is refused, the list page fails safe when
// Headscale cannot be read, and the wiring validation refuses incomplete configs.
func TestAPIKeys_GuardRails(t *testing.T) {
	h := newAPIKeysHarness(t, []admin.APIKey{apiKey(8, "aaaa7777")})

	if rec := h.get(t, "/headscale/keys/api/99/delete", "devops"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown key confirm = %d, want 404", rec.Code)
	}
	if rec := h.postForm(t, "/headscale/keys/api/8/expire", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Errorf("expire without version = %d, want 400", rec.Code)
	}

	h.hs.setListErr(errors.New("headscale/admin: ListApiKeys: down"))
	if rec := h.get(t, "/headscale/keys/api", "devops"); rec.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", rec.Code)
	}
	body := h.get(t, "/headscale/keys/api", "devops").Body.String()
	if !strings.Contains(body, "API key&#39;ler okunamadı") || strings.Contains(body, "aaaa7777") {
		t.Errorf("failed read does not fail safe:\n%s", body)
	}

	if _, err := NewAPIKeysHandler(APIKeysHandlerConfig{}); err == nil {
		t.Error("accepted an empty config")
	}
	if _, err := NewAPIKeysHandler(APIKeysHandlerConfig{Writer: h.hs, Executor: h.exec, DryRun: h.dry, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing reader")
	}
	if _, err := NewAPIKeysHandler(APIKeysHandlerConfig{Reader: h.hs, Executor: h.exec, DryRun: h.dry, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing writer")
	}
	if _, err := NewAPIKeysHandler(APIKeysHandlerConfig{Reader: h.hs, Writer: h.hs, DryRun: h.dry, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing executor")
	}
	if _, err := NewAPIKeysHandler(APIKeysHandlerConfig{Reader: h.hs, Writer: h.hs, Executor: h.exec, CSRF: testCSRF(t)}); err == nil {
		t.Error("accepted a missing dry-run source")
	}
}
