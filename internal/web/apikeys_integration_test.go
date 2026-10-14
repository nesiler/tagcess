//go:build integration

package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// AC7 (F3-018): against a real DB-mode Headscale, a key created through the raw admin API (the
// surface tagcess deliberately does not have) is listed, expired and deleted through the UI
// handler, and every step is verified in Headscale.
func TestAPIKeys_Integration_Lifecycle(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()

	// The key exists before tagcess sees it; only the raw client can create one.
	expiration := time.Now().Add(24 * time.Hour)
	created, err := h.Raw().CreateApiKey(ctx, &v1.CreateApiKeyRequest{Expiration: timestamppb.New(expiration)})
	if err != nil {
		t.Fatalf("raw CreateApiKey: %v", err)
	}
	rawKey := created.GetApiKey()
	if rawKey == "" {
		t.Fatal("raw CreateApiKey returned no key")
	}

	adminHS, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	t.Cleanup(func() { _ = adminHS.Close() })

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
	handler, err := web.NewAPIKeysHandler(web.APIKeysHandlerConfig{
		Reader:   adminHS,
		Writer:   adminHS,
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

	get := func(t *testing.T, target string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		req.Header.Set("X-Auth-Request-User", "devops-user")
		req.Header.Set("X-Auth-Request-Email", "devops@example.com")
		req.Header.Set("X-Auth-Request-Groups", "devops")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}
	post := func(t *testing.T, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("X-Auth-Request-User", "devops-user")
		req.Header.Set("X-Auth-Request-Email", "devops@example.com")
		req.Header.Set("X-Auth-Request-Groups", "devops")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrf.Token())
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}
	liveKeys := func() []*v1.ApiKey {
		t.Helper()
		resp, err := h.Raw().ListApiKeys(ctx, &v1.ListApiKeysRequest{})
		if err != nil {
			t.Fatalf("raw ListApiKeys: %v", err)
		}
		return resp.GetApiKeys()
	}

	// 1. List: the page shows the raw-created key's prefix and never a key value.
	page := get(t, "/headscale/keys/api")
	if page.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", page.Code)
	}

	keys0 := liveKeys()
	if len(keys0) != 1 {
		t.Fatalf("fixture has %d keys, want 1", len(keys0))
	}
	createdKey := keys0[0]
	if body := page.Body.String(); !strings.Contains(body, createdKey.GetPrefix()) {
		t.Fatalf("page lacks the key prefix %q:\n%s", createdKey.GetPrefix(), body)
	}
	if strings.Contains(page.Body.String(), rawKey) {
		t.Fatal("page leaks the full key value")
	}

	// 2. Expire: by id only; Headscale afterwards reports a past expiration.
	key := createdKey
	rec := post(t, "/headscale/keys/api/"+strconv.FormatUint(key.GetId(), 10)+"/expire",
		url.Values{"version": {hsadmin.APIKeyVersion(admin.APIKey{
			ID: key.GetId(), Prefix: key.GetPrefix(),
			Expiration: expiryOrNil(key.GetExpiration()),
		})}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expire = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	var expired *v1.ApiKey
	for _, k := range liveKeys() {
		if k.GetId() == key.GetId() {
			expired = k
			break
		}
	}
	if expired == nil {
		t.Fatalf("key %d vanished after expire", key.GetId())
	}
	if expired.GetExpiration() == nil || !expired.GetExpiration().AsTime().Before(time.Now()) {
		t.Errorf("expiration after expire = %v, want a past instant", expired.GetExpiration())
	}

	// 3. Delete: confirm page, unconfirmed post refused, confirmed post removes the key.
	if rec := get(t, "/headscale/keys/api/"+strconv.FormatUint(key.GetId(), 10)+"/delete"); rec.Code != http.StatusOK {
		t.Fatalf("confirm page = %d, want 200", rec.Code)
	}
	form := url.Values{"version": {hsadmin.APIKeyVersion(admin.APIKey{
		ID:         expired.GetId(),
		Prefix:     expired.GetPrefix(),
		Expiration: expiryOrNil(expired.GetExpiration()),
	})}}
	if rec := post(t, "/headscale/keys/api/"+strconv.FormatUint(key.GetId(), 10)+"/delete", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed delete = %d, want 400", rec.Code)
	}
	form.Set("confirm", "1")
	if rec := post(t, "/headscale/keys/api/"+strconv.FormatUint(key.GetId(), 10)+"/delete", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirmed delete = %d (%s), want 303", rec.Code, rec.Body.String())
	}
	for _, k := range liveKeys() {
		if k.GetId() == key.GetId() {
			t.Errorf("key %d still exists after delete", key.GetId())
		}
	}

	// 4. The audit trail recorded both operations.
	events, err := audit.New(q).List(ctx, audit.Filter{Event: "headscale.apikey.expire", Limit: 10})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expire audit events = %d, want 2", len(events))
	}
	events, err = audit.New(q).List(ctx, audit.Filter{Event: "headscale.apikey.delete", Limit: 10})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("delete audit events = %d, want 2", len(events))
	}
}

func expiryOrNil(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil || ts.AsTime().Unix() <= 0 {
		return nil
	}
	t := ts.AsTime()
	return &t
}
