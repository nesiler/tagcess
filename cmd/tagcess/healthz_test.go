package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
)

// AC3: /healthz is the only route that answers without identity headers; every other route still
// refuses 403 (including unknown paths and the static files).
func TestUIHandler_HealthzIsTheOnlyOpenRoute(t *testing.T) {
	csrf, err := web.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	h := newUIHandler(csrf, uiPages{Health: web.NewHealthz(func(context.Context) error { return nil }, "test")})

	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
		return rec.Code
	}
	if got := do(http.MethodGet, "/healthz"); got != http.StatusOK {
		t.Errorf("GET /healthz without headers = %d, want 200", got)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/audit"},
		{http.MethodGet, "/sites"},
		{http.MethodGet, "/headscale/users"},
		{http.MethodGet, "/static/app.css"},
		{http.MethodGet, "/healthz/"},
		{http.MethodGet, "/healthz/x"},
		{http.MethodPost, "/healthz"},
		{http.MethodGet, "/nope"},
	} {
		if got := do(tc.method, tc.path); got != http.StatusForbidden {
			t.Errorf("%s %s without headers = %d, want 403", tc.method, tc.path, got)
		}
	}
}

// AC2 with a real store: open, 200; closed, 503.
func TestUIHandler_HealthzClosedStore(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	h := web.NewHealthz(func(ctx context.Context) error { return st.DB().PingContext(ctx) }, "test")
	get := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
		return rec.Code
	}
	if got := get(); got != http.StatusOK {
		t.Fatalf("open store = %d, want 200", got)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("closed store = %d, want 503", got)
	}
}
