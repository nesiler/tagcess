package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// B1, B2, B4: the nav targets that used to be 404 now answer, behind the devops middleware.
func TestNavPages(t *testing.T) {
	csrf, err := NewCSRF(bytes.Repeat([]byte("k"), csrfKeySize))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewNavPages(csrf).Register(mux)
	h := RequireDevops(mux)

	get := func(path string, devops bool) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Header.Set(headerUser, "someone")
		if devops {
			req.Header.Set(headerGroups, "devops")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/settings", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("/settings = %d, want 200", rec.Code)
	}
	for _, link := range []string{`href="/sites/settings"`, `href="/monitor/settings"`, `href="/headscale/settings"`} {
		if !strings.Contains(rec.Body.String(), link) {
			t.Errorf("/settings lacks %s", link)
		}
	}
	for _, path := range []string{"/k8s", "/k8s/drafts"} {
		rec := get(path, true)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/k8s/discovery" {
			t.Errorf("%s = %d -> %q, want 303 -> /k8s/discovery", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := get("/favicon.ico", true); rec.Code != http.StatusNoContent {
		t.Errorf("/favicon.ico = %d, want 204", rec.Code)
	}
	// Positive control: without the devops group nothing is served.
	for _, path := range []string{"/settings", "/k8s", "/k8s/drafts"} {
		if rec := get(path, false); rec.Code != http.StatusForbidden {
			t.Errorf("%s without devops = %d, want 403", path, rec.Code)
		}
	}
}
