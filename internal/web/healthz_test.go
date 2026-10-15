package web_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/web"
)

func TestHealthz(t *testing.T) {
	tests := []struct {
		name       string
		ping       error
		method     string
		wantCode   int
		wantStatus string
	}{
		{"database readable", nil, http.MethodGet, http.StatusOK, "ok"},
		{"database unreadable", errors.New("sql: database is closed"), http.MethodGet, http.StatusServiceUnavailable, "unavailable"},
		{"head is allowed", nil, http.MethodHead, http.StatusOK, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := web.NewHealthz(func(context.Context) error { return tc.ping }, "1.2.3")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), tc.method, "/healthz", nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantStatus == "" {
				return
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
			}
			if body["status"] != tc.wantStatus || body["version"] != "1.2.3" || len(body) != 2 {
				t.Errorf("body = %v, want status=%s version=1.2.3 only", body, tc.wantStatus)
			}
			if strings.Contains(rec.Body.String(), "closed") {
				t.Errorf("body leaks the error: %q", rec.Body.String())
			}
		})
	}
}
