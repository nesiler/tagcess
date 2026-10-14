package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	muxKey     = "groups-key-with-trailing-newline\n"
	muxProject = "289100000000000001"
)

func muxSig(key string, body []byte) string {
	ts := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func muxPost(t *testing.T, h http.Handler, path, sig string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(body))
	if sig != "" {
		req.Header.Set("Zitadel-Signature", sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHookMux_GroupsEndpoint(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hook := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	body := []byte(fmt.Sprintf(`{"function":"function/preuserinfo","user":{"id":"u1"},"userinfo":{"sub":"u1"},"user_grants":[{"project_id":%q,"roles":["devops"]}]}`, muxProject))

	mux, err := newHookMux(hook, []byte(muxKey), muxProject, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("signed request gets groups", func(t *testing.T) {
		rec := muxPost(t, mux, groupsPath, muxSig(muxKey, body), body)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"groups"`) || !strings.Contains(rec.Body.String(), "devops") {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
	})
	t.Run("unsigned and badly signed are 401", func(t *testing.T) {
		for name, sig := range map[string]string{"unsigned": "", "bad": muxSig("other", body)} {
			if rec := muxPost(t, mux, groupsPath, sig, body); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: status %d, want 401", name, rec.Code)
			}
		}
	})
	t.Run("hook keeps working", func(t *testing.T) {
		if rec := muxPost(t, mux, webhookPath, "", body); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("off when no key", func(t *testing.T) {
		off, err := newHookMux(hook, nil, muxProject, nil, nil, log)
		if err != nil {
			t.Fatal(err)
		}
		if rec := muxPost(t, off, groupsPath, muxSig(muxKey, body), body); rec.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404", rec.Code)
		}
		if rec := muxPost(t, off, webhookPath, "", body); rec.Code != http.StatusNoContent {
			t.Fatalf("hook status %d", rec.Code)
		}
	})
}

// I13: the sign-in sync is limited to one run per window; the window is measured by the clock.
func TestDebounced(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	calls := 0
	fn := debounced(func() { calls++ }, 30*time.Second, func() time.Time { return now })

	fn()
	fn()
	now = now.Add(29 * time.Second)
	fn()
	if calls != 1 {
		t.Fatalf("calls inside the window = %d, want 1", calls)
	}
	now = now.Add(2 * time.Second)
	fn()
	if calls != 2 {
		t.Fatalf("calls after the window = %d, want 2", calls)
	}
}
