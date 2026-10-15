package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/setup"
	"github.com/nesiler/tagcess/internal/store"
)

type setupEnv struct {
	h     http.Handler
	svc   *setup.Service
	csrf  *setupCSRF
	key   []byte
	token string
	logs  *bytes.Buffer
	aud   *audit.Logger
}

func newSetupEnv(t *testing.T) *setupEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := setup.New(st.Queries(), "")
	tok, err := svc.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte("k"), 32)
	csrf, err := newSetupCSRF(key)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	aud := audit.New(st.Queries())
	h, err := NewSetupHandler(svc, key, aud, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &setupEnv{h: h, svc: svc, csrf: csrf, key: key, token: tok, logs: logs, aud: aud}
}

func (e *setupEnv) post(path, remote, clientIP string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = remote
	if clientIP != "" {
		r.Header.Set(SetupClientIPHeader, clientIP)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *setupEnv) form(token string) url.Values {
	return url.Values{setupTokenField: {token}, CSRFParam: {e.csrf.token("")}}
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SetupCookie {
			return c
		}
	}
	t.Fatalf("no setup cookie; status %d", w.Code)
	return nil
}

const badToken = "0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000"

func TestSetup_RateLimit429KeepsToken(t *testing.T) {
	tests := []struct {
		name      string
		remote    string
		clientIP  func(i int) string
		wantLimit bool
	}{
		{"loopback: header is the source", "127.0.0.1:5000", func(int) string { return "203.0.113.7" }, true},
		{"off loopback: spoofed header ignored", "198.51.100.9:5000", func(i int) string { return "203.0.113.1" + string(rune('0'+i%10)) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSetupEnv(t)
			for i := 0; i < setup.PerSourceFailures; i++ {
				if w := e.post("/setup/session", tt.remote, tt.clientIP(i), e.form(badToken), nil); w.Code != http.StatusUnauthorized {
					t.Fatalf("attempt %d: %d", i, w.Code)
				}
			}
			w := e.post("/setup/session", tt.remote, tt.clientIP(0), e.form(e.token), nil)
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("sixth attempt: %d, want 429", w.Code)
			}
			// the token was not burned: another source gets in
			other := e.post("/setup/session", "127.0.0.1:6000", "192.0.2.55", e.form(e.token), nil)
			if other.Code != http.StatusSeeOther {
				t.Fatalf("token burned, other source got %d", other.Code)
			}
		})
	}
}

func TestSetup_SpoofedHeaderOffLoopbackDoesNotEvadeLimit(t *testing.T) {
	e := newSetupEnv(t)
	for i := 0; i < setup.PerSourceFailures; i++ {
		// a different spoofed value each time must not give a fresh budget
		e.post("/setup/session", "198.51.100.9:5000", "203.0.113."+string(rune('1'+i)), e.form(badToken), nil)
	}
	if w := e.post("/setup/session", "198.51.100.9:5001", "203.0.113.200", e.form(badToken), nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
}

func TestSetup_SessionReachesOnlySetup(t *testing.T) {
	e := newSetupEnv(t)
	w := e.post("/setup/session", "127.0.0.1:1", "", e.form(e.token), nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("exchange: %d", w.Code)
	}
	c := sessionCookie(t, w)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie flags: %+v", c)
	}
	for _, p := range []string{"/", "/devices", "/sites", "/api/x", "/setupx", "/hook"} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, p, nil)
		r.AddCookie(c)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s with session: %d, want 404", p, rec.Code)
		}
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/setup", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Setup session active") {
		t.Fatalf("GET /setup: %d", rec.Code)
	}
}

func TestSetup_StateChangeNeedsCSRF(t *testing.T) {
	e := newSetupEnv(t)
	// exchange without CSRF
	if w := e.post("/setup/session", "127.0.0.1:1", "", url.Values{setupTokenField: {e.token}}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("exchange without csrf: %d", w.Code)
	}
	w := e.post("/setup/session", "127.0.0.1:1", "", e.form(e.token), nil)
	c := sessionCookie(t, w)
	// logout without CSRF keeps the session
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{}, c); w.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf: %d", w.Code)
	}
	if _, err := e.svc.Validate(context.Background(), c.Value); err != nil {
		t.Fatalf("session ended without csrf: %v", err)
	}
	// logout without a session is refused even with CSRF
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{CSRFParam: {e.csrf.token("")}}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("logout without session: %d", w.Code)
	}
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{CSRFParam: {e.csrf.token(sessHash(t, e, c))}}, c); w.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", w.Code)
	}
	if _, err := e.svc.Validate(context.Background(), c.Value); err == nil {
		t.Fatal("session survived logout")
	}
}

func TestSetup_TokenNeverLeaks(t *testing.T) {
	e := newSetupEnv(t)
	e.post("/setup/session", "127.0.0.1:1", "", e.form(badToken), nil)
	w := e.post("/setup/session", "127.0.0.1:1", "", e.form(e.token), nil)
	c := sessionCookie(t, w)
	var responses strings.Builder
	responses.WriteString(w.Body.String() + w.Header().Get("Location"))
	for k, v := range w.Header() {
		responses.WriteString(k + strings.Join(v, ","))
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/setup", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	responses.WriteString(rec.Body.String())
	bare := strings.ReplaceAll(e.token, "-", "")
	events, err := e.aud.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil || len(events) < 2 {
		t.Fatalf("audit events %d err %v", len(events), err)
	}
	var auditText strings.Builder
	for _, ev := range events {
		auditText.WriteString(ev.Actor + ev.Event + ev.Target + ev.Result)
		if ev.Actor == "setup:anonymous" {
			continue
		}
		if !strings.HasPrefix(ev.Actor, "setup:") || len(ev.Actor) != 14 || !strings.Contains(ev.Result, "source=") {
			t.Errorf("audit actor/source: %+v", ev)
		}
	}
	for name, text := range map[string]string{"responses": responses.String(), "logs": e.logs.String(), "audit": auditText.String()} {
		if strings.Contains(text, e.token) || strings.Contains(text, bare) || strings.Contains(text, badToken) {
			t.Errorf("token leaked into %s", name)
		}
	}
}

func sessHash(t *testing.T, e *setupEnv, c *http.Cookie) string {
	t.Helper()
	sess, err := e.svc.Validate(context.Background(), c.Value)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Hash
}

func TestSetup_CSRFBoundToSession(t *testing.T) {
	e := newSetupEnv(t)
	c1 := sessionCookie(t, e.post("/setup/session", "127.0.0.1:1", "", e.form(e.token), nil))
	good := e.csrf.token(sessHash(t, e, c1))
	// minted publicly (no session) is refused for logout, session intact
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{CSRFParam: {e.csrf.token("")}}, c1); w.Code != http.StatusForbidden {
		t.Fatalf("session-less token: %d", w.Code)
	}
	// a token minted for another session is refused
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{CSRFParam: {e.csrf.token("another-session")}}, c1); w.Code != http.StatusForbidden {
		t.Fatalf("other-session token: %d", w.Code)
	}
	// the page served to an authenticated session carries a session-bound token
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/setup", nil)
	r.AddCookie(c1)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if strings.Contains(rec.Body.String(), "csrf_token") && !strings.Contains(rec.Body.String(), "End session") {
		t.Fatal("unexpected page")
	}
	if _, err := e.svc.Validate(context.Background(), c1.Value); err != nil {
		t.Fatalf("session ended by a refused request: %v", err)
	}
	if w := e.post("/setup/logout", "127.0.0.1:1", "", url.Values{CSRFParam: {good}}, c1); w.Code != http.StatusSeeOther {
		t.Fatalf("bound token: %d", w.Code)
	}
}

func TestSetup_CSRFKeySeparate(t *testing.T) {
	e := newSetupEnv(t)
	plain, err := NewCSRF(e.key)
	if err != nil {
		t.Fatal(err)
	}
	// a token of the gated UI signer is no setup token, and the reverse
	if e.csrf.valid(plain.Token(), "") {
		t.Fatal("gated-UI token accepted by setup")
	}
	if plain.Valid(e.csrf.token("")) {
		t.Fatal("setup token accepted by the gated UI")
	}
	if w := e.post("/setup/session", "127.0.0.1:1", "", url.Values{setupTokenField: {e.token}, CSRFParam: {plain.Token()}}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("exchange with UI token: %d", w.Code)
	}
}
