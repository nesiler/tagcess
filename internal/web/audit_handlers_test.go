package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/store"
)

// openAuditLogger opens a fresh database and returns an audit logger writing to it.
func openAuditLogger(t *testing.T) (*audit.Logger, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return audit.New(s.Queries()), s
}

// newAuditPage wires an audit handler behind the same identity middleware as production.
func newAuditPage(t *testing.T, logger *audit.Logger, pageSize int) http.Handler {
	t.Helper()
	h, err := NewAuditHandler(AuditHandlerConfig{Auditor: logger, CSRF: testCSRF(t), PageSize: pageSize})
	if err != nil {
		t.Fatalf("NewAuditHandler: %v", err)
	}
	return RequireDevops(h)
}

// getAudit issues an authenticated GET and returns the response.
func getAudit(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// seedAudit writes one event per (actor, event) pair.
func seedAudit(t *testing.T, logger *audit.Logger, pairs [][2]string) {
	t.Helper()
	for i, p := range pairs {
		if _, err := logger.Write(context.Background(), audit.Entry{
			Actor:  p[0],
			Event:  p[1],
			Target: fmt.Sprintf("target-%d", i),
			Result: "applied",
		}); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
}

// AC1: the audit page lists events newest first and pages them. With a page size of two, the first
// page holds the two most recent records and the second page the rest.
func TestAuditPage_ListPaged(t *testing.T) {
	logger, _ := openAuditLogger(t)
	seedAudit(t, logger, [][2]string{
		{"actor-1@example.com", "event.one"},
		{"actor-2@example.com", "event.two"},
		{"actor-3@example.com", "event.three"},
	})
	h := newAuditPage(t, logger, 2)

	first := getAudit(t, h, "/audit")
	if first.Code != http.StatusOK {
		t.Fatalf("page 1 status = %d, want 200", first.Code)
	}
	body := first.Body.String()
	for _, want := range []string{"event.three", "event.two"} {
		if !strings.Contains(body, want) {
			t.Errorf("page 1 does not contain %q", want)
		}
	}
	if strings.Contains(body, "event.one") {
		t.Error("page 1 contains a record that belongs to page 2")
	}
	if strings.Index(body, "event.three") > strings.Index(body, "event.two") {
		t.Error("page 1 is not newest first (event.three should precede event.two)")
	}
	if !strings.Contains(body, "page=2") {
		t.Error("page 1 has no link to the next page")
	}

	second := getAudit(t, h, "/audit?page=2")
	if second.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200", second.Code)
	}
	body2 := second.Body.String()
	if !strings.Contains(body2, "event.one") {
		t.Error("page 2 does not contain the oldest record")
	}
	if strings.Contains(body2, "event.three") {
		t.Error("page 2 contains a record that belongs to page 1")
	}
}

// AC2: an actor or event filter shows only the matching records.
func TestAuditPage_Filter(t *testing.T) {
	logger, _ := openAuditLogger(t)
	seedAudit(t, logger, [][2]string{
		{"alice@example.com", "policy.update"},
		{"bob@example.com", "policy.update"},
		{"alice@example.com", "node.expire"},
		{"bob@example.com", "node.expire"},
	})
	h := newAuditPage(t, logger, 50)

	byActor := getAudit(t, h, "/audit?actor=alice%40example.com").Body.String()
	if !strings.Contains(byActor, "alice@example.com") {
		t.Error("actor filter dropped the matching rows")
	}
	if strings.Contains(byActor, "bob@example.com") {
		t.Error("actor filter shows rows from another actor")
	}

	byEvent := getAudit(t, h, "/audit?event=node.expire").Body.String()
	if !strings.Contains(byEvent, "node.expire") {
		t.Error("event filter dropped the matching rows")
	}
	if strings.Contains(byEvent, "policy.update") {
		t.Error("event filter shows rows of another event type")
	}
}

// AC3: the audit page offers no way to change or delete a record, in the handler and through the
// production middleware chain. The stored record survives every attempt (A-01.2).
func TestAuditPage_NoMutationRoutes(t *testing.T) {
	logger, _ := openAuditLogger(t)
	seedAudit(t, logger, [][2]string{{"alice@example.com", "policy.update"}})

	csrf := testCSRF(t)
	h, err := NewAuditHandler(AuditHandlerConfig{Auditor: logger, CSRF: csrf, PageSize: 50})
	if err != nil {
		t.Fatalf("NewAuditHandler: %v", err)
	}

	// Handler level: only GET is answered; every state-changing method is refused.
	if rec := getAudit(t, h, "/audit"); rec.Code != http.StatusOK {
		t.Fatalf("GET /audit status = %d, want 200", rec.Code)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), method, "/audit", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /audit status = %d, want 405", method, rec.Code)
		}
	}

	// Production chain: the same identity + CSRF middleware as main.go. A state-changing request is
	// rejected before it reaches the handler, with or without a token.
	mux := http.NewServeMux()
	mux.Handle("/audit", h)
	chain := RequireDevops(csrf.Protect(mux))
	for _, token := range []string{"", csrf.Token()} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/audit", nil)
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerGroups, "devops")
		if token != "" {
			req.Header.Set(CSRFHeader, token)
		}
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE /audit (token=%v) status = %d, want 403 or 405", token != "", rec.Code)
		}
	}

	events, err := logger.List(context.Background(), audit.Filter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want the seeded record intact", len(events))
	}
}

// Audit values come from Zitadel and Headscale, so they must be escaped before they reach the page
// (F1-003 follow-up). A value that looks like markup is shown as text, not executed.
func TestAuditPage_EscapesValues(t *testing.T) {
	logger, _ := openAuditLogger(t)
	if _, err := logger.Write(context.Background(), audit.Entry{
		Actor:  `<script>alert(1)</script>@example.com`,
		Event:  `policy.<img src=x onerror=alert(1)>`,
		Target: `headscale/"><script>`,
		Diff:   audit.Diff{{Field: "groups", Before: `<b>a</b>`, After: `<b>b</b>`}},
		Result: "applied",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := getAudit(t, newAuditPage(t, logger, 50), "/audit").Body.String()

	for _, raw := range []string{"<script>", "<img", "<b>"} {
		if strings.Contains(body, raw) {
			t.Errorf("page contains unescaped %q", raw)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("page does not show the escaped markup as text")
	}
}
