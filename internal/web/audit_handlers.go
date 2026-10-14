package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
)

// defaultAuditPageSize is the number of records shown per page when a config leaves it unset.
const defaultAuditPageSize = 50

// maxAuditPage bounds the page number so the offset cannot overflow. The UI never links past the
// available pages, so this only affects a hand-crafted URL.
const maxAuditPage = 1 << 20

// Auditor lists audit events for the audit page. It is read-only: *audit.Logger satisfies it, and the
// page exposes no way to write, change or delete a record (A-01.2).
type Auditor interface {
	List(ctx context.Context, f audit.Filter) ([]audit.Event, error)
}

// AuditHandlerConfig wires the audit page.
type AuditHandlerConfig struct {
	// Auditor reads the records. Required.
	Auditor Auditor
	// CSRF signs the token embedded in the page. Required.
	CSRF *CSRF
	// PageSize bounds one page; 0 uses the default.
	PageSize int
}

// AuditHandler renders the read-only audit log. It answers only GET; every other method is refused, so
// the page can never become an endpoint that changes or deletes a record (A-01.2).
type AuditHandler struct {
	auditor  Auditor
	csrf     *CSRF
	pageSize int
}

// NewAuditHandler validates the wiring.
func NewAuditHandler(cfg AuditHandlerConfig) (*AuditHandler, error) {
	switch {
	case cfg.Auditor == nil:
		return nil, errors.New("web: audit page needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: audit page needs a CSRF signer")
	case cfg.PageSize < 0:
		return nil, errors.New("web: audit page size cannot be negative")
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = defaultAuditPageSize
	}
	return &AuditHandler{auditor: cfg.Auditor, csrf: cfg.CSRF, pageSize: cfg.PageSize}, nil
}

// ServeHTTP renders one page of the log, optionally filtered by actor and event type. It fetches one
// record beyond the page size to know whether a next page exists without a second query.
func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor, _ := ActorFrom(r.Context())
	query := r.URL.Query()
	actorFilter := strings.TrimSpace(query.Get("actor"))
	eventFilter := strings.TrimSpace(query.Get("event"))
	page := parseAuditPage(query.Get("page"))

	events, err := h.auditor.List(r.Context(), audit.Filter{
		Actor:  actorFilter,
		Event:  eventFilter,
		Offset: (page - 1) * h.pageSize,
		Limit:  h.pageSize + 1,
	})
	if err != nil {
		http.Error(w, "audit read failed", http.StatusInternalServerError)
		return
	}
	hasNext := len(events) > h.pageSize
	if hasNext {
		events = events[:h.pageSize]
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "audit", "Audit",
		AuditPage(events, actorFilter, eventFilter, page, hasNext)).Render(r.Context(), w)
}

// parseAuditPage returns the 1-based page number, falling back to 1 for anything invalid and capping
// the value so the offset stays in range.
func parseAuditPage(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 {
		return 1
	}
	return min(n, maxAuditPage)
}

// auditPageURL builds a page link that keeps the current filter.
func auditPageURL(actor, event string, page int) string {
	values := url.Values{}
	if actor != "" {
		values.Set("actor", actor)
	}
	if event != "" {
		values.Set("event", event)
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if len(values) == 0 {
		return "/audit"
	}
	return "/audit?" + values.Encode()
}
