// Package hook is the Zitadel Actions v2 webhook receiver (architecture.md §2). It authenticates
// the request with the HMAC signature Zitadel computes (Zitadel-Signature), rejects stale and
// replayed deliveries, and then only signals the scheduler: the payload is never a source of truth
// (Y-01.4). The scheduler debounces the signals and runs the reconcile (F1-013).
//
// The listener is reached over Tailscale only (ADR 0003); the HMAC plus the ACL rule for
// tag:k8s → tag:vpn-server:<port> are the only defences, so a request that fails any check is
// dropped before the body is parsed.
package hook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

const (
	// Header is the signature header Zitadel sends. Zitadel's code constant is "ZITADEL-Signature"
	// but the wire name is "Zitadel-Signature"; http.Header is case-insensitive anyway.
	Header = "Zitadel-Signature"
	// maxBody mirrors security.md §6.1: bodies above 64 KiB are refused before the signature is
	// checked and before any parsing.
	maxBody = 64 << 10
	// tolerance is the accepted clock window around the header timestamp (security.md §6.3).
	tolerance = 5 * time.Minute
	// replayWindow is how long an event id is remembered to drop duplicates (security.md §6.3).
	replayWindow = 24 * time.Hour
	// eventTimeFormat matches the rest of the store: fixed-width UTC milliseconds, so the text
	// comparison in ClaimWebhookEvent is chronological.
	eventTimeFormat = "2006-01-02T15:04:05.000Z"
	// rejectLogWindow is the rate limit on rejection logging: at most one entry per window, so a
	// flood cannot fill the log or grow memory (security.md §6.5).
	rejectLogWindow = time.Second
)

// Rejection reasons. They are fixed tokens, never request content, so a logged entry can carry
// no body, header or secret (security.md §6.5).
const (
	reasonBadSignature   = "bad_signature"
	reasonStaleTimestamp = "stale_timestamp"
	reasonBadBody        = "bad_body"
	reasonBodyTooLarge   = "body_too_large"
	reasonMethod         = "method_not_allowed"
	reasonBadPayload     = "bad_payload"
	reasonClaimFailed    = "claim_failed"
)

// errBadSignature is returned for a missing, empty or malformed signature header. It never carries
// the header content: responses stay free of detail (security.md §6.5).
var errBadSignature = errors.New("hook: invalid signature header")

// errStaleTimestamp is returned for a well-formed signature whose timestamp falls outside the
// accepted window (security.md §6.3).
var errStaleTimestamp = errors.New("hook: signature timestamp outside the accepted window")

// Signaler receives one signal per accepted event. The scheduler (F1-013) implements it; the hook
// never runs a reconcile itself (Y-01.1, Y-01.4).
type Signaler interface {
	Signal()
}

// Logger records rejection entries. It matches *slog.Logger. Implementations must be safe for
// concurrent use.
type Logger interface {
	Warn(msg string, args ...any)
}

// Config wires a Handler. SigningKey, Queries and Trigger are required; Clock defaults to time.Now
// and Logger to slog.Default.
type Config struct {
	SigningKey []byte
	Queries    *db.Queries
	Trigger    Signaler
	Clock      func() time.Time
	Logger     Logger
}

// Handler is the webhook http.Handler.
type Handler struct {
	key     []byte
	q       *db.Queries
	trigger Signaler
	clock   func() time.Time
	log     Logger
	rejects *rejectLimiter
}

// NewHandler validates the wiring and returns the receiver.
func NewHandler(cfg Config) (*Handler, error) {
	switch {
	case len(cfg.SigningKey) == 0:
		return nil, errors.New("hook: a signing key is required")
	case cfg.Queries == nil:
		return nil, errors.New("hook: a query set is required")
	case cfg.Trigger == nil:
		return nil, errors.New("hook: a trigger is required")
	}
	h := &Handler{key: cfg.SigningKey, q: cfg.Queries, trigger: cfg.Trigger, clock: cfg.Clock, log: cfg.Logger}
	if h.clock == nil {
		h.clock = time.Now
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	h.rejects = &rejectLimiter{clock: h.clock}
	return h, nil
}

// ServeHTTP authenticates and deduplicates one delivery, then signals. Responses are short and
// carry no reason (security.md §6.5): 200 when accepted or ignored as a replay, 401 when the
// signature or timestamp fails, 413 when the body is too large, 400 for a signed but unusable
// payload, 405 for a non-POST.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.reject(w, r, http.StatusMethodNotAllowed, reasonMethod)
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	sig, err := parseSignatureHeader(r.Header.Get(Header))
	if err != nil {
		h.reject(w, r, http.StatusUnauthorized, reasonBadSignature)
		return
	}
	now := h.clock().UTC()
	if !withinTolerance(now, sig.timestamp) {
		h.reject(w, r, http.StatusUnauthorized, reasonStaleTimestamp)
		return
	}
	if !h.verify(body, sig) {
		h.reject(w, r, http.StatusUnauthorized, reasonBadSignature)
		return
	}
	// Only now is the trusted body parsed, and only for the replay key (Y-01.4).
	id, err := eventID(body)
	if err != nil {
		h.reject(w, r, http.StatusBadRequest, reasonBadPayload)
		return
	}
	fresh, err := h.claim(r.Context(), id, now)
	if err != nil {
		h.reject(w, r, http.StatusInternalServerError, reasonClaimFailed)
		return
	}
	if fresh {
		h.trigger.Signal()
	}
	h.accepted(r, fresh)
	w.WriteHeader(http.StatusOK)
}

// accepted writes the one INFO line of an authenticated delivery, so a working signing key is visible
// in the log (F5 F1). It carries the source and whether the delivery was new; never the body, the
// headers, the event id or any secret.
func (h *Handler) accepted(r *http.Request, fresh bool) {
	if l, ok := h.log.(interface{ Info(msg string, args ...any) }); ok {
		l.Info("webhook accepted", "fresh", fresh, "source", r.RemoteAddr)
	}
}

// readBody reads the raw body, refusing anything above maxBody before the signature is checked
// (security.md §6.1, Y-01.5). Reading is not parsing; the caller verifies the signature over these
// exact bytes.
func (h *Handler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > maxBody {
		h.reject(w, r, http.StatusRequestEntityTooLarge, reasonBodyTooLarge)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.reject(w, r, http.StatusRequestEntityTooLarge, reasonBodyTooLarge)
			return nil, false
		}
		h.reject(w, r, http.StatusBadRequest, reasonBadBody)
		return nil, false
	}
	return body, true
}

// verify recomputes HMAC-SHA256(key, "<unix_ts>.<rawBody>") and compares it against every offered
// v1 value.
func (h *Handler) verify(body []byte, sig signature) bool {
	return verifyMAC(h.key, body, sig)
}

// VerifySignature authenticates a signed Zitadel Actions v2 delivery: it parses the
// Zitadel-Signature header, requires the timestamp to be within ±tolerance of now (security.md
// §6.3) and checks HMAC-SHA256(key, "<unix_ts>.<rawBody>"). It is the shared verifier behind the
// webhook receiver (F1-012) and the groups-claim endpoint (F1-026). A non-nil error always means
// the request must be rejected; the error never carries the header content.
func VerifySignature(key, body []byte, header string, now time.Time) error {
	sig, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	if !withinTolerance(now, sig.timestamp) {
		return errStaleTimestamp
	}
	if !verifyMAC(key, body, sig) {
		return errBadSignature
	}
	return nil
}

// verifyMAC recomputes the HMAC over the timestamp and raw body and compares it against every
// offered v1 value. The loop does not exit early and hmac.Equal is constant time (security.md §6.2).
func verifyMAC(key, body []byte, sig signature) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strconv.FormatInt(sig.timestamp.Unix(), 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)
	matched := false
	for _, offer := range sig.values {
		if hmac.Equal(expected, offer) {
			matched = true
		}
	}
	return matched
}

// claim records the event id and reports whether it is fresh. An id seen within replayWindow is a
// duplicate and returns false without touching the row (Y-01.3).
func (h *Handler) claim(ctx context.Context, id string, now time.Time) (bool, error) {
	cutoff := now.Add(-replayWindow)
	n, err := h.q.ClaimWebhookEvent(ctx, db.ClaimWebhookEventParams{
		EventID:    id,
		ReceivedAt: now.Format(eventTimeFormat),
		FreshSince: cutoff.Format(eventTimeFormat),
	})
	if err != nil {
		return false, fmt.Errorf("hook: claim event %q: %w", id, err)
	}
	if n == 0 {
		return false, nil
	}
	// Retention is best effort: a failed cleanup must not reject an accepted event.
	_, _ = h.q.DeleteWebhookEventsBefore(ctx, cutoff.Format(eventTimeFormat))
	return true, nil
}

// reject writes a bare status (no body, no reason in the response) and, when the rate limiter
// allows it, records one entry with the reason and the source only: never the body, the headers or
// any secret (Y-01.2, security.md §6.5).
func (h *Handler) reject(w http.ResponseWriter, r *http.Request, status int, reason string) {
	if h.rejects.allow() {
		h.log.Warn("webhook rejected", "reason", reason, "source", r.RemoteAddr)
	}
	w.WriteHeader(status)
}

// rejectLimiter admits at most one rejection entry per rejectLogWindow across all sources. It keeps
// no per-source state, so its memory is constant however many sources a flood uses.
type rejectLimiter struct {
	mu     sync.Mutex
	window time.Time
	n      int
	clock  func() time.Time
}

// allow reports whether a rejection may be logged now.
func (l *rejectLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if now.Sub(l.window) >= rejectLogWindow {
		l.window = now
		l.n = 0
	}
	if l.n >= 1 {
		return false
	}
	l.n++
	return true
}

// signature is a parsed Zitadel-Signature header.
type signature struct {
	timestamp time.Time
	values    [][]byte
}

// parseSignatureHeader reads the "t=<unix_ts>,v1=<hex>[,v1=<hex>...]" format. Unknown pairs and a
// malformed rotation value are skipped; a missing timestamp or no decodable v1 is an error.
func parseSignatureHeader(header string) (signature, error) {
	var sig signature
	haveTimestamp := false
	for _, pair := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			sec, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return signature{}, errBadSignature
			}
			sig.timestamp = time.Unix(sec, 0).UTC()
			haveTimestamp = true
		case "v1":
			raw, err := hex.DecodeString(value)
			if err != nil {
				continue
			}
			sig.values = append(sig.values, raw)
		}
	}
	if !haveTimestamp || len(sig.values) == 0 {
		return signature{}, errBadSignature
	}
	return sig, nil
}

// withinTolerance reports whether t is inside ±tolerance of now (security.md §6.3). The two
// branches avoid Duration overflow for timestamps far outside the representable span.
func withinTolerance(now, t time.Time) bool {
	if t.After(now) {
		return t.Sub(now) <= tolerance
	}
	return now.Sub(t) <= tolerance
}

// event is the part of the Actions v2 payload used for the replay key. The payload has no event id;
// aggregateID + sequence is the key (stack-notes, security.md §6.3).
type event struct {
	AggregateID string `json:"aggregateID"`
	Sequence    uint64 `json:"sequence"`
}

// eventID builds the replay key from a verified payload.
func eventID(body []byte) (string, error) {
	var e event
	if err := json.Unmarshal(body, &e); err != nil {
		return "", fmt.Errorf("hook: parse payload: %w", err)
	}
	if e.AggregateID == "" {
		return "", errors.New("hook: payload has no aggregateID")
	}
	return e.AggregateID + ":" + strconv.FormatUint(e.Sequence, 10), nil
}
