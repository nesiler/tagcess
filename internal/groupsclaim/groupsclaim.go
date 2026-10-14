// Package groupsclaim is the Zitadel Actions v2 `preuserinfo` receiver that flattens a user's
// `vpn` project role grants into the `groups` claim (F1-026). It is the test-stack counterpart of
// the Action that production Zitadel already manages in its console (overview.md §6.3): the
// v2 `rest_call` target delivers a signed OIDC ContextInfo payload, and this handler answers with
//
//	{"append_claims":[{"key":"groups","value":["devops", ...]}]}
//
// which Zitadel copies into the ID token / userinfo verbatim (stack-notes: only a `rest_call`
// response is applied, and a bare `{"groups":[...]}` does not work).
//
// Roles have exactly two sources, both read-only, and there is no separate role store (AGENTS rule
// 3): the grants embedded in the payload are authoritative when present, otherwise the configured
// GrantReader (the F1-007 Zitadel client) is asked. If neither source has anything — including a
// failed read — no claim is added, so a broken read can never widen access (fail safe, rule 7).
package groupsclaim

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const (
	// claimName is the claim Zitadel copies from the response into the token/userinfo.
	claimName = "groups"
	// maxBody caps the ContextInfo payload: it is refused before the signature is checked. It
	// matches the webhook limit (security.md §6.1); the ContextInfo body is a few KB.
	maxBody = 64 << 10
	// rejectLogWindow bounds rejection logging to one entry per window, so a flood cannot fill the
	// log or grow memory (security.md §6.5).
	rejectLogWindow = time.Second
)

// GrantReader reads the role grants of the configured project (see zitadel.Client). It is the
// fallback source when the payload carries no `vpn` grant.
type GrantReader interface {
	ListGrants(ctx context.Context) ([]zitadel.Grant, error)
}

// Logger records rejection entries; it matches *slog.Logger. Implementations must be safe for
// concurrent use.
type Logger interface {
	Warn(msg string, args ...any)
}

// Config wires a Handler. SigningKey and ProjectID are required; Grants may be nil, in which case
// the payload grants are the only source.
type Config struct {
	// SigningKey verifies the Zitadel-Signature header (the target's key, shown once by
	// CreateTarget).
	SigningKey []byte
	// ProjectID is the `vpn` project whose grants become groups; grants of other projects are
	// ignored.
	ProjectID string
	// Grants reads the project's grants when the payload has none. Nil disables the fallback.
	Grants GrantReader
	// Clock overrides time.Now (tests).
	Clock func() time.Time
	// OnRoles, when set, is called after a signed request for a user that has at least one role was
	// answered: the user just signed in, so their Headscale group membership may be stale (F5 I13).
	// It must not block; the caller debounces it.
	OnRoles func()
	// Logger defaults to slog.Default.
	Logger Logger
}

// Handler is the http.Handler Zitadel's `preuserinfo` rest_call target posts to.
type Handler struct {
	key       []byte
	projectID string
	grants    GrantReader
	clock     func() time.Time
	log       Logger
	onRoles   func()
	rejects   *rejectLimiter
}

// New validates the wiring and returns the handler.
func New(cfg Config) (*Handler, error) {
	if len(cfg.SigningKey) == 0 {
		return nil, errors.New("groupsclaim: a signing key is required")
	}
	if cfg.ProjectID == "" {
		return nil, errors.New("groupsclaim: a project id is required")
	}
	h := &Handler{
		key:       cfg.SigningKey,
		projectID: cfg.ProjectID,
		grants:    cfg.Grants,
		clock:     cfg.Clock,
		log:       cfg.Logger,
		onRoles:   cfg.OnRoles,
	}
	if h.clock == nil {
		h.clock = time.Now
	}
	if h.log == nil {
		h.log = defaultLogger{}
	}
	h.rejects = &rejectLimiter{clock: h.clock}
	return h, nil
}

// contextInfo is the subset of Zitadel's oidc.ContextInfo function payload this handler needs
// (stack-notes: the top-level fields, `user.id`/`userinfo.sub` and `user_grants[]`).
type contextInfo struct {
	Function string `json:"function"`
	UserInfo struct {
		Sub string `json:"sub"`
	} `json:"userinfo"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	UserGrants []payloadGrant `json:"user_grants"`
}

type payloadGrant struct {
	ProjectID   string   `json:"project_id"`
	ProjectName string   `json:"project_name"`
	Roles       []string `json:"roles"`
}

func (c contextInfo) userID() string {
	if c.User.ID != "" {
		return c.User.ID
	}
	return c.UserInfo.Sub
}

// ServeHTTP verifies the signature, derives the user's `vpn` roles and answers with the
// `append_claims` contract. Responses carry no reason (security.md §6.5): 200 with the (possibly
// empty) claim list, 401 on a bad signature/timestamp, 400 on an unparsable body, 413 on an
// oversized body, 405 for a non-POST.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.reject(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	if err := hook.VerifySignature(h.key, body, r.Header.Get(hook.Header), h.clock().UTC()); err != nil {
		h.reject(w, r, http.StatusUnauthorized, "bad_signature")
		return
	}
	var info contextInfo
	if err := json.Unmarshal(body, &info); err != nil {
		h.reject(w, r, http.StatusBadRequest, "bad_body")
		return
	}

	roles, found := h.payloadRoles(info)
	if !found && h.grants != nil {
		userID := info.userID()
		if userID != "" {
			apiRoles, err := h.apiRoles(r.Context(), userID)
			if err != nil {
				// A failed read is treated like an absent source: no claim, no widened access.
				h.log.Warn("groups claim fallback read failed", "user", userID, "error", err)
			} else {
				roles = apiRoles
			}
		}
	}
	h.writeClaims(w, r, roles)
	if l, ok := h.log.(interface{ Info(msg string, args ...any) }); ok {
		// One INFO line per authenticated call (F5 F1): a working signing key is visible in the log.
		// Source and role count only; never the user, the roles, the body or the headers.
		l.Info("groups claim served", "roles", len(roles), "source", r.RemoteAddr)
	}
	if len(roles) > 0 && h.onRoles != nil {
		h.onRoles()
	}
}

// payloadRoles returns the roles of the configured project found in the payload's grants and
// whether that project's grant was present at all. A present-but-empty grant is authoritative:
// callers must not fall back to the API for it.
func (h *Handler) payloadRoles(info contextInfo) (roles []string, found bool) {
	for _, g := range info.UserGrants {
		if g.ProjectID != h.projectID {
			continue
		}
		found = true
		roles = append(roles, g.Roles...)
	}
	return dedupeSorted(roles), found
}

// apiRoles reads the project's grants and keeps the ones of userID.
func (h *Handler) apiRoles(ctx context.Context, userID string) ([]string, error) {
	grants, err := h.grants.ListGrants(ctx)
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, g := range grants {
		if g.UserID == userID {
			roles = append(roles, g.Role)
		}
	}
	return dedupeSorted(roles), nil
}

// claim is one append_claims entry.
type claim struct {
	Key   string   `json:"key"`
	Value []string `json:"value"`
}

// writeClaims always answers 200 with the append_claims envelope; an empty list means "add
// nothing", which Zitadel accepts.
func (h *Handler) writeClaims(w http.ResponseWriter, req *http.Request, roles []string) {
	resp := struct {
		AppendClaims []claim `json:"append_claims"`
	}{AppendClaims: []claim{}}
	if len(roles) > 0 {
		resp.AppendClaims = []claim{{Key: claimName, Value: roles}}
	}
	out, err := json.Marshal(resp)
	if err != nil {
		h.reject(w, req, http.StatusInternalServerError, "encode_failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// readBody reads the raw body, refusing anything above maxBody before the signature is checked.
func (h *Handler) readBody(w http.ResponseWriter, req *http.Request) ([]byte, bool) {
	if req.ContentLength > maxBody {
		h.reject(w, req, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxBody)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.reject(w, req, http.StatusRequestEntityTooLarge, "body_too_large")
			return nil, false
		}
		h.reject(w, req, http.StatusBadRequest, "bad_body")
		return nil, false
	}
	return body, true
}

// reject writes a bare status and, when the rate limiter allows it, one entry with the reason and
// the source only — never the body, the headers or a secret (security.md §6.5).
func (h *Handler) reject(w http.ResponseWriter, req *http.Request, status int, reason string) {
	if h.rejects.allow() {
		h.log.Warn("groups claim rejected", "reason", reason, "source", req.RemoteAddr)
	}
	w.WriteHeader(status)
}

// defaultLogger routes to the standard logger.
type defaultLogger struct{}

func (defaultLogger) Warn(msg string, args ...any) { slog.Default().Warn(msg, args...) }
func (defaultLogger) Info(msg string, args ...any) { slog.Default().Info(msg, args...) }

func dedupeSorted(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	sort.Strings(roles)
	out := roles[:0]
	for i, role := range roles {
		if i == 0 || role != roles[i-1] {
			out = append(out, role)
		}
	}
	return out
}

// rejectLimiter admits at most one rejection entry per rejectLogWindow across all sources. It keeps
// no per-source state, so its memory is constant however many sources a flood uses.
type rejectLimiter struct {
	mu     sync.Mutex
	window time.Time
	n      int
	clock  func() time.Time
}

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
