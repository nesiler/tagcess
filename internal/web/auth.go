// Package web serves tagcess's own interface. The interface only listens on a unix socket that
// Caddy proxies to (ADR 0004, NFR-02): identity headers are trusted only there, and only requests
// whose groups contain the admin group (default "devops") pass. State-changing requests must carry a CSRF token (NFR-03).
package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"unicode"
)

// Identity headers set by Caddy from oauth2-proxy. Caddy strips any client-supplied header of the
// same name before forward_auth (security.md §3.1), and the UI socket is the only listener, so a
// request that reaches the handler can only carry proxy-set values.
const (
	headerUser   = "X-Auth-Request-User"
	headerEmail  = "X-Auth-Request-Email"
	headerGroups = "X-Auth-Request-Groups"
)

// devopsGroup is the admin group while no setting says otherwise (NFR-02).
const devopsGroup = "devops"

// AdminGroupSource returns the group allowed into the interface; it is read on every request so a
// changed setting applies without a restart.
type AdminGroupSource func(ctx context.Context) (string, error)

// AdminGroupState is the admin group the UI middleware enforces right now. A group change moves it
// only after the generated Caddy gate carries the same group (hs_settings), so the two gates never
// disagree; until then the previous group stays in force. Until set it loads from load once.
type AdminGroupState struct {
	mu    sync.Mutex
	group string
	load  AdminGroupSource
}

// NewAdminGroupState returns a state whose first value comes from load (the stored setting).
func NewAdminGroupState(load AdminGroupSource) *AdminGroupState { return &AdminGroupState{load: load} }

// Current is the effective group; an unreadable first load returns the error and stays unset.
func (s *AdminGroupState) Current(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.group == "" && s.load != nil {
		g, err := s.load(ctx)
		if err != nil {
			return "", err
		}
		s.group = g
	}
	return s.group, nil
}

// Set makes g the effective group.
func (s *AdminGroupState) Set(g string) {
	s.mu.Lock()
	s.group = g
	s.mu.Unlock()
}

// Pin fixes g as the effective group unless one is already in force.
func (s *AdminGroupState) Pin(g string) {
	s.mu.Lock()
	if s.group == "" {
		s.group = g
	}
	s.mu.Unlock()
}

// Actor is the authenticated devops user bound to a request by RequireDevops.
type Actor struct {
	User   string
	Email  string
	Groups []string
}

// HasGroup reports whether the actor belongs to group.
func (a Actor) HasGroup(group string) bool {
	for _, g := range a.Groups {
		if g == group {
			return true
		}
	}
	return false
}

type actorKey struct{}

// ActorFrom returns the actor bound to ctx by RequireDevops.
func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// RequireDevops wraps h so only requests carrying the devops group reach it. Anything else gets 403;
// the body is empty because the identity comes from Caddy and is not tagcess's to explain. The
// parsed actor is bound to the request context for handlers downstream.
func RequireDevops(h http.Handler) http.Handler {
	return RequireGroup(nil, h)
}

// RequireGroup is RequireDevops with the admitted group read from src. A nil src means "devops". If
// src fails or returns nothing, the last good group is kept (fail safe, never widened); with none
// yet, the request is refused.
func RequireGroup(src AdminGroupSource, h http.Handler) http.Handler {
	var mu sync.Mutex
	last := ""
	current := func(ctx context.Context) string {
		if src == nil {
			return devopsGroup
		}
		g, err := src(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err == nil && g != "" {
			last = g
		}
		return last
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := Actor{
			User:   r.Header.Get(headerUser),
			Email:  r.Header.Get(headerEmail),
			Groups: parseGroups(r.Header.Values(headerGroups)),
		}
		if g := current(r.Context()); g == "" || !actor.HasGroup(g) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}

// parseGroups splits the groups header into tokens. oauth2-proxy has joined the groups claim with
// commas in some versions and with spaces in others, so both separators are accepted; the identity
// boundary is the proxy header, not this parsing. Zitadel role keys cannot contain either character.
func parseGroups(values []string) []string {
	var out []string
	for _, v := range values {
		out = append(out, strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})...)
	}
	return out
}
