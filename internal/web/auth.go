// Package web serves tagcess's own interface. The interface only listens on a unix socket that
// Caddy proxies to (ADR 0004, NFR-02): identity headers are trusted only there, and only requests
// whose groups contain "devops" pass. State-changing requests must carry a CSRF token (NFR-03).
package web

import (
	"context"
	"net/http"
	"strings"
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

// devopsGroup is the only group allowed into the interface (NFR-02).
const devopsGroup = "devops"

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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := Actor{
			User:   r.Header.Get(headerUser),
			Email:  r.Header.Get(headerEmail),
			Groups: parseGroups(r.Header.Values(headerGroups)),
		}
		if !actor.HasGroup(devopsGroup) {
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
