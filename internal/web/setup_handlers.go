package web

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/setup"
)

const (
	// SetupCookie is the setup session cookie (setup-flow.md §2.2). The __Host- prefix needs
	// Secure, Path=/ and no Domain.
	SetupCookie = "__Host-tagcess_setup"
	// SetupClientIPHeader carries the connection's address from the bootstrap Caddyfile, which
	// overwrites any client value. It is read only on loopback connections (setup-flow.md §2.1).
	SetupClientIPHeader = "X-Tagcess-Client-IP"

	setupTokenField = "token"
)

// SetupSessions is what the setup handler needs from internal/setup.
type SetupSessions interface {
	Exchange(ctx context.Context, token, source string) (string, error)
	Validate(ctx context.Context, cookie string) (setup.Session, error)
	End(ctx context.Context, sess setup.Session) error
}

// SetupHandler serves the setup listener: the token exchange and the pages behind the setup
// session. It reads no identity headers and serves nothing outside /setup/*.
type SetupHandler struct {
	sessions SetupSessions
	csrf     *CSRF
	audit    *audit.Logger
	log      *slog.Logger
	mux      *http.ServeMux
}

// NewSetupHandler returns the handler for the setup listener. Every state change needs CSRF.
func NewSetupHandler(sessions SetupSessions, csrf *CSRF, aud *audit.Logger, log *slog.Logger) http.Handler {
	h := &SetupHandler{sessions: sessions, csrf: csrf, audit: aud, log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /setup", h.page)
	h.mux.HandleFunc("GET /setup/{$}", h.page)
	h.mux.HandleFunc("POST /setup/session", h.exchange)
	h.mux.HandleFunc("POST /setup/logout", h.logout)
	return csrf.Protect(h)
}

func (h *SetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	p := r.URL.Path
	if p != "/setup" && !strings.HasPrefix(p, "/setup/") {
		http.NotFound(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// sourceAddr is the address the attempt limits and the audit use. The forwarded header counts only
// when the connection itself is loopback (Caddy or an SSH tunnel); from anywhere else it is a
// spoofable client value and is ignored.
func sourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if fwd := net.ParseIP(strings.TrimSpace(r.Header.Get(SetupClientIPHeader))); fwd != nil {
			return fwd.String()
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

var setupPage = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>tagcess setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>
<main><h1>tagcess setup</h1>
{{if .Authenticated}}
<p>Setup session active.</p>
<form method="post" action="/setup/logout"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button type="submit">End session</button></form>
{{else}}
<form method="post" action="/setup/session" autocomplete="off">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label>Setup token <input type="password" name="token" autocomplete="off" required></label>
<button type="submit">Continue</button></form>
{{end}}
</main></body></html>
`))

func (h *SetupHandler) page(w http.ResponseWriter, r *http.Request) {
	_, authed := h.session(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setupPage.Execute(w, struct {
		Authenticated bool
		CSRF          string
	}{authed, h.csrf.Token()})
}

func (h *SetupHandler) session(r *http.Request) (setup.Session, bool) {
	c, err := r.Cookie(SetupCookie)
	if err != nil {
		return setup.Session{}, false
	}
	sess, err := h.sessions.Validate(r.Context(), c.Value)
	return sess, err == nil
}

func (h *SetupHandler) exchange(w http.ResponseWriter, r *http.Request) {
	src := sourceAddr(r)
	cookie, err := h.sessions.Exchange(r.Context(), r.PostFormValue(setupTokenField), src)
	switch {
	case errors.Is(err, setup.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	case errors.Is(err, setup.ErrInvalidToken):
		h.record(r.Context(), "setup:anonymous", "setup_session_denied", src)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	case err != nil:
		h.log.Error("setup exchange failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The audit actor needs the session's id; validating the fresh cookie yields it.
	actor := "setup:unknown"
	if sess, verr := h.sessions.Validate(r.Context(), cookie); verr == nil {
		actor = sess.Actor
	}
	h.record(r.Context(), actor, "setup_session_started", src)
	http.SetCookie(w, &http.Cookie{
		Name: SetupCookie, Value: cookie, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(setup.SessionMax.Seconds()),
	})
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (h *SetupHandler) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.session(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.sessions.End(r.Context(), sess); err != nil {
		h.log.Error("setup end session failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.record(r.Context(), sess.Actor, "setup_session_ended", sourceAddr(r))
	http.SetCookie(w, &http.Cookie{Name: SetupCookie, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

// record writes an audit event with the source address. It never receives the token.
func (h *SetupHandler) record(ctx context.Context, actor, event, source string) {
	if h.audit == nil {
		return
	}
	if _, err := h.audit.Write(ctx, audit.Entry{Actor: actor, Event: event, Target: "setup", Result: "source=" + source}); err != nil {
		h.log.Error("setup audit failed", "event", event, "error", err)
	}
}
