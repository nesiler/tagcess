package web

import "net/http"

// NavPages serves the small routes behind the top navigation and the browser: the settings index,
// the k8s section root and the draft list redirect, and an empty favicon. It is mounted behind
// RequireDevops like every other page.
type NavPages struct {
	csrf *CSRF
}

// NewNavPages returns the handler; csrf signs the layout's logout/forms token.
func NewNavPages(csrf *CSRF) *NavPages { return &NavPages{csrf: csrf} }

// Register adds the routes to mux.
func (h *NavPages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings", h.settings)
	mux.HandleFunc("GET /k8s", redirectTo("/k8s/discovery"))
	mux.HandleFunc("GET /k8s/drafts", redirectTo("/k8s/discovery"))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func redirectTo(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}

func (h *NavPages) settings(w http.ResponseWriter, r *http.Request) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "ayarlar", "Ayarlar", SettingsIndexPage()).Render(r.Context(), w)
}
