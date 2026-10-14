package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/nesiler/tagcess/internal/change"
)

// UsersHandlerConfig wires the users page.
type UsersHandlerConfig struct {
	// Reader assembles the page snapshot. Required.
	Reader UsersReader
	// DryRun carries the dry-run state of the section tab bar's note (R2 karar 22, F3-012). Required.
	DryRun change.DryRun
	CSRF   *CSRF
}

// UsersReader assembles the users page snapshot. The production reader is *UsersService; it is an
// interface so handler tests can supply a fixed snapshot.
type UsersReader interface {
	Users(ctx context.Context) (UsersView, error)
}

// UsersHandler serves the read-only Headscale users screen (H-02). It is mounted behind
// RequireDevops like every page. It has exactly one route and no write action: users are created
// by OIDC sign-in and are never deleted or renamed from tagcess (R2 karar 8), so POST/PUT/DELETE
// on the page get 405 and anything under it 404 from the mux.
type UsersHandler struct {
	cfg UsersHandlerConfig
}

// NewUsersHandler validates the wiring.
func NewUsersHandler(cfg UsersHandlerConfig) (*UsersHandler, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("web: users page needs a reader")
	case cfg.DryRun == nil:
		return nil, errors.New("web: users page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: users page needs a CSRF signer")
	}
	return &UsersHandler{cfg: cfg}, nil
}

// Register adds the users page. Deliberately the only route of the handler.
func (h *UsersHandler) Register(mux *http.ServeMux) {
	mux.Handle("/headscale/users", http.HandlerFunc(h.page))
}

// page renders the snapshot. It is read-only: only GET is answered.
func (h *UsersHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view, err := h.cfg.Reader.Users(r.Context())
	if err != nil {
		http.Error(w, "kullanıcılar okunamadı", http.StatusInternalServerError)
		return
	}
	view.DryRun = dryRun
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Headscale kullanıcıları",
		UsersPage(view)).Render(r.Context(), w)
}
