package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/nesiler/tagcess/internal/change"
)

// DevicesHandlerConfig wires the devices screens.
type DevicesHandlerConfig struct {
	// Reader assembles the list and detail snapshots. Required.
	Reader DevicesReader
	// DryRun carries the dry-run state of the section tab bar's note (R2 karar 22). Required.
	DryRun change.DryRun
	CSRF   *CSRF
	// Actions is the device write panel (F3-014). Nil keeps the screens read-only (the F3-012
	// shape); the POST routes are served by DeviceActionsHandler regardless.
	Actions *DeviceActionsService
}

// DevicesReader assembles the devices snapshots. The production reader is *DevicesService; it is
// an interface so tests can supply a fixed snapshot.
type DevicesReader interface {
	Devices(ctx context.Context) (DevicesView, error)
	Device(ctx context.Context, id uint64) (DeviceDetailView, error)
}

// DevicesHandler serves the read-only devices screens (H-01 read side): the list whose table
// refreshes itself every 30 s (R2 karar 9), the table fragment the poll swaps, the detail page
// and the /headscale redirect to the default tab. Device actions and the protected-node badge
// arrive with F3-014/015/016.
type DevicesHandler struct {
	cfg DevicesHandlerConfig
}

// NewDevicesHandler validates the wiring.
func NewDevicesHandler(cfg DevicesHandlerConfig) (*DevicesHandler, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("web: devices page needs a reader")
	case cfg.DryRun == nil:
		return nil, errors.New("web: devices page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: devices page needs a CSRF signer")
	}
	return &DevicesHandler{cfg: cfg}, nil
}

// Register adds the devices routes: the section root redirect, the list page, the polled table
// fragment and the detail page. Deliberately no write route exists.
func (h *DevicesHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale", h.sectionRoot)
	mux.HandleFunc("GET /headscale/devices", h.page)
	mux.HandleFunc("GET /headscale/devices/table", h.table)
	mux.HandleFunc("GET /headscale/devices/{id}", h.detail)
}

// sectionRoot sends /headscale to the default tab, the device list.
func (h *DevicesHandler) sectionRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	http.Redirect(w, r, "/headscale/devices", http.StatusFound)
}

// page renders the list inside the shared layout. A failed read is the page's error state (AC5):
// the reason is shown, never rows.
func (h *DevicesHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view, err := h.cfg.Reader.Devices(r.Context())
	if err != nil {
		view = DevicesView{Err: err}
	}
	view.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Headscale cihazları",
		DevicesPage(view)).Render(r.Context(), w)
}

// table renders only the polled list fragment (AC4). The response stays a 2xx body even when
// Headscale is down: htmx does not swap error responses, so a 500 would leave the stale table on
// screen instead of the error (AC5).
func (h *DevicesHandler) table(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view, err := h.cfg.Reader.Devices(r.Context())
	if err != nil {
		view = DevicesView{Err: err}
	}
	view.DryRun = dryRun
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = DevicesTable(view).Render(r.Context(), w)
}

// detail renders one device (AC3). A failed read is the page's error state; an unknown or
// malformed id is 404.
func (h *DevicesHandler) detail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	detail, err := h.cfg.Reader.Device(r.Context(), id)
	switch {
	case errors.Is(err, errDeviceNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		detail = DeviceDetailView{Err: err}
	}
	if h.cfg.Actions != nil && detail.Err == nil {
		detail.Actions = h.cfg.Actions.Panel(r.Context(), detail.Row)
	}
	detail.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Cihaz ayrıntısı",
		DeviceDetailPage(detail, h.cfg.CSRF.Token())).Render(r.Context(), w)
}
