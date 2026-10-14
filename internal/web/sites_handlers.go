package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// healthUnknown is the status shown when no health data exists (K-02/F4). The list never assumes
// a site is healthy: an unknown status is shown as unknown, not left blank and not made green.
const healthUnknown = "bilinmiyor"

// SiteLister reads the site records for the list page. It is satisfied by *site.Store.
type SiteLister interface {
	ListSites(ctx context.Context) ([]site.Site, error)
}

// SiteHealthReader reports a site's health when configured (ObservationSiteHealth). Without a
// reader, or when it knows nothing, the list shows "bilinmiyor".
type SiteHealthReader interface {
	Health(ctx context.Context, s site.Site) (SiteHealth, bool)
}

// SiteView is one row of the site list.
type SiteView struct {
	ID             int64
	Hosts          []string
	Kind           string
	SystemTemplate string
	Roles          []string
	Target         string
	TargetURL      string
	Health         string
	// CheckedAt is the time of the latest health check; zero when unknown.
	CheckedAt time.Time
	UpdatedAt time.Time
}

// SitesHandlerConfig wires the site list page.
type SitesHandlerConfig struct {
	// Lister reads the sites. Required.
	Lister SiteLister
	// Health is optional; nil means no health data is available.
	Health SiteHealthReader
	// CSRF signs the token embedded in the page. Required.
	CSRF *CSRF
}

// SitesHandler serves the read-only site list at /sites (S-01). It is mounted behind
// RequireDevops and CSRF.Protect, like the other pages.
type SitesHandler struct {
	cfg SitesHandlerConfig
}

// NewSitesHandler validates the wiring.
func NewSitesHandler(cfg SitesHandlerConfig) (*SitesHandler, error) {
	switch {
	case cfg.Lister == nil:
		return nil, errors.New("web: sites page needs a lister")
	case cfg.CSRF == nil:
		return nil, errors.New("web: sites page needs a CSRF signer")
	}
	return &SitesHandler{cfg: cfg}, nil
}

// Register adds the sites routes to mux. The form's routes (F2-013) are registered by
// SiteFormHandler under the same /sites namespace.
func (h *SitesHandler) Register(mux *http.ServeMux) {
	mux.Handle("GET /sites", http.HandlerFunc(h.list))
}

// list renders the site list. It is read-only: only GET is answered.
func (h *SitesHandler) list(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	sites, err := h.cfg.Lister.ListSites(r.Context())
	if err != nil {
		http.Error(w, "siteler okunamadı", http.StatusInternalServerError)
		return
	}
	views := make([]SiteView, 0, len(sites))
	for _, s := range sites {
		views = append(views, h.view(r.Context(), s))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "siteler", "Siteler",
		SitesPage(views, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// view turns a stored site into a list row. Health is looked up when a reader is configured and
// falls back to healthUnknown otherwise.
func (h *SitesHandler) view(ctx context.Context, s site.Site) SiteView {
	health := healthUnknown
	var checked time.Time
	if h.cfg.Health != nil {
		if got, ok := h.cfg.Health.Health(ctx, s); ok && strings.TrimSpace(got.Status) != "" {
			health, checked = got.Status, got.CheckedAt
		}
	}
	return SiteView{
		ID:             s.ID,
		Hosts:          s.Hosts,
		Kind:           s.Kind,
		SystemTemplate: s.SystemTemplate,
		Roles:          append(append([]string{}, s.Roles...), s.TargetRoles...),
		Target:         s.TargetKind,
		TargetURL:      s.TargetURL,
		Health:         health,
		CheckedAt:      checked,
		UpdatedAt:      s.UpdatedAt,
	}
}

// kindLabel is the Turkish label of a site kind for the list.
func kindLabel(kind string) string {
	switch kind {
	case site.KindRole:
		return "rol"
	case site.KindOpen:
		return "açık"
	case site.KindSystem:
		return "sistem"
	default:
		return kind
	}
}

// targetLabel is the list's target text: the url for url targets, the kind otherwise.
func targetLabel(v SiteView) string {
	if v.Kind == site.KindSystem {
		// A system site's upstream comes from its template; the stored k8s kind is only the
		// placeholder the renderer requires and must not be shown as the target.
		return "sistem şablonunun kendi hedefi"
	}
	if v.Target == site.TargetURL && v.TargetURL != "" {
		return v.TargetURL
	}
	return v.Target
}

// healthTone colours a health status: without data it is never shown as healthy.
func healthTone(h string) ui.Tone {
	switch h {
	case "sağlıklı":
		return ui.OK
	case "başarısız", "hata", siteHealthProblem:
		return ui.Err
	case "güncel değil", "eski":
		return ui.Stale
	default:
		return ui.Off
	}
}

// systemLabel names a system site by its template, e.g. "sistem (zitadel)".
func systemLabel(v SiteView) string {
	if v.Kind != site.KindSystem {
		return kindLabel(v.Kind)
	}
	if v.SystemTemplate == "" {
		return kindLabel(v.Kind)
	}
	return fmt.Sprintf("%s (%s)", kindLabel(v.Kind), v.SystemTemplate)
}
