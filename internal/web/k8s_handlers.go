package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// The k8s discovery screen (F4-011): the read-only view of one stored profile's inventory. It shows
// the new host candidates and their R1 draft suggestions (F4-010 draft.go), the existing site
// mappings and route loss (F4-010), the ambiguous/conflicting routes (F4-008/010) and the snapshot
// freshness (F4-007 snapshot.go) as separate observations. Nothing here applies, deletes or widens
// access, and no credential is read by this screen: it only consumes the mapping value and the
// stored snapshot state. The screen answers GET only; mounting it behind RequireDevops is the
// caller's (F4-031) job, and this task tests it in a controlled router.

// K8sDiscovery is the read-only discovery data of one stored profile: the host-based mapping
// (F4-010) and the snapshot freshness (F4-007). A failed read is not an error here: the mapping is
// the last good observation and State carries the failure, so the screen never loses the last known
// state.
type K8sDiscovery struct {
	Report k8s.DraftReport
	State  k8s.State
	// PublicChecked is false when the profile declares no public listener: the internet-exposure
	// check was not performed (F5 I3) and the screens say so instead of inventing a result.
	PublicChecked bool
}

// K8sDiscoveryReader builds the discovery data. F4-031 wires it to the reader over the stored
// profile and snapshot store; the screen itself holds no credential and reads no cluster.
type K8sDiscoveryReader interface {
	Discovery(ctx context.Context) (K8sDiscovery, error)
}

// K8sDiscoveryConfig wires the discovery screen. Every field is required.
type K8sDiscoveryConfig struct {
	// Reader supplies the F4-010 mapping and the F4-007 freshness.
	Reader K8sDiscoveryReader
	// CSRF signs the token embedded in the shared layout.
	CSRF *CSRF
}

// K8sDiscoveryHandler serves the discovery screen.
type K8sDiscoveryHandler struct {
	cfg K8sDiscoveryConfig
}

// NewK8sDiscoveryHandler validates the wiring.
func NewK8sDiscoveryHandler(cfg K8sDiscoveryConfig) (*K8sDiscoveryHandler, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("web: k8s discovery needs a reader")
	case cfg.CSRF == nil:
		return nil, errors.New("web: k8s discovery needs a CSRF signer")
	}
	return &K8sDiscoveryHandler{cfg: cfg}, nil
}

// Register adds the discovery route to mux. The caller mounts it behind RequireDevops; only GET is
// served, so the screen cannot mutate anything.
func (h *K8sDiscoveryHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /k8s/discovery", h.page)
}

// K8sFreshnessView is the F4-007 snapshot state: the last good snapshot, the last attempt and the
// old-scope snapshot, each shown separately so old data is never presented as current.
type K8sFreshnessView struct {
	Current     *k8s.Snapshot
	LastAttempt *k8s.Attempt
	Stale       bool
	Previous    *k8s.Snapshot
}

// K8sCandidateView is one new host candidate and its R1 draft suggestion.
type K8sCandidateView struct {
	Host             string
	Target           string
	Cert             string
	AccessChoice     string
	Roles            []string
	Note             string
	ReviewState      string
	ReviewReason     string
	ReviewCandidates []string
	ReviewDefault    string
	Routes           []k8s.Route
	Complete         bool
}

// K8sManagedView is one applied site's read-only mapping observation. AccessChoice and Roles are the
// preserved site values, never an apply proposal.
type K8sManagedView struct {
	SiteID       int64
	Hosts        []string
	Status       k8s.ManagedStatus
	AccessChoice string
	Roles        []string
}

// K8sDiscoveryView is the page data.
type K8sDiscoveryView struct {
	Complete      bool
	Freshness     K8sFreshnessView
	Candidates    []K8sCandidateView
	Managed       []K8sManagedView
	Uncertainties []k8s.Uncertainty
	Conflicts     []k8s.Conflict
	Scope         k8s.Scope
	Error         string
	// NotSetUp is true while no connection profile exists: the screen asks for the setup (F5 G3).
	NotSetUp      bool
	PublicChecked bool
}

// page renders the discovery screen. A failed seam read keeps the screen usable: the error is shown
// and no data is invented (fail safe).
func (h *K8sDiscoveryHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	v := h.view(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "k8s", "k8s discovery",
		K8sDiscoveryPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// view reads the seam and flattens the mapping into the page model. A read failure yields an error
// view with no discovery data.
func (h *K8sDiscoveryHandler) view(ctx context.Context) K8sDiscoveryView {
	got, err := h.cfg.Reader.Discovery(ctx)
	if errors.Is(err, k8s.ErrNotSet) {
		// Not an error: the cluster is simply not configured yet (F5 G4).
		slog.Default().Info("k8s discovery: no connection profile yet")
		return K8sDiscoveryView{NotSetUp: true}
	}
	if err != nil {
		slog.Default().Warn("k8s discovery: read failed", "err", err)
		return K8sDiscoveryView{Error: "discovery verisi okunamadı; gösterilen erişim/okuma durumu değişmedi"}
	}
	report := got.Report
	v := K8sDiscoveryView{
		Complete:      report.Complete,
		Freshness:     K8sFreshnessView{Current: got.State.Current, LastAttempt: got.State.LastAttempt, Stale: got.State.Stale, Previous: got.State.Previous},
		Uncertainties: report.Uncertainties,
		Conflicts:     report.Conflicts,
		Scope:         report.Scope,
		PublicChecked: got.PublicChecked,
	}
	for _, d := range report.Drafts {
		v.Candidates = append(v.Candidates, K8sCandidateView{
			Host: d.Host, Target: d.Target, Cert: d.Cert,
			AccessChoice: d.AccessChoice, Roles: d.Roles, Note: d.Note,
			ReviewState: d.ReviewState, ReviewReason: d.ReviewReason,
			ReviewCandidates: d.ReviewCandidates, ReviewDefault: d.ReviewDefault,
			Routes: d.Routes, Complete: d.Complete(),
		})
	}
	for _, m := range report.Managed {
		v.Managed = append(v.Managed, K8sManagedView{
			SiteID: m.SiteID, Hosts: m.Hosts, Status: m.Status,
			AccessChoice: m.AccessChoice, Roles: m.Roles,
		})
	}
	return v
}

// freshnessState is the machine-readable freshness of the display, used by the template's
// data-freshness attribute: only a current, non-stale snapshot is "current".
func freshnessState(f K8sFreshnessView) string {
	switch {
	case f.Current != nil && !f.Stale:
		return "current"
	case f.Current != nil:
		return "stale"
	case f.Previous != nil:
		return "previous"
	default:
		return "none"
	}
}

// reasonLabel is the Turkish label of a review reason. Unknown codes fall back to the code itself so
// nothing is hidden.
func reasonLabel(r k8s.Reason) string {
	switch r {
	case k8s.ReasonClassAmbiguous:
		return "sınıf belirsiz"
	case k8s.ReasonClassUnknown:
		return "profil dışı sınıf"
	case k8s.ReasonControllerMismatch:
		return "controller uyuşmuyor"
	case k8s.ReasonEntryPointUnresolved:
		return "entryPoint çözülemedi"
	case k8s.ReasonWildcardHost:
		return "wildcard host"
	case k8s.ReasonEmptyHost:
		return "boş host"
	case k8s.ReasonResourceBackend:
		return "resource backend"
	case k8s.ReasonBackendUnresolved:
		return "backend çözülemedi"
	case k8s.ReasonDefaultBackend:
		return "default backend"
	case k8s.ReasonImplementationSpecific:
		return "ImplementationSpecific path"
	case k8s.ReasonTargetUnresolved:
		return "internal hedef çözülemedi"
	case k8s.ReasonInvalidHost:
		return "geçersiz host"
	case k8s.ReasonRouteConflict:
		return "route çelişkisi"
	case k8s.ReasonProfileIncomplete:
		return "profil eksik"
	case k8s.ReasonServiceNotInSnapshot:
		return "servis taramada yok"
	case k8s.ReasonServicePortUnresolved:
		return "servis portu çözülemedi"
	default:
		return string(r)
	}
}

// reviewReasonLabel renders the comma-joined Draft.ReviewReason as labels.
func reviewReasonLabel(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		label := reasonLabel(k8s.Reason(p))
		if catchAllReason(k8s.Reason(p)) {
			// The reason comes from a catch-all Ingress, not from the host's own rules (U-17); the
			// draft names where to look instead of reading as a flaw of this host.
			label += " (bir Ingress'teki catch-all kural tüm host'ları kapsar; bkz. Belirsiz route'lar)"
		}
		out = append(out, label)
	}
	return strings.Join(out, ", ")
}

// catchAllReason reports a reason an Ingress-wide uncertainty (empty host, default backend) adds to
// every candidate host it could cover.
func catchAllReason(r k8s.Reason) bool {
	return r == k8s.ReasonDefaultBackend || r == k8s.ReasonEmptyHost
}

// managedStatusLabel is the Turkish label of a managed-site observation status.
func managedStatusLabel(s k8s.ManagedStatus) string {
	switch s {
	case k8s.ManagedMatched:
		return "eşleşti"
	case k8s.ManagedNoRoute:
		return "route eşleşmesi yok"
	case k8s.ManagedChanged:
		return "route değişti"
	case k8s.ManagedUnknown:
		return "bilinmiyor"
	case k8s.ManagedSystem:
		return "sistem şablonu (k8s dışı)"
	case k8s.ManagedConflict:
		return "route çelişkisi: inceleme gerekli"
	default:
		return string(s)
	}
}

// accessChoiceLabel is the Turkish label of a draft's private access choice.
func accessChoiceLabel(choice string) string {
	switch choice {
	case k8s.AccessChoiceOpen:
		return "tüm VPN kullanıcıları (açık)"
	case k8s.AccessChoiceRole:
		return "seçili roller"
	default:
		return "seçilmedi"
	}
}

// scopeItemLabel is the Turkish label of a scanned/unscanned scope item.
func scopeItemLabel(s k8s.ScopeItem) string {
	switch s {
	case k8s.ScannedIngress:
		return "Ingress"
	case k8s.ScannedService:
		return "Service"
	case k8s.ScannedIngressClass:
		return "IngressClass"
	case k8s.UnscannedGatewayAPI:
		return "Gateway API"
	case k8s.UnscannedTraefikCRD:
		return "Traefik CRD'leri"
	case k8s.UnscannedOtherController:
		return "diğer controller'lar"
	case k8s.UnscannedOtherPaths:
		return "hostNetwork ve diğer Ingress dışı yollar"
	default:
		return string(s)
	}
}

// backendLabel renders a route backend as service:port, preferring the named port.
func backendLabel(b k8s.Backend) string {
	if b.Service == "" {
		return "backend yok"
	}
	port := b.PortName
	if port == "" {
		port = fmt.Sprintf("%d", b.PortNumber)
	}
	return b.Service + ":" + port
}

// routeProvenance is the route identity shown with a candidate: namespace/Ingress UID host path.
func routeProvenance(r k8s.Route) string {
	return fmt.Sprintf("%s/%s [%s] %s%s -> %s", r.Namespace, r.Ingress, r.UID, r.Host, r.Path, backendLabel(r.Backend))
}

// fmtUTC renders a stored time in UTC RFC3339.
func fmtUTC(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// discoverySnapshotScope is the namespace list of the scan the screen shows (current, else previous).
func discoverySnapshotScope(f K8sFreshnessView) string {
	switch {
	case f.Current != nil:
		return f.Current.Scope
	case f.Previous != nil:
		return f.Previous.Scope
	}
	return ""
}

// discoverySnapshotTime is the time of the scan the screen shows.
func discoverySnapshotTime(f K8sFreshnessView) string {
	switch {
	case f.Current != nil:
		return fmtUTC(f.Current.ObservedAt)
	case f.Previous != nil:
		return fmtUTC(f.Previous.ObservedAt)
	}
	return ""
}

// namespaceItems splits a stored namespace list ("a,b") into its names.
func namespaceItems(scope string) []string {
	var out []string
	for _, p := range strings.Split(scope, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// scopeLabels is the readable list of scanned or unscanned resource kinds.
func scopeLabels(items []k8s.ScopeItem) string {
	if len(items) == 0 {
		return "–"
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, scopeItemLabel(it))
	}
	return strings.Join(parts, ", ")
}

// scopeRawNames lists the API names of the resource kinds, for the tooltip.
func scopeRawNames(items []k8s.ScopeItem) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, string(it))
	}
	return strings.Join(parts, ", ")
}

// reasonLabels joins the review reasons of a route on one line.
func reasonLabels(reasons []k8s.Reason) string {
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, reasonLabel(r))
	}
	return strings.Join(parts, ", ")
}

// reasonCodes keeps the reason codes in a data attribute.
func reasonCodes(reasons []k8s.Reason) string {
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, ",")
}

// managedStatusTone colours a managed-site mapping: only a match is good; a missing or changed
// route needs a look, a conflict needs review, the rest is unknown.
func managedStatusTone(s k8s.ManagedStatus) ui.Tone {
	switch s {
	case k8s.ManagedMatched:
		return ui.OK
	case k8s.ManagedNoRoute, k8s.ManagedChanged:
		return ui.Warn
	case k8s.ManagedConflict:
		return ui.Err
	default:
		return ui.Off
	}
}

// discoverySnapshotID is the id of the scan the screen shows, so a draft's source can be matched.
func discoverySnapshotID(f K8sFreshnessView) string {
	switch {
	case f.Current != nil:
		return strconv.FormatInt(f.Current.ID, 10)
	case f.Previous != nil:
		return strconv.FormatInt(f.Previous.ID, 10)
	}
	return ""
}
