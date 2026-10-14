package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// The alerts screen (F4-026, P-02, A-01): devops reads the monitor-alert lifecycle, acknowledges a
// raised alert and opens/closes site monitoring maintenance. The page is a GET; every mutation is a
// POST behind RequireDevops and CSRF.Protect, with the actor read only from the trusted request
// context and the change audited before it runs (audit failure blocks the mutation). Maintenance
// only mutes that site's monitoring alert; it neither stops measurement nor touches the H-07
// access/write gate. The screen sends nothing outside the dashboard.

// AlertsSource is the F4-023 service surface the screen needs: the lifecycle listing (resolved rows
// included, so the resolution state stays visible) and the two audited mutations. *alert.Service
// satisfies it.
type AlertsSource interface {
	List(ctx context.Context) ([]alert.Alert, error)
	Acknowledge(ctx context.Context, kind, subject, source string) (alert.Alert, error)
	SetMaintenance(ctx context.Context, subject string, muted bool) error
}

// AlertsAuditor writes the operator actions to the append-only audit log (A-01). *audit.Logger
// satisfies it.
type AlertsAuditor interface {
	Write(ctx context.Context, e audit.Entry) (audit.Event, error)
}

// AlertsHandlerConfig wires the alerts screen.
type AlertsHandlerConfig struct {
	Alerts  AlertsSource
	Auditor AlertsAuditor
	CSRF    *CSRF
}

// AlertsHandler serves the alerts screen and its two state-changing forms.
type AlertsHandler struct {
	cfg AlertsHandlerConfig
}

// NewAlertsHandler validates the wiring.
func NewAlertsHandler(cfg AlertsHandlerConfig) (*AlertsHandler, error) {
	switch {
	case cfg.Alerts == nil:
		return nil, errors.New("web: alerts screen needs an alert source")
	case cfg.Auditor == nil:
		return nil, errors.New("web: alerts screen needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: alerts screen needs a CSRF signer")
	}
	return &AlertsHandler{cfg: cfg}, nil
}

// Register adds the alerts screen and its action routes to mux.
func (h *AlertsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /alerts", h.page)
	mux.HandleFunc("POST /alerts/ack", h.ack)
	mux.HandleFunc("POST /alerts/maintenance", h.maintenance)
}

// AlertRow is one alert on the screen: the lifecycle state, the muted/freshness labels and the
// source/subject/last-seen identity shown as separate fields.
type AlertRow struct {
	ID       int64
	Kind     string
	Subject  string
	Source   string
	Severity string
	State    string
	// StateLabel is the Turkish label; the stable state identifier stays in data-state and title.
	StateLabel string
	Muted      bool
	// SiteMaintenance marks rows whose subject is a site, so the maintenance toggle is offered.
	SiteMaintenance bool
	Freshness       string
	Evidence        string

	LastSeen       time.Time
	AcknowledgedAt time.Time
	ResolvedAt     time.Time
	Resolved       bool
}

// AlertsView is the screen snapshot: open (active/acknowledged) and resolved alerts shown
// separately, plus a notice or error banner. Loaded is false when the listing itself failed, so the
// page never claims "no alerts" from a read error.
type AlertsView struct {
	Open     []AlertRow
	Resolved []AlertRow
	Notice   string
	Err      string
	Loaded   bool
	// Maintenance lists the sites whose monitoring maintenance is on, even when no alert is open.
	Maintenance []string
	// ResolvedPage is the page of the resolved list shown in Resolved.
	ResolvedPage AlertsPager
}

// resolvedPerPage is the number of resolved alerts per page; the open list is never paged.
const resolvedPerPage = 25

// AlertsPager is the position in the resolved list.
type AlertsPager struct {
	Page, Pages, Total int
}

func (p AlertsPager) info() string {
	return fmt.Sprintf("Sayfa %d / %d · %d çözülmüş uyarı", p.Page, p.Pages, p.Total)
}

func (p AlertsPager) prev() string {
	if p.Page <= 1 {
		return ""
	}
	return fmt.Sprintf("/alerts?resolved=%d", p.Page-1)
}

func (p AlertsPager) next() string {
	if p.Page >= p.Pages {
		return ""
	}
	return fmt.Sprintf("/alerts?resolved=%d", p.Page+1)
}

// pageResolved cuts rows (newest first) to the requested page. An out-of-range or malformed page
// shows the nearest valid one.
func pageResolved(rows []AlertRow, raw string) ([]AlertRow, AlertsPager) {
	p := AlertsPager{Page: 1, Total: len(rows)}
	p.Pages = (len(rows) + resolvedPerPage - 1) / resolvedPerPage
	if p.Pages == 0 {
		p.Pages = 1
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 1 {
		p.Page = min(n, p.Pages)
	}
	start := (p.Page - 1) * resolvedPerPage
	end := min(start+resolvedPerPage, len(rows))
	return rows[start:end], p
}

// siteMaintenanceKind reports whether kind is a per-site alert (health or TLS). Drift and stale-source
// subjects are not sites, so site maintenance must never mute them.
func siteMaintenanceKind(kind string) bool {
	return kind == alert.KindTargetHealth || kind == alert.KindTLSExpiry
}

// maintenanceLister is the optional surface that lists every site in maintenance. Without it the page
// lists the sites of muted open alert rows.
type maintenanceLister interface {
	MaintenanceSubjects(ctx context.Context) ([]string, error)
}

// page renders the lifecycle snapshot (GET only).
func (h *AlertsHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	h.render(w, r, http.StatusOK, "", "")
}

// render rebuilds the snapshot and writes the page with the given banner. A failed listing is shown
// as an error next to whatever mutation message is already there (fail safe: no invented state).
func (h *AlertsHandler) render(w http.ResponseWriter, r *http.Request, status int, notice, errMsg string) {
	actor, _ := ActorFrom(r.Context())
	v := AlertsView{Notice: notice, Err: errMsg}
	alerts, err := h.cfg.Alerts.List(r.Context())
	if err != nil {
		v.Err = joinBanner(v.Err, "uyarılar okunamadı: "+err.Error())
	} else {
		v.Loaded = true
		v.Maintenance = h.maintenanceSubjects(r.Context(), alerts, &v)
		for _, a := range alerts {
			row := toAlertRow(a)
			if a.Resolved {
				v.Resolved = append(v.Resolved, row)
			} else {
				v.Open = append(v.Open, row)
			}
		}
		v.Resolved, v.ResolvedPage = pageResolved(v.Resolved, r.URL.Query().Get("resolved"))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "pano", "Uyarılar",
		AlertsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// maintenanceSubjects returns the sorted, de-duplicated sites in maintenance.
func (h *AlertsHandler) maintenanceSubjects(ctx context.Context, alerts []alert.Alert, v *AlertsView) []string {
	set := map[string]bool{}
	if l, ok := h.cfg.Alerts.(maintenanceLister); ok {
		subjects, err := l.MaintenanceSubjects(ctx)
		if err != nil {
			v.Err = joinBanner(v.Err, "bakımdaki siteler okunamadı: "+err.Error())
		}
		for _, s := range subjects {
			set[s] = true
		}
	}
	for _, a := range alerts {
		if a.Muted && !a.Resolved && siteMaintenanceKind(a.Kind) {
			set[a.Subject] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ack marks one raised alert read. The audit entry is written before the service call, so an
// acknowledgement that cannot be recorded is never applied; the returned acknowledgement time is
// recorded in the outcome. Acknowledging never resolves the alert (P-02.4).
func (h *AlertsHandler) ack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	kind := strings.TrimSpace(r.PostFormValue("kind"))
	subject := strings.TrimSpace(r.PostFormValue("subject"))
	source := strings.TrimSpace(r.PostFormValue("source"))
	if kind == "" || subject == "" || source == "" {
		http.Error(w, "geçersiz uyarı", http.StatusBadRequest)
		return
	}
	target := alertTarget(kind, subject, source)
	if err := h.writeAudit(r.Context(), actor, "alert.acknowledge", target, "requested", nil); err != nil {
		h.render(w, r, http.StatusInternalServerError, "", "işlem kaydedilemedi: "+err.Error())
		return
	}
	acked, err := h.cfg.Alerts.Acknowledge(r.Context(), kind, subject, source)
	if err != nil {
		h.writeAuditOutcome(r.Context(), actor, "alert.acknowledge", target, "failed", err.Error(), nil)
		h.render(w, r, http.StatusInternalServerError, "", "uyarı okundu işaretlenemedi: "+err.Error())
		return
	}
	h.writeAuditOutcome(r.Context(), actor, "alert.acknowledge", target, "acknowledged", "",
		audit.Diff{{Field: "acknowledged_at", After: stampedTime(acked.AcknowledgedAt)}})
	h.render(w, r, http.StatusOK, "Uyarı okundu işaretlendi.", "")
}

// maintenance opens or closes the persistent per-site monitoring maintenance. The audit entry is
// written before the service writes the preference; the outcome records the stored value. Only the
// monitoring label changes: measurement continues and the H-07 gate is untouched (P-02.5).
func (h *AlertsHandler) maintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	subject := strings.TrimSpace(r.PostFormValue("subject"))
	muted, ok := parseMuted(r.PostFormValue("muted"))
	if subject == "" || !ok {
		http.Error(w, "geçersiz bakım isteği", http.StatusBadRequest)
		return
	}
	if !h.knownSite(r.Context(), subject) {
		http.Error(w, "bakım yalnız sağlık/TLS uyarısı olan siteler için açılır", http.StatusBadRequest)
		return
	}
	target := "site:" + subject
	if err := h.writeAudit(r.Context(), actor, "alert.maintenance", target, "requested", nil); err != nil {
		h.render(w, r, http.StatusInternalServerError, "", "işlem kaydedilemedi: "+err.Error())
		return
	}
	if err := h.cfg.Alerts.SetMaintenance(r.Context(), subject, muted); err != nil {
		h.writeAuditOutcome(r.Context(), actor, "alert.maintenance", target, "failed", err.Error(), nil)
		h.render(w, r, http.StatusInternalServerError, "", "bakım durumu değiştirilemedi: "+err.Error())
		return
	}
	h.writeAuditOutcome(r.Context(), actor, "alert.maintenance", target, "applied", "",
		audit.Diff{{Field: "monitor.maintenance", After: boolFlag(muted)}})
	h.render(w, r, http.StatusOK, maintenanceNotice(subject, muted), "")
}

// knownSite reports whether subject is a site the screen knows: it has a health/TLS alert, or it is
// already in maintenance (so a stale maintenance can still be closed). Unreadable state refuses.
func (h *AlertsHandler) knownSite(ctx context.Context, subject string) bool {
	alerts, err := h.cfg.Alerts.List(ctx)
	if err != nil {
		return false
	}
	for _, a := range alerts {
		if a.Subject == subject && siteMaintenanceKind(a.Kind) {
			return true
		}
	}
	if l, ok := h.cfg.Alerts.(maintenanceLister); ok {
		if subjects, err := l.MaintenanceSubjects(ctx); err == nil {
			for _, s := range subjects {
				if s == subject {
					return true
				}
			}
		}
	}
	return false
}

// writeAudit records one operator action and returns its error so a failed pre-write can block the
// mutation.
func (h *AlertsHandler) writeAudit(ctx context.Context, actor, event, target, result string, diff audit.Diff) error {
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: event, Target: target, Diff: diff, Result: result,
	})
	return err
}

// writeAuditOutcome records the post-action result; the requested entry already names the action, so
// a failure to write the outcome is logged, never hidden.
func (h *AlertsHandler) writeAuditOutcome(ctx context.Context, actor, event, target, result, reason string, diff audit.Diff) {
	if reason != "" {
		diff = append(diff, audit.Change{Field: "error", After: reason})
	}
	if err := h.writeAudit(ctx, actor, event, target, result, diff); err != nil {
		slog.Default().Warn("alerts: audit outcome write failed", "event", event, "target", target, "err", err)
	}
}

// toAlertRow flattens a service alert for the view.
func toAlertRow(a alert.Alert) AlertRow {
	return AlertRow{
		ID:              a.ID,
		Kind:            a.Kind,
		Subject:         a.Subject,
		Source:          a.Source,
		Severity:        string(a.Severity),
		State:           string(a.State),
		StateLabel:      alertStateLabel(a.State),
		Muted:           a.Muted,
		SiteMaintenance: siteMaintenanceKind(a.Kind),
		Freshness:       a.Freshness,
		Evidence:        a.Evidence,
		Resolved:        a.Resolved,
		LastSeen:        a.LastSeen,
		AcknowledgedAt:  a.AcknowledgedAt,
		ResolvedAt:      a.ResolvedAt,
	}
}

// alertStateLabel is the Turkish label for a lifecycle state.
func alertStateLabel(state alert.State) string {
	switch state {
	case alert.StateActive:
		return "aktif"
	case alert.StateAcknowledged:
		return "okundu"
	case alert.StateResolved:
		return "çözüldü"
	default:
		return ""
	}
}

// alertStateTone colours a lifecycle state: an active alert is an error, an acknowledged one is
// information, a resolved one is healthy. An unknown state is never shown as healthy (fail safe).
func alertStateTone(state string) ui.Tone {
	switch state {
	case string(alert.StateActive):
		return ui.Err
	case string(alert.StateAcknowledged):
		return ui.Info
	case string(alert.StateResolved):
		return ui.OK
	default:
		return ui.Off
	}
}

// alertTarget names one alert in the audit log.
func alertTarget(kind, subject, source string) string {
	return fmt.Sprintf("alert:%s:%s:%s", kind, subject, source)
}

// parseMuted reads the maintenance target flag; anything but the two values is a tampered form.
func parseMuted(value string) (muted, ok bool) {
	switch strings.TrimSpace(value) {
	case "1", "true":
		return true, true
	case "0", "false":
		return false, true
	default:
		return false, false
	}
}

// boolFlag renders a boolean the way the maintenance setting is stored.
func boolFlag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// stampedTime formats a stored timestamp for the audit diff; the zero time stays empty.
func stampedTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(storedTimeFormat)
}

// joinBanner appends a new message to a possibly empty banner.
func joinBanner(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// maintenanceNotice is the visible confirmation of the toggle.
func maintenanceNotice(subject string, muted bool) string {
	if muted {
		return subject + " için site izleme bakımı açıldı; kontroller sürer, uyarılar sessize alındı."
	}
	return subject + " için site izleme bakımı kapatıldı; sonraki kontrol sonucu geçerli."
}
