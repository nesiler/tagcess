package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/monitor"
)

// The monitoring settings screen (F4-029, K-02/P-02/A-01, R3-AC-17): /monitor/settings shows and edits
// the F4-024 typed durations/thresholds and the target check path/expected HTTP statuses. The F4-024
// store reads the settings on every measurement cycle, so a save needs no restart. Every change is a
// POST behind RequireDevops and CSRF.Protect: the trusted actor is read only from the request context
// and the audit entry is written before the persistent write (an unwritable audit blocks the change).
// Invalid input keeps the previous settings and is shown as a field error.

// monitorSettingsEvent is the audit event of one monitoring-settings change.
const monitorSettingsEvent = "monitor.settings"

// monitorSettingsTarget names the settings row group in the audit log.
const monitorSettingsTarget = "monitor_settings"

// MonitorSettingsStore is the F4-024 typed settings surface: the getter every measurement cycle reads
// and the atomic validated setter. *monitor.SettingsStore satisfies it.
type MonitorSettingsStore interface {
	Get(ctx context.Context) (monitor.Settings, error)
	Set(ctx context.Context, s monitor.Settings) error
}

// MonitorSettingsConfig wires the monitoring settings screen. Every field is required.
type MonitorSettingsConfig struct {
	Settings MonitorSettingsStore
	Auditor  SiteAuditor
	CSRF     *CSRF
}

// MonitorSettingsHandler serves the monitoring settings screen and its save form.
type MonitorSettingsHandler struct {
	cfg MonitorSettingsConfig
}

// NewMonitorSettingsHandler validates the wiring.
func NewMonitorSettingsHandler(cfg MonitorSettingsConfig) (*MonitorSettingsHandler, error) {
	switch {
	case cfg.Settings == nil:
		return nil, errors.New("web: monitoring settings needs a settings store")
	case cfg.Auditor == nil:
		return nil, errors.New("web: monitoring settings needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: monitoring settings needs a CSRF signer")
	}
	return &MonitorSettingsHandler{cfg: cfg}, nil
}

// Register adds the monitoring settings routes to mux.
func (h *MonitorSettingsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /monitor/settings", h.page)
	mux.HandleFunc("POST /monitor/settings", h.save)
}

// maxFormSeconds is far above monitor.Validate's own 30-day limit (which gives the real message) and
// far below the point where seconds * time.Second overflows.
const maxFormSeconds = 365 * 24 * 3600

// monitorSettingsForm is the screen's form as text, so a refused input is shown back unchanged.
type monitorSettingsForm struct {
	TargetInterval    string
	InventoryInterval string
	TLSInterval       string
	HealthFail        string
	HealthOK          string
	TLSInfo           string
	TLSWarn           string
	TLSCritical       string
	Path              string
	ExpectedStatuses  string
	Timeout           string
	Concurrency       string
}

func monitorSettingsFormFromRequest(r *http.Request) monitorSettingsForm {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return monitorSettingsForm{
		TargetInterval:    get("target_interval"),
		InventoryInterval: get("inventory_interval"),
		TLSInterval:       get("tls_interval"),
		HealthFail:        get("health_fail"),
		HealthOK:          get("health_ok"),
		TLSInfo:           get("tls_info"),
		TLSWarn:           get("tls_warn"),
		TLSCritical:       get("tls_critical"),
		Path:              get("path"),
		ExpectedStatuses:  get("expected_statuses"),
		Timeout:           get("timeout"),
		Concurrency:       get("concurrency"),
	}
}

func monitorSettingsFormFromSettings(s monitor.Settings) monitorSettingsForm {
	return monitorSettingsForm{
		TargetInterval:    secondsText(s.TargetInterval),
		InventoryInterval: secondsText(s.InventoryInterval),
		TLSInterval:       secondsText(s.TLSInterval),
		HealthFail:        strconv.Itoa(s.HealthFailThreshold),
		HealthOK:          strconv.Itoa(s.HealthOKThreshold),
		TLSInfo:           strconv.Itoa(s.TLSInfoDays),
		TLSWarn:           strconv.Itoa(s.TLSWarnDays),
		TLSCritical:       strconv.Itoa(s.TLSCriticalDays),
		Path:              s.Path,
		ExpectedStatuses:  statusesText(s.ExpectedStatuses),
		Timeout:           secondsText(s.Timeout),
		Concurrency:       strconv.Itoa(s.Concurrency),
	}
}

// settings parses the text fields into typed settings, returning the form field errors it found. The
// strict range and whole-second rules are monitor.Validate's, applied by the caller after parsing.
func (f monitorSettingsForm) settings() (monitor.Settings, map[string]string) {
	errs := map[string]string{}
	seconds := func(field, value string) time.Duration {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			errs[field] = "tam sayı saniye olmalı"
			return 0
		}
		// Range-check before multiplying: a huge value would wrap around to a small duration.
		if n < -maxFormSeconds || n > maxFormSeconds {
			errs[field] = "saniye değeri aralık dışı"
			return 0
		}
		return time.Duration(n) * time.Second
	}
	integer := func(field, value string) int {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			errs[field] = "tam sayı olmalı"
			return 0
		}
		return n
	}
	var s monitor.Settings
	s.TargetInterval = seconds("target_interval", f.TargetInterval)
	s.InventoryInterval = seconds("inventory_interval", f.InventoryInterval)
	s.TLSInterval = seconds("tls_interval", f.TLSInterval)
	s.HealthFailThreshold = integer("health_fail", f.HealthFail)
	s.HealthOKThreshold = integer("health_ok", f.HealthOK)
	s.TLSInfoDays = integer("tls_info", f.TLSInfo)
	s.TLSWarnDays = integer("tls_warn", f.TLSWarn)
	s.TLSCriticalDays = integer("tls_critical", f.TLSCritical)
	s.Path = strings.TrimSpace(f.Path)
	statuses, err := parseMonitorStatuses(f.ExpectedStatuses)
	if err != nil {
		errs["expected_statuses"] = err.Error()
	} else {
		s.ExpectedStatuses = statuses
	}
	s.Timeout = seconds("timeout", f.Timeout)
	s.Concurrency = integer("concurrency", f.Concurrency)
	return s, errs
}

// classifyMonitorSettingsError attributes each monitor.Validate error line to the form field it names,
// so a refused value is shown next to the input as well as in the banner.
func classifyMonitorSettingsError(err error) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(err.Error(), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.Contains(line, "tls thresholds"):
			out["tls"] = line
		case strings.Contains(line, "target_interval"):
			out["target_interval"] = line
		case strings.Contains(line, "inventory_interval"):
			out["inventory_interval"] = line
		case strings.Contains(line, "tls_interval"):
			out["tls_interval"] = line
		case strings.Contains(line, "timeout"):
			out["timeout"] = line
		case strings.Contains(line, "health_fail_threshold"):
			out["health_fail"] = line
		case strings.Contains(line, "health_ok_threshold"):
			out["health_ok"] = line
		case strings.Contains(line, "path"):
			out["path"] = line
		case strings.Contains(line, "expected_statuses") || strings.Contains(line, "expected status"):
			out["expected_statuses"] = line
		case strings.Contains(line, "concurrency"):
			out["concurrency"] = line
		}
	}
	return out
}

// MonitorSettingsView is the page data. Form holds the stored values, or the refused input; Errors a
// field error per form field; Default marks the documented starting values.
type MonitorSettingsView struct {
	Form    monitorSettingsForm
	Errors  map[string]string
	Default bool
	Loaded  bool
	Error   string
	Notice  string
	// Refusal is a refusal banner shown as an error; Warning is a non-fatal problem with the page data.
	Refusal string
	Warning string
}

// page renders the current settings (GET only).
func (h *MonitorSettingsHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	cur, err := h.cfg.Settings.Get(r.Context())
	if err != nil {
		slog.Default().Warn("monitoring settings: stored settings unreadable", "err", err)
		// Show the defaults form so the operator can overwrite the corrupt rows from the UI.
		h.render(w, r, http.StatusOK, MonitorSettingsView{
			Form:   monitorSettingsFormFromSettings(monitor.DefaultSettings()),
			Loaded: true,
			Warning: "kayıtlı izleme ayarları okunamadı veya bozuk (" + err.Error() +
				"); form varsayılanlarla dolu, doğrulanmış bir kayıt bozuk ayarların üzerine yazar",
		})
		return
	}
	h.render(w, r, http.StatusOK, MonitorSettingsView{
		Form:    monitorSettingsFormFromSettings(cur),
		Default: reflect.DeepEqual(cur, monitor.DefaultSettings()),
		Loaded:  true,
	})
}

// save validates the form, then audits the verified actor before it writes the persistent setting. An
// invalid value or an unwritable audit leaves the previous settings untouched.
func (h *MonitorSettingsHandler) save(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	form := monitorSettingsFormFromRequest(r)
	next, fieldErrs := form.settings()
	if len(fieldErrs) > 0 {
		h.result(w, r, http.StatusBadRequest, form, fieldErrs, "", "girilen değerler geçersiz; hiçbir şey kaydedilmedi.")
		return
	}
	if err := monitor.Validate(next); err != nil {
		h.result(w, r, http.StatusBadRequest, form, classifyMonitorSettingsError(err), err.Error(), "girilen değerler geçersiz; hiçbir şey kaydedilmedi.")
		return
	}

	ctx := r.Context()
	// Unreadable stored settings must not lock the screen: the input was fully validated above, so it
	// may overwrite them; the audit records the previous value as unreadable.
	before, err := h.cfg.Settings.Get(ctx)
	diff := monitorSettingsDiff(before, next)
	if err != nil {
		slog.Default().Warn("monitoring settings: stored settings unreadable, overwriting", "err", err)
		for i := range diff {
			diff[i].Before = "okunamadı"
		}
	}
	if _, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: monitorSettingsEvent, Target: monitorSettingsTarget, Diff: diff, Result: "requested",
	}); err != nil {
		h.result(w, r, http.StatusInternalServerError, form, nil, "", "işlem kaydedilemedi; ayar değiştirilmedi")
		return
	}
	if err := h.cfg.Settings.Set(ctx, next); err != nil {
		h.auditOutcome(ctx, actor, "failed", err.Error(), diff)
		h.result(w, r, http.StatusInternalServerError, form, nil, "", "ayar yazılamadı: "+err.Error())
		return
	}
	h.auditOutcome(ctx, actor, "applied", "", diff)
	h.render(w, r, http.StatusOK, MonitorSettingsView{
		Form:    monitorSettingsFormFromSettings(next),
		Default: reflect.DeepEqual(next, monitor.DefaultSettings()),
		Loaded:  true,
		Notice:  "İzleme ayarları kaydedildi; sonraki kontrol çevrimi yeni değerleri kullanır.",
	})
}

// auditOutcome records the post-action result; a failure to write it is logged, never hidden. The
// requested entry already names the action, so the outcome never blocks the applied change.
func (h *MonitorSettingsHandler) auditOutcome(ctx context.Context, actor, result, reason string, diff audit.Diff) {
	if reason != "" {
		diff = append(diff, audit.Change{Field: "error", After: reason})
	}
	if _, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: monitorSettingsEvent, Target: monitorSettingsTarget, Diff: diff, Result: result,
	}); err != nil {
		slog.Default().Warn("monitoring settings: audit outcome write failed", "result", result, "err", err)
	}
}

// result renders the page with the given form, field errors and banner. status says whether it is a
// refusal.
func (h *MonitorSettingsHandler) result(w http.ResponseWriter, r *http.Request, status int, form monitorSettingsForm, fieldErrs map[string]string, errMsg, notice string) {
	h.render(w, r, status, MonitorSettingsView{
		Form: form, Errors: fieldErrs, Loaded: true, Error: errMsg, Refusal: notice,
	})
}

func (h *MonitorSettingsHandler) render(w http.ResponseWriter, r *http.Request, status int, v MonitorSettingsView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "pano", "İzleme ayarları",
		MonitorSettingsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// monitorSettingsDiff records the before/after of every setting in the audit log.
func monitorSettingsDiff(before, after monitor.Settings) audit.Diff {
	return audit.Diff{
		{Field: "monitor.target_interval_seconds", Before: secondsText(before.TargetInterval), After: secondsText(after.TargetInterval)},
		{Field: "monitor.inventory_interval_seconds", Before: secondsText(before.InventoryInterval), After: secondsText(after.InventoryInterval)},
		{Field: "monitor.tls_interval_seconds", Before: secondsText(before.TLSInterval), After: secondsText(after.TLSInterval)},
		{Field: "monitor.health_fail_threshold", Before: strconv.Itoa(before.HealthFailThreshold), After: strconv.Itoa(after.HealthFailThreshold)},
		{Field: "monitor.health_success_threshold", Before: strconv.Itoa(before.HealthOKThreshold), After: strconv.Itoa(after.HealthOKThreshold)},
		{Field: "monitor.tls_info_days", Before: strconv.Itoa(before.TLSInfoDays), After: strconv.Itoa(after.TLSInfoDays)},
		{Field: "monitor.tls_warn_days", Before: strconv.Itoa(before.TLSWarnDays), After: strconv.Itoa(after.TLSWarnDays)},
		{Field: "monitor.tls_critical_days", Before: strconv.Itoa(before.TLSCriticalDays), After: strconv.Itoa(after.TLSCriticalDays)},
		{Field: "monitor.check_path", Before: before.Path, After: after.Path},
		{Field: "monitor.expected_statuses", Before: statusesText(before.ExpectedStatuses), After: statusesText(after.ExpectedStatuses)},
		{Field: "monitor.timeout_seconds", Before: secondsText(before.Timeout), After: secondsText(after.Timeout)},
		{Field: "monitor.concurrency", Before: strconv.Itoa(before.Concurrency), After: strconv.Itoa(after.Concurrency)},
	}
}

// parseMonitorStatuses reads a comma/space separated list of expected HTTP status codes.
func parseMonitorStatuses(raw string) ([]int, error) {
	var out []int
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		n, err := strconv.Atoi(part)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("HTTP durum kodu 100-599 aralığında olmalı: %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("en az bir HTTP durum kodu girilmeli")
	}
	return out, nil
}

func secondsText(d time.Duration) string { return strconv.Itoa(int(d / time.Second)) }

func statusesText(list []int) string {
	parts := make([]string, len(list))
	for i, code := range list {
		parts[i] = strconv.Itoa(code)
	}
	return strings.Join(parts, ", ")
}

// sortedFieldErrors returns the error keys in a deterministic order for rendering.
func sortedFieldErrors(errs map[string]string) []string {
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
