package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// The H-07 config screen (F3b-020, H-07, ADR 0021): /headscale/config shows the helper's secret-free
// status.json summary (current allowed_groups, base_rev, last request state/phase), builds the
// diff for a new list and applies it with an explicit approval through the F3b-018 service, and
// offers the operator's "close the maintenance" from F3b-019. No raw or masked config.yaml is read
// or shown. While the write switch (F3b-021) is off the page is read-only; the service refuses too.

// hsConfigGroupsForm is the ordered closed set the screen offers.
var hsConfigGroupsForm = []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper, hostpatch.GroupStandart}

// hsConfigRestartWarning is the disruption the operator approves (AC2).
const hsConfigRestartWarning = "restart ~120 sn'ye kadar kontrol düzlemini keser; mevcut oturumlar sürer, " +
	"yeni girişler yeni şarta tabidir."

// HSConfigService is the H-07 apply surface (F3b-018/019); *hostapply.Service satisfies it.
type HSConfigService interface {
	Preview(ctx context.Context, wanted []string) (hostapply.Preview, error)
	Apply(ctx context.Context, req hostapply.ApplyRequest) (hostapply.ApplyResult, error)
	CloseMaintenance(ctx context.Context, req hostapply.CloseRequest) (hostapply.CloseResult, error)
}

// HSConfigMaintenance reads the durable maintenance row; *maintenance.Service satisfies it.
type HSConfigMaintenance interface {
	Get(ctx context.Context) (maintenance.Status, error)
}

// HSConfigHost reads the helper's status.json; *hostapply.Client satisfies it.
type HSConfigHost interface {
	Status() (hostpatch.Status, error)
}

// HSConfigSwitch reads the H-07 write switch; *db.Queries satisfies it.
type HSConfigSwitch interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// HSConfigConfig wires the screen. Every field is required.
type HSConfigConfig struct {
	Service     HSConfigService
	Maintenance HSConfigMaintenance
	Host        HSConfigHost
	Switch      HSConfigSwitch
	DryRun      change.DryRun
	CSRF        *CSRF
}

// HSConfigHandler serves /headscale/config.
type HSConfigHandler struct {
	cfg HSConfigConfig
}

// NewHSConfigHandler validates the wiring.
func NewHSConfigHandler(cfg HSConfigConfig) (*HSConfigHandler, error) {
	switch {
	case cfg.Service == nil:
		return nil, errors.New("web: headscale config needs the host apply service")
	case cfg.Maintenance == nil:
		return nil, errors.New("web: headscale config needs the maintenance reader")
	case cfg.Host == nil:
		return nil, errors.New("web: headscale config needs the host status reader")
	case cfg.Switch == nil:
		return nil, errors.New("web: headscale config needs the settings reader")
	case cfg.DryRun == nil:
		return nil, errors.New("web: headscale config needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: headscale config needs a CSRF signer")
	}
	return &HSConfigHandler{cfg: cfg}, nil
}

// Register adds the config routes.
func (h *HSConfigHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/config", h.page)
	mux.HandleFunc("GET /headscale/config/status", h.status)
	mux.HandleFunc("POST /headscale/config/preview", h.preview)
	mux.HandleFunc("POST /headscale/config/apply", h.apply)
	mux.HandleFunc("POST /headscale/config/close", h.close)
}

// hsConfigLastResult is the secret-free last host result kept in the maintenance row.
type hsConfigLastResult struct {
	Status         string `json:"status"`
	RequestID      string `json:"request_id"`
	Phase          string `json:"phase"`
	ErrorCode      string `json:"error_code"`
	ConfigChanged  *bool  `json:"config_changed"`
	HealthVerified bool   `json:"health_verified"`
	FinishedAt     string `json:"finished_at"`
}

// hsConfigView is the page data. Preview holds a built diff, Close the outcome of a close request.
type hsConfigView struct {
	DryRun bool

	WriteEnabled bool
	WriteStored  bool
	WriteError   string

	HostUnreadable bool
	HostError      string

	Current       []string
	BaseRev       string
	HostRequestID string
	HostState     hostpatch.State
	HostPhase     hostpatch.Phase

	MaintUnreadable bool
	MaintError      string
	MaintState      maintenance.State
	MaintID         string
	MaintElapsed    string
	CloseNote       string
	LastResult      *hsConfigLastResult

	Preview *hostapply.Preview
	Close   *hostapply.CloseResult

	// Unknowns are the unresolved outcomes returned with a refusal for ErrUnknownOutcome; they are
	// listed next to the refusal so the operator sees what blocks opening the maintenance.
	Unknowns []hostapply.Unknown

	Error  string
	Notice string
}

// baseView reads the write switch (fail-closed), the helper status and the maintenance row. None of
// the three being unreadable fails the page: each is shown as its own reason instead.
func (h *HSConfigHandler) baseView(ctx context.Context) hsConfigView {
	var v hsConfigView

	on, stored, err := readConfigWriteSwitch(ctx, h.cfg.Switch)
	if err != nil {
		v.WriteError = "Config yazma switch'i okunamadı; kapalı varsayıldı: " + err.Error()
	}
	v.WriteEnabled, v.WriteStored = on, stored

	hs, err := h.cfg.Host.Status()
	switch {
	case err != nil:
		v.HostUnreadable, v.HostError = true, err.Error()
	case hs.ConfigError != "":
		v.HostUnreadable = true
		v.HostError = "host Headscale config'i okunamıyor veya beklenmeyen değerler içeriyor (" + string(hs.ConfigError) + ")"
	default:
		v.Current, v.BaseRev = hs.AllowedGroups, hs.BaseRev
		v.HostRequestID, v.HostState, v.HostPhase = hs.RequestID, hs.State, hs.Phase
	}

	st, err := h.cfg.Maintenance.Get(ctx)
	if err != nil {
		v.MaintUnreadable, v.MaintError = true, err.Error()
	} else {
		v.MaintState, v.MaintID = st.State, st.RequestID
		v.MaintElapsed, v.CloseNote = formatElapsed(st.Elapsed), st.CloseNote
		if st.LastHostResult != "" {
			var lr hsConfigLastResult
			if json.Unmarshal([]byte(st.LastHostResult), &lr) == nil {
				v.LastResult = &lr
			}
		}
	}
	return v
}

// render writes the page with the given status.
func (h *HSConfigHandler) render(w http.ResponseWriter, r *http.Request, status int, v hsConfigView) {
	dry, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dry
	actor, _ := ActorFrom(r.Context())
	token := h.cfg.CSRF.Token()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, token, "headscale", "Headscale config",
		HSConfigPage(v, token)).Render(r.Context(), w)
}

// renderBase shows the page with the stored state and the given message.
func (h *HSConfigHandler) renderBase(w http.ResponseWriter, r *http.Request, status int, v hsConfigView) {
	base := h.baseView(r.Context())
	v.DryRun = base.DryRun
	// Keep the caller's message and preview, but take the freshly read state.
	v.WriteEnabled, v.WriteStored, v.WriteError = base.WriteEnabled, base.WriteStored, base.WriteError
	v.HostUnreadable, v.HostError = base.HostUnreadable, base.HostError
	v.Current, v.BaseRev = base.Current, base.BaseRev
	v.HostRequestID, v.HostState, v.HostPhase = base.HostRequestID, base.HostState, base.HostPhase
	v.MaintUnreadable, v.MaintError = base.MaintUnreadable, base.MaintError
	v.MaintState, v.MaintID, v.MaintElapsed = base.MaintState, base.MaintID, base.MaintElapsed
	v.CloseNote, v.LastResult = base.CloseNote, base.LastResult
	h.render(w, r, status, v)
}

// renderRefusal shows err with the hostapply-specific HTTP status.
func (h *HSConfigHandler) renderRefusal(w http.ResponseWriter, r *http.Request, err error) {
	h.renderRefusalWith(w, r, err, nil)
}

// renderRefusalWith is renderRefusal and the unresolved outcomes that came with the refusal.
func (h *HSConfigHandler) renderRefusalWith(w http.ResponseWriter, r *http.Request, err error, unknowns []hostapply.Unknown) {
	status, msg := hsConfigRefusal(err)
	h.renderBase(w, r, status, hsConfigView{Error: msg, Unknowns: unknowns})
}

func (h *HSConfigHandler) page(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h.renderBase(w, r, http.StatusOK, hsConfigView{})
}

// status is the htmx fragment that refreshes the status panel while the maintenance is open.
func (h *HSConfigHandler) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	v := h.baseView(r.Context())
	dry, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dry
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = HSConfigStatusRegion(v).Render(r.Context(), w)
}

// preview builds the diff for the wanted list; it writes nothing.
func (h *HSConfigHandler) preview(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.writeEnabled(r.Context()); err != nil {
		h.renderRefusal(w, r, err)
		return
	}
	wanted, ok := h.readWanted(w, r)
	if !ok {
		return
	}
	p, err := h.cfg.Service.Preview(r.Context(), wanted)
	if err != nil {
		h.renderRefusal(w, r, err)
		return
	}
	v := hsConfigView{Preview: &p, Notice: "fark hazır; apply etmek için açık onay gerekir"}
	h.renderBase(w, r, http.StatusOK, v)
}

// apply starts the request after an explicit approval; on success the page redirects to the status
// screen.
func (h *HSConfigHandler) apply(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.writeEnabled(r.Context()); err != nil {
		h.renderRefusal(w, r, err)
		return
	}
	if r.PostFormValue("confirm") != "1" {
		h.renderBase(w, r, http.StatusBadRequest, hsConfigView{Error: hostapply.ErrConfirmRequired.Error()})
		return
	}
	wanted, ok := h.readWanted(w, r)
	if !ok {
		return
	}
	baseRev := strings.TrimSpace(r.PostFormValue("base_rev"))
	if baseRev == "" {
		h.renderBase(w, r, http.StatusBadRequest, hsConfigView{Error: "base_rev eksik; sayfayı yenileyip preview'u tekrarlayın"})
		return
	}
	res, err := h.cfg.Service.Apply(r.Context(), hostapply.ApplyRequest{Actor: actor, Wanted: wanted, BaseRev: baseRev})
	if err != nil {
		// Keep the outcome the service named: on ErrUnknownOutcome it lists what blocks the opening.
		h.renderRefusalWith(w, r, err, res.Unknowns)
		return
	}
	http.Redirect(w, r, "/headscale/config", http.StatusSeeOther)
}

// close is the operator's confirmed "close the maintenance" (F3b-019); it shows the host state and a
// warning while a request is still applying.
func (h *HSConfigHandler) close(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	res, err := h.cfg.Service.CloseMaintenance(r.Context(), hostapply.CloseRequest{
		Actor:     actor,
		RequestID: strings.TrimSpace(r.PostFormValue("request_id")),
		Confirm:   r.PostFormValue("confirm") == "1",
	})
	if err != nil {
		h.renderRefusal(w, r, err)
		return
	}
	h.renderBase(w, r, http.StatusOK, hsConfigView{
		Close:  &res,
		Notice: "bakım kapatma istendi; reconcile genişleten yazmalardan önce çalışır",
	})
}

// readWanted parses the group checkboxes and applies the shared F3b-004 rules (devops required).
func (h *HSConfigHandler) readWanted(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	if err := r.ParseForm(); err != nil {
		h.renderBase(w, r, http.StatusBadRequest, hsConfigView{Error: "geçersiz form"})
		return nil, false
	}
	wanted := append([]string(nil), r.PostForm["group"]...)
	if err := hostpatch.ValidateGroups(wanted); err != nil {
		h.renderBase(w, r, http.StatusBadRequest, hsConfigView{Error: "geçersiz liste: " + err.Error()})
		return nil, false
	}
	return wanted, true
}

// writeEnabled is the page's fail-closed read of the write switch, mirroring the service.
func (h *HSConfigHandler) writeEnabled(ctx context.Context) error {
	on, _, err := readConfigWriteSwitch(ctx, h.cfg.Switch)
	if err != nil {
		return fmt.Errorf("%w: ayar okunamadı", hostapply.ErrWriteDisabled)
	}
	if !on {
		return hostapply.ErrWriteDisabled
	}
	return nil
}

// readConfigWriteSwitch reads the H-07 write switch; a missing row is the default off and any other
// read error is fail-closed (off, reported).
func readConfigWriteSwitch(ctx context.Context, s HSConfigSwitch) (on, stored bool, err error) {
	v, gerr := s.GetSetting(ctx, hostapply.SettingConfigWriteEnabled)
	switch {
	case errors.Is(gerr, sql.ErrNoRows):
		return false, false, nil
	case gerr != nil:
		return false, false, gerr
	}
	parsed, perr := strconv.ParseBool(strings.TrimSpace(v))
	if perr != nil {
		return false, true, nil
	}
	return parsed, true, nil
}

// hsConfigRefusal maps a service refusal to an HTTP status and the message to show.
func hsConfigRefusal(err error) (int, string) {
	switch {
	case errors.Is(err, hostapply.ErrWriteDisabled), errors.Is(err, hostapply.ErrActorRequired):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, hostapply.ErrConfirmRequired), errors.Is(err, hostpatch.ErrInvalidRequest):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, hostapply.ErrStale), errors.Is(err, hostapply.ErrStaleRequestID),
		errors.Is(err, hostapply.ErrNotOpen), errors.Is(err, hostapply.ErrHostBusy),
		errors.Is(err, hostapply.ErrAwaitingClose), errors.Is(err, hostapply.ErrUnknownOutcome),
		errors.Is(err, hostapply.ErrNoChange):
		return http.StatusConflict, err.Error()
	case errors.Is(err, hostapply.ErrStatusUnavailable), errors.Is(err, hostapply.ErrHostConfig):
		return http.StatusBadGateway, err.Error()
	default:
		return http.StatusInternalServerError, "işlem tamamlanamadı; hiçbir şey yazılmadı: " + err.Error()
	}
}

// currentLabel renders the current allowed_groups for the status panel.
func (v hsConfigView) currentLabel() string {
	if len(v.Current) == 0 {
		return "(liste yok)"
	}
	return strings.Join(v.Current, ", ")
}

// joinGroups renders a group list for the preview, with a dash when empty.
func joinGroups(groups []string) string {
	if len(groups) == 0 {
		return "—"
	}
	return strings.Join(groups, ", ")
}

// currentHas reports whether g is in the current list, for the pre-checked form.
func (v hsConfigView) currentHas(g string) bool { return slices.Contains(v.Current, g) }

// hasFailure reports a terminal failure/interruption that must never read as success (AC5).
func (v hsConfigView) hasFailure() bool {
	if v.LastResult == nil {
		return false
	}
	return v.LastResult.Status == string(hostpatch.StateFailed) || v.LastResult.Status == string(hostpatch.StateInterrupted)
}

// canStartPatch reports whether the page may offer the new-patch form: the write switch on, the
// host readable, and the maintenance either off or stuck on a terminal failure (recovery patch).
func (v hsConfigView) canStartPatch() bool {
	if !v.WriteEnabled || v.HostUnreadable || v.MaintUnreadable {
		return false
	}
	switch v.MaintState {
	case maintenance.Off:
		return true
	case maintenance.Active:
		return v.hasFailure()
	default:
		return false
	}
}

// closeAvailable reports whether "close the maintenance" is offered (only while active).
func (v hsConfigView) closeAvailable() bool { return v.MaintState == maintenance.Active }

// hostApplying reports a host write still in flight for the close warning.
func (v hsConfigView) hostApplying() bool {
	return v.HostState != "" && !v.HostState.Terminal()
}

// dryRunSkipped is the last close note from a dry-run reconcile (AC8).
func (v hsConfigView) dryRunSkipped() bool { return v.CloseNote == "dry_run_skipped" }

// statusPollTrigger refreshes the panel only while the maintenance is open (F3b-020 [Ö]).
func (v hsConfigView) statusPollTrigger() string {
	if v.MaintState == maintenance.Active || v.MaintState == maintenance.ReconcilePending {
		return "every 2s"
	}
	return ""
}

// lastResultClock is the last host result's finished_at, or the host status has no time: the empty
// string is shown as a dash by the template.
func (v hsConfigView) lastResultClock() string {
	if v.LastResult != nil && v.LastResult.FinishedAt != "" {
		return v.LastResult.FinishedAt
	}
	return "—"
}

// configChangedText states whether the live config changed, and says so explicitly when the helper
// does not know (AC5).
func (v hsConfigView) configChangedText() string {
	if v.LastResult == nil {
		return ""
	}
	switch {
	case v.LastResult.ConfigChanged == nil:
		return "config'in değişip değişmediği bilinmiyor"
	case *v.LastResult.ConfigChanged:
		return "canlı config değişmiş olabilir; geri yükleme yapılmadı"
	default:
		return "canlı config değişmedi"
	}
}
