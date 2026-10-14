package web

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The dashboard screen (F4-028, P-01/P-02, R3 B-05/B-07, ADR 0031/0032 proposed): the devops start
// page. It is strictly read-only. It never calls a writer of the F4 alert/drift pipelines
// (alert.Sources.Evaluate and alert.Drift.Check write the alerts table) and never touches an access
// setting: the monitor rows are read from what those loops already stored. Each card carries its own
// source time and freshness; a failed or empty source is shown "bilinmiyor", a failed last attempt
// with an older good result is shown "güncel değil" (stale) with the last good time, and a key that
// was never good is shown "hiç iyi olmadı". A configuration-risk row is never presented as healthy,
// and stored raw error text or risk context is never echoed: only fixed labels are rendered.
//
// The real adapters (the F4-027 model, the observation reader and the k8s snapshot reader) are wired
// in F4-031; this screen only defines the small read interfaces so it is testable with fakes.

// Observation categories and sources of the F4-017/F4-020 store (health/gates.go, alert/sources.go).
// They are repeated here as the render keys of the read screen so web does not depend on a writer.
const (
	obsCategoryTarget = "target"
	obsCategoryGate   = "caddy_gate"
	obsCategoryTLS    = "tls"
	obsCategoryRisk   = "config_risk"

	cardTwoGate = "two_gate"

	obsSourceConfig = "k8s_config"
	obsSourceProbe  = "net_probe"
)

// Freshness labels of one card or row. They are distinct from the model's own labels because the
// screen also distinguishes "never good" from "unknown".
const (
	freshnessFresh   = "fresh"
	freshnessStale   = "stale"
	freshnessNever   = "never"
	freshnessUnknown = "unknown"
)

// obsTimeFormat is the observation store's fixed-width UTC format; text order is time order.
const obsTimeFormat = health.TimeFormat

// twoGateNote is always shown on the two-gate card: a measurement from tagcess's network says
// nothing about the internet, and it never clears the configuration risk.
const twoGateNote = "Config riski ile ağ kontrolü ayrı gösterilir; başarılı bir kontrol riski kaldırmaz. İnternet erişimi test edilmedi."

// Keys of the installation steps the dashboard can report as pending (F5 A2).
const (
	SetupFirstImport = "first_import"
	SetupProbePolicy = "probe_policy"
	SetupK8sProfile  = "k8s_profile"
	SetupK8sAccess   = "k8s_access"
)

// SetupStep is one unfinished installation step with the page that finishes it. While any step is
// pending the dashboard shows them in ONE "kurulum bekliyor" box, and the cards that depend on a
// step say so instead of raising alerts or an unexplained "bilinmiyor".
type SetupStep struct {
	Key   string
	Label string
	Href  string
}

// setupStep returns the pending step with key.
func setupStep(steps []SetupStep, key string) (*SetupStep, bool) {
	for i := range steps {
		if steps[i].Key == key {
			return &steps[i], true
		}
	}
	return nil, false
}

// firstSetupStep returns the first pending step among keys, or nil.
func firstSetupStep(steps []SetupStep, keys ...string) *SetupStep {
	for _, k := range keys {
		if st, ok := setupStep(steps, k); ok {
			return st
		}
	}
	return nil
}

// DashboardModel is the F4-027 read model surface: devices, expected matrix, boundaries, alerts and
// sync. *dashboard.Model satisfies it. The screen never re-derives these cards itself.
type DashboardModel interface {
	View(ctx context.Context) dashboard.View
}

// DashboardObservations reads every stored measurement observation row in one complete read. The
// adapter (F4-031) lists the current sites and reads each site's rows; any read error must fail the
// whole call, so a partial inventory is never shown as green.
type DashboardObservations interface {
	Observations(ctx context.Context) ([]db.Observation, error)
}

// DashboardSnapshot reads the k8s inventory snapshot state (F4-007). *k8s.Reader satisfies it.
type DashboardSnapshot interface {
	State(ctx context.Context) (k8s.State, error)
}

// DashboardHandlerConfig wires the dashboard screen. Every field is required.
type DashboardHandlerConfig struct {
	Model        DashboardModel
	Observations DashboardObservations
	Snapshot     DashboardSnapshot
	CSRF         *CSRF
	// Settings supplies the measurement intervals that decide when a row is too old to be current
	// (twice its interval). Optional: nil, or a read error, uses the documented defaults.
	Settings func(ctx context.Context) (monitor.Settings, error)
	// Now defaults to time.Now.
	Now func() time.Time
	// DriftHeld, when set, reports that the last drift check was held by an apply or a maintenance
	// window; the drift card then says so instead of "no open drift alert". Optional.
	DriftHeld func() bool
	// Loops, when set, supplies the job states of the F4 loops for the "döngüler" block. Optional.
	Loops func() []monitor.JobStatus
	// Setup, when set, lists the pending installation steps (F5 A2). Optional.
	Setup func(ctx context.Context) []SetupStep
}

// DashboardHandler serves the read-only start page.
type DashboardHandler struct {
	cfg DashboardHandlerConfig
}

// NewDashboardHandler validates the wiring.
func NewDashboardHandler(cfg DashboardHandlerConfig) (*DashboardHandler, error) {
	switch {
	case cfg.Model == nil:
		return nil, errors.New("web: dashboard needs the F4-027 model")
	case cfg.Observations == nil:
		return nil, errors.New("web: dashboard needs an observation reader")
	case cfg.Snapshot == nil:
		return nil, errors.New("web: dashboard needs a k8s snapshot reader")
	case cfg.CSRF == nil:
		return nil, errors.New("web: dashboard needs a CSRF signer")
	}
	return &DashboardHandler{cfg: cfg}, nil
}

// Register adds the dashboard route to mux. The caller mounts it behind RequireDevops (F4-031);
// only GET is answered, so the screen cannot mutate anything.
func (h *DashboardHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.page)
}

// page renders the snapshot (GET only).
func (h *DashboardHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "pano", "Pano", DashboardPage(h.view(r.Context()))).Render(r.Context(), w)
}

// view reads every source once and flattens it into the page model. A failed source never fails the
// page: the model keeps last-good cards and the observation/snapshot cards show "bilinmiyor".
func (h *DashboardHandler) view(ctx context.Context) DashboardPageView {
	model := h.cfg.Model.View(ctx)
	rows, obsErr := h.cfg.Observations.Observations(ctx)
	state, snapErr := h.cfg.Snapshot.State(ctx)
	var setup []SetupStep
	if h.cfg.Setup != nil {
		setup = h.cfg.Setup(ctx)
	}
	v := DashboardPageView{
		Model:        model,
		Drift:        driftAlerts(model.Alerts.Alerts),
		DriftUnknown: driftUnknown(model.Alerts.Alerts),
		DriftHeld:    h.cfg.DriftHeld != nil && h.cfg.DriftHeld(),
		Loops:        h.loops(),
		Health:       buildHealthCards(rows, obsErr, h.judge(ctx)),
		Snapshot:     buildSnapshotCard(state, snapErr),
		Setup:        setup,
	}
	v.DriftWaiting = firstSetupStep(setup, SetupFirstImport)
	for i := range v.Health {
		c := &v.Health[i]
		if c.Kind == cardTwoGate {
			if len(c.Groups) == 0 {
				c.Waiting = firstSetupStep(setup, SetupProbePolicy, SetupK8sProfile, SetupK8sAccess)
			}
		} else if len(c.Rows) == 0 {
			c.Waiting = firstSetupStep(setup, SetupProbePolicy)
		}
	}
	if v.Snapshot.Freshness.Current == nil {
		v.Snapshot.Waiting = firstSetupStep(setup, SetupK8sProfile, SetupK8sAccess)
	}
	return v
}

// LoopRow is one loop job as the dashboard shows it. The job's raw error is never rendered.
type LoopRow struct {
	Job         string
	State       string
	LastAttempt time.Time
	// Reason is a fixed Turkish sentence for a waiting job (state "missing"); empty otherwise.
	Reason string
}

// loopMissingReason says why a job is "missing": it is waiting for the installation, not broken.
func loopMissingReason(job string) string {
	switch job {
	case monitor.JobInventory:
		return "Kurulum bekleniyor: k8s bağlantı profili kaydedilmedi (envanter okunmadı)."
	case monitor.JobHealth:
		return "Kurulum bekleniyor: probe IP policy'si kaydedilmedi (kontrol yapılmadı)."
	case monitor.JobDrift:
		return "Kurulum bekleniyor: ilk import apply edilmedi (karşılaştırılacak temel yok)."
	default:
		return "Kurulum bekleniyor."
	}
}

func (h *DashboardHandler) loops() []LoopRow {
	if h.cfg.Loops == nil {
		return nil
	}
	var out []LoopRow
	for _, j := range h.cfg.Loops() {
		row := LoopRow{Job: j.Job, State: string(j.State), LastAttempt: j.LastAttempt}
		if j.State == monitor.StateMissing {
			row.Reason = loopMissingReason(j.Job)
		}
		out = append(out, row)
	}
	return out
}

// obsJudge decides how current a stored row is: its age against twice the measurement interval.
type obsJudge struct {
	now      time.Time
	settings monitor.Settings
}

// judge reads the clock and the settings once per page; unreadable settings fall back to the defaults.
func (h *DashboardHandler) judge(ctx context.Context) obsJudge {
	j := obsJudge{now: time.Now(), settings: monitor.DefaultSettings()}
	if h.cfg.Now != nil {
		j.now = h.cfg.Now()
	}
	if h.cfg.Settings != nil {
		if s, err := h.cfg.Settings(ctx); err == nil {
			j.settings = s
		}
	}
	return j
}

// DashboardPageView is the whole page data. DriftUnknown lists the artifacts whose drift could not be
// evaluated (no baseline, first import pending, unreadable source).
type DashboardPageView struct {
	Model        dashboard.View
	Drift        []dashboard.Alert
	DriftUnknown []dashboard.Alert
	DriftHeld    bool
	Loops        []LoopRow
	Health       []HealthCard
	Snapshot     SnapshotCard
	// Setup is the pending installation steps; DriftWaiting is the one the drift card waits for.
	Setup        []SetupStep
	DriftWaiting *SetupStep
}

// HealthCard is one observation-derived card: target, Caddy gate, TLS or the two-gate card. Health
// cards are always rendered (Kind and Title are stable) so a failed source stays visible instead of
// disappearing into a healthy-looking page.
type HealthCard struct {
	Kind       string
	Title      string
	Freshness  string
	ObservedAt time.Time
	Rows       []HealthRow
	Groups     []TwoGateGroup
	Note       string
	Err        string
	// Waiting is the pending setup step this empty card waits for (F5 A2); nil when none.
	Waiting *SetupStep
}

// HealthRow is one stored observation as the screen shows it. Result and RiskFinding are fixed
// labels; the stored raw error text and risk context are deliberately absent.
type HealthRow struct {
	Site, Host, Route, Source, Vantage, Endpoint, SNI, Path string
	ObservedAt                                              time.Time
	LastAttemptAt                                           time.Time
	Success                                                 bool
	HTTPStatus                                              int64
	Result                                                  string
	Freshness                                               string
	TLSNotAfter                                             time.Time
	TLSUnverified                                           bool
	RiskFinding                                             string
	Untested                                                []string
}

// TwoGateGroup is one configuration-risk route: the declared risk row plus every network
// measurement of the same site/host/route, kept together but never merged.
type TwoGateGroup struct {
	Site         string
	Host         string
	Route        string
	Risk         *HealthRow
	Measurements []HealthRow
	Untested     []string
}

// SnapshotCard is the k8s inventory freshness card.
type SnapshotCard struct {
	Loaded    bool
	Freshness K8sFreshnessView
	// Waiting is the pending setup step the card waits for (F5 A2); nil when none.
	Waiting *SetupStep
}

// State is the machine-readable freshness of the snapshot card ("unknown" when the read failed).
func (c SnapshotCard) State() string {
	if !c.Loaded {
		return freshnessUnknown
	}
	return freshnessState(c.Freshness)
}

// buildSnapshotCard maps the F4-007 state; a read failure is "bilinmiyor", never a fresh claim.
func buildSnapshotCard(state k8s.State, err error) SnapshotCard {
	if err != nil {
		return SnapshotCard{Loaded: false}
	}
	return SnapshotCard{Loaded: true, Freshness: K8sFreshnessView{
		Current: state.Current, LastAttempt: state.LastAttempt, Stale: state.Stale, Previous: state.Previous,
	}}
}

// driftAlerts keeps only the F4-039 monitor drift rows; the screen never triggers a drift check.
func driftAlerts(alerts []dashboard.Alert) []dashboard.Alert {
	var out []dashboard.Alert
	for _, a := range alerts {
		if a.Kind == alert.KindDrift {
			out = append(out, a)
		}
	}
	return out
}

// alertAcknowledged reports whether a devops already read the alert: the dashboard shows it as
// "okundu", not with its raised severity (F5 L3).
func alertAcknowledged(a dashboard.Alert) bool { return a.State == string(alert.StateAcknowledged) }

// acknowledgedCount counts the read alerts among the open ones.
func acknowledgedCount(alerts []dashboard.Alert) int {
	n := 0
	for _, a := range alerts {
		if alertAcknowledged(a) {
			n++
		}
	}
	return n
}

// driftUnknown keeps the freshness alerts of the drift source: an artifact that could not be compared
// is "bilinmiyor", never "no drift".
func driftUnknown(alerts []dashboard.Alert) []dashboard.Alert {
	var out []dashboard.Alert
	for _, a := range alerts {
		if a.Kind == alert.KindSourceStale && a.Source == alert.SourceDrift {
			out = append(out, a)
		}
	}
	return out
}

// buildHealthCards groups the stored rows into the four fixed cards. A read error marks every card
// unknown; an empty category is unknown too, so a silent source is never shown as healthy.
func buildHealthCards(rows []db.Observation, readErr error, j obsJudge) []HealthCard {
	defs := []struct{ kind, category, title string }{
		{obsCategoryTarget, obsCategoryTarget, "Hedef sağlığı"},
		{obsCategoryGate, obsCategoryGate, "Caddy gate'i"},
		{obsCategoryTLS, obsCategoryTLS, "TLS sertifikaları"},
		{cardTwoGate, obsCategoryRisk, "İki gate"},
	}
	cards := make([]HealthCard, len(defs))
	for i, d := range defs {
		cards[i] = HealthCard{Kind: d.kind, Title: d.title}
	}
	if readErr != nil {
		for i := range cards {
			cards[i].Freshness = freshnessUnknown
			cards[i].Err = "kontrol kayıtları okunamadı"
		}
		return cards
	}

	grouped := map[string][]db.Observation{}
	// Only the newest attempt per (category, subject) counts: a row left by a changed path or endpoint
	// must not keep showing green beside the current one.
	for _, r := range health.NewestPerSubject(rows) {
		grouped[r.Category] = append(grouped[r.Category], r)
	}
	for i, d := range defs {
		catRows := grouped[d.category]
		if d.category == obsCategoryRisk {
			cards[i].Groups = buildTwoGateGroups(catRows, j)
			cards[i].Freshness = twoGateFreshness(catRows, j)
			cards[i].Note = twoGateNote
			continue
		}
		sorted := sortObservations(catRows)
		cards[i].Rows = make([]HealthRow, 0, len(sorted))
		for _, r := range sorted {
			cards[i].Rows = append(cards[i].Rows, toHealthRow(r, j))
		}
		cards[i].Freshness = cardFreshness(sorted, j)
		cards[i].ObservedAt = latestObservedAt(sorted)
	}
	return cards
}

// buildTwoGateGroups keeps the declared risk and the measurements of the same route together; a
// measurement never replaces its risk row.
func buildTwoGateGroups(rows []db.Observation, j obsJudge) []TwoGateGroup {
	type key struct{ site, host, route string }
	order := make([]key, 0, len(rows))
	groups := map[key]*TwoGateGroup{}
	for _, r := range sortObservations(rows) {
		k := key{r.Site, r.Host, r.Route}
		g := groups[k]
		if g == nil {
			g = &TwoGateGroup{Site: r.Site, Host: r.Host, Route: r.Route}
			groups[k] = g
			order = append(order, k)
		}
		row := toHealthRow(r, j)
		switch r.Source {
		case obsSourceConfig:
			risk := row
			g.Risk = &risk
			g.Untested = row.Untested
		default:
			g.Measurements = append(g.Measurements, row)
		}
	}
	out := make([]TwoGateGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	return out
}

// toHealthRow maps one stored row to the display row. Only fixed labels are used; raw stored error
// text and risk context are never carried into the view.
func toHealthRow(r db.Observation, j obsJudge) HealthRow {
	row := HealthRow{
		Site: r.Site, Host: r.Host, Route: r.Route, Source: r.Source,
		Vantage: r.Vantage, Endpoint: r.Endpoint, SNI: r.Sni, Path: r.Path,
		ObservedAt:    parseObsTime(r.ObservedAt),
		LastAttemptAt: parseObsTime(r.LastAttemptAt),
		Success:       r.Success == 1,
		HTTPStatus:    r.HttpStatus,
		Freshness:     j.rowFreshness(r),
		Result:        resultLabel(r),
		RiskFinding:   riskLabel(r.RiskFinding),
		Untested:      untestedLabels(r.UnscannedScope),
	}
	if r.Category == obsCategoryTLS {
		if v := parseObsTime(r.TlsNotAfter); !v.IsZero() {
			row.TLSNotAfter = v
		} else if v := parseObsTime(r.LastTlsNotAfter); !v.IsZero() {
			row.TLSNotAfter = v
			row.TLSUnverified = true
		}
		if r.LastTlsVerifyError != "" {
			row.TLSUnverified = true
		}
	}
	return row
}

// rowFreshness is one row's evidence state: never good, fresh (the last attempt met the expectation
// and is not older than twice its measurement interval) or stale (a newer attempt failed, or the
// measurement went silent, and the older good result is kept).
func (j obsJudge) rowFreshness(r db.Observation) string {
	if r.ObservedAt == "" {
		return freshnessNever
	}
	if health.ObservationFreshness(r, j.now, health.ObservationInterval(r.Category, j.settings)) == health.RowFresh {
		return freshnessFresh
	}
	return freshnessStale
}

// cardFreshness is the worst row freshness; an empty card is unknown, never fresh.
func cardFreshness(rows []db.Observation, j obsJudge) string {
	if len(rows) == 0 {
		return freshnessUnknown
	}
	worst := freshnessFresh
	for _, r := range rows {
		f := j.rowFreshness(r)
		if obsRank(f) > obsRank(worst) {
			worst = f
		}
	}
	return worst
}

// twoGateFreshness is the freshness of the network measurements only. The configuration-risk rows
// are never a health signal, so they never make the card look good.
func twoGateFreshness(rows []db.Observation, j obsJudge) string {
	measured := make([]db.Observation, 0, len(rows))
	for _, r := range rows {
		if r.Source != obsSourceConfig {
			measured = append(measured, r)
		}
	}
	return cardFreshness(measured, j)
}

// obsRank orders the observation freshness so the worst one wins: unknown worse than never, never
// worse than stale, stale worse than fresh.
func obsRank(f string) int {
	switch f {
	case freshnessFresh:
		return 0
	case freshnessStale:
		return 1
	case freshnessNever:
		return 2
	default:
		return 3
	}
}

// latestObservedAt is the newest last-good time of the rows, or the zero time.
func latestObservedAt(rows []db.Observation) time.Time {
	var latest time.Time
	for _, r := range rows {
		if at := parseObsTime(r.ObservedAt); at.After(latest) {
			latest = at
		}
	}
	return latest
}

// sortObservations orders the rows deterministically by their full measurement key.
func sortObservations(rows []db.Observation) []db.Observation {
	out := append([]db.Observation(nil), rows...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Category != b.Category:
			return a.Category < b.Category
		case a.Site != b.Site:
			return a.Site < b.Site
		case a.Host != b.Host:
			return a.Host < b.Host
		case a.Route != b.Route:
			return a.Route < b.Route
		case a.Source != b.Source:
			return a.Source < b.Source
		case a.Vantage != b.Vantage:
			return a.Vantage < b.Vantage
		case a.Endpoint != b.Endpoint:
			return a.Endpoint < b.Endpoint
		case a.Sni != b.Sni:
			return a.Sni < b.Sni
		case a.Path != b.Path:
			return a.Path < b.Path
		default:
			return a.ID < b.ID
		}
	})
	return out
}

func parseObsTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(obsTimeFormat, value)
	if err != nil {
		return time.Time{}
	}
	return t
}

// observationResultText is the fixed, sanitized display of a failed attempt's class. The stored raw
// error text is deliberately never used (it could echo an address, header or response body).
var observationResultText = map[string]string{
	"unexpected_status":     "beklenmeyen HTTP durumu",
	"timeout":               "zaman aşımı",
	"unreachable":           "bağlantı veya TLS el sıkışması başarısız",
	"tls_unverified":        "sertifika doğrulanamadı",
	"guard_rejected":        "istek gönderilmeden reddedildi",
	"source_error":          "kontrol çalıştırılamadı",
	"redirect_not_followed": "redirect takip edilmedi",
	"not_measurable":        "kontrol edilemez",
	"gate_open":             "gate kimliksiz isteğe yanıt verdi",
}

func resultLabel(r db.Observation) string {
	if r.Success == 1 {
		return ""
	}
	if text, ok := observationResultText[r.LastResult]; ok {
		return text
	}
	return "kontrol başarısız"
}

// riskFindingText is the fixed display of a stored risk finding; an unknown finding is shown as a
// risk, never as a clean result.
var riskFindingText = map[string]string{
	"alternate_path_candidate": "alternatif yol adayı (config riski)",
	"unknown":                  "belirsiz config riski",
}

func riskLabel(finding string) string {
	if text, ok := riskFindingText[finding]; ok {
		return text
	}
	return "config riski"
}

// untestedLabelText maps the stored unscanned/untested scope labels to fixed display text.
var untestedLabelText = map[string]string{
	"internet":         "İnternet erişimi test edilmedi",
	"ipv4":             "IPv4 yolu test edilmedi",
	"ipv6":             "IPv6 yolu test edilmedi",
	"gateway":          "Gateway API taranmadı",
	"crd":              "Traefik CRD'leri taranmadı",
	"other_controller": "Diğer controller'lar taranmadı",
	"hostnetwork":      "hostNetwork ve diğer Ingress dışı yollar taranmadı",
}

func untestedLabels(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(scope, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if text, ok := untestedLabelText[part]; ok {
			out = append(out, text)
		} else {
			out = append(out, part)
		}
	}
	return out
}

// freshnessLabel is the Turkish label of an observation or snapshot freshness.
func freshnessLabel(f string) string {
	switch f {
	case freshnessFresh, "current":
		return "güncel"
	case freshnessStale:
		return "güncel değil"
	case freshnessNever:
		return "hiç iyi olmadı"
	case "previous":
		return "önceki tarama"
	case "none":
		return "henüz taranmadı"
	case freshnessUnknown, "":
		return "bilinmiyor"
	default:
		// An unrecognised value is shown as-is (templ escapes it), never disguised as "bilinmiyor".
		return f
	}
}

func deviceOnlineLabel(online bool) string {
	if online {
		return "bağlı"
	}
	return "bağlı değil"
}
