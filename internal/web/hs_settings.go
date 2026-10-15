package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The Headscale settings screen (F3-020, H-01/H-04, R2 decisions 5 and 6): /headscale/settings
// edits the protected server tags (headscale.protected_tags) and the locked policy test parameters
// (headscale.locked_tests). Adding a tag and tightening a locked parameter are one step; removing a
// tag or weakening a locked parameter goes through a confirmation page bound to the stored value.
// New locked parameters are first checked against the live policy (F3-006 validation, CheckPolicy
// included) and refused if it cannot pass them. Every change is audited with before and after. The
// readers (hsadmin.Executor, the policy writer's LockedSource) read the settings on each operation,
// so a save needs no restart.

// hsSettingsCheckTimeout bounds the live-policy read and CheckPolicy of one locked-parameter save.
const hsSettingsCheckTimeout = 20 * time.Second

const (
	hsTagsEvent   = "headscale.settings.protected_tags"
	hsLockedEvent = "headscale.settings.locked_tests"
	// Opening and closing the H-07 write switch are separate events so the direction shows in the
	// audit list (M4).
	hsConfigWriteOnEvent  = "headscale.settings.config_write_enabled"
	hsConfigWriteOffEvent = "headscale.settings.config_write_disabled"
)

// HSSettingsStore is the settings table. *db.Queries satisfies it.
type HSSettingsStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	UpsertSetting(ctx context.Context, arg db.UpsertSettingParams) error
}

// HSSettingsPolicy reads the live Headscale policy. *headscale.Client satisfies it.
type HSSettingsPolicy = DevicePolicyReader

// HSSettingsConfig wires the settings screen. Every field is required.
type HSSettingsConfig struct {
	Store   HSSettingsStore
	Policy  HSSettingsPolicy
	Checker policydoc.Checker
	Auditor SiteAuditor
	// WebhookPort is the hook.listen port, the default of the locked webhook rule.
	WebhookPort int
	DryRun      change.DryRun
	CSRF        *CSRF
	// AdminApply and AdminState make an admin-group change (DevopsGroup) one operation: the new
	// group reaches the Caddy gate and is validated before the middleware switches (issue #3).
	// Both are required for such a change; without them it is refused.
	AdminApply AdminGroupApplier
	AdminState *AdminGroupState
	// Now stamps the stored value; it defaults to time.Now.
	Now func() time.Time
}

// AdminGroupApplier applies the Caddy system site with the stored admin group. The caller holds the
// writer lock. *change.SitePipeline satisfies it.
type AdminGroupApplier interface {
	ResyncLocked(ctx context.Context, actor string) (change.SiteResult, error)
}

// HSSettingsHandler serves the settings screen.
type HSSettingsHandler struct {
	cfg HSSettingsConfig
}

// NewHSSettingsHandler validates the wiring.
func NewHSSettingsHandler(cfg HSSettingsConfig) (*HSSettingsHandler, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("web: headscale settings needs a settings store")
	case cfg.Policy == nil:
		return nil, errors.New("web: headscale settings needs a policy reader")
	case cfg.Checker == nil:
		return nil, errors.New("web: headscale settings needs a policy checker")
	case cfg.Auditor == nil:
		return nil, errors.New("web: headscale settings needs an auditor")
	case cfg.WebhookPort < 1 || cfg.WebhookPort > 65535:
		return nil, errors.New("web: headscale settings needs the webhook port")
	case cfg.DryRun == nil:
		return nil, errors.New("web: headscale settings needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: headscale settings needs a CSRF signer")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &HSSettingsHandler{cfg: cfg}, nil
}

// Register adds the settings routes to mux.
func (h *HSSettingsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/settings", h.page)
	mux.HandleFunc("POST /headscale/settings/tags", h.tags)
	mux.HandleFunc("POST /headscale/settings/locked", h.locked)
	mux.HandleFunc("POST /headscale/settings/config-write", h.configWrite)
}

// hsLockedFields is the locked parameter form, as text so a refused input is shown back unchanged.
type hsLockedFields struct {
	DevopsGroup, ServerTag, UIPort, K8sTag, WebhookPort, SSHSrc, SSHDst, SSHPort string
}

func lockedFields(c policydoc.LockedConfig) hsLockedFields {
	return hsLockedFields{
		DevopsGroup: c.DevopsGroup, ServerTag: c.ServerTag, UIPort: strconv.Itoa(c.UIPort), K8sTag: c.K8sTag,
		WebhookPort: strconv.Itoa(c.WebhookPort), SSHSrc: c.SSHSrc, SSHDst: strings.Join(c.SSHDst, ", "),
		SSHPort: strconv.Itoa(c.SSHPort),
	}
}

func lockedFieldsFromForm(r *http.Request) hsLockedFields {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return hsLockedFields{
		DevopsGroup: get("devops_group"), ServerTag: get("server_tag"), UIPort: get("ui_port"), K8sTag: get("k8s_tag"),
		WebhookPort: get("webhook_port"), SSHSrc: get("ssh_src"), SSHDst: get("ssh_dst"), SSHPort: get("ssh_port"),
	}
}

// config parses the text fields; the strict validation is LockedConfig.Validate's.
func (f hsLockedFields) config() (policydoc.LockedConfig, error) {
	port := func(name, s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("%s bir sayı olmalı (1-65535): %q", name, s)
		}
		return n, nil
	}
	var c policydoc.LockedConfig
	var err error
	c.DevopsGroup, c.ServerTag, c.K8sTag, c.SSHSrc = f.DevopsGroup, f.ServerTag, f.K8sTag, f.SSHSrc
	if c.UIPort, err = port("tagcess arayüz portu", f.UIPort); err != nil {
		return c, err
	}
	if c.WebhookPort, err = port("webhook portu", f.WebhookPort); err != nil {
		return c, err
	}
	if c.SSHPort, err = port("SSH portu", f.SSHPort); err != nil {
		return c, err
	}
	for _, d := range strings.FieldsFunc(f.SSHDst, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if !slices.Contains(c.SSHDst, d) {
			c.SSHDst = append(c.SSHDst, d)
		}
	}
	return c, nil
}

// hsSettingsView is the page data. Error is a refusal shown above the forms, Notice a result; Locked
// holds the form values (the stored ones, or the refused input).
type hsSettingsView struct {
	Tags          []string
	TagsDefault   bool
	Locked        hsLockedFields
	LockedDefault bool
	// ConfigWrite is the H-07 write switch (F3b-021); ConfigWriteStored says a row exists and
	// ConfigWriteError carries an unreadable setting (fail-closed: off).
	ConfigWrite       bool
	ConfigWriteStored bool
	ConfigWriteError  string
	Error             string
	Notice            string
	DryRun            bool
}

// hsConfirmView is the confirmation page of a weakening change: Fields are posted back with the
// confirm flag and Base, the hash of the stored value the operator saw.
type hsConfirmView struct {
	Action  string
	Heading string
	Reasons []string
	Fields  []hsField
	Base    string
	// Warning overrides the default "this weakens the protection" line; ConfirmLabel the button.
	Warning      string
	ConfirmLabel string
}

type hsField struct{ Name, Value string }

// baseView reads the stored values; an unreadable or corrupt tag/locked setting is an error (fail
// safe). The write switch is read separately and fail-closed: an unreadable row shows off with a
// reason instead of failing the page.
func (h *HSSettingsHandler) baseView(ctx context.Context) (hsSettingsView, error) {
	var v hsSettingsView
	tags, isDefault, err := hsadmin.LoadProtectedTags(ctx, h.cfg.Store)
	if err != nil {
		return v, err
	}
	locked, lockedDefault, err := policydoc.LoadLocked(ctx, h.cfg.Store, h.cfg.WebhookPort)
	if err != nil {
		return v, err
	}
	v.Tags, v.TagsDefault = tags, isDefault
	v.Locked, v.LockedDefault = lockedFields(locked), lockedDefault
	on, stored, err := h.configWriteSwitch(ctx)
	if err != nil {
		slog.Default().Warn("headscale settings: write switch unreadable", "err", err)
		v.ConfigWriteError = "Config yazma switch'i okunamadı; kapalı varsayıldı: " + err.Error()
	}
	v.ConfigWrite, v.ConfigWriteStored = on, stored
	return v, nil
}

func (h *HSSettingsHandler) render(w http.ResponseWriter, r *http.Request, status int, v hsSettingsView) {
	dry, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dry
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Headscale ayarları",
		HSSettingsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderBase shows the page with the stored values and the given message; status says whether it is
// a refusal.
func (h *HSSettingsHandler) renderBase(w http.ResponseWriter, r *http.Request, status int, mut func(*hsSettingsView)) {
	v, err := h.baseView(r.Context())
	if err != nil {
		slog.Default().Warn("headscale settings: stored setting unreadable", "err", err)
		http.Error(w, "ayar okunamadı veya bozuk; değişiklik yapılmadı: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if mut != nil {
		mut(&v)
	}
	h.render(w, r, status, v)
}

func (h *HSSettingsHandler) renderConfirm(w http.ResponseWriter, r *http.Request, v hsConfirmView) {
	actor, _ := ActorFrom(r.Context())
	if v.Warning == "" {
		v.Warning = "Bu değişiklik korumayı zayıflatır:"
	}
	if v.ConfirmLabel == "" {
		v.ConfirmLabel = "Zayıflatmayı onayla"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Korumayı zayıflatan değişiklik",
		HSSettingsConfirmPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

func (h *HSSettingsHandler) page(w http.ResponseWriter, r *http.Request) {
	h.renderBase(w, r, http.StatusOK, nil)
}

// outcome is what a locked-section decision produced; the handler renders it after the writer lock
// is released.
type outcome struct {
	status  int
	notice  string
	errText string
	confirm *hsConfirmView
	// form replaces the shown locked form values (the refused input).
	form *hsLockedFields
}

func refuse(status int, format string, args ...any) outcome {
	return outcome{status: status, errText: fmt.Sprintf(format, args...)}
}

func (h *HSSettingsHandler) respond(w http.ResponseWriter, r *http.Request, o outcome) {
	if o.confirm != nil {
		h.renderConfirm(w, r, *o.confirm)
		return
	}
	h.renderBase(w, r, o.status, func(v *hsSettingsView) {
		v.Error, v.Notice = o.errText, o.notice
		if o.form != nil {
			v.Locked = *o.form
		}
	})
}

// tags handles add and remove of one protected tag.
func (h *HSSettingsHandler) tags(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	action := strings.TrimSpace(r.PostFormValue("action"))
	tag := strings.TrimSpace(r.PostFormValue("tag"))
	confirmed := r.PostFormValue("confirm") == "1"
	base := r.PostFormValue("base")

	var o outcome
	_ = change.WithWriterLock(func() error {
		o = h.applyTags(r.Context(), actor, action, tag, confirmed, base)
		return nil
	})
	h.respond(w, r, o)
}

func (h *HSSettingsHandler) applyTags(ctx context.Context, actor, action, tag string, confirmed bool, base string) outcome {
	cur, _, err := hsadmin.LoadProtectedTags(ctx, h.cfg.Store)
	if err != nil {
		return refuse(http.StatusInternalServerError, "korumalı tag listesi okunamadı veya bozuk; değişiklik yapılmadı: %v", err)
	}
	if !policydoc.ValidTag(tag) {
		return h.failTags(ctx, actor, cur, cur, http.StatusBadRequest,
			fmt.Sprintf("geçersiz tag %q: tag:ad biçiminde olmalı (küçük harf, rakam, tire)", tag))
	}
	var next []string
	switch action {
	case "add":
		if slices.Contains(cur, tag) {
			return outcome{status: http.StatusOK, notice: tag + " zaten korumalı listede; değişiklik yok"}
		}
		next = append(slices.Clone(cur), tag)
	case "remove":
		i := slices.Index(cur, tag)
		if i < 0 {
			return h.failTags(ctx, actor, cur, cur, http.StatusBadRequest, tag+" korumalı listede değil")
		}
		next = slices.Delete(slices.Clone(cur), i, i+1)
		if len(next) == 0 {
			return h.failTags(ctx, actor, cur, cur, http.StatusBadRequest,
				"korumalı tag listesi boş bırakılamaz; en az bir sunucu tag'i korunmalı")
		}
		if !confirmed {
			return outcome{confirm: &hsConfirmView{
				Action:  "/headscale/settings/tags",
				Heading: tag + " korumalı listeden çıkarılsın mı?",
				Reasons: []string{
					"Bu tag'i taşıyan node'lar silme, expire ve tag değişikliğine karşı artık korumasız kalır.",
					"Tag kişisel cihazlara atanabilir hale gelir.",
				},
				Fields: []hsField{{"action", "remove"}, {"tag", tag}},
				Base:   listBase(cur),
			}}
		}
		if base != listBase(cur) {
			return h.failTags(ctx, actor, cur, next, http.StatusConflict,
				"korumalı liste onay sayfası açıldıktan sonra değişti; sayfayı yenileyip yeniden deneyin")
		}
	default:
		return h.failTags(ctx, actor, cur, cur, http.StatusBadRequest, fmt.Sprintf("bilinmeyen işlem %q", action))
	}

	raw, err := hsadmin.ProtectedTagsSetting(next)
	if err != nil {
		return h.failTags(ctx, actor, cur, next, http.StatusBadRequest, err.Error())
	}
	before, _ := json.Marshal(cur)
	if status, msg := h.store(ctx, actor, hsTagsEvent, hsadmin.ProtectedTagsKey, string(before), raw); msg != "" {
		return refuse(status, "%s", msg)
	}
	return outcome{status: http.StatusOK, notice: "korumalı tag listesi güncellendi"}
}

// failTags audits a refused tag change and returns the refusal.
func (h *HSSettingsHandler) failTags(ctx context.Context, actor string, cur, next []string, status int, reason string) outcome {
	b, _ := json.Marshal(cur)
	a, _ := json.Marshal(next)
	h.auditOutcome(ctx, actor, hsTagsEvent, "failed", audit.Diff{
		{Field: hsadmin.ProtectedTagsKey, Before: string(b), After: string(a)},
		{Field: "error", After: reason},
	})
	return refuse(status, "%s", reason)
}

// locked handles the locked test parameters.
func (h *HSSettingsHandler) locked(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fields := lockedFieldsFromForm(r)
	confirmed := r.PostFormValue("confirm") == "1"
	base := r.PostFormValue("base")

	// Read, validate against the live policy and write under the writer lock: no policy save can
	// change the live policy between the check and the write.
	ctx, cancel := context.WithTimeout(r.Context(), hsSettingsCheckTimeout)
	defer cancel()
	var o outcome
	_ = change.WithWriterLock(func() error {
		o = h.applyLocked(ctx, actor, fields, confirmed, base)
		return nil
	})
	h.respond(w, r, o)
}

func (h *HSSettingsHandler) applyLocked(ctx context.Context, actor string, fields hsLockedFields, confirmed bool, base string) outcome {
	cur, _, err := policydoc.LoadLocked(ctx, h.cfg.Store, h.cfg.WebhookPort)
	if err != nil {
		return refuse(http.StatusInternalServerError, "kilitli test ayarı okunamadı veya bozuk; değişiklik yapılmadı: %v", err)
	}
	curRaw, _ := cur.Setting()
	fail := func(status int, reason string) outcome {
		h.auditOutcome(ctx, actor, hsLockedEvent, "failed", audit.Diff{
			{Field: policydoc.LockedTestsKey, Before: curRaw},
			{Field: "error", After: reason},
		})
		o := refuse(status, "%s", reason)
		o.form = &fields
		return o
	}

	next, err := fields.config()
	if err == nil {
		err = next.Validate()
	}
	if err != nil {
		return fail(http.StatusBadRequest, "geçersiz değer: "+err.Error())
	}
	nextRaw, err := next.Setting()
	if err != nil {
		return fail(http.StatusBadRequest, "geçersiz değer: "+err.Error())
	}
	if nextRaw == curRaw {
		return outcome{status: http.StatusOK, notice: "kilitli test parametreleri zaten bu değerlerde; değişiklik yok"}
	}
	if confirmed && base != settingBase(curRaw) {
		return fail(http.StatusConflict, "kilitli parametreler onay sayfası açıldıktan sonra değişti; sayfayı yenileyip yeniden deneyin")
	}

	// The new tests must pass on the live policy, or the lock would be born broken.
	live, err := h.cfg.Policy.GetPolicy(ctx)
	if err != nil {
		return fail(http.StatusBadGateway, "canlı policy okunamadı; yeni kilitli testler doğrulanamadığı için kaydedilmedi: "+err.Error())
	}
	injected, err := policydoc.Inject(live.Text, next)
	if err != nil {
		return fail(http.StatusUnprocessableEntity, "canlı policy yeni kilitli testlerle kurulamadı: "+err.Error())
	}
	if rep := policydoc.Validate(ctx, injected.Text, next, h.cfg.Checker); !rep.Valid() {
		return fail(http.StatusUnprocessableEntity, "canlı policy yeni kilitli testleri geçemiyor; ayar kaydedilmedi: "+reportFailure(rep))
	}

	if weak := cur.Weakens(next); len(weak) > 0 && !confirmed {
		reasons := make([]string, 0, len(weak)+1)
		for _, f := range weak {
			reasons = append(reasons, lockedFieldLabel(f)+" değişiyor: eski değerin korunduğu artık sınanmaz.")
		}
		reasons = append(reasons, "Yeni kilitli testler canlı policy'de geçti; bir sonraki policy kaydında işaretli girdiler yeni cluster'la değiştirilir.")
		return outcome{confirm: &hsConfirmView{
			Action:  "/headscale/settings/locked",
			Heading: "Kilitli test parametreleri zayıflatılsın mı?",
			Reasons: reasons,
			Fields: []hsField{
				{"devops_group", fields.DevopsGroup}, {"server_tag", fields.ServerTag}, {"ui_port", fields.UIPort},
				{"k8s_tag", fields.K8sTag}, {"webhook_port", fields.WebhookPort}, {"ssh_src", fields.SSHSrc},
				{"ssh_dst", fields.SSHDst}, {"ssh_port", fields.SSHPort},
			},
			Base: settingBase(curRaw),
		}}
	}

	adminChanged := cur.AdminGroup() != next.AdminGroup()
	if adminChanged {
		// The new group must pass both gates before it takes effect, and the saving admin must
		// still get in afterwards, or nobody could reach the UI to undo it (S-05, hard rule 7).
		switch me, _ := ActorFrom(ctx); {
		case h.cfg.AdminApply == nil || h.cfg.AdminState == nil:
			return fail(http.StatusServiceUnavailable, "yönetici grubu değişikliği Caddy'ye apply edilemiyor (site pipeline bağlı değil); değişiklik yapılmadı")
		case !me.HasGroup(next.AdminGroup()):
			return fail(http.StatusForbidden, "yeni yönetici grubuna ("+next.AdminGroup()+") siz de üye değilsiniz; kendinizi kilitleyeceğiniz için kaydedilmedi")
		}
		if on, err := h.cfg.DryRun.DryRun(ctx); err != nil || on {
			return fail(http.StatusConflict, "dry-run açıkken veya okunamazken yönetici grubu değiştirilemez; Caddy'ye apply edilemez")
		}
		h.cfg.AdminState.Pin(cur.AdminGroup()) // the middleware keeps the old group until the apply succeeds
	}

	if status, msg := h.store(ctx, actor, hsLockedEvent, policydoc.LockedTestsKey, curRaw, nextRaw); msg != "" {
		o := refuse(status, "%s", msg)
		o.form = &fields
		return o
	}
	if adminChanged {
		res, err := h.cfg.AdminApply.ResyncLocked(ctx, actor)
		if err != nil || (res.Status != change.StatusApplied && res.Status != change.StatusNoChange) {
			why := res.Status
			if err != nil {
				why = err.Error()
			}
			// Keep the last good group everywhere: the stored value goes back, the middleware never moved.
			note := "eski yönetici grubu korundu"
			if status, msg := h.store(ctx, actor, hsLockedEvent, policydoc.LockedTestsKey, nextRaw, curRaw); msg != "" {
				note = fmt.Sprintf("kayıtlı ayar eski değerine döndürülemedi (%d: %s); kontrol edin", status, msg)
			}
			return fail(http.StatusBadGateway, "yeni yönetici grubu Caddy'ye apply edilemedi ("+why+"); "+note)
		}
		h.cfg.AdminState.Set(next.AdminGroup())
		return outcome{status: http.StatusOK, notice: "kilitli test parametreleri kaydedildi; yönetici grubu Caddy'de ve arayüzde etkin; yeni testler bir sonraki policy kaydında enjekte edilir"}
	}
	return outcome{status: http.StatusOK, notice: "kilitli test parametreleri kaydedildi; yeni testler bir sonraki policy kaydında enjekte edilir"}
}

// configWrite handles the H-07 write switch (F3b-021, R2:29 c): the service reads
// headscale.config_write_enabled and refuses unless it is "true". Both opening and closing are
// protection changes, so each carries an explicit confirmation and is audited with actor and
// before/after. A missing row is off; an unreadable row is off and refuses every change.
func (h *HSSettingsHandler) configWrite(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	want, ok := parseSwitchValue(r.PostFormValue("enabled"))
	if !ok {
		http.Error(w, "geçersiz istek", http.StatusBadRequest)
		return
	}
	confirmed := r.PostFormValue("confirm") == "1"
	base := r.PostFormValue("base")

	var o outcome
	_ = change.WithWriterLock(func() error {
		o = h.applyConfigWrite(r.Context(), actor, want, confirmed, base)
		return nil
	})
	h.respond(w, r, o)
}

func (h *HSSettingsHandler) applyConfigWrite(ctx context.Context, actor string, want, confirmed bool, base string) outcome {
	on, _, err := h.configWriteSwitch(ctx)
	if err != nil {
		return refuse(http.StatusInternalServerError, "Config yazma switch'i okunamadı; değişiklik yapılmadı: %v", err)
	}
	if on == want {
		return outcome{status: http.StatusOK, notice: configWriteNotice(want, true)}
	}
	before, after := strconv.FormatBool(on), strconv.FormatBool(want)
	if !confirmed {
		return outcome{confirm: &hsConfirmView{
			Action:       "/headscale/settings/config-write",
			Heading:      configWriteHeading(want),
			Warning:      configWriteWarning(want),
			Reasons:      configWriteReasons(want),
			Fields:       []hsField{{Name: "enabled", Value: after}},
			Base:         settingBase(before),
			ConfirmLabel: configWriteConfirmLabel(want),
		}}
	}
	if base != settingBase(before) {
		return refuse(http.StatusConflict, "Config yazma switch'i onay sayfası açıldıktan sonra değişti; sayfayı yenileyip yeniden deneyin")
	}
	event := hsConfigWriteOnEvent
	if !want {
		event = hsConfigWriteOffEvent
	}
	if status, msg := h.store(ctx, actor, event, hostapply.SettingConfigWriteEnabled, before, after); msg != "" {
		return refuse(status, "%s", msg)
	}
	return outcome{status: http.StatusOK, notice: configWriteNotice(want, false)}
}

// configWriteSwitch reads the write switch. A missing row is the default off; any other read error
// is fail-closed (off, no row) and is refused rather than assumed on. A stored value that is not a
// boolean is not "true", so the switch shows off.
func (h *HSSettingsHandler) configWriteSwitch(ctx context.Context) (on, stored bool, err error) {
	v, gerr := h.cfg.Store.GetSetting(ctx, hostapply.SettingConfigWriteEnabled)
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

// parseSwitchValue accepts only the two explicit values the form sends.
func parseSwitchValue(v string) (bool, bool) {
	switch strings.TrimSpace(v) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func configWriteNotice(on, unchanged bool) string {
	if unchanged {
		if on {
			return "Config yazma switch'i zaten açık; değişiklik yok"
		}
		return "Config yazma switch'i zaten kapalı; değişiklik yok"
	}
	if on {
		return "Config yazma switch'i açıldı; config yazması artık başlatılabilir"
	}
	return "Config yazma switch'i kapatıldı; yeni config yazması başlatılamaz"
}

func configWriteHeading(on bool) string {
	if on {
		return "Config yazma switch'i açılsın mı?"
	}
	return "Config yazma switch'i kapatılsın mı?"
}

func configWriteWarning(on bool) string {
	if on {
		return "Bu değişiklik Headscale config yazmasını açar (korumayı zayıflatır):"
	}
	return "Bu değişiklik Headscale config yazmasını kapatır:"
}

func configWriteConfirmLabel(on bool) string {
	if on {
		return "Yazma switch'ini aç"
	}
	return "Yazma switch'ini kapat"
}

func configWriteReasons(on bool) []string {
	if on {
		return []string{
			"Açıkken devops, allowed_groups değişikliğini onaylayıp Headscale config'ini tagcess üzerinden yazabilir.",
			"Bu switch üretimde yalnız lab groups-claim kabul/ret matrisi geçtikten sonra açılmalıdır.",
		}
	}
	return []string{
		"Tagcess yeni bir config yazması başlatamaz.",
		"Devam eden bakım veya host işlemi etkilenmez; yalnız yeni patch başlaması engellenir.",
	}
}

// store writes the setting with its audit entries: "requested" (with before and after) first, so an
// audit failure writes nothing, then the outcome. A non-empty message is the refusal.
func (h *HSSettingsHandler) store(ctx context.Context, actor, event, key, before, after string) (int, string) {
	diff := audit.Diff{{Field: key, Before: before, After: after}}
	if err := h.audit(ctx, actor, event, "requested", diff); err != nil {
		return http.StatusInternalServerError, "işlem kaydedilemedi; ayar değiştirilmedi"
	}
	err := h.cfg.Store.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: key, Value: after, UpdatedAt: h.cfg.Now().UTC().Format(storedTimeFormat),
	})
	if err != nil {
		h.auditOutcome(ctx, actor, event, "failed", append(diff, audit.Change{Field: "error", After: err.Error()}))
		return http.StatusInternalServerError, "ayar yazılamadı: " + err.Error()
	}
	h.auditOutcome(ctx, actor, event, "applied", diff)
	return 0, ""
}

func (h *HSSettingsHandler) audit(ctx context.Context, actor, event, result string, diff audit.Diff) error {
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: event, Target: "setting", Diff: diff, Result: result,
	})
	return err
}

func (h *HSSettingsHandler) auditOutcome(ctx context.Context, actor, event, result string, diff audit.Diff) {
	if err := h.audit(ctx, actor, event, result, diff); err != nil {
		slog.Default().Warn("headscale settings: audit outcome write failed", "event", event, "err", err)
	}
}

// reportFailure names the first validation stage that did not pass.
func reportFailure(rep policydoc.Report) string {
	for _, s := range rep.Stages {
		switch s.State {
		case policydoc.StateFail:
			return fmt.Sprintf("%s: %s", s.Stage, s.Message)
		case policydoc.StateUnverified:
			return fmt.Sprintf("%s: doğrulanamadı: %s", s.Stage, s.Message)
		}
	}
	return "rapor eksik"
}

// lockedFieldLabel is the screen's name for a LockedConfig field.
func lockedFieldLabel(field string) string {
	labels := map[string]string{
		"DevopsGroup": "devops grubu (DevopsGroup)", "ServerTag": "sunucu tag'i (ServerTag)",
		"UIPort": "tagcess arayüz portu (UIPort)", "K8sTag": "webhook çağıran tag'i (K8sTag)",
		"WebhookPort": "webhook portu (WebhookPort)", "SSHSrc": "SSH kaynak grubu (SSHSrc)",
		"SSHDst": "SSH hedef tag'leri (SSHDst)", "SSHPort": "SSH portu (SSHPort)",
	}
	if l, ok := labels[field]; ok {
		return l
	}
	return field
}

// listBase binds a tag confirmation to the list the operator saw.
func listBase(tags []string) string { return settingBase(strings.Join(tags, "\n")) }

// settingBase is a short hash of a stored value.
func settingBase(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}
