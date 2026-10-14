package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/policydoc"
)

// The pre-auth key screens (F3-017, H-03/H-05): the key list, expire and delete behind a
// confirmation page, and the creation of tagged keys for shared devices. Every write goes through
// the hsadmin executor (writer lock, audit, read-back); the key value exists only in the create
// response (R2 B-04): it is shown once, never stored, never logged, never audited.

const (
	// defaultKeyExpiry applies when the form gives no expiry; the expiry is always explicit.
	defaultKeyExpiry = time.Hour
	// maxKeyExpiry is the longest a tagged (shared device) key may live (R2 karar 10).
	maxKeyExpiry = 30 * 24 * time.Hour
	// maxTechnicalKeyExpiry bounds a key without a policy limit (personal keys) so the instant stays
	// representable; it is not a policy.
	maxTechnicalKeyExpiry = 100 * 365 * 24 * time.Hour
)

// unknownKeyCreate is the page text of an unknown create outcome (AC7): the RPC may have made a
// key whose value was lost, so a blind retry could make a second one.
const unknownKeyCreate = "Key oluşturma isteği yanıtsız kaldı; sonuç belirsiz: listeyi kontrol edin; yeniden denemek ikinci bir key üretebilir."

var errKeyNotFound = errors.New("web: pre-auth key not found")

// keyAdmin is the Headscale key surface the screens use; *admin.AdminClient satisfies it.
type keyAdmin interface {
	ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error)
	CreatePreAuthKey(ctx context.Context, userID uint64, opts admin.PreAuthKeyOptions) (admin.PreAuthKey, string, error)
	ExpirePreAuthKey(ctx context.Context, id uint64) error
	DeletePreAuthKey(ctx context.Context, id uint64) error
}

// keyPolicyReader reads the live policy; *headscale.Client satisfies it.
type keyPolicyReader interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
}

// keyExecutor is the F3-009 pipeline; *hsadmin.Executor satisfies it.
type keyExecutor interface {
	Do(ctx context.Context, op hsadmin.Op) (hsadmin.Result, error)
	ProtectedTags(ctx context.Context) ([]string, error)
}

// KeysServiceConfig wires the key service. Now is optional (tests pin it).
type KeysServiceConfig struct {
	Admin  keyAdmin
	Policy keyPolicyReader
	Exec   keyExecutor
	Now    func() time.Time
}

// KeysService builds the key screens and runs their operations. Use NewKeysService.
type KeysService struct {
	hs     keyAdmin
	policy keyPolicyReader
	exec   keyExecutor
	now    func() time.Time
}

// NewKeysService validates the wiring.
func NewKeysService(cfg KeysServiceConfig) (*KeysService, error) {
	switch {
	case cfg.Admin == nil:
		return nil, errors.New("web: keys page needs a Headscale admin client")
	case cfg.Policy == nil:
		return nil, errors.New("web: keys page needs a policy reader")
	case cfg.Exec == nil:
		return nil, errors.New("web: keys page needs an admin executor")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &KeysService{hs: cfg.Admin, policy: cfg.Policy, exec: cfg.Exec, now: now}, nil
}

// KeyRowView is one row of the key list; the display texts are ready to render. It has no field
// for a key value on purpose.
type KeyRowView struct {
	ID        uint64
	Owner     string
	Tags      []string
	Reusable  bool
	Ephemeral bool
	Used      bool
	Expiry    string
	Created   string
	Status    string
	Expired   bool
}

// activeKeys and expiredKeys split the list: expired keys cannot be used any more and are folded
// away under the active ones (F5 E4).
func activeKeys(rows []KeyRowView) []KeyRowView { return filterKeys(rows, false) }

func expiredKeys(rows []KeyRowView) []KeyRowView { return filterKeys(rows, true) }

func filterKeys(rows []KeyRowView, expired bool) []KeyRowView {
	var out []KeyRowView
	for _, r := range rows {
		if r.Expired == expired {
			out = append(out, r)
		}
	}
	return out
}

// KeysView is the /headscale/keys snapshot. Err means the key list could not be read (no rows are
// shown); TagsErr means the tag choices could not be read (the create form is not shown).
type KeysView struct {
	Rows       []KeyRowView
	Err        error
	TagOptions []string
	TagsErr    error
	FormError  string
	DryRun     bool
}

// KeyConfirmView is the confirm page of an expire or delete; Version binds the POST to the state
// the page showed.
type KeyConfirmView struct {
	Row     KeyRowView
	Action  string
	Version string
	DryRun  bool
}

// Key operation outcomes, as the handler maps them to a status code.
const (
	keyApplied = "applied"
	keyRefused = "refused"
	keyStale   = "stale"
	keyFailed  = "failed"
	keyUnknown = "unknown"
)

// KeyOutcome is what a key operation did. Secret is set only on an applied create and is for the
// one response that shows it.
type KeyOutcome struct {
	Status  string
	Message string
	KeyID   uint64
	Secret  string
}

// TagKeyInput is the create form of a tagged key. ExpiresIn is empty for the default.
type TagKeyInput struct {
	Tags      []string
	Reusable  bool
	Ephemeral bool
	ExpiresIn string
}

// Keys reads the key list and the tag choices; each failure is carried in the view.
func (s *KeysService) Keys(ctx context.Context) KeysView {
	var v KeysView
	keys, err := s.hs.ListPreAuthKeys(ctx)
	if err != nil {
		v.Err = fmt.Errorf("web: list pre-auth keys: %w", err)
	} else {
		now := s.now()
		for _, k := range keys {
			v.Rows = append(v.Rows, keyRowView(k, now))
		}
		sort.Slice(v.Rows, func(i, j int) bool { return v.Rows[i].ID > v.Rows[j].ID })
	}
	v.TagOptions, v.TagsErr = s.tagOptions(ctx)
	return v
}

// Confirm reads one key for its confirm page; an unknown id is errKeyNotFound.
func (s *KeysService) Confirm(ctx context.Context, id uint64, action string) (KeyConfirmView, error) {
	keys, err := s.hs.ListPreAuthKeys(ctx)
	if err != nil {
		return KeyConfirmView{}, fmt.Errorf("web: list pre-auth keys: %w", err)
	}
	for _, k := range keys {
		if k.ID == id {
			return KeyConfirmView{Row: keyRowView(k, s.now()), Action: action, Version: hsadmin.PreAuthVersion(k)}, nil
		}
	}
	return KeyConfirmView{}, errKeyNotFound
}

// Expire expires the key after the confirmation; the read-back must show it expired.
func (s *KeysService) Expire(ctx context.Context, actor string, id uint64, version string) KeyOutcome {
	op := hsadmin.Op{
		Actor: actor, Kind: hsadmin.KindPreAuthExpire, ID: id,
		Target:   "preauth:" + strconv.FormatUint(id, 10),
		Expected: version,
		Diff:     audit.Diff{{Field: "expiration", After: "expired"}},
		Apply:    func(ctx context.Context) error { return s.hs.ExpirePreAuthKey(ctx, id) },
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) {
			k, found, err := findKey(ctx, r, id)
			if err != nil || !found {
				return false, err
			}
			return k.Expiration != nil && !k.Expiration.After(s.now()), nil
		},
	}
	return s.run(ctx, op, "Key iptal edildi: süresi doldu. Bu key ile yeni kayıt yapılamaz; mevcut node'lar etkilenmez.", id)
}

// Delete deletes the key after the confirmation; the read-back must show it gone. The devices
// registered with it stay (R2 B-04).
func (s *KeysService) Delete(ctx context.Context, actor string, id uint64, version string) KeyOutcome {
	op := hsadmin.Op{
		Actor: actor, Kind: hsadmin.KindPreAuthDelete, ID: id,
		Target:   "preauth:" + strconv.FormatUint(id, 10),
		Expected: version,
		Diff:     audit.Diff{{Field: "key", After: "deleted"}},
		Apply:    func(ctx context.Context) error { return s.hs.DeletePreAuthKey(ctx, id) },
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) {
			_, found, err := findKey(ctx, r, id)
			return err == nil && !found, err
		},
	}
	return s.run(ctx, op, "Key silindi; node'lar silinmedi.", id)
}

// CreateTagKey makes a tagged key for shared devices. The input is checked first (tags present,
// expiry in range); the tags are checked against the live policy and the protected list under the
// writer lock, right before the RPC. The RPC runs once: a failed or unanswered create is an
// unknown outcome, never retried.
func (s *KeysService) CreateTagKey(ctx context.Context, actor string, in TagKeyInput) KeyOutcome {
	tags := uniqueSorted(in.Tags)
	if len(tags) == 0 {
		return KeyOutcome{Status: keyRefused, Message: "En az bir tag seçilmeli."}
	}
	expiry, err := parseKeyExpiry(in.ExpiresIn, s.now(), maxKeyExpiry)
	if err != nil {
		return KeyOutcome{Status: keyRefused, Message: err.Error()}
	}

	diff := audit.Diff{
		{Field: "tags", After: strings.Join(tags, ",")},
		{Field: "reusable", After: strconv.FormatBool(in.Reusable)},
		{Field: "ephemeral", After: strconv.FormatBool(in.Ephemeral)},
		{Field: "expiration", After: expiry.UTC().Format(time.RFC3339)},
	}
	return createPreAuthKey(ctx, s.exec, s.hs, createKey{
		Actor: actor, UserID: 0, Diff: diff,
		Opts:     admin.PreAuthKeyOptions{Reusable: in.Reusable, Ephemeral: in.Ephemeral, Expiration: expiry, Tags: tags},
		Precheck: func(ctx context.Context) error { return s.checkTags(ctx, tags) },
	})
}

// createKey describes one key creation for createPreAuthKey. Diff holds the audit fields known
// beforehand; the key id and the masked value are appended by the helper.
type createKey struct {
	Actor    string
	UserID   uint64 // 0 for a tagged key: the nodes it registers are owned by their tags
	Opts     admin.PreAuthKeyOptions
	Diff     audit.Diff
	Precheck func(ctx context.Context) error
}

// createPreAuthKey runs one key creation through the executor and returns the outcome with the
// one-time value. The RPC runs once; an RPC error or a lost answer is an unknown outcome and is
// never retried. The value stays in this function's closure: it is neither audited nor logged, and
// an RPC error text is stripped of anything that looks like a key before it can reach the audit.
func createPreAuthKey(ctx context.Context, exec keyExecutor, hs keyAdmin, c createKey) KeyOutcome {
	var (
		created admin.PreAuthKey
		secret  string
		made    bool
	)
	tags := uniqueSorted(c.Opts.Tags)
	diff := append(slices.Clone(c.Diff),
		audit.Change{Field: "id"},                // filled in by Apply, once the key exists
		audit.Change{Field: "key", Secret: true}, // the value itself is never recorded
	)
	idSlot := &diff[len(diff)-2]
	op := hsadmin.Op{
		Actor: c.Actor, Kind: hsadmin.KindPreAuthCreate, Target: "preauth:new",
		Diff:     diff,
		Precheck: c.Precheck,
		Apply: func(ctx context.Context) error {
			pk, sec, err := hs.CreatePreAuthKey(ctx, c.UserID, c.Opts)
			if err != nil {
				return errors.New(scrubKeyTokens(err.Error()))
			}
			created, secret, made = pk, sec, true
			idSlot.After = strconv.FormatUint(pk.ID, 10)
			return nil
		},
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) {
			if !made {
				return false, errors.New("oluşturma yanıtı alınamadı; sonuç bilinmiyor")
			}
			k, found, err := findKey(ctx, r, created.ID)
			if err != nil || !found {
				return false, err
			}
			return slices.Equal(uniqueSorted(k.Tags), tags) && k.Reusable == c.Opts.Reusable &&
				k.Ephemeral == c.Opts.Ephemeral && k.UserID == c.UserID, nil
		},
	}
	out := runKeyOp(ctx, exec, op, "", 0)
	switch out.Status {
	case keyApplied:
		if secret == "" {
			return KeyOutcome{Status: keyUnknown, Message: unknownKeyCreate, KeyID: created.ID}
		}
		out.KeyID, out.Secret, out.Message = created.ID, secret, "Key oluşturuldu."
	case keyFailed, keyUnknown:
		// An RPC that failed or whose answer was lost may still have made a key.
		out.Message = unknownKeyCreate
	}
	return out
}

// run executes op and maps the executor's result to an outcome; applied carries doneMsg.
func (s *KeysService) run(ctx context.Context, op hsadmin.Op, doneMsg string, id uint64) KeyOutcome {
	return runKeyOp(ctx, s.exec, op, doneMsg, id)
}

func runKeyOp(ctx context.Context, exec keyExecutor, op hsadmin.Op, doneMsg string, id uint64) KeyOutcome {
	res, err := exec.Do(ctx, op)
	out := KeyOutcome{KeyID: id}
	switch {
	case err == nil:
		out.Status, out.Message = keyApplied, doneMsg
	case errors.Is(err, hsadmin.ErrBlocked):
		out.Status, out.Message = keyRefused, "Reddedildi, hiçbir şey yazılmadı: "+res.Note
	case errors.Is(err, hsadmin.ErrStale):
		out.Status, out.Message = keyStale, "Key sayfa açıldıktan sonra değişti veya artık yok; listeyi yenileyip yeniden deneyin."
	case errors.Is(err, hsadmin.ErrUnknown):
		out.Status, out.Message = keyUnknown, "Sonuç doğrulanamadı; sonuç belirsiz: listeyi kontrol edin. Neden: "+res.Note
	default:
		out.Status, out.Message = keyFailed, "İşlem başarısız: "+firstNonEmpty(res.Note, err.Error())
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// tagOptions is the set of tags a tagged key may carry: the policy's tagOwners keys minus the
// protected server tags. Any read failure is an error and no tag is offered (fail safe).
func (s *KeysService) tagOptions(ctx context.Context) ([]string, error) {
	p, err := s.policy.GetPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy okunamadı: %w", err)
	}
	owners, err := policydoc.TagOwners(p.Text)
	if err != nil {
		return nil, fmt.Errorf("policy tagOwners okunamadı: %w", err)
	}
	protected, err := s.exec.ProtectedTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("korumalı tag listesi okunamadı: %w", err)
	}
	var out []string
	for tag := range owners {
		if !slices.Contains(protected, tag) {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out, nil
}

// checkTags refuses any tag that is not a selectable one, reading the policy and the protected
// list again so the decision is made at the moment of writing.
func (s *KeysService) checkTags(ctx context.Context, tags []string) error {
	allowed, err := s.tagOptions(ctx)
	if err != nil {
		return err
	}
	var bad []string
	for _, t := range tags {
		if !slices.Contains(allowed, t) {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("tag(ler) seçilemez (policy tagOwners'ta yok veya korumalı sunucu tag'i): %s", strings.Join(bad, ", "))
	}
	return nil
}

// keyToken matches a Headscale key value (hskey-auth-..., legacy and prefixed forms).
var keyToken = regexp.MustCompile(`hskey-[A-Za-z]+-[A-Za-z0-9_-]+`)

// scrubKeyTokens masks anything that looks like a key value in an error text, so an RPC error can
// never carry one into the audit log.
func scrubKeyTokens(s string) string { return keyToken.ReplaceAllString(s, audit.Mask) }

func findKey(ctx context.Context, r hsadmin.Reader, id uint64) (admin.PreAuthKey, bool, error) {
	keys, err := r.ListPreAuthKeys(ctx)
	if err != nil {
		return admin.PreAuthKey{}, false, err
	}
	for _, k := range keys {
		if k.ID == id {
			return k, true, nil
		}
	}
	return admin.PreAuthKey{}, false, nil
}

func uniqueSorted(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// parseKeyExpiry turns the form's relative expiry ("90m", "24h", "7d", "2w", "1y"; empty means one
// hour) into an absolute instant. max is the policy limit; 0 means none (personal keys, which also
// make long-lived server keys: 2026-10-06 item 8). A key never has no expiry: Headscale v0.29.4
// stores an omitted expiration as the zero time, which makes the key expired at once
// (hscontrol/grpcv1.go CreatePreAuthKey, types/preauth_key.go Validate). Without a policy limit the
// instant is still capped at maxTechnicalKeyExpiry so the arithmetic cannot overflow.
func parseKeyExpiry(raw string, now time.Time, max time.Duration) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return now.Add(defaultKeyExpiry), nil
	}
	limit := max
	if limit <= 0 {
		limit = maxTechnicalKeyExpiry
	}
	tooLong := errKeyExpiryTooLong
	if max <= 0 {
		tooLong = errKeyExpiryTechnical
	}
	var d time.Duration
	if n, unit, ok := dayUnits(raw); ok {
		if unit == 0 {
			return time.Time{}, errKeyExpiryUnparsable(raw)
		}
		if n > int64(limit/unit) {
			return time.Time{}, tooLong
		}
		d = time.Duration(n) * unit
	} else {
		var err error
		if d, err = time.ParseDuration(raw); err != nil {
			return time.Time{}, errKeyExpiryUnparsable(raw)
		}
	}
	switch {
	case d <= 0:
		return time.Time{}, errKeyExpiryPast
	case d < time.Minute:
		// A key that expires before anyone can use it is refused rather than made.
		return time.Time{}, errKeyExpiryTooShort
	case d > limit:
		return time.Time{}, tooLong
	}
	return now.Add(d), nil
}

// dayUnits reads "<n>d", "<n>w" and "<n>y" (365 days); ok is false for anything else, which then goes
// to time.ParseDuration. A malformed number is reported as ok with a zero unit so it is refused.
func dayUnits(raw string) (int64, time.Duration, bool) {
	const day = 24 * time.Hour
	for _, u := range []struct {
		suffix string
		unit   time.Duration
	}{{"d", day}, {"w", 7 * day}, {"y", 365 * day}} {
		if num, ok := strings.CutSuffix(raw, u.suffix); ok {
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				return 0, 0, true
			}
			return n, u.unit, true
		}
	}
	return 0, 0, false
}

// inputError is a refused form value; its text is the Turkish reason shown to the operator.
type inputError string

func (e inputError) Error() string { return string(e) }

var (
	errKeyExpiryTooLong   = inputError("Süre en fazla 30 gün olabilir.")
	errKeyExpiryTechnical = inputError("Süre en fazla 100 yıl olabilir.")
	errKeyExpiryTooShort  = inputError("Süre en az 1 dakika olmalı.")
	errKeyExpiryPast      = inputError("Süre gelecekte olmalı.")
)

func errKeyExpiryUnparsable(raw string) error {
	return inputError(fmt.Sprintf("Süre anlaşılamadı: %q (örnek: 90m, 24h, 7d, 1y).", raw))
}

// keyRowView maps a key to its list row. The key's value is not part of the DTO, so it cannot be
// rendered. A used one-time key is spent; a reusable key stays active after its first use.
func keyRowView(k admin.PreAuthKey, now time.Time) KeyRowView {
	row := KeyRowView{
		ID: k.ID, Tags: k.Tags, Reusable: k.Reusable, Ephemeral: k.Ephemeral, Used: k.Used,
		Created: formatDeviceTime(k.CreatedAt), Status: "aktif",
	}
	switch {
	case len(k.Tags) > 0:
		row.Owner = "tag'li"
	case k.UserName != "":
		row.Owner = k.UserName
	default:
		row.Owner = "kullanıcı #" + strconv.FormatUint(k.UserID, 10)
	}
	if k.Expiration == nil {
		row.Expiry = "yok"
	} else {
		row.Expiry = formatDeviceTime(*k.Expiration)
	}
	switch {
	case k.Expiration != nil && !k.Expiration.After(now):
		row.Status, row.Expired = "süresi doldu", true
	case k.Used && !k.Reusable:
		row.Status = "kullanıldı"
	}
	return row
}

// KeysHandlerConfig wires the key screens.
type KeysHandlerConfig struct {
	Service KeysManager
	// DryRun carries the dry-run note of the section tab bar (R2 karar 22). Required.
	DryRun change.DryRun
	CSRF   *CSRF
}

// KeysManager is the service the handler drives; *KeysService is the production one.
type KeysManager interface {
	Keys(ctx context.Context) KeysView
	Confirm(ctx context.Context, id uint64, action string) (KeyConfirmView, error)
	Expire(ctx context.Context, actor string, id uint64, version string) KeyOutcome
	Delete(ctx context.Context, actor string, id uint64, version string) KeyOutcome
	CreateTagKey(ctx context.Context, actor string, in TagKeyInput) KeyOutcome
}

// KeysHandler serves the pre-auth key screens.
type KeysHandler struct {
	cfg KeysHandlerConfig
}

// NewKeysHandler validates the wiring.
func NewKeysHandler(cfg KeysHandlerConfig) (*KeysHandler, error) {
	switch {
	case cfg.Service == nil:
		return nil, errors.New("web: keys page needs a service")
	case cfg.DryRun == nil:
		return nil, errors.New("web: keys page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: keys page needs a CSRF signer")
	}
	return &KeysHandler{cfg: cfg}, nil
}

// Register adds the pre-auth routes. /headscale/keys/personal and /headscale/keys/api belong to
// their own tasks.
func (h *KeysHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/keys", h.page)
	mux.HandleFunc("GET /headscale/keys/preauth", h.page)
	mux.HandleFunc("POST /headscale/keys/preauth/create", h.create)
	mux.HandleFunc("GET /headscale/keys/preauth/{id}/{action}", h.confirm)
	mux.HandleFunc("POST /headscale/keys/preauth/{id}/{action}", h.act)
}

// noStore keeps a response out of every cache; the create response carries the key value.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *KeysHandler) page(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, r, "", http.StatusOK)
}

// renderPage renders the list with the create form; formErr is a refused create shown above it.
func (h *KeysHandler) renderPage(w http.ResponseWriter, r *http.Request, formErr string, status int) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view := h.cfg.Service.Keys(r.Context())
	view.DryRun, view.FormError = dryRun, formErr
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Pre-auth key'leri",
		KeysPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// create makes a tagged key and shows its value in this one response.
func (h *KeysHandler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	out := h.cfg.Service.CreateTagKey(r.Context(), actor, TagKeyInput{
		Tags:      r.PostForm["tags"],
		Reusable:  r.PostFormValue("reusable") == "1",
		Ephemeral: r.PostFormValue("ephemeral") == "1",
		ExpiresIn: r.PostFormValue("expires_in"),
	})
	if out.Status == keyRefused {
		h.renderPage(w, r, out.Message, http.StatusBadRequest)
		return
	}
	h.renderOutcome(w, r, "Tag'li pre-auth key", out)
}

// keyAction maps the path's action word to its confirm text; anything else is a 404.
func keyAction(action string) bool { return action == "expire" || action == "delete" }

func (h *KeysHandler) confirm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	action := r.PathValue("action")
	if err != nil || !keyAction(action) {
		http.NotFound(w, r)
		return
	}
	view, err := h.cfg.Service.Confirm(r.Context(), id, action)
	switch {
	case errors.Is(err, errKeyNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "key'ler okunamadı: "+err.Error(), http.StatusBadGateway)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Pre-auth key'i",
		KeyConfirmPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

func (h *KeysHandler) act(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	action := r.PathValue("action")
	if err != nil || !keyAction(action) {
		http.NotFound(w, r)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	version := r.PostFormValue("version")
	var out KeyOutcome
	if action == "expire" {
		out = h.cfg.Service.Expire(r.Context(), actor, id, version)
	} else {
		out = h.cfg.Service.Delete(r.Context(), actor, id, version)
	}
	h.renderOutcome(w, r, "Pre-auth key", out)
}

// renderOutcome renders the result page of an operation on the pre-auth screens.
func (h *KeysHandler) renderOutcome(w http.ResponseWriter, r *http.Request, title string, out KeyOutcome) {
	renderKeyOutcome(w, r, h.cfg.CSRF, title, "preauth", false, out)
}

// renderKeyOutcome renders the result page of a key operation with the status code its outcome maps
// to. bypass adds the OIDC bypass warning of the personal key flow.
func renderKeyOutcome(w http.ResponseWriter, r *http.Request, csrf *CSRF, title, subNav string, bypass bool, out KeyOutcome) {
	status := http.StatusOK
	switch out.Status {
	case keyRefused:
		status = http.StatusBadRequest
	case keyStale:
		status = http.StatusConflict
	case keyFailed, keyUnknown:
		status = http.StatusBadGateway
	}
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, csrf.Token(), "headscale", title,
		KeyResultPage(title, subNav, bypass, out)).Render(r.Context(), w)
}
