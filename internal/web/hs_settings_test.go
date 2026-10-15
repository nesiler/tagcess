package web

import (
	"bytes"
	"context"
	"errors"
	"html"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Harness of the Headscale settings screen (F3-020, H-01/H-04): the protected server tags and the
// locked policy test parameters, over a real settings store and audit log, a fake live policy and a
// fake CheckPolicy.

const (
	hsSettingsActor  = "devops@example.com"
	hsSettingsPolicy = `{
  "tagOwners": {"tag:vpn-server": ["group:devops"], "tag:k8s": ["group:devops"], "tag:db": ["group:devops"]},
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`
)

type fakeSettingsHS struct {
	mu        sync.Mutex
	policy    string
	policyErr error
	checkErr  error
	checked   []string
}

func (f *fakeSettingsHS) GetPolicy(context.Context) (headscale.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return headscale.Policy{Text: f.policy}, f.policyErr
}

func (f *fakeSettingsHS) CheckPolicy(_ context.Context, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, text)
	return f.checkErr
}

func (f *fakeSettingsHS) lastChecked() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.checked) == 0 {
		return ""
	}
	return f.checked[len(f.checked)-1]
}

type hsSettingsHarness struct {
	t     *testing.T
	store *store.Store
	hs    *fakeSettingsHS
	audit *audit.Logger
	exec  *hsadmin.Executor
	csrf  *CSRF
	chain http.Handler
	// apply and state are the admin-group coordination (issue #3).
	apply *fakeAdminApply
	state *AdminGroupState
	// cancelRequest cancels the context of the request being served.
	cancelRequest context.CancelFunc
}

// fakeAdminApply stands in for the site pipeline's targeted admin-group apply. It records the
// group the middleware enforced and the stored setting while the apply runs, and the context it ran on.
type fakeAdminApply struct {
	err         error
	calls       []string // "from>to"
	stateDuring string
	storedAt    string
	ctxErrAtEnd error
	onApply     func() // runs inside the first apply (e.g. cancels the request)
	state       *AdminGroupState
	store       HSSettingsStore
}

func (f *fakeAdminApply) ApplyAdminGroup(ctx context.Context, _, from, to string) error {
	f.calls = append(f.calls, from+">"+to)
	f.stateDuring, _ = f.state.Current(ctx)
	f.storedAt, _ = f.store.GetSetting(ctx, policydoc.LockedTestsKey)
	if f.onApply != nil {
		f.onApply()
	}
	f.ctxErrAtEnd = ctx.Err()
	return f.err
}

func newHSSettingsHarness(t *testing.T) *hsSettingsHarness {
	t.Helper()
	return newHSSettingsHarnessStore(t, nil)
}

// newHSSettingsHarnessStore builds the harness with a settings store wrapper, so a test can make one
// key unreadable or unwritable without touching the others (the fail-closed cases).
func newHSSettingsHarnessStore(t *testing.T, wrap func(HSSettingsStore) HSSettingsStore) *hsSettingsHarness {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h := &hsSettingsHarness{
		t: t, store: s, hs: &fakeSettingsHS{policy: hsSettingsPolicy},
		audit: audit.New(s.Queries()), csrf: testCSRF(t),
	}
	h.state = NewAdminGroupState(func(ctx context.Context) (string, error) {
		c, _, err := policydoc.LoadLocked(ctx, s.Queries(), 9000)
		return c.AdminGroup(), err
	})
	h.exec = hsadmin.New(hsadmin.Config{
		Reader: noopReader{}, Audit: h.audit, Store: s.Queries(),
		Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	var settings HSSettingsStore = s.Queries()
	if wrap != nil {
		settings = wrap(settings)
	}
	h.apply = &fakeAdminApply{state: h.state, store: s.Queries()}
	handler, err := NewHSSettingsHandler(HSSettingsConfig{
		Store: settings, Policy: h.hs, Checker: h.hs, Auditor: h.audit,
		WebhookPort: 9000, DryRun: &fakeDryRunReader{}, CSRF: h.csrf,
		AdminApply: h.apply, AdminState: h.state,
	})
	if err != nil {
		t.Fatalf("NewHSSettingsHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireGroup(h.state.Current, h.csrf.Protect(mux))
	return h
}

// flakySettingsStore fails one key's read or write to exercise the write switch's fail-closed path.
type flakySettingsStore struct {
	HSSettingsStore
	failGet, failPut string
	err              error
}

func (f flakySettingsStore) GetSetting(ctx context.Context, key string) (string, error) {
	if key == f.failGet {
		return "", f.err
	}
	return f.HSSettingsStore.GetSetting(ctx, key)
}

func (f flakySettingsStore) UpsertSetting(ctx context.Context, arg db.UpsertSettingParams) error {
	if arg.Key == f.failPut {
		return f.err
	}
	return f.HSSettingsStore.UpsertSetting(ctx, arg)
}

// noopReader satisfies hsadmin.Reader for tests that only read settings through the executor.
type noopReader struct{}

func (noopReader) ListNodes(context.Context) ([]admin.AdminNode, error)        { return nil, nil }
func (noopReader) ListPreAuthKeys(context.Context) ([]admin.PreAuthKey, error) { return nil, nil }
func (noopReader) ListApiKeys(context.Context) ([]admin.APIKey, error)         { return nil, nil }

func (h *hsSettingsHarness) request(method, target string, form url.Values, groups string, csrf bool) *httptest.ResponseRecorder {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		form = maps.Clone(form) // the caller may reuse its form
		if csrf {
			form.Set(CSRFParam, h.csrf.Token())
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	rctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.cancelRequest = cancel
	req := httptest.NewRequestWithContext(rctx, method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, hsSettingsActor)
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *hsSettingsHarness) get() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/headscale/settings", nil, "devops", false)
}

func (h *hsSettingsHarness) post(target string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, target, form, "devops", true)
}

func (h *hsSettingsHarness) setting(key string) (string, bool) {
	h.t.Helper()
	v, err := h.store.Queries().GetSetting(context.Background(), key)
	if err != nil {
		return "", false
	}
	return v, true
}

func (h *hsSettingsHarness) put(key, value string) {
	h.t.Helper()
	err := h.store.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{Key: key, Value: value, UpdatedAt: "2026-10-01T00:00:00.000Z"})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *hsSettingsHarness) events(event string) []audit.Event {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Event: event, Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	return evs // newest first
}

func (h *hsSettingsHarness) tags() []string {
	h.t.Helper()
	tags, err := h.exec.ProtectedTags(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return tags
}

func (h *hsSettingsHarness) locked() policydoc.LockedConfig {
	h.t.Helper()
	cfg, _, err := policydoc.LoadLocked(context.Background(), h.store.Queries(), 9000)
	if err != nil {
		h.t.Fatal(err)
	}
	return cfg
}

// lockedForm is the form the locked parameter section posts; mut edits the defaults.
func lockedForm(mut func(url.Values)) url.Values {
	v := url.Values{
		"devops_group": {"group:devops"}, "server_tag": {"tag:vpn-server"}, "ui_port": {"443"},
		"k8s_tag": {"tag:k8s"}, "webhook_port": {"9000"}, "ssh_src": {"group:devops"},
		"ssh_dst": {"tag:vpn-server, tag:k8s"}, "ssh_port": {"22"},
	}
	if mut != nil {
		mut(v)
	}
	return v
}

const (
	hsTagsPath   = "/headscale/settings/tags"
	hsLockedPath = "/headscale/settings/locked"
)

// AC1: with nothing stored the page shows the default protected tags and locked parameters and says
// they are defaults; once stored, the stored values show without the default note.
func TestHSSettings_ShowsDefaults(t *testing.T) {
	h := newHSSettingsHarness(t)
	rec := h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"tag:vpn-server", "tag:k8s", "group:devops", "443", "9000", "22", "varsayılan", "Ayarlar",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(body, "varsayılan") < 2 {
		t.Errorf("both sections should say they are defaults:\n%s", body)
	}

	h.put(hsadmin.ProtectedTagsKey, `["tag:edge"]`)
	h.put(policydoc.LockedTestsKey, mustSetting(t, func(c *policydoc.LockedConfig) { c.UIPort = 8443 }))
	body = h.get().Body.String()
	if !strings.Contains(body, "tag:edge") || !strings.Contains(body, "8443") {
		t.Errorf("stored values not shown:\n%s", body)
	}
	if strings.Contains(body, "varsayılan") {
		t.Errorf("stored values are labelled default")
	}
}

func mustSetting(t *testing.T, mut func(*policydoc.LockedConfig)) string {
	t.Helper()
	c := policydoc.DefaultLockedConfig(9000)
	mut(&c)
	raw, err := c.Setting()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// AC2: adding a tag validates and stores it with a before/after audit entry; removing a tag needs the
// confirmation page; the list cannot be emptied; an invalid tag is refused.
func TestHSSettings_ProtectedTags(t *testing.T) {
	h := newHSSettingsHarness(t)

	// Add: one step, stored, audited with the list before and after.
	rec := h.post(hsTagsPath, url.Values{"action": {"add"}, "tag": {"tag:db"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("add: status %d: %s", rec.Code, rec.Body)
	}
	if got := h.tags(); !slices.Equal(got, []string{"tag:vpn-server", "tag:k8s", "tag:db"}) {
		t.Fatalf("after add: %v", got)
	}
	evs := h.events("headscale.settings.protected_tags")
	if len(evs) == 0 || evs[0].Actor != hsSettingsActor || evs[0].Result != "applied" {
		t.Fatalf("audit = %+v", evs)
	}
	var ch audit.Change
	for _, c := range evs[0].Diff {
		if c.Field == hsadmin.ProtectedTagsKey {
			ch = c
		}
	}
	if !strings.Contains(ch.Before, "tag:k8s") || strings.Contains(ch.Before, "tag:db") || !strings.Contains(ch.After, "tag:db") {
		t.Errorf("audit diff before/after = %q / %q", ch.Before, ch.After)
	}

	// Invalid tags are refused, nothing changes.
	for _, bad := range []string{"db", "tag:DB", "tag:", "tag:a b", ""} {
		rec = h.post(hsTagsPath, url.Values{"action": {"add"}, "tag": {bad}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("add %q: status %d, want 400", bad, rec.Code)
		}
	}
	if got := h.tags(); len(got) != 3 {
		t.Errorf("invalid add changed the list: %v", got)
	}

	// Remove without confirmation: confirmation page, nothing stored.
	rec = h.post(hsTagsPath, url.Values{"action": {"remove"}, "tag": {"tag:k8s"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "korumasız") {
		t.Fatalf("remove step 1: status %d, want the weakening page:\n%s", rec.Code, rec.Body)
	}
	if got := h.tags(); len(got) != 3 {
		t.Fatalf("remove before confirmation changed the list: %v", got)
	}
	// Confirmation page carries a base; confirming applies the removal.
	form := confirmForm(t, rec.Body.String())
	rec = h.post(hsTagsPath, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove confirm: status %d: %s", rec.Code, rec.Body)
	}
	if got := h.tags(); !slices.Equal(got, []string{"tag:vpn-server", "tag:db"}) {
		t.Fatalf("after remove: %v", got)
	}
	evs = h.events("headscale.settings.protected_tags")
	if evs[0].Result != "applied" || !strings.Contains(evs[0].Diff[0].After, "tag:vpn-server") {
		t.Errorf("remove audit = %+v", evs[0])
	}

	// A confirmation whose base is stale (the list changed meanwhile) is refused.
	rec = h.post(hsTagsPath, url.Values{"action": {"remove"}, "tag": {"tag:db"}})
	stale := confirmForm(t, rec.Body.String())
	h.post(hsTagsPath, url.Values{"action": {"add"}, "tag": {"tag:edge"}})
	if rec = h.post(hsTagsPath, stale); rec.Code != http.StatusConflict {
		t.Errorf("stale confirm: status %d, want 409", rec.Code)
	}

	// The list cannot be emptied: removing the last tags is refused at the confirmation too.
	h.put(hsadmin.ProtectedTagsKey, `["tag:vpn-server"]`)
	rec = h.post(hsTagsPath, url.Values{"action": {"remove"}, "tag": {"tag:vpn-server"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "boş") {
		t.Errorf("empty list: status %d: %s", rec.Code, rec.Body)
	}
	if got := h.tags(); !slices.Equal(got, []string{"tag:vpn-server"}) {
		t.Errorf("list was emptied: %v", got)
	}
	// Removing a tag that is not in the list is refused.
	if rec = h.post(hsTagsPath, url.Values{"action": {"remove"}, "tag": {"tag:nope"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("remove unknown: status %d", rec.Code)
	}
	// A corrupt stored list blocks every change (fail safe) and never gets overwritten blindly.
	h.put(hsadmin.ProtectedTagsKey, `garbage`)
	if rec = h.post(hsTagsPath, url.Values{"action": {"add"}, "tag": {"tag:new"}}); rec.Code < 500 {
		t.Errorf("corrupt list: status %d, want a server error", rec.Code)
	}
	if v, _ := h.setting(hsadmin.ProtectedTagsKey); v != "garbage" {
		t.Errorf("corrupt value was overwritten: %q", v)
	}
}

// confirmForm extracts the hidden fields of the confirmation form from a page, so a test can post
// exactly what the browser would.
func confirmForm(t *testing.T, page string) url.Values {
	t.Helper()
	form := url.Values{}
	i := strings.Index(page, `id="confirm-form"`)
	if i < 0 {
		t.Fatalf("no confirmation form in page:\n%s", page)
	}
	rest := page[i:]
	if j := strings.Index(rest, "</form>"); j >= 0 {
		rest = rest[:j]
	}
	for _, part := range strings.Split(rest, "<input")[1:] {
		name := attr(part, "name")
		if name == "" || name == CSRFParam {
			continue
		}
		form.Set(name, attr(part, "value"))
	}
	if form.Get("confirm") == "" {
		t.Fatalf("confirmation form has no confirm field:\n%s", rest)
	}
	return form
}

func attr(tag, name string) string {
	key := name + `="`
	i := strings.Index(tag, key)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return htmlUnescape(rest[:j])
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&quot;", `"`, "&lt;", "<", "&gt;", ">", "&#39;", "'").Replace(s)
}

// AC3: new locked parameters are validated against the live policy; a rejection stores nothing and
// shows the reason; an accepted tightening stores in one step; a weakening needs the confirmation page.
func TestHSSettings_LockedParamsValidated(t *testing.T) {
	h := newHSSettingsHarness(t)

	// Invalid field values: refused before the live policy is asked.
	for name, mut := range map[string]func(url.Values){
		"bad tag":   func(v url.Values) { v.Set("server_tag", "tag:UP") },
		"bad group": func(v url.Values) { v.Set("ssh_src", "devops") },
		"port 0":    func(v url.Values) { v.Set("ui_port", "0") },
		"port text": func(v url.Values) { v.Set("webhook_port", "abc") },
		"no dst":    func(v url.Values) { v.Set("ssh_dst", " ") },
	} {
		rec := h.post(hsLockedPath, lockedForm(mut))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	if _, ok := h.setting(policydoc.LockedTestsKey); ok {
		t.Fatal("an invalid form stored a setting")
	}
	if len(h.hs.checked) != 0 {
		t.Errorf("CheckPolicy ran for invalid input")
	}

	// The live policy cannot pass the new test: refused with Headscale's reason, nothing stored.
	h.hs.checkErr = &headscale.PolicyError{Message: "group:devops -> tag:vpn-server:8443: expected ALLOWED, got DENIED"}
	rec := h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ui_port", "8443") }))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("rejected params: status %d, want 422:\n%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "expected ALLOWED, got DENIED") {
		t.Errorf("the reason is not shown:\n%s", rec.Body)
	}
	if _, ok := h.setting(policydoc.LockedTestsKey); ok {
		t.Fatal("a rejected change was stored")
	}
	if !strings.Contains(h.hs.lastChecked(), "tag:vpn-server:8443") {
		t.Errorf("CheckPolicy did not get the new locked test:\n%s", h.hs.lastChecked())
	}
	if evs := h.events("headscale.settings.locked_tests"); len(evs) == 0 || evs[0].Result != "failed" {
		t.Errorf("rejection not audited: %+v", evs)
	}

	// Headscale unreadable or CheckPolicy unreachable: not verified, not stored (fail safe).
	h.hs.checkErr = errors.New("connection refused")
	if rec = h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ui_port", "8443") })); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("unverified: status %d, want 422", rec.Code)
	}
	h.hs.checkErr = nil
	h.hs.policyErr = errors.New("socket closed")
	if rec = h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ui_port", "8443") })); rec.Code < 500 {
		t.Errorf("policy unreadable: status %d, want a server error", rec.Code)
	}
	h.hs.policyErr = nil
	if _, ok := h.setting(policydoc.LockedTestsKey); ok {
		t.Fatal("an unverifiable change was stored")
	}

	// Tightening (one more SSH destination) is accepted in one step.
	rec = h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ssh_dst", "tag:vpn-server, tag:k8s, tag:db") }))
	if rec.Code != http.StatusOK {
		t.Fatalf("tightening: status %d: %s", rec.Code, rec.Body)
	}
	if got := h.locked(); !slices.Equal(got.SSHDst, []string{"tag:vpn-server", "tag:k8s", "tag:db"}) {
		t.Fatalf("stored SSHDst = %v", got.SSHDst)
	}
	evs := h.events("headscale.settings.locked_tests")
	if evs[0].Result != "applied" || len(evs[0].Diff) == 0 || !strings.Contains(evs[0].Diff[0].After, "tag:db") {
		t.Errorf("applied audit = %+v", evs[0])
	}

	// Weakening (a changed port): the page that explains it, nothing stored until confirmed.
	rec = h.post(hsLockedPath, lockedForm(func(v url.Values) {
		v.Set("ssh_dst", "tag:vpn-server, tag:k8s, tag:db")
		v.Set("ui_port", "8443")
	}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "UIPort") {
		t.Fatalf("weakening step 1: status %d:\n%s", rec.Code, rec.Body)
	}
	if h.locked().UIPort != 443 {
		t.Fatal("stored before confirmation")
	}
	form := confirmForm(t, rec.Body.String())
	if rec = h.post(hsLockedPath, form); rec.Code != http.StatusOK {
		t.Fatalf("weakening confirm: status %d:\n%s", rec.Code, rec.Body)
	}
	if h.locked().UIPort != 8443 {
		t.Fatalf("confirmed weakening not stored: %+v", h.locked())
	}

	// The confirmation validates again: if the live policy no longer passes, it is refused.
	rec = h.post(hsLockedPath, lockedForm(func(v url.Values) {
		v.Set("ssh_dst", "tag:vpn-server, tag:k8s, tag:db")
		v.Set("ui_port", "9443")
	}))
	form = confirmForm(t, rec.Body.String())
	h.hs.checkErr = &headscale.PolicyError{Message: "group:devops -> tag:vpn-server:9443: expected ALLOWED, got DENIED"}
	if rec = h.post(hsLockedPath, form); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("confirm after the policy changed: status %d, want 422", rec.Code)
	}
	if h.locked().UIPort != 8443 {
		t.Errorf("stored despite the failed re-validation: %+v", h.locked())
	}
	h.hs.checkErr = nil

	// A confirmation bound to an older stored value is refused.
	rec = h.post(hsLockedPath, lockedForm(func(v url.Values) {
		v.Set("ssh_dst", "tag:vpn-server, tag:k8s, tag:db")
		v.Set("ui_port", "9443")
	}))
	stale := confirmForm(t, rec.Body.String())
	h.put(policydoc.LockedTestsKey, mustSetting(t, func(c *policydoc.LockedConfig) { c.UIPort = 7443 }))
	if rec = h.post(hsLockedPath, stale); rec.Code != http.StatusConflict {
		t.Errorf("stale confirm: status %d, want 409", rec.Code)
	}
}

// AC4: after parameters change, the next policy preview rebuilds the marked locked entries from the
// new canonical set and reports it. The marked entries Inject sees are the stale ones from the old
// parameters.
func TestHSSettings_ParamChangeRebuildsLockedTests(t *testing.T) {
	h := newHSSettingsHarness(t)
	old := policydoc.DefaultLockedConfig(9000)
	live, err := policydoc.Inject(hsSettingsPolicy, old)
	if err != nil || !live.Changed() {
		t.Fatalf("seed live policy: %v", err)
	}
	h.hs.policy = live.Text

	rec := h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ui_port", "8443") }))
	form := confirmForm(t, rec.Body.String())
	if rec = h.post(hsLockedPath, form); rec.Code != http.StatusOK {
		t.Fatalf("save: status %d", rec.Code)
	}

	// The policy writer's source reads the new setting; Inject replaces the old marked entry.
	src := policydoc.LockedSource(h.store.Queries(), 9000)
	cfg, err := src(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res, err := policydoc.Inject(live.Text, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed() {
		t.Fatal("the new parameters did not change the locked entries")
	}
	var replaced bool
	for _, c := range res.Changes {
		if c.Kind == policydoc.ChangeReplaced && c.Rule == policydoc.RuleUI {
			replaced = true
		}
	}
	if !replaced || strings.Contains(res.Text, "tag:vpn-server:443") || !strings.Contains(res.Text, "tag:vpn-server:8443") {
		t.Errorf("locked entries were not rebuilt (changes %+v):\n%s", res.Changes, res.Text)
	}
	if n := strings.Count(res.Text, `/* tagcess:locked */`); n != 3 {
		t.Errorf("marked entries = %d, want 3", n)
	}

	// The save page tells the operator that the next policy save rebuilds them.
	if !strings.Contains(h.get().Body.String(), "bir sonraki policy kaydında") {
		t.Errorf("the page does not say when the new locked tests are injected")
	}
}

// AC5: after a save, the executor's protected list and the policy writer's locked source return the
// new values on the next call (no restart, no cache).
func TestHSSettings_ReadersSeeNewValues(t *testing.T) {
	h := newHSSettingsHarness(t)
	src := policydoc.LockedSource(h.store.Queries(), 9000)

	before, err := src(context.Background())
	if err != nil || before.UIPort != 443 || !slices.Equal(h.tags(), []string{"tag:vpn-server", "tag:k8s"}) {
		t.Fatalf("before: %+v, %v, %v", before, err, h.tags())
	}

	if rec := h.post(hsTagsPath, url.Values{"action": {"add"}, "tag": {"tag:db"}}); rec.Code != http.StatusOK {
		t.Fatalf("add tag: %d", rec.Code)
	}
	rec := h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("ssh_dst", "tag:vpn-server, tag:k8s, tag:db") }))
	if rec.Code != http.StatusOK {
		t.Fatalf("locked: %d: %s", rec.Code, rec.Body)
	}

	if got := h.tags(); !slices.Contains(got, "tag:db") {
		t.Errorf("executor still sees %v", got)
	}
	after, err := src(context.Background())
	if err != nil || !slices.Contains(after.SSHDst, "tag:db") {
		t.Errorf("locked source still returns %+v, %v", after, err)
	}
}

// AC6: only devops may use the screen and every POST needs the CSRF token.
func TestHSSettings_RequiresDevopsAndCSRF(t *testing.T) {
	h := newHSSettingsHarness(t)
	for _, tc := range []struct {
		name, method, target string
		form                 url.Values
	}{
		{"page", http.MethodGet, "/headscale/settings", nil},
		{"tags", http.MethodPost, hsTagsPath, url.Values{"action": {"add"}, "tag": {"tag:db"}}},
		{"locked", http.MethodPost, hsLockedPath, lockedForm(nil)},
	} {
		if rec := h.request(tc.method, tc.target, tc.form, "dev", true); rec.Code != http.StatusForbidden {
			t.Errorf("%s as non-devops: status %d, want 403", tc.name, rec.Code)
		}
		if tc.method == http.MethodPost {
			if rec := h.request(tc.method, tc.target, tc.form, "devops", false); rec.Code != http.StatusForbidden {
				t.Errorf("%s without CSRF: status %d, want 403", tc.name, rec.Code)
			}
		}
	}
	if _, ok := h.setting(hsadmin.ProtectedTagsKey); ok {
		t.Error("a refused request stored a setting")
	}
	if _, ok := h.setting(policydoc.LockedTestsKey); ok {
		t.Error("a refused request stored a setting")
	}
}

const hsConfigWritePath = "/headscale/settings/config-write"

// AC1: the write switch shows its current state, off and default when nothing is stored, with the
// groups-claim matrix note; once stored it shows the stored state.
func TestHSSettings_ConfigWriteSwitchShown(t *testing.T) {
	h := newHSSettingsHarness(t)
	rec := h.get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{"Config yazma switch'i", `role="switch" aria-checked="false"`, "kapalı", "Lab groups-claim kabul/ret matrisi"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if _, ok := h.setting(hostapply.SettingConfigWriteEnabled); ok {
		t.Fatal("opening the page stored a setting")
	}

	h.put(hostapply.SettingConfigWriteEnabled, "true")
	body = h.get().Body.String()
	if !strings.Contains(body, "config yazması etkin") || !strings.Contains(body, `aria-checked="true"`) {
		t.Errorf("stored-on switch is not shown as open:\n%s", body)
	}
}

// AC2: opening and closing the switch each need the confirmation page, the store write and the
// audit entry with actor and before/after; an unconfirmed or CSRF-less request changes nothing.
func TestHSSettings_ConfigWriteSwitch(t *testing.T) {
	h := newHSSettingsHarness(t)
	key := hostapply.SettingConfigWriteEnabled

	// Open without confirmation: the confirmation page, nothing stored.
	rec := h.post(hsConfigWritePath, url.Values{"enabled": {"true"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "config-write") {
		t.Fatalf("open step 1: status %d:\n%s", rec.Code, rec.Body)
	}
	if _, ok := h.setting(key); ok {
		t.Fatal("unconfirmed open stored a setting")
	}
	// Confirming stores "true" and audits actor plus before/after.
	rec = h.post(hsConfigWritePath, confirmForm(t, rec.Body.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("open confirm: status %d:\n%s", rec.Code, rec.Body)
	}
	if v, _ := h.setting(key); v != "true" {
		t.Fatalf("stored value = %q, want true", v)
	}
	evs := h.events("headscale.settings.config_write_enabled")
	if len(evs) == 0 || evs[0].Actor != hsSettingsActor || evs[0].Result != "applied" {
		t.Fatalf("open audit = %+v", evs)
	}
	var ch audit.Change
	for _, c := range evs[0].Diff {
		if c.Field == key {
			ch = c
		}
	}
	if ch.Before != "false" || ch.After != "true" {
		t.Errorf("open audit before/after = %q -> %q", ch.Before, ch.After)
	}

	// Close: confirmation page, nothing changes until confirmed.
	rec = h.post(hsConfigWritePath, url.Values{"enabled": {"false"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "config-write") {
		t.Fatalf("close step 1: status %d:\n%s", rec.Code, rec.Body)
	}
	if v, _ := h.setting(key); v != "true" {
		t.Fatal("unconfirmed close changed the setting")
	}
	if rec = h.post(hsConfigWritePath, confirmForm(t, rec.Body.String())); rec.Code != http.StatusOK {
		t.Fatalf("close confirm: status %d:\n%s", rec.Code, rec.Body)
	}
	if v, _ := h.setting(key); v != "false" {
		t.Fatalf("stored value = %q, want false", v)
	}
	// M4 (F5 live findings): closing has its own event name, so the direction shows in the list.
	if n := len(h.events("headscale.settings.config_write_enabled")); n != len(evs) {
		t.Errorf("close was audited under the open event: %d entries, want %d", n, len(evs))
	}
	evs = h.events("headscale.settings.config_write_disabled")
	if len(evs) == 0 {
		t.Fatal("close audit missing: no headscale.settings.config_write_disabled entry")
	}
	ch = audit.Change{}
	for _, c := range evs[0].Diff {
		if c.Field == key {
			ch = c
		}
	}
	if evs[0].Result != "applied" || ch.Before != "true" || ch.After != "false" {
		t.Errorf("close audit = %+v", evs[0])
	}

	// A confirmation bound to a different stored state is refused.
	rec = h.post(hsConfigWritePath, url.Values{"enabled": {"true"}, "confirm": {"1"}, "base": {"deadbeef"}})
	if rec.Code != http.StatusConflict {
		t.Errorf("wrong base: status %d, want 409", rec.Code)
	}
	if v, _ := h.setting(key); v != "false" {
		t.Errorf("wrong-base request changed the setting to %q", v)
	}

	// Without CSRF the request is refused before the handler runs and nothing changes.
	rec = h.request(http.MethodPost, hsConfigWritePath, url.Values{"enabled": {"true"}, "confirm": {"1"}}, "devops", false)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF: status %d, want 403", rec.Code)
	}
	if v, _ := h.setting(key); v != "false" {
		t.Errorf("CSRF-less request changed the setting to %q", v)
	}
}

// AC3: only devops may see the switch or post to it.
func TestHSSettings_ConfigWriteSwitchDevopsOnly(t *testing.T) {
	h := newHSSettingsHarness(t)
	if rec := h.request(http.MethodGet, "/headscale/settings", nil, "dev", false); rec.Code != http.StatusForbidden {
		t.Errorf("GET as non-devops: status %d, want 403", rec.Code)
	}
	rec := h.request(http.MethodPost, hsConfigWritePath, url.Values{"enabled": {"true"}}, "dev", true)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST as non-devops: status %d, want 403", rec.Code)
	}
	if _, ok := h.setting(hostapply.SettingConfigWriteEnabled); ok {
		t.Error("a refused request stored a setting")
	}
}

// AC4: when the stored switch cannot be read the page shows it off with the reason and refuses the
// change; when it cannot be written the change is refused and nothing is stored.
func TestHSSettings_ConfigWriteSwitchFailsClosed(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		h := newHSSettingsHarnessStore(t, func(s HSSettingsStore) HSSettingsStore {
			return flakySettingsStore{HSSettingsStore: s, failGet: hostapply.SettingConfigWriteEnabled, err: errors.New("disk error")}
		})
		body := h.get().Body.String()
		if !strings.Contains(body, "config yazması engelli") || !strings.Contains(body, "okunamadı") {
			t.Errorf("unreadable switch not shown off with the reason:\n%s", body)
		}
		rec := h.post(hsConfigWritePath, url.Values{"enabled": {"true"}, "confirm": {"1"}})
		if rec.Code < 500 {
			t.Errorf("read error: status %d, want a server error", rec.Code)
		}
		if _, ok := h.setting(hostapply.SettingConfigWriteEnabled); ok {
			t.Error("read error stored a setting")
		}
	})

	t.Run("write error", func(t *testing.T) {
		h := newHSSettingsHarnessStore(t, func(s HSSettingsStore) HSSettingsStore {
			return flakySettingsStore{HSSettingsStore: s, failPut: hostapply.SettingConfigWriteEnabled, err: errors.New("disk full")}
		})
		rec := h.post(hsConfigWritePath, url.Values{"enabled": {"true"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("confirmation: status %d", rec.Code)
		}
		rec = h.post(hsConfigWritePath, confirmForm(t, rec.Body.String()))
		if rec.Code < 500 {
			t.Errorf("write error: status %d, want a server error", rec.Code)
		}
		if _, ok := h.setting(hostapply.SettingConfigWriteEnabled); ok {
			t.Error("write error stored a setting")
		}
	})
}

// Issue #3 AC5: an empty admin group or one with characters outside [A-Za-z0-9._-] is refused with
// a visible error and nothing is stored.
func TestHSSettings_AdminGroupInvalid(t *testing.T) {
	h := newHSSettingsHarness(t)
	for name, val := range map[string]string{
		"empty": "", "prefix only": "group:", "space": "group:a b", "slash": "group:a/b",
		"query injection": "group:a&allowed_groups=x", "comma": "group:a,b", "newline": "group:a\nb",
	} {
		rec := h.post(hsLockedPath, lockedForm(func(v url.Values) { v.Set("devops_group", val) }))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "DevopsGroup") && !strings.Contains(rec.Body.String(), "devops") {
			t.Errorf("%s: no visible error in the body", name)
		}
	}
	if _, ok := h.setting(policydoc.LockedTestsKey); ok {
		t.Fatal("an invalid admin group stored a setting")
	}
}

func (h *hsSettingsHarness) adminGroupSetting() string {
	h.t.Helper()
	c, _, err := policydoc.LoadLocked(context.Background(), h.store.Queries(), 9000)
	if err != nil {
		h.t.Fatal(err)
	}
	return c.AdminGroup()
}

func (h *hsSettingsHarness) saveAdminGroup(groups, group string) *httptest.ResponseRecorder {
	h.t.Helper()
	form := lockedForm(func(v url.Values) { v.Set("devops_group", "group:"+group); v.Set("ssh_src", "group:"+group) })
	form.Set("confirm", "1")
	form.Set("base", settingBase(h.currentLockedRaw()))
	return h.request(http.MethodPost, hsLockedPath, form, groups, true)
}

func (h *hsSettingsHarness) currentLockedRaw() string {
	h.t.Helper()
	c, _, err := policydoc.LoadLocked(context.Background(), h.store.Queries(), 9000)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := c.Setting()
	return raw
}

// Issue #3 review: a save whose actor is not in the new group is refused (it would lock them, and
// with disjoint memberships everyone, out); nothing is stored, applied or switched.
func TestHSSettings_AdminGroupDisjointRefused(t *testing.T) {
	h := newHSSettingsHarness(t)
	rec := h.saveAdminGroup("devops", "ops")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403\n%s", rec.Code, rec.Body.String())
	}
	if len(h.apply.calls) != 0 {
		t.Error("Caddy was applied for a refused change")
	}
	if g := h.adminGroupSetting(); g != "devops" {
		t.Errorf("stored group %q, want devops", g)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "devops", false).Code; got != http.StatusOK {
		t.Errorf("devops lost UI access after a refused change: %d", got)
	}
}

// An admin in both groups: the middleware keeps the old group while the apply runs, and switches
// together with the stored value only after it succeeded.
func TestHSSettings_AdminGroupSwitchesAfterApply(t *testing.T) {
	h := newHSSettingsHarness(t)
	if rec := h.saveAdminGroup("devops,ops", "ops"); rec.Code != http.StatusOK {
		t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
	}
	if len(h.apply.calls) != 1 || h.apply.stateDuring != "devops" {
		t.Errorf("calls=%v, middleware group during the apply %q, want 1 and devops", h.apply.calls, h.apply.stateDuring)
	}
	if strings.Contains(h.apply.storedAt, "group:ops") {
		t.Errorf("the setting was stored before Caddy applied: %s", h.apply.storedAt)
	}
	if g := h.adminGroupSetting(); g != "ops" {
		t.Errorf("stored group %q, want ops", g)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "devops", false).Code; got != http.StatusForbidden {
		t.Errorf("old-only actor: %d, want 403", got)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "ops", false).Code; got != http.StatusOK {
		t.Errorf("new-group actor: %d, want 200", got)
	}
}

// Caddy cannot apply the new group (apply error, e.g. a refused drift or a Caddy failure): the
// setting is never written, the middleware never moved, and the old group keeps working.
func TestHSSettings_AdminGroupApplyFailureKeepsOld(t *testing.T) {
	h := newHSSettingsHarness(t)
	h.apply.err = errors.New("caddy unreadable")
	rec := h.saveAdminGroup("devops,ops", "ops")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502\n%s", rec.Code, rec.Body.String())
	}
	if g := h.adminGroupSetting(); g != "devops" {
		t.Errorf("stored group %q, want devops", g)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "devops", false).Code; got != http.StatusOK {
		t.Errorf("old group lost access: %d", got)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "ops", false).Code; got != http.StatusForbidden {
		t.Errorf("new group got in before Caddy had it: %d", got)
	}
}

// The setting cannot be stored after Caddy took the new group: Caddy is put back to the old group
// and the middleware never moves.
func TestHSSettings_AdminGroupStoreFailureRestoresCaddy(t *testing.T) {
	h := newHSSettingsHarnessStore(t, func(s HSSettingsStore) HSSettingsStore {
		return flakySettingsStore{HSSettingsStore: s, failPut: policydoc.LockedTestsKey, err: errors.New("disk full")}
	})
	rec := h.saveAdminGroup("devops,ops", "ops")
	if rec.Code == http.StatusOK {
		t.Fatalf("a failed store reported success\n%s", rec.Body.String())
	}
	if want := []string{"devops>ops", "ops>devops"}; !slices.Equal(h.apply.calls, want) {
		t.Errorf("apply calls %v, want %v (apply, then restore)", h.apply.calls, want)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "ops", false).Code; got != http.StatusForbidden {
		t.Errorf("new group got in: %d", got)
	}
}

// The request context is cancelled while Caddy is being applied (closed tab, request deadline):
// the change runs on its own context and completes consistently, setting and middleware together.
func TestHSSettings_AdminGroupRequestCancelledMidChange(t *testing.T) {
	h := newHSSettingsHarness(t)
	h.apply.onApply = func() { h.cancelRequest() }
	h.saveAdminGroup("devops,ops", "ops")
	if h.apply.ctxErrAtEnd != nil {
		t.Errorf("the change ran on the request's context: %v", h.apply.ctxErrAtEnd)
	}
	if g := h.adminGroupSetting(); g != "ops" {
		t.Errorf("stored group %q, want ops (the change must complete)", g)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "ops", false).Code; got != http.StatusOK {
		t.Errorf("new-group actor: %d, want 200", got)
	}
	if got := h.request(http.MethodGet, "/headscale/settings", nil, "devops", false).Code; got != http.StatusForbidden {
		t.Errorf("old-only actor: %d, want 403", got)
	}
}
