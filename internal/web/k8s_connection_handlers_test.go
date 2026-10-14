package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store"
	k8sfix "github.com/nesiler/tagcess/test/k8s"
)

// Harness of the k8s connection screen (F4-030): the F4-002 profile, the F4-003 credential file and an
// injected stand-in for the F4-004 read-only connection attempt, over a real settings store, audit log
// and API policy.

const k8sConnActor = "devops@example.com"

type k8sConnHarness struct {
	t         *testing.T
	store     *store.Store
	profiles  *k8s.ProfileStore
	creds     *k8s.CredentialStore
	connector *fakeK8sConnector
	audit     *audit.Logger
	csrf      *CSRF
	chain     http.Handler
	clock     *k8sfix.Clock
	actor     string
	credDir   string
	saved     atomic.Int32 // OnSaved calls (F5 I4)
}

func newK8sConnHarness(t *testing.T) *k8sConnHarness {
	return newK8sConnHarnessAuditor(t, nil)
}

// newK8sConnHarnessAuditor builds the harness with an auditor override so a test can make the audit
// write fail (the fail-closed case).
func newK8sConnHarnessAuditor(t *testing.T, auditor SiteAuditor) *k8sConnHarness {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	policy := netpolicy.New(s.DB(), s.Queries())
	if err := policy.Set(context.Background(), netpolicy.ScopeAPI, netpolicy.Input{
		Addresses: []string{"10.0.0.0/8"}, Ports: []int{6443, 443},
	}); err != nil {
		t.Fatalf("policy.Set: %v", err)
	}
	clock := k8sfix.NewClock(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	credDir := filepath.Join(t.TempDir(), "credentials")
	h := &k8sConnHarness{
		t: t, store: s,
		profiles:  k8s.NewProfileStore(s.DB(), s.Queries(), policy, clock.Now),
		creds:     k8s.NewCredentialStore(credDir),
		connector: &fakeK8sConnector{},
		audit:     audit.New(s.Queries()),
		csrf:      testCSRF(t),
		clock:     clock,
		actor:     k8sConnActor,
		credDir:   credDir,
	}
	var aud SiteAuditor = h.audit
	if auditor != nil {
		aud = auditor
	}
	handler, err := NewK8sConnectionHandler(K8sConnectionConfig{
		Profiles: h.profiles, Creds: h.creds, Connector: h.connector, Auditor: aud, CSRF: h.csrf,
		OnSaved: func() { h.saved.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewK8sConnectionHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))
	return h
}

func (h *k8sConnHarness) request(method, target string, form url.Values, groups string, csrf bool) *httptest.ResponseRecorder {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		form = k8sConnCloneValues(form)
		if csrf {
			form.Set(CSRFParam, h.csrf.Token())
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, h.actor)
	req.Header.Set(headerGroups, groups)
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *k8sConnHarness) get() *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/k8s/connection", nil, "devops", false)
}

func (h *k8sConnHarness) postProfile(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, "/k8s/connection/profile", form, "devops", true)
}

func (h *k8sConnHarness) postCredential(form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodPost, "/k8s/connection/credential", form, "devops", true)
}

func (h *k8sConnHarness) events(event string) []audit.Event {
	h.t.Helper()
	evs, err := h.audit.List(context.Background(), audit.Filter{Event: event, Limit: 100})
	if err != nil {
		h.t.Fatalf("audit.List: %v", err)
	}
	return evs // newest first
}

func (h *k8sConnHarness) profile() (k8s.Profile, error) {
	h.t.Helper()
	return h.profiles.Get(context.Background())
}

// fakeK8sConnector stands in for the F4-004 read-only connection attempt (wired for real in F4-031).
type fakeK8sConnector struct {
	mu    sync.Mutex
	calls []k8s.Credential
	err   error
	hook  func(k8s.Credential)
}

func (f *fakeK8sConnector) Connect(_ context.Context, cred k8s.Credential) error {
	f.mu.Lock()
	f.calls = append(f.calls, cred)
	hook := f.hook
	err := f.err
	f.mu.Unlock()
	if hook != nil {
		hook(cred)
	}
	return err
}

func (f *fakeK8sConnector) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeK8sConnector) setHook(hook func(k8s.Credential)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = hook
}

func (f *fakeK8sConnector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeK8sConnector) last() (k8s.Credential, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return k8s.Credential{}, false
	}
	return f.calls[len(f.calls)-1], true
}

// failingAuditor makes every audit write fail, to prove nothing is changed when it cannot be recorded.
type failingAuditor struct{ err error }

func (f failingAuditor) Write(context.Context, audit.Entry) (audit.Event, error) {
	return audit.Event{}, f.err
}

func k8sConnCloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func k8sConnToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return "sentinel-" + hex.EncodeToString(b)
}

func k8sConnCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tagcess k8s connection test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// k8sConnProfileForm returns a valid profile-form body with the narrow scope the ACs ask to keep.
func k8sConnProfileForm() url.Values {
	return url.Values{
		"endpoint":              {"https://10.1.2.3:6443"},
		"namespaces":            {"web, apps"},
		"controller":            {"traefik.io/ingress-controller"},
		"ingress_classes":       {"traefik"},
		"internal":              {"10.1.2.10 443 websecure-internal\n10.1.2.9 8443"},
		"public":                {"10.1.2.11 443 websecure"},
		"declared_token_expiry": {""},
	}
}

// k8sConnCredForm returns a valid credential-form body; ca is generated at test time.
func k8sConnCredForm(t *testing.T, ca, token string) url.Values {
	t.Helper()
	return url.Values{
		"endpoint":        {"https://10.1.2.3:6443"},
		"tls_server_name": {"kubernetes.example.test"},
		"ca_data":         {ca},
		"token":           {token},
	}
}

// sqliteHolds reports whether any text/blob cell of the database contains needle. It is the leak check
// for SQLite: settings and audit rows both live here.
func sqliteHolds(t *testing.T, db *sql.DB, needle string) bool {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table: %v", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	_ = rows.Close()
	for _, table := range tables {
		q := `SELECT * FROM "` + strings.ReplaceAll(table, `"`, `""`) + `"`
		tr, err := db.QueryContext(context.Background(), q)
		if err != nil {
			t.Fatalf("select %s: %v", table, err)
		}
		cols, err := tr.Columns()
		if err != nil {
			t.Fatalf("columns %s: %v", table, err)
		}
		for tr.Next() {
			vals := make([]sql.RawBytes, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := tr.Scan(ptrs...); err != nil {
				t.Fatalf("scan %s: %v", table, err)
			}
			for _, v := range vals {
				if bytes.Contains(v, []byte(needle)) {
					_ = tr.Close()
					return true
				}
			}
		}
		if err := tr.Err(); err != nil {
			t.Fatalf("iterate %s: %v", table, err)
		}
		_ = tr.Close()
	}
	return false
}

// auditHolds reports whether a stored audit event's actor, event, target, result or diff carries s.
func auditHolds(events []audit.Event, s string) bool {
	for _, e := range events {
		if strings.Contains(e.Actor+e.Event+e.Target+e.Result, s) {
			return true
		}
		for _, c := range e.Diff {
			if strings.Contains(c.Before, s) || strings.Contains(c.After, s) {
				return true
			}
		}
	}
	return false
}

// AC1: a credential upload goes through the F4-002 profile and the F4-003 protected file; the token
// never reaches the response, SQLite, the audit log or slog, and the response is no-store.
func TestK8sConnectionUploadDoesNotExposeCredential(t *testing.T) {
	h := newK8sConnHarness(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if rec := h.postProfile(k8sConnProfileForm()); rec.Code != http.StatusOK {
		t.Fatalf("profile POST = %d, body %s", rec.Code, rec.Body.String())
	}
	ca, token := k8sConnCA(t), k8sConnToken(t)
	rec := h.postCredential(k8sConnCredForm(t, ca, token))
	if rec.Code != http.StatusOK {
		t.Fatalf("credential POST = %d, body %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if body := rec.Body.String(); strings.Contains(body, token) {
		t.Fatalf("response body carries the token")
	}
	// The credential landed in the F4-003 runtime file, so Load returns it.
	stored, err := h.creds.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if stored.Token != token {
		t.Fatalf("stored token = %q, want the uploaded one", stored.Token)
	}
	// No surface may carry it.
	if sqliteHolds(t, h.store.DB(), token) {
		t.Fatalf("SQLite holds the token")
	}
	if auditHolds(h.events("k8s.connection.credential"), token) {
		t.Fatalf("audit holds the token")
	}
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), ca) {
		t.Fatalf("log holds the credential: %s", logs.String())
	}
	// The screen shows only safe metadata (the CA fingerprint), never the token.
	page := h.get()
	if page.Code != http.StatusOK {
		t.Fatalf("GET = %d", page.Code)
	}
	if body := page.Body.String(); strings.Contains(body, token) || strings.Contains(body, ca) {
		t.Fatalf("page carries the credential")
	}
	if !strings.Contains(page.Body.String(), "10.1.2.3") {
		t.Fatalf("page does not show the endpoint")
	}
	// The credential lives in the F4-003 runtime directory, not in the repository working tree.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if strings.HasPrefix(h.credsRuntimeDir(), wd) {
		t.Fatalf("credential dir %q is inside the repository %q", h.credsRuntimeDir(), wd)
	}
}

// AC2: saving namespace/class/listener metadata round-trips into a reopened page, and an invalid
// metadata input leaves the previous working profile in place.
func TestK8sConnectionProfileRoundTripAndInvalidScope(t *testing.T) {
	h := newK8sConnHarness(t)
	if rec := h.postProfile(k8sConnProfileForm()); rec.Code != http.StatusOK {
		t.Fatalf("profile POST = %d, body %s", rec.Code, rec.Body.String())
	}
	want := k8s.Profile{
		Endpoint: "https://10.1.2.3:6443", Namespaces: []string{"apps", "web"},
		Controller: "traefik.io/ingress-controller", IngressClasses: []string{"traefik"},
		Internal:    []k8s.Listener{{Address: "10.1.2.9", Port: 8443}, {Address: "10.1.2.10", Port: 443, EntryPoint: "websecure-internal"}},
		Public:      []k8s.Listener{{Address: "10.1.2.11", Port: 443, EntryPoint: "websecure"}},
		PolicyScope: netpolicy.ScopeAPI,
	}
	got, err := h.profile()
	if err != nil {
		t.Fatalf("profile Get: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("profile = %+v, want %+v", got, want)
	}
	page := h.get()
	for _, needle := range []string{"10.1.2.3:6443", "web", "apps", "traefik.io/ingress-controller", "traefik", "10.1.2.9", "8443", "websecure-internal"} {
		if !strings.Contains(page.Body.String(), needle) {
			t.Fatalf("page does not show %q:\n%s", needle, page.Body.String())
		}
	}

	for _, bad := range []url.Values{
		setField(k8sConnProfileForm(), "namespaces", ""),
		setField(k8sConnProfileForm(), "ingress_classes", ""),
		setField(k8sConnProfileForm(), "internal", ""),
		setField(k8sConnProfileForm(), "controller", ""),
		setField(k8sConnProfileForm(), "endpoint", "http://10.1.2.3:6443"),
		setField(k8sConnProfileForm(), "namespaces", "Web"),
	} {
		rec := h.postProfile(bad)
		if rec.Code == http.StatusOK {
			t.Fatalf("invalid profile accepted: %v", bad)
		}
		after, err := h.profile()
		if err != nil {
			t.Fatalf("profile Get after refusal: %v", err)
		}
		if !reflect.DeepEqual(after, want) {
			t.Fatalf("invalid input changed the stored profile: %+v", after)
		}
	}
}

func setField(form url.Values, key, value string) url.Values {
	out := k8sConnCloneValues(form)
	out.Set(key, value)
	return out
}

// AC3: a token change is only applied after a successful F4-004 connection attempt; a failure keeps
// the previous credential and never shows the expired declared token as healthy.
func TestK8sConnectionManualRotationAndFailure(t *testing.T) {
	h := newK8sConnHarness(t)
	pf := k8sConnProfileForm()
	pf.Set("declared_token_expiry", "2026-01-01T00:00:00Z")
	if rec := h.postProfile(pf); rec.Code != http.StatusOK {
		t.Fatalf("profile POST = %d", rec.Code)
	}
	old := k8sConnToken(t)
	ca := k8sConnCA(t)
	if rec := h.postCredential(k8sConnCredForm(t, ca, old)); rec.Code != http.StatusOK {
		t.Fatalf("first credential POST = %d, body %s", rec.Code, rec.Body.String())
	}
	firstCheck := h.clock.Now()
	if got, _ := h.profile(); !got.LastIdentityCheck.Equal(firstCheck) {
		t.Fatalf("identity check = %v, want %v", got.LastIdentityCheck, firstCheck)
	}
	h.clock.Advance(time.Hour)

	// A failed attempt: the new credential must never become effective, and the previous file survives.
	newTok := k8sConnToken(t)
	h.connector.setErr(errors.New("connection refused"))
	var during k8s.Credential
	h.connector.setHook(func(k8s.Credential) {
		c, err := h.creds.Load()
		if err != nil {
			t.Errorf("Load during attempt: %v", err)
		}
		during = c
	})
	rec := h.postCredential(k8sConnCredForm(t, ca, newTok))
	if rec.Code == http.StatusOK {
		t.Fatalf("failed attempt accepted")
	}
	last, ok := h.connector.last()
	if !ok || last.Token != newTok {
		t.Fatalf("connection attempt was not made with the new credential")
	}
	if during.Token != old {
		t.Fatalf("effective credential changed before the attempt completed")
	}
	cur, err := h.creds.Load()
	if err != nil || cur.Token != old {
		t.Fatalf("previous credential not preserved: %+v, %v", cur, err)
	}
	if got, _ := h.profile(); !got.LastIdentityCheck.Equal(firstCheck) {
		t.Fatalf("failed rotation stamped an identity check: %v", got.LastIdentityCheck)
	}
	if auditHolds(h.events("k8s.connection.credential"), newTok) {
		t.Fatalf("audit holds the attempted token")
	}
	// The page marks the declared expiry as expired and does not present it as a healthy token.
	page := h.get().Body.String()
	if !strings.Contains(page, "beyan edilen süre geçti") {
		t.Fatalf("page does not warn the declared token expiry passed:\n%s", page)
	}
	// The success notice would present the expired token as healthy. The positive control below
	// proves the success notice exists.
	if strings.Contains(page, "credential güncellendi; bağlantı denemesi başarılı") {
		t.Fatalf("page presents an expired token as healthy:\n%s", page)
	}

	// A successful attempt applies the new credential and stamps the check.
	h.connector.setErr(nil)
	h.connector.setHook(nil)
	okRec := h.postCredential(k8sConnCredForm(t, ca, newTok))
	if okRec.Code != http.StatusOK {
		t.Fatalf("successful rotation = %d, body %s", okRec.Code, okRec.Body.String())
	}
	if !strings.Contains(okRec.Body.String(), "credential güncellendi; bağlantı denemesi başarılı") {
		t.Fatalf("positive control: a successful rotation does not render the success notice")
	}
	cur, err = h.creds.Load()
	if err != nil || cur.Token != newTok {
		t.Fatalf("rotation did not apply the new credential: %+v, %v", cur, err)
	}
	if got, _ := h.profile(); !got.LastIdentityCheck.Equal(firstCheck.Add(time.Hour)) {
		t.Fatalf("identity check = %v, want %v", got.LastIdentityCheck, firstCheck.Add(time.Hour))
	}
}

// AC4: without a verified devops actor, without CSRF or when the audit write fails, nothing changes;
// the audit actor comes only from the request context, never from a form/header field.
func TestK8sConnectionAuthorizationAndAudit(t *testing.T) {
	h := newK8sConnHarness(t)
	ca, token := k8sConnCA(t), k8sConnToken(t)

	// Not devops: refused before any handler runs.
	rec := h.request(http.MethodPost, "/k8s/connection/credential", k8sConnCredForm(t, ca, token), "developer", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-devops POST = %d, want 403", rec.Code)
	}
	if _, err := h.creds.Load(); !errors.Is(err, k8s.ErrCredentialNotSet) {
		t.Fatalf("non-devops POST changed the credential: %v", err)
	}

	// Missing CSRF: refused by the middleware.
	rec = h.request(http.MethodPost, "/k8s/connection/credential", k8sConnCredForm(t, ca, token), "devops", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF POST = %d, want 403", rec.Code)
	}

	// A form actor/email cannot impersonate: the audit actor is the context actor.
	spoof := k8sConnCredForm(t, ca, token)
	spoof.Set("actor", "evil@example.com")
	spoof.Set("email", "evil@example.com")
	if rec := h.postCredential(spoof); rec.Code != http.StatusOK {
		t.Fatalf("spoof POST = %d, body %s", rec.Code, rec.Body.String())
	}
	var applied bool
	for _, e := range h.events("k8s.connection.credential") {
		if e.Result != "applied" {
			continue
		}
		applied = true
		if e.Actor != k8sConnActor {
			t.Fatalf("audit actor = %q, want the context actor %q", e.Actor, k8sConnActor)
		}
	}
	if !applied {
		t.Fatalf("no applied audit entry")
	}

	// An audit failure must change nothing: neither the profile nor the credential.
	failing := newK8sConnHarnessAuditor(t, failingAuditor{err: errors.New("audit unavailable")})
	if rec := failing.postProfile(k8sConnProfileForm()); rec.Code == http.StatusOK {
		t.Fatalf("profile saved although audit failed")
	}
	if _, err := failing.profile(); !errors.Is(err, k8s.ErrNotSet) {
		t.Fatalf("profile changed although audit failed: %v", err)
	}
	rec = failing.postCredential(k8sConnCredForm(t, ca, k8sConnToken(t)))
	if rec.Code == http.StatusOK {
		t.Fatalf("credential saved although audit failed")
	}
	if _, err := failing.creds.Load(); !errors.Is(err, k8s.ErrCredentialNotSet) {
		t.Fatalf("credential changed although audit failed: %v", err)
	}
	if failing.connector.callCount() != 0 {
		t.Fatalf("connection attempted although audit failed")
	}
}

// k8sConnKubeconfig builds a narrow kubeconfig, optionally with an executable mechanism, so the F4-003
// importer can be exercised through the UI.
func k8sConnKubeconfig(t *testing.T, ca, token string, executable bool) string {
	t.Helper()
	user := "    token: " + token
	if executable {
		user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/true"
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: c
clusters:
- name: c
  cluster:
    server: https://10.1.2.3:6443
    certificate-authority-data: %s
contexts:
- name: c
  context:
    cluster: c
    user: u
users:
- name: u
  user:
%s
`, base64.StdEncoding.EncodeToString([]byte(ca)), user)
}

// A kubeconfig upload goes through the same narrow importer and never exposes the token; an
// executable mechanism is refused and the previous credential stays.
func TestK8sConnectionKubeconfigUpload(t *testing.T) {
	h := newK8sConnHarness(t)
	ca, token := k8sConnCA(t), k8sConnToken(t)
	if rec := h.postCredential(url.Values{"kubeconfig": {k8sConnKubeconfig(t, ca, token, false)}}); rec.Code != http.StatusOK {
		t.Fatalf("kubeconfig upload = %d, body %s", rec.Code, rec.Body.String())
	}
	if cur, err := h.creds.Load(); err != nil || cur.Token != token {
		t.Fatalf("kubeconfig did not land as the credential: %+v, %v", cur, err)
	}
	if body := h.get().Body.String(); strings.Contains(body, token) {
		t.Fatalf("page carries the kubeconfig token")
	}

	rec := h.postCredential(url.Values{"kubeconfig": {k8sConnKubeconfig(t, ca, k8sConnToken(t), true)}})
	if rec.Code == http.StatusOK {
		t.Fatalf("executable kubeconfig accepted")
	}
	if strings.Contains(rec.Body.String(), "command:") {
		t.Fatalf("refusal echoed the kubeconfig body")
	}
	if cur, err := h.creds.Load(); err != nil || cur.Token != token {
		t.Fatalf("refused kubeconfig changed the credential: %+v, %v", cur, err)
	}
}

// credsRuntimeDir exposes the credential store's directory for the leak-location check. The field is
// unexported in k8s, so the harness records it itself.
func (h *k8sConnHarness) credsRuntimeDir() string {
	return h.credDir
}

// B-M-1: the body cap holds on the header-token path too, so an oversize POST is refused and nothing
// is stored.
func TestK8sConnectionHeaderTokenOversizeBodyRefused(t *testing.T) {
	h := newK8sConnHarness(t)
	ca, token := k8sConnCA(t), k8sConnToken(t)
	if rec := h.postCredential(k8sConnCredForm(t, ca, token)); rec.Code != http.StatusOK {
		t.Fatalf("seed credential POST = %d", rec.Code)
	}
	calls := h.connector.callCount()

	for _, path := range []string{"/k8s/connection/credential", "/k8s/connection/profile"} {
		form := url.Values{"kubeconfig": {strings.Repeat("a", 5<<20)}, "endpoint": {"https://10.1.2.3:6443"}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
		counter := &countingBody{ReadCloser: req.Body}
		req.Body = counter
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(CSRFHeader, h.csrf.Token())
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, h.actor)
		req.Header.Set(headerGroups, "devops")
		rec := httptest.NewRecorder()
		h.chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s oversize header-token POST = %d, want 413/400", path, rec.Code)
		}
		if counter.n > maxFormBody+4096 {
			t.Fatalf("%s read %d body bytes, cap is %d", path, counter.n, maxFormBody)
		}
	}
	if cur, err := h.creds.Load(); err != nil || cur.Token != token {
		t.Fatalf("oversize POST changed the credential: %+v, %v", cur, err)
	}
	if h.connector.callCount() != calls {
		t.Fatalf("oversize POST reached the connection attempt")
	}
	if _, err := h.profile(); !errors.Is(err, k8s.ErrNotSet) {
		t.Fatalf("oversize POST stored a profile: %v", err)
	}
}

// B-L-1: a lower layer that echoes the trimmed token must still be redacted when the form carried
// surrounding whitespace.
func TestK8sConnectionRedactsTrimmedTokenInConnectorError(t *testing.T) {
	h := newK8sConnHarness(t)
	ca, token := k8sConnCA(t), k8sConnToken(t)
	h.connector.setErr(fmt.Errorf("dial failed with bearer %s", token))
	rec := h.postCredential(k8sConnCredForm(t, ca, token+"\n"))
	if rec.Code == http.StatusOK {
		t.Fatalf("failed attempt accepted")
	}
	if strings.Contains(rec.Body.String(), token) {
		t.Fatalf("response echoed the token")
	}
	if auditHolds(h.events("k8s.connection.credential"), token) {
		t.Fatalf("audit holds the token")
	}
	if !strings.Contains(rec.Body.String(), "&lt;redacted&gt;") {
		t.Fatalf("positive control: redaction marker missing:\n%s", rec.Body.String())
	}
}

// B-L-2: a credential file that exists but cannot be read is not treated as "not set": nothing is
// written and no connection attempt is made.
func TestK8sConnectionUnreadableCredentialFileBlocksRotation(t *testing.T) {
	h := newK8sConnHarness(t)
	if err := os.MkdirAll(h.credDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	file := filepath.Join(h.credDir, "k8s-credential.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	rec := h.postCredential(k8sConnCredForm(t, k8sConnCA(t), k8sConnToken(t)))
	if rec.Code == http.StatusOK {
		t.Fatalf("rotation accepted over a corrupt credential file")
	}
	if h.connector.callCount() != 0 {
		t.Fatalf("connection attempted over a corrupt credential file")
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != "{not json" {
		t.Fatalf("corrupt file was overwritten: %q, %v", got, err)
	}
}

// countingBody records how many bytes a handler pulled from the request body.
type countingBody struct {
	io.ReadCloser
	n int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += n
	return n, err
}

// L2: with no k8s_auth_dir the screen says so in fixed text, refuses an upload before any audit or
// connection attempt, and never names a path.
func TestK8sConnectionWithoutCredentialDirRefusesUpload(t *testing.T) {
	h := newK8sConnHarness(t)
	handler, err := NewK8sConnectionHandler(K8sConnectionConfig{
		Profiles: h.profiles, Creds: k8s.NewCredentialStore(""), Connector: h.connector, Auditor: h.audit, CSRF: h.csrf,
	})
	if err != nil {
		t.Fatalf("NewK8sConnectionHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = RequireDevops(h.csrf.Protect(mux))

	const want = "k8s_auth_dir ayarlanmamış"
	if body := h.get().Body.String(); !strings.Contains(body, want) {
		t.Fatalf("connection page lacks the setup error %q", want)
	}
	rec := h.postCredential(k8sConnCredForm(t, k8sConnCA(t), k8sConnToken(t)))
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("upload without k8s_auth_dir = %d, want a refusal with %q:\n%s", rec.Code, want, rec.Body.String())
	}
	if h.connector.callCount() != 0 {
		t.Error("a connection attempt was made although the credential cannot be stored")
	}
	if evs := h.events(k8sCredEvent); len(evs) != 0 {
		t.Errorf("audit events = %d, want none for a refused-before-anything upload", len(evs))
	}
}

// F5 I4: a saved profile or credential triggers the monitoring loops; a refused one does not.
func TestK8sConnectionSaveTriggersLoops(t *testing.T) {
	h := newK8sConnHarness(t)
	bad := setField(k8sConnProfileForm(), "namespaces", "")
	if rec := h.postProfile(bad); rec.Code == http.StatusOK {
		t.Fatalf("invalid profile accepted: %d", rec.Code)
	}
	if got := h.saved.Load(); got != 0 {
		t.Fatalf("OnSaved after a refused profile = %d, want 0", got)
	}
	if rec := h.postProfile(k8sConnProfileForm()); rec.Code != http.StatusOK {
		t.Fatalf("profile POST = %d", rec.Code)
	}
	if got := h.saved.Load(); got != 1 {
		t.Fatalf("OnSaved after a saved profile = %d, want 1", got)
	}
	if rec := h.postCredential(k8sConnCredForm(t, k8sConnCA(t), k8sConnToken(t))); rec.Code != http.StatusOK {
		t.Fatalf("credential POST = %d", rec.Code)
	}
	if got := h.saved.Load(); got != 2 {
		t.Fatalf("OnSaved after a saved credential = %d, want 2", got)
	}
}

// F5 C-I3: a profile without public listeners saves (public listeners are optional).
func TestK8sConnectionProfileWithoutPublicListenerSaves(t *testing.T) {
	h := newK8sConnHarness(t)
	form := setField(k8sConnProfileForm(), "public", "")
	if rec := h.postProfile(form); rec.Code != http.StatusOK {
		t.Fatalf("profile POST without public = %d, body %s", rec.Code, rec.Body.String())
	}
	p, err := h.profile()
	if err != nil || len(p.Public) != 0 {
		t.Fatalf("profile = %+v err=%v, want saved with no public listener", p, err)
	}
}

// F5 I5: both forms are named and every field has a label bound to it.
func TestK8sConnectionFormsAreLabelled(t *testing.T) {
	body := newK8sConnHarness(t).get().Body.String()
	for _, want := range []string{`id="profile-form"`, `id="credential-form"`, `aria-label="Bağlantı profili"`, `aria-label="Credential yükleme"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	fields := regexp.MustCompile(`<(?:input|textarea)[^>]*\sid="([^"]+)"`).FindAllStringSubmatch(body, -1)
	if len(fields) < 8 {
		t.Fatalf("found %d fields, want the profile and credential fields", len(fields))
	}
	for _, f := range fields {
		if !strings.Contains(body, `for="`+f[1]+`"`) {
			t.Errorf("field %q has no <label for>", f[1])
		}
	}
}

// F5 G2: an unconfigured connection page says what comes first; once the profile is saved it does not.
func TestK8sConnectionPageNamesSetupOrder(t *testing.T) {
	h := newK8sConnHarness(t)
	if body := h.get().Body.String(); !strings.Contains(body, "Kurulum bekleniyor") || !strings.Contains(body, `href="/k8s/setup"`) {
		t.Errorf("fresh connection page lacks the setup order:\n%s", body)
	}
	if rec := h.postProfile(k8sConnProfileForm()); rec.Code != http.StatusOK {
		t.Fatalf("profile POST = %d", rec.Code)
	}
	if body := h.get().Body.String(); strings.Contains(body, "Kurulum bekleniyor") {
		t.Error("a saved profile still shows the setup note")
	}
}
