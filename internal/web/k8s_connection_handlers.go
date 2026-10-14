package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/k8s"
)

// The k8s connection screen (F4-030): the F4-002 connection profile (endpoint, namespace scope,
// ingress class/controller, internal/public listeners and the declared token expiry) and the F4-003
// credential (CA, token, optional kubeconfig). The token is never rendered back, written to SQLite,
// audit or the log, and a rotation is applied only after the F4-004 read-only connection attempt with
// the candidate credential succeeds (F4-004 is wired through K8sConnector by F4-031). Every response
// is no-store.

const (
	k8sProfileEvent = "k8s.connection.profile"
	k8sCredEvent    = "k8s.connection.credential"
	k8sTarget       = "k8s_connection"
)

// K8sConnector makes the F4-004 read-only connection attempt with a candidate credential before it
// becomes effective. It is satisfied at wiring time (F4-031) by an adapter over k8s.NewClient.
type K8sConnector interface {
	Connect(ctx context.Context, cred k8s.Credential) error
}

// K8sProfileStore is the F4-002 profile surface; *k8s.ProfileStore satisfies it.
type K8sProfileStore interface {
	Get(ctx context.Context) (k8s.Profile, error)
	Save(ctx context.Context, p k8s.Profile) error
	RecordIdentityCheck(ctx context.Context) error
}

// K8sCredentialStore is the F4-003 protected runtime-file surface; *k8s.CredentialStore satisfies it.
type K8sCredentialStore interface {
	Load() (k8s.Credential, error)
	Info() (k8s.Info, error)
	Replace(c k8s.Credential) (k8s.Info, error)
}

// authDirMissingText is the fixed setup error shown when k8s_auth_dir is empty. It names the
// setting, never a path.
const authDirMissingText = "k8s_auth_dir ayarlanmamış: credential saklanamaz; ayar dosyasında credential dizinini (k8s_auth_dir) verin"

// K8sConnectionConfig wires the connection screen. Every field is required.
type K8sConnectionConfig struct {
	Profiles  K8sProfileStore
	Creds     K8sCredentialStore
	Connector K8sConnector
	Auditor   SiteAuditor
	CSRF      *CSRF
	// Now stamps the screen's "declared expiry passed" comparison; it defaults to time.Now.
	Now func() time.Time
	// OnSaved, when set, is called after a profile or credential was saved, so the monitoring loops
	// run at once instead of at their next interval (F5 I4). Optional.
	OnSaved func()
}

// K8sConnectionHandler serves the connection screen.
type K8sConnectionHandler struct {
	cfg K8sConnectionConfig
}

// NewK8sConnectionHandler validates the wiring.
func NewK8sConnectionHandler(cfg K8sConnectionConfig) (*K8sConnectionHandler, error) {
	switch {
	case cfg.Profiles == nil:
		return nil, errors.New("web: k8s connection needs a profile store")
	case cfg.Creds == nil:
		return nil, errors.New("web: k8s connection needs a credential store")
	case cfg.Connector == nil:
		return nil, errors.New("web: k8s connection needs a connector (F4-004)")
	case cfg.Auditor == nil:
		return nil, errors.New("web: k8s connection needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: k8s connection needs a CSRF signer")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &K8sConnectionHandler{cfg: cfg}, nil
}

// Register adds the connection routes to mux.
func (h *K8sConnectionHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /k8s/connection", h.page)
	mux.HandleFunc("POST /k8s/connection/profile", h.saveProfile)
	mux.HandleFunc("POST /k8s/connection/credential", h.saveCredential)
}

// k8sProfileFields is the profile form as text, so a refused input can be shown back unchanged.
type k8sProfileFields struct {
	Endpoint, TLSServerName, Namespaces, Controller, IngressClasses, Internal, Public, DeclaredTokenExpiry string
}

func k8sProfileFieldsFromForm(r *http.Request) k8sProfileFields {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return k8sProfileFields{
		Endpoint: get("endpoint"), TLSServerName: get("tls_server_name"), Namespaces: get("namespaces"),
		Controller: get("controller"), IngressClasses: get("ingress_classes"), Internal: get("internal"),
		Public: get("public"), DeclaredTokenExpiry: get("declared_token_expiry"),
	}
}

func profileFieldsOf(p k8s.Profile) k8sProfileFields {
	out := k8sProfileFields{
		Endpoint: p.Endpoint, TLSServerName: p.TLSServerName, Namespaces: strings.Join(p.Namespaces, ", "),
		Controller: p.Controller, IngressClasses: strings.Join(p.IngressClasses, ", "),
		Internal: listenersText(p.Internal), Public: listenersText(p.Public),
	}
	if !p.DeclaredTokenExpiry.IsZero() {
		// The form field is a datetime-local in UTC; parseDeclaredExpiry reads it back.
		out.DeclaredTokenExpiry = p.DeclaredTokenExpiry.UTC().Format("2006-01-02T15:04")
	}
	return out
}

// profile parses the text fields; the strict field validation is k8s.ProfileStore.Save's.
func (f k8sProfileFields) profile() (k8s.Profile, error) {
	p := k8s.Profile{
		Endpoint: f.Endpoint, TLSServerName: f.TLSServerName, Controller: f.Controller,
		Namespaces: splitList(f.Namespaces), IngressClasses: splitList(f.IngressClasses),
	}
	var err error
	if p.Internal, err = parseListeners(f.Internal); err != nil {
		return k8s.Profile{}, k8sFieldError{"internal", err}
	}
	if p.Public, err = parseListeners(f.Public); err != nil {
		return k8s.Profile{}, k8sFieldError{"public", err}
	}
	if p.DeclaredTokenExpiry, err = parseDeclaredExpiry(f.DeclaredTokenExpiry); err != nil {
		return k8s.Profile{}, k8sFieldError{"declared_token_expiry", err}
	}
	return p, nil
}

// parseListeners parses one listener per line: "address port [entrypoint]". The profile validator
// checks the values; this only reads the shape.
func parseListeners(raw string) ([]k8s.Listener, error) {
	var out []k8s.Listener
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("listener satırı %d geçersiz: \"<ip> <port> [entrypoint]\" bekleniyor", i+1)
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("listener satırı %d: port bir sayı olmalı", i+1)
		}
		l := k8s.Listener{Address: parts[0], Port: port}
		if len(parts) == 3 {
			l.EntryPoint = parts[2]
		}
		out = append(out, l)
	}
	return out, nil
}

func listenersText(ls []k8s.Listener) string {
	lines := make([]string, len(ls))
	for i, l := range ls {
		if l.EntryPoint != "" {
			lines[i] = fmt.Sprintf("%s %d %s", l.Address, l.Port, l.EntryPoint)
		} else {
			lines[i] = fmt.Sprintf("%s %d", l.Address, l.Port)
		}
	}
	return strings.Join(lines, "\n")
}

// parseDeclaredExpiry reads an optional RFC3339 or datetime-local value. It is declared metadata,
// never a verified expiry.
func parseDeclaredExpiry(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Truncate(time.Second), nil
		}
	}
	return time.Time{}, errors.New("süre biçimi geçersiz (RFC3339 veya YYYY-MM-DDTHH:MM)")
}

// k8sCredentialFields is the credential form. The CA/token are secrets: they are read from the form
// but never put back into the view.
type k8sCredentialFields struct {
	Endpoint, TLSServerName, CAData, Token, Kubeconfig, Context string
}

func k8sCredentialFieldsFromForm(r *http.Request) k8sCredentialFields {
	get := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return k8sCredentialFields{
		Endpoint: get("endpoint"), TLSServerName: get("tls_server_name"), CAData: r.PostFormValue("ca_data"),
		Token: r.PostFormValue("token"), Kubeconfig: r.PostFormValue("kubeconfig"), Context: get("context"),
	}
}

// credential builds the narrow model from a kubeconfig or the direct fields. It never executes
// anything; parsing is k8s.ParseKubeconfig's.
func (f k8sCredentialFields) credential() (k8s.Credential, error) {
	if strings.TrimSpace(f.Kubeconfig) != "" {
		return k8s.ParseKubeconfig([]byte(f.Kubeconfig), f.Context)
	}
	return k8s.Credential{
		Endpoint: f.Endpoint, TLSServerName: f.TLSServerName, CAData: f.CAData, Token: f.Token,
	}, nil
}

// k8sConnectionView is the page data. The profile fields are shown back; the credential is only safe
// metadata (endpoint, TLS name, CA fingerprints). Declared expiry and the last successful identity
// check are separate, and a declared expiry in the past is a warning, never a healthy state.
type k8sConnectionView struct {
	Profile         k8sProfileFields
	ProfileSet      bool
	ProfileErr      string
	Credential      *k8s.Info
	CredentialSet   bool
	CredentialErr   string
	DeclaredExpiry  string
	DeclaredExpired bool
	LastCheck       string
	Mismatch        bool
	CredEndpoint    string
	CredTLSServer   string
	Error           string
	Notice          string
	// FieldErr holds the refusal of the profile form per field (form name -> message).
	FieldErr map[string]string
}

func (h *K8sConnectionHandler) page(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, nil)
}

// baseView reads the stored profile and credential. An unreadable stored value is shown as an error
// rather than silently treated as "not set".
func (h *K8sConnectionHandler) baseView(ctx context.Context) k8sConnectionView {
	var v k8sConnectionView
	p, perr := h.cfg.Profiles.Get(ctx)
	switch {
	case perr == nil:
		v.ProfileSet = true
		v.Profile = profileFieldsOf(p)
		if !p.DeclaredTokenExpiry.IsZero() {
			v.DeclaredExpiry = p.DeclaredTokenExpiry.UTC().Format(time.RFC3339)
			v.DeclaredExpired = p.DeclaredTokenExpiry.Before(h.cfg.Now().UTC())
		}
		if !p.LastIdentityCheck.IsZero() {
			v.LastCheck = p.LastIdentityCheck.UTC().Format(time.RFC3339)
		}
	case !errors.Is(perr, k8s.ErrNotSet):
		v.ProfileErr = "bağlantı profili okunamadı veya bozuk; gösterilen değerler kullanılamaz: " + perr.Error()
	}

	info, cerr := h.cfg.Creds.Info()
	switch {
	case cerr == nil:
		v.CredentialSet = true
		v.Credential = &info
	case errors.Is(cerr, k8s.ErrCredentialDirNotSet):
		v.CredentialErr = authDirMissingText
	case !errors.Is(cerr, k8s.ErrCredentialNotSet):
		v.CredentialErr = "kayıtlı credential okunamadı; yeni yükleme önceki çalışan dosyayı ezmez: " + cerr.Error()
	}

	if v.ProfileSet && v.CredentialSet {
		v.Mismatch = info.Endpoint != p.Endpoint || info.TLSServerName != p.TLSServerName
	}
	switch {
	case v.ProfileSet:
		v.CredEndpoint, v.CredTLSServer = p.Endpoint, p.TLSServerName
	case v.CredentialSet:
		v.CredEndpoint, v.CredTLSServer = info.Endpoint, info.TLSServerName
	}
	return v
}

func (h *K8sConnectionHandler) render(w http.ResponseWriter, r *http.Request, status int, mutate func(*k8sConnectionView)) {
	v := h.baseView(r.Context())
	if mutate != nil {
		mutate(&v)
	}
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "k8s", "k8s bağlantısı",
		K8sConnectionPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// saveProfile stores the F4-002 metadata. The audit "requested" entry is written first, so an audit
// failure changes nothing; an invalid input leaves the stored profile untouched.
func (h *K8sConnectionHandler) saveProfile(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !readBoundedForm(w, r) {
		return
	}
	fields := k8sProfileFieldsFromForm(r)
	next, err := fields.profile()
	if err != nil {
		h.refuseProfile(w, r, http.StatusBadRequest, fields, "%v", err)
		return
	}

	before, gerr := h.cfg.Profiles.Get(r.Context())
	var beforeLabel string
	switch {
	case gerr == nil:
		beforeLabel = profileLabel(before)
	case errors.Is(gerr, k8s.ErrNotSet):
		beforeLabel = ""
	default:
		h.refuseProfile(w, r, http.StatusInternalServerError, fields,
			"mevcut profil okunamadı; değişiklik yapılmadı: %v", gerr)
		return
	}
	afterLabel := profileLabel(next)
	diff := audit.Diff{{Field: "profile", Before: beforeLabel, After: afterLabel}}
	if err := h.audit(r.Context(), actor, k8sProfileEvent, "requested", diff); err != nil {
		h.refuseProfile(w, r, http.StatusInternalServerError, fields, "işlem kaydedilemedi; profil değiştirilmedi")
		return
	}
	if err := h.cfg.Profiles.Save(r.Context(), next); err != nil {
		h.auditOutcome(r.Context(), actor, k8sProfileEvent, "failed", append(diff, audit.Change{Field: "error", After: err.Error()}))
		h.refuseProfile(w, r, http.StatusBadRequest, fields, "profil kaydedilemedi: %v", err)
		return
	}
	h.auditOutcome(r.Context(), actor, k8sProfileEvent, "applied", diff)
	h.saved()
	h.render(w, r, http.StatusOK, func(v *k8sConnectionView) {
		v.Notice = "bağlantı profili kaydedildi"
	})
}

// saved tells the wiring that stored k8s settings changed.
func (h *K8sConnectionHandler) saved() {
	if h.cfg.OnSaved != nil {
		h.cfg.OnSaved()
	}
}

func (h *K8sConnectionHandler) refuseProfile(w http.ResponseWriter, r *http.Request, status int, fields k8sProfileFields, format string, args ...any) {
	h.render(w, r, status, func(v *k8sConnectionView) {
		v.Profile = fields
		v.Error = fmt.Sprintf(format, args...)
		// A refusal that names fields is also shown next to each of them.
		for _, a := range args {
			if err, ok := a.(error); ok {
				if fe, ok := k8sProfileFieldErrors(err); ok {
					v.FieldErr = fe
					v.Error = "Profil kaydedilmedi; işaretli alanları düzeltin."
				}
			}
		}
	})
}

// saveCredential rotates the F4-003 credential. Order: audit requested → F4-004 read-only attempt
// with the candidate → atomic replace → audit applied. A failed attempt or write leaves the previous
// credential file untouched; the token is never echoed or audited.
func (h *K8sConnectionHandler) saveCredential(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !readBoundedForm(w, r) {
		return
	}
	fields := k8sCredentialFieldsFromForm(r)
	cand, err := fields.credential()
	if err != nil {
		h.refuseCredential(w, r, http.StatusBadRequest, safeCredentialError(err, fields.Token))
		return
	}

	before, ierr := h.cfg.Creds.Info()
	var beforePtr *k8s.Info
	switch {
	case ierr == nil:
		beforePtr = &before
	case errors.Is(ierr, k8s.ErrCredentialNotSet):
		beforePtr = nil
	case errors.Is(ierr, k8s.ErrCredentialDirNotSet):
		h.refuseCredential(w, r, http.StatusInternalServerError, authDirMissingText)
		return
	default:
		h.refuseCredential(w, r, http.StatusInternalServerError,
			"kayıtlı credential okunamadı; güvenli biçimde değiştirilemediği için yeni yükleme yapılmadı")
		return
	}

	requested := k8s.Info{Endpoint: cand.Endpoint, TLSServerName: cand.TLSServerName}
	diff := k8sCredDiff(beforePtr, &requested)
	if err := h.audit(r.Context(), actor, k8sCredEvent, "requested", diff); err != nil {
		h.refuseCredential(w, r, http.StatusInternalServerError, "işlem kaydedilemedi; credential değiştirilmedi")
		return
	}

	if err := h.cfg.Connector.Connect(r.Context(), cand); err != nil {
		reason := "yeni credential ile read-only bağlantı denemesi başarısız; önceki credential korundu: " +
			safeCredentialError(err, cand.Token)
		h.auditOutcome(r.Context(), actor, k8sCredEvent, "failed", append(diff, audit.Change{Field: "error", After: reason}))
		h.refuseCredential(w, r, http.StatusBadGateway, reason)
		return
	}

	info, err := h.cfg.Creds.Replace(cand)
	if err != nil {
		reason := "credential yazılamadı; önceki dosya korundu: " + safeCredentialError(err, cand.Token)
		h.auditOutcome(r.Context(), actor, k8sCredEvent, "failed", append(diff, audit.Change{Field: "error", After: reason}))
		h.refuseCredential(w, r, http.StatusInternalServerError, reason)
		return
	}
	// The successful attempt is the identity check of the F4-002 profile. Without a profile there is
	// nothing to stamp; a stamping failure must not undo a proven credential.
	if err := h.cfg.Profiles.RecordIdentityCheck(r.Context()); err != nil && !errors.Is(err, k8s.ErrNotSet) {
		slog.Default().Warn("k8s connection: identity check not stamped", "err", err)
	}
	h.auditOutcome(r.Context(), actor, k8sCredEvent, "applied", k8sCredDiff(beforePtr, &info))
	h.saved()
	h.render(w, r, http.StatusOK, func(v *k8sConnectionView) {
		v.Notice = "credential güncellendi; bağlantı denemesi başarılı"
	})
}

// readBoundedForm parses the form under the request-body cap and answers 413 itself when the body is
// too large, so an oversize POST never turns into a half-empty form.
func readBoundedForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "request body too large or malformed", http.StatusRequestEntityTooLarge)
		return false
	}
	return true
}

func (h *K8sConnectionHandler) refuseCredential(w http.ResponseWriter, r *http.Request, status int, reason string) {
	h.render(w, r, status, func(v *k8sConnectionView) { v.Error = reason })
}

// k8sCredDiff is the audit diff of a credential change: safe metadata only (endpoint, TLS name, CA
// fingerprints). The token and CA body are never part of it.
func k8sCredDiff(before, after *k8s.Info) audit.Diff {
	label := func(i *k8s.Info) string {
		if i == nil {
			return ""
		}
		b, _ := json.Marshal(i)
		return string(b)
	}
	return audit.Diff{{Field: "credential", Before: label(before), After: label(after)}}
}

// safeCredentialError keeps a candidate token out of any message, even if a lower layer echoed it.
func safeCredentialError(err error, token string) string {
	msg := err.Error()
	for _, t := range []string{token, strings.TrimSpace(token)} {
		if t != "" {
			msg = strings.ReplaceAll(msg, t, "<redacted>")
		}
	}
	return msg
}

// profileLabel serializes the secretless profile for the audit diff.
func profileLabel(p k8s.Profile) string {
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (h *K8sConnectionHandler) audit(ctx context.Context, actor, event, result string, diff audit.Diff) error {
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: event, Target: k8sTarget, Diff: diff, Result: result,
	})
	return err
}

func (h *K8sConnectionHandler) auditOutcome(ctx context.Context, actor, event, result string, diff audit.Diff) {
	if err := h.audit(ctx, actor, event, result, diff); err != nil {
		slog.Default().Warn("k8s connection: audit outcome write failed", "event", event, "err", err)
	}
}
