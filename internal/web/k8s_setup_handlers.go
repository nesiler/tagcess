package web

import (
	"cmp"
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
	"github.com/nesiler/tagcess/internal/netpolicy"
)

// The k8s setup help screen (F4-041): the read-only bootstrap manifest of F4-005, the selected
// effective-permission evidence and the shared F4-043 API/probe IP policy. The manifest is a
// download the authorised cluster administrator applies; tagcess never writes to the cluster. The
// policy screen owns no rule of its own: it shows the field errors and typed values of the F4-043
// service. The permission review is a seam (K8sReviewRunner): the binary wires it to the runtime
// read-only client, so this screen holds no credential.

const (
	k8sSetupPolicyEvent = "k8s.setup.policy"
	// k8sSetupSANamespace is the default namespace the operator is offered for the reader
	// ServiceAccount; the operator can change it before downloading.
	k8sSetupSANamespace = "tagcess"
)

// K8sReviewRunner runs the F4-005 selected effective-permission review for the given namespaces.
type K8sReviewRunner func(ctx context.Context, namespaces []string) (k8s.Review, error)

// K8sSetupConfig wires the setup help screen. Every field is required.
type K8sSetupConfig struct {
	// Profiles is the F4-002 metadata whose namespace scope the manifest and review use.
	Profiles *k8s.ProfileStore
	// Policy is the F4-043 store; the screen only calls Get/Set on it.
	Policy *netpolicy.Store
	// Review runs the effective-permission check (F4-005) with the runtime client.
	Review K8sReviewRunner
	// Creds, when set, lets the page tell whether the credential was uploaded (the next-step hint).
	Creds interface {
		Info() (k8s.Info, error)
	}
	Auditor SiteAuditor
	CSRF    *CSRF
	// Now stamps audit entries; it defaults to time.Now.
	Now func() time.Time
	// OnSaved, when set, is called after a policy was saved, so the monitoring loops run at once
	// instead of at their next interval (F5 I4). Optional.
	OnSaved func()
}

// K8sSetupHandler serves the setup help screen.
type K8sSetupHandler struct {
	cfg K8sSetupConfig
}

// NewK8sSetupHandler validates the wiring.
func NewK8sSetupHandler(cfg K8sSetupConfig) (*K8sSetupHandler, error) {
	switch {
	case cfg.Profiles == nil:
		return nil, errors.New("web: k8s setup needs a profile store")
	case cfg.Policy == nil:
		return nil, errors.New("web: k8s setup needs the shared policy store")
	case cfg.Review == nil:
		return nil, errors.New("web: k8s setup needs a permission review runner")
	case cfg.Auditor == nil:
		return nil, errors.New("web: k8s setup needs an auditor")
	case cfg.CSRF == nil:
		return nil, errors.New("web: k8s setup needs a CSRF signer")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &K8sSetupHandler{cfg: cfg}, nil
}

// Register adds the setup routes to mux. The caller mounts them behind RequireDevops and
// CSRF.Protect.
func (h *K8sSetupHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /k8s/setup", h.page)
	mux.HandleFunc("GET /k8s/setup/manifest", h.manifest)
	mux.HandleFunc("POST /k8s/setup/review", h.review)
	mux.HandleFunc("POST /k8s/setup/policy", h.savePolicy)
}

// k8sPolicyForm is one scope's policy as the form shows it. ReadErr carries an unreadable stored
// value; the form is left empty and never presented as "no policy".
type k8sPolicyForm struct {
	Scope     netpolicy.Scope
	Addresses string
	Ports     string
	Stored    bool
	ReadErr   string
}

// k8sSetupView is the page data.
type k8sSetupView struct {
	ProfileSet     bool
	ProfileErr     string
	Namespaces     []string
	Controller     string
	IngressClasses []string
	SA             k8s.ServiceAccountRef
	API, Probe     k8sPolicyForm
	Review         *k8s.Review
	ReviewErr      string
	Error          string
	Notice         string
	// NextStep is the one thing to do next, with its link (F5 G1); empty when every step is done.
	NextStep     string
	NextStepHref string
}

func (h *K8sSetupHandler) renderPage(w http.ResponseWriter, r *http.Request, status int, mut func(*k8sSetupView)) {
	v := h.baseView(r.Context())
	if mut != nil {
		mut(&v)
	}
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "k8s", "k8s kurulum yardımı",
		K8sSetupPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// baseView reads the profile scope and both stored policies. A missing profile or policy is not an
// error; an unreadable one is shown and broadens nothing.
func (h *K8sSetupHandler) baseView(ctx context.Context) k8sSetupView {
	v := k8sSetupView{SA: k8s.ServiceAccountRef{Namespace: k8sSetupSANamespace, Name: k8s.DefaultServiceAccountName}}
	if p, err := h.cfg.Profiles.Get(ctx); err != nil {
		if !errors.Is(err, k8s.ErrNotSet) {
			v.ProfileErr = err.Error()
		}
	} else {
		v.ProfileSet = true
		v.Namespaces = p.Namespaces
		v.Controller = p.Controller
		v.IngressClasses = p.IngressClasses
	}
	v.API = h.policyForm(ctx, netpolicy.ScopeAPI)
	v.Probe = h.policyForm(ctx, netpolicy.ScopeProbe)
	v.NextStep, v.NextStepHref = h.nextStep(ctx, v)
	return v
}

// nextStep names the first unfinished setup step in the order the stores need it: the API policy
// (the profile is validated against it), the connection profile, the credential, then the probe
// policy.
func (h *K8sSetupHandler) nextStep(ctx context.Context, v k8sSetupView) (text, href string) {
	switch {
	case !v.API.Stored:
		return "API IP policy'sini kaydedin: bağlantı ayarları buna göre doğrulanır.", "#policy-api"
	case !v.ProfileSet:
		return "bağlantı profilini kaydedin.", "/k8s/connection"
	}
	if h.cfg.Creds == nil {
		return "", ""
	}
	if _, err := h.cfg.Creds.Info(); err != nil {
		return "manifesti indirip cluster yöneticisine apply ettirin, sonra credential'ı yükleyin.", "/k8s/connection"
	}
	if !v.Probe.Stored {
		return "probe IP policy'sini kaydedin: site sağlık kontrolleri bunu bekler.", "#policy-probe"
	}
	return "", ""
}

// policyForm reads one scope's policy. An unreadable value is shown as an error, never as empty.
func (h *K8sSetupHandler) policyForm(ctx context.Context, scope netpolicy.Scope) k8sPolicyForm {
	f := k8sPolicyForm{Scope: scope}
	pol, err := h.cfg.Policy.Get(ctx, scope)
	switch {
	case errors.Is(err, netpolicy.ErrNotSet):
	case err != nil:
		f.ReadErr = "kayıtlı policy okunamadı veya bozuk: " + err.Error()
	default:
		f.Stored = true
		f.Addresses = strings.Join(pol.Addresses, "\n")
		f.Ports = joinPorts(pol.Ports)
	}
	return f
}

func (h *K8sSetupHandler) page(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, r, http.StatusOK, nil)
}

// manifest serves the F4-005 narrow manifest as a download. It never applies it: it builds the
// bytes locally and asks the cluster for nothing.
func (h *K8sSetupHandler) manifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p, err := h.cfg.Profiles.Get(r.Context())
	if err != nil {
		http.Error(w, "bağlantı profili okunamadı; manifest üretilmedi", http.StatusConflict)
		return
	}
	sa := k8s.ServiceAccountRef{
		Namespace: cmp.Or(strings.TrimSpace(r.URL.Query().Get("sa_namespace")), k8sSetupSANamespace),
		Name:      cmp.Or(strings.TrimSpace(r.URL.Query().Get("sa_name")), k8s.DefaultServiceAccountName),
	}
	body, err := k8s.RBACManifest(p.Namespaces, sa)
	if err != nil {
		http.Error(w, "manifest girdisi geçersiz: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="tagcess-readonly-rbac.yaml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// review runs the selected effective-permission check over the profile scope and renders what it
// asked and what the API answered. A failure is a shown result, not a broader claim.
func (h *K8sSetupHandler) review(w http.ResponseWriter, r *http.Request) {
	if _, ok := operatorActor(r); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p, err := h.cfg.Profiles.Get(r.Context())
	if err != nil {
		h.renderPage(w, r, http.StatusOK, func(v *k8sSetupView) {
			v.ReviewErr = "bağlantı profili okunamadı; izin testi çalıştırılmadı"
		})
		return
	}
	got, err := h.cfg.Review(r.Context(), p.Namespaces)
	if err != nil {
		h.renderPage(w, r, http.StatusOK, func(v *k8sSetupView) {
			v.ReviewErr = "izin testi tamamlanamadı: " + err.Error()
		})
		return
	}
	h.renderPage(w, r, http.StatusOK, func(v *k8sSetupView) { v.Review = &got })
}

// savePolicy validates and stores one scope's F4-043 policy. A refused save keeps the stored
// policy. The audit "requested" entry is written before the policy, so a failing audit log stops
// the change (A-01).
func (h *K8sSetupHandler) savePolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	scope := netpolicy.Scope(strings.TrimSpace(r.PostFormValue("scope")))
	if scope != netpolicy.ScopeAPI && scope != netpolicy.ScopeProbe {
		http.Error(w, "geçersiz policy türü", http.StatusBadRequest)
		return
	}
	addresses, ports := r.PostFormValue("addresses"), r.PostFormValue("ports")
	in, fieldErrs := parsePolicyInput(addresses, ports)
	before := h.policyJSON(r.Context(), scope)
	event := audit.Diff{{Field: policySettingKey(scope), Before: before, After: policyAttempt(in)}}

	if len(fieldErrs) > 0 {
		h.auditOutcome(r.Context(), actor, "failed", append(event, audit.Change{Field: "error", After: errorText(fieldErrs)}))
		h.renderPage(w, r, http.StatusBadRequest, func(v *k8sSetupView) {
			v.submitPolicy(scope, addresses, ports)
			v.Error = "geçersiz policy: " + errorText(fieldErrs)
		})
		return
	}
	if err := h.audit(r.Context(), actor, "requested", event); err != nil {
		http.Error(w, "işlem kaydedilemedi; policy değiştirilmedi", http.StatusInternalServerError)
		return
	}
	if err := h.cfg.Policy.Set(r.Context(), scope, in); err != nil {
		var verr *netpolicy.ValidationError
		if errors.As(err, &verr) {
			text := errorText(verr.Fields)
			h.auditOutcome(r.Context(), actor, "failed", append(event, audit.Change{Field: "error", After: text}))
			h.renderPage(w, r, http.StatusBadRequest, func(v *k8sSetupView) {
				v.submitPolicy(scope, addresses, ports)
				v.Error = "geçersiz policy: " + text
			})
			return
		}
		h.auditOutcome(r.Context(), actor, "failed", append(event, audit.Change{Field: "error", After: err.Error()}))
		http.Error(w, "policy yazılamadı; değişiklik yapılmadı", http.StatusInternalServerError)
		return
	}
	h.auditOutcome(r.Context(), actor, "applied", audit.Diff{
		{Field: policySettingKey(scope), Before: before, After: h.policyJSON(r.Context(), scope)},
	})
	if h.cfg.OnSaved != nil {
		h.cfg.OnSaved()
	}
	h.renderPage(w, r, http.StatusOK, func(v *k8sSetupView) {
		v.Notice = "policy kaydedildi; sonraki API/probe kurulumu bu değerleri kullanır"
	})
}

// submitPolicy replaces the form values with the refused input so the operator sees it again.
func (v *k8sSetupView) submitPolicy(scope netpolicy.Scope, addresses, ports string) {
	f := k8sPolicyForm{Scope: scope, Addresses: addresses, Ports: ports}
	switch scope {
	case netpolicy.ScopeAPI:
		v.API = f
	case netpolicy.ScopeProbe:
		v.Probe = f
	}
}

func (h *K8sSetupHandler) audit(ctx context.Context, actor, result string, diff audit.Diff) error {
	_, err := h.cfg.Auditor.Write(ctx, audit.Entry{
		Actor: actor, Event: k8sSetupPolicyEvent, Target: "setting", Diff: diff, Result: result,
	})
	return err
}

func (h *K8sSetupHandler) auditOutcome(ctx context.Context, actor, result string, diff audit.Diff) {
	if err := h.audit(ctx, actor, result, diff); err != nil {
		slog.Default().Warn("k8s setup: audit write failed", "event", k8sSetupPolicyEvent, "result", result, "err", err)
	}
}

// policyJSON renders a stored policy for the audit diff; a missing or unreadable value is described
// without echoing its text.
func (h *K8sSetupHandler) policyJSON(ctx context.Context, scope netpolicy.Scope) string {
	pol, err := h.cfg.Policy.Get(ctx, scope)
	switch {
	case errors.Is(err, netpolicy.ErrNotSet):
		return ""
	case err != nil:
		return "<okunamadı>"
	}
	b, err := json.Marshal(pol)
	if err != nil {
		return "<kodlanamadı>"
	}
	return string(b)
}

// policySettingKey is the settings key F4-043 uses, for the audit diff.
func policySettingKey(scope netpolicy.Scope) string { return "netpolicy." + string(scope) }

// policyAttempt summarises the submitted input for the audit "requested" entry without storing
// unbounded form text.
func policyAttempt(in netpolicy.Input) string {
	return fmt.Sprintf("%d IP/CIDR, %d port", len(in.Addresses), len(in.Ports))
}

// parsePolicyInput splits the two form fields. A port that is not a number is a field error; the
// shared validator decides whether an address or port is allowed.
func parsePolicyInput(addresses, ports string) (netpolicy.Input, []netpolicy.FieldError) {
	in := netpolicy.Input{Addresses: splitList(addresses)}
	var fieldErrs []netpolicy.FieldError
	for i, tok := range splitList(ports) {
		n, err := strconv.Atoi(tok)
		if err != nil {
			fieldErrs = append(fieldErrs, netpolicy.FieldError{
				Field: fmt.Sprintf("ports[%d]", i), Message: "port must be a number",
			})
			continue
		}
		in.Ports = append(in.Ports, n)
	}
	return in, fieldErrs
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

func errorText(fields []netpolicy.FieldError) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return strings.Join(parts, "; ")
}
