package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	policyrender "github.com/nesiler/tagcess/internal/render" // aliased: the package name collides with a web test helper
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// The personal pre-auth key screen (F3-022, H-03): a devops makes a one-time, untagged, short-lived
// key for an existing OIDC user, only when a fresh Zitadel read, made under the writer lock right
// before the RPC, shows an active account with a role in the vpn project. The key bypasses the OIDC
// sign-in, which every page of the flow says. Value handling is F3-017's: shown once, never kept.

// personalExtras are the request fields the personal flow does not have (R2: no reusable, ephemeral
// or tagged personal keys); a request that carries one is refused.
var personalExtras = []string{"reusable", "ephemeral", "tags"}

// personalUsers lists the Headscale users; *headscale.Client satisfies it.
type personalUsers interface {
	ListUsers(ctx context.Context) ([]headscale.User, error)
}

// personalResolver is the vpnuser surface the screen uses; *vpnuser.Resolver satisfies it.
type personalResolver interface {
	List(ctx context.Context, users []headscale.User) vpnuser.Snapshot
	Eligible(ctx context.Context, u headscale.User) (bool, error)
}

// PersonalKeyServiceConfig wires the personal key service. Now is optional (tests pin it).
type PersonalKeyServiceConfig struct {
	Admin    keyAdmin
	Users    personalUsers
	Resolver personalResolver
	Exec     keyExecutor
	// Issuer is the Zitadel issuer; it turns a provider identifier into the Zitadel user id the
	// audit row records.
	Issuer string
	Now    func() time.Time
}

// PersonalKeyService builds the personal key screen and makes the keys. Use NewPersonalKeyService.
type PersonalKeyService struct {
	hs       keyAdmin
	users    personalUsers
	resolver personalResolver
	exec     keyExecutor
	issuer   string
	now      func() time.Time
}

// NewPersonalKeyService validates the wiring.
func NewPersonalKeyService(cfg PersonalKeyServiceConfig) (*PersonalKeyService, error) {
	switch {
	case cfg.Admin == nil:
		return nil, errors.New("web: personal key page needs a Headscale admin client")
	case cfg.Users == nil:
		return nil, errors.New("web: personal key page needs a Headscale user reader")
	case cfg.Resolver == nil:
		return nil, errors.New("web: personal key page needs a vpnuser resolver")
	case cfg.Exec == nil:
		return nil, errors.New("web: personal key page needs an admin executor")
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("web: personal key page needs the Zitadel issuer")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &PersonalKeyService{hs: cfg.Admin, users: cfg.Users, resolver: cfg.Resolver, exec: cfg.Exec, issuer: cfg.Issuer, now: now}, nil
}

// PersonalUserOption is one user the form offers: matched, active and holding a vpn role.
type PersonalUserOption struct {
	ID    uint64
	Label string
}

// PersonalKeyView is the form page snapshot. Err means the Headscale users could not be read;
// ZitadelErr that eligibility could not be proven; in both cases no user is offered (fail safe).
type PersonalKeyView struct {
	Options    []PersonalUserOption
	Err        error
	ZitadelErr error
	FormError  string
	DryRun     bool
}

// PersonalKeyInput is the create form. Extras names the request fields that must not be there
// (reusable, ephemeral, tags); the handler fills it.
type PersonalKeyInput struct {
	User      string
	ExpiresIn string
	Extras    []string
}

// Options reads the users and offers the eligible ones. The offer is a convenience; the check that
// counts is the one under the lock at creation.
func (s *PersonalKeyService) Options(ctx context.Context) PersonalKeyView {
	users, err := s.users.ListUsers(ctx)
	if err != nil {
		return PersonalKeyView{Err: fmt.Errorf("web: list headscale users: %w", err)}
	}
	snap := s.resolver.List(ctx, users)
	if snap.ZitadelErr != nil {
		return PersonalKeyView{ZitadelErr: snap.ZitadelErr}
	}
	var v PersonalKeyView
	for _, row := range snap.Rows {
		if !row.Matched || !row.Verified || row.State != zitadel.UserActive || len(row.Roles) == 0 {
			continue
		}
		label := row.User.Name
		if row.User.Email != "" {
			label += " (" + row.User.Email + ")"
		}
		v.Options = append(v.Options, PersonalUserOption{ID: row.User.ID, Label: label + " — " + strings.Join(row.Roles, ", ")})
	}
	sort.Slice(v.Options, func(i, j int) bool { return v.Options[i].ID < v.Options[j].ID })
	return v
}

// Create makes the key. Everything that does not need an external read is checked first (fields,
// expiry, user); the eligibility is then read under the writer lock, right before the RPC, and a
// failure there refuses without an RPC. The RPC runs once; an error or a lost answer is an
// unknown outcome.
func (s *PersonalKeyService) Create(ctx context.Context, actor string, in PersonalKeyInput) KeyOutcome {
	if len(in.Extras) > 0 {
		return KeyOutcome{Status: keyRefused, Message: "Kişisel key yalnız tek kullanımlıktır ve tag'sizdir; şu alanlar kabul edilmez: " + strings.Join(in.Extras, ", ") + "."}
	}
	// Personal keys have no policy maximum (2026-10-06 item 8): server keys are made this way too.
	expiry, err := parseKeyExpiry(in.ExpiresIn, s.now(), 0)
	if err != nil {
		return KeyOutcome{Status: keyRefused, Message: err.Error()}
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(in.User), 10, 64)
	if err != nil || uid == 0 {
		return KeyOutcome{Status: keyRefused, Message: "Geçersiz kullanıcı seçimi."}
	}
	users, err := s.users.ListUsers(ctx)
	if err != nil {
		return KeyOutcome{Status: keyRefused, Message: fmt.Sprintf("Headscale kullanıcıları okunamadı: %v", err)}
	}
	var user headscale.User
	var found bool
	for _, u := range users {
		if u.ID == uid {
			user, found = u, true
			break
		}
	}
	if !found {
		return KeyOutcome{Status: keyRefused, Message: fmt.Sprintf("Headscale kullanıcısı %d bulunamadı.", uid)}
	}

	zid, _ := policyrender.MatchUserID(user.ProviderID, s.issuer)
	return createPreAuthKey(ctx, s.exec, s.hs, createKey{
		Actor:  actor,
		UserID: uid,
		Opts:   admin.PreAuthKeyOptions{Expiration: expiry},
		Diff: audit.Diff{
			{Field: "headscale_user", After: fmt.Sprintf("%s (%d)", user.Name, user.ID)},
			{Field: "zitadel_user", After: zid},
			{Field: "reusable", After: "false"},
			{Field: "ephemeral", After: "false"},
			{Field: "expiration", After: expiry.UTC().Format(time.RFC3339)},
		},
		Precheck: func(ctx context.Context) error {
			if _, err := s.resolver.Eligible(ctx, user); err != nil {
				return fmt.Errorf("%s için key üretilemez: %w", user.Name, err)
			}
			return nil
		},
	})
}

// PersonalKeyHandlerConfig wires the personal key screen.
type PersonalKeyHandlerConfig struct {
	Service PersonalKeyManager
	// DryRun carries the dry-run note of the section tab bar (R2 karar 22). Required.
	DryRun change.DryRun
	CSRF   *CSRF
}

// PersonalKeyManager is the service the handler drives; *PersonalKeyService is the production one.
type PersonalKeyManager interface {
	Options(ctx context.Context) PersonalKeyView
	Create(ctx context.Context, actor string, in PersonalKeyInput) KeyOutcome
}

// PersonalKeyHandler serves /headscale/keys/personal.
type PersonalKeyHandler struct {
	cfg PersonalKeyHandlerConfig
}

// NewPersonalKeyHandler validates the wiring.
func NewPersonalKeyHandler(cfg PersonalKeyHandlerConfig) (*PersonalKeyHandler, error) {
	switch {
	case cfg.Service == nil:
		return nil, errors.New("web: personal key page needs a service")
	case cfg.DryRun == nil:
		return nil, errors.New("web: personal key page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: personal key page needs a CSRF signer")
	}
	return &PersonalKeyHandler{cfg: cfg}, nil
}

// Register adds the personal key routes.
func (h *PersonalKeyHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/keys/personal", h.page)
	mux.HandleFunc("POST /headscale/keys/personal", h.create)
}

func (h *PersonalKeyHandler) page(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, r, "", http.StatusOK)
}

// renderPage renders the form; formErr is a refused create shown above it.
func (h *PersonalKeyHandler) renderPage(w http.ResponseWriter, r *http.Request, formErr string, status int) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view := h.cfg.Service.Options(r.Context())
	view.DryRun, view.FormError = dryRun, formErr
	actor, _ := ActorFrom(r.Context())
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Kişisel pre-auth key",
		PersonalKeyPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// create makes the key and shows its value in this one response.
func (h *PersonalKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "geçersiz form", http.StatusBadRequest)
		return
	}
	var extras []string
	for _, name := range personalExtras {
		if _, present := r.PostForm[name]; present {
			extras = append(extras, name)
		}
	}
	out := h.cfg.Service.Create(r.Context(), actor, PersonalKeyInput{
		User:      r.PostFormValue("user"),
		ExpiresIn: r.PostFormValue("expires_in"),
		Extras:    extras,
	})
	if out.Status == keyRefused {
		h.renderPage(w, r, out.Message, http.StatusBadRequest)
		return
	}
	renderKeyOutcome(w, r, h.cfg.CSRF, "Kişisel pre-auth key", "personal", true, out)
}
