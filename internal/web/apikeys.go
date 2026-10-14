package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
)

// The API keys screen (F3-018, H-03): list Headscale's API keys, expire and delete them. There is
// deliberately no create (R2 karar 7): an API key carries Headscale's full admin rights (R2 B-04)
// and tagcess itself talks to Headscale over the unix socket. Expire and delete go through the
// F3-009 executor, addressed by the stable id only; delete asks for its own irreversible-confirm
// page first.

// APIKeysReader is the read surface of the API keys screen.
type APIKeysReader interface {
	ListApiKeys(ctx context.Context) ([]admin.APIKey, error)
}

// APIKeysWriter is the write surface; the production writer is *admin.AdminClient. Both actions
// take the id only — the UI never addresses a key by prefix (R2 karar 8).
type APIKeysWriter interface {
	ExpireApiKey(ctx context.Context, id uint64) error
	DeleteApiKey(ctx context.Context, id uint64) error
}

// APIKeysHandlerConfig wires the API keys screen. Every field is required.
type APIKeysHandlerConfig struct {
	Reader   APIKeysReader
	Writer   APIKeysWriter
	Executor *hsadmin.Executor
	DryRun   change.DryRun
	CSRF     *CSRF
}

// APIKeysHandler serves the /headscale/keys/api routes.
type APIKeysHandler struct {
	cfg APIKeysHandlerConfig
}

// NewAPIKeysHandler validates the wiring.
func NewAPIKeysHandler(cfg APIKeysHandlerConfig) (*APIKeysHandler, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("web: api keys page needs a reader")
	case cfg.Writer == nil:
		return nil, errors.New("web: api keys page needs a writer")
	case cfg.Executor == nil:
		return nil, errors.New("web: api keys page needs the admin executor")
	case cfg.DryRun == nil:
		return nil, errors.New("web: api keys page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: api keys page needs a CSRF signer")
	}
	return &APIKeysHandler{cfg: cfg}, nil
}

// Register adds the API keys routes. No create route exists, on purpose.
func (h *APIKeysHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/keys/api", h.page)
	mux.HandleFunc("GET /headscale/keys/api/{id}/delete", h.confirmDelete)
	mux.HandleFunc("POST /headscale/keys/api/{id}/expire", h.expire)
	mux.HandleFunc("POST /headscale/keys/api/{id}/delete", h.deleteKey)
}

// APIKeyRowView is one row of the API keys list with its display state.
type APIKeyRowView struct {
	ID         uint64
	Prefix     string
	CreatedAt  string
	Expiration string
	LastSeen   string
	Expired    bool
	NeverUsed  bool
	NoExpiry   bool
	// Version is the APIKeyVersion the row's forms post back as Expected.
	Version string
}

// APIKeysView is the /headscale/keys/api snapshot.
type APIKeysView struct {
	Rows   []APIKeyRowView
	DryRun bool
	Err    error
}

// APIKeyConfirmView is the delete confirmation snapshot.
type APIKeyConfirmView struct {
	Key     APIKeyRowView
	Version string
	DryRun  bool
	Err     error
}

// page renders the list with the full-admin warning.
func (h *APIKeysHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	view, err := h.snapshot(r.Context())
	if err != nil {
		view = APIKeysView{Err: err}
	}
	view.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "API key'ler",
		APIKeysPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// snapshot reads the keys and maps them to rows, ordered by id so the page is deterministic.
func (h *APIKeysHandler) snapshot(ctx context.Context) (APIKeysView, error) {
	keys, err := h.cfg.Reader.ListApiKeys(ctx)
	if err != nil {
		return APIKeysView{}, fmt.Errorf("web: list headscale api keys: %w", err)
	}
	slices.SortFunc(keys, func(a, b admin.APIKey) int { return cmpID(a.ID, b.ID) })
	now := time.Now()
	rows := make([]APIKeyRowView, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, apiKeyRowView(k, now))
	}
	return APIKeysView{Rows: rows}, nil
}

// confirmDelete renders the irreversible-delete confirmation page.
func (h *APIKeysHandler) confirmDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	key, err := h.lookup(r.Context(), id)
	var view APIKeyConfirmView
	switch {
	case errors.Is(err, errAPIKeyNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		view = APIKeyConfirmView{Err: err}
	default:
		view = APIKeyConfirmView{Key: apiKeyRowView(key, time.Now()), Version: hsadmin.APIKeyVersion(key)}
	}
	view.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "API key sil",
		APIKeyDeleteConfirmPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// expire marks the key expired: ExpireApiKey with the id only, read-back confirms the
// expiration is in the past (AC3).
func (h *APIKeysHandler) expire(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, func(k admin.APIKey) hsadmin.Op {
		return hsadmin.Op{
			Kind: hsadmin.KindAPIKeyExpire,
			Diff: apiKeyDiff(k),
			Apply: func(ctx context.Context) error {
				return h.cfg.Writer.ExpireApiKey(ctx, k.ID)
			},
			Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
				keys, err := rd.ListApiKeys(ctx)
				if err != nil {
					return false, err
				}
				key, ok := findAPIKey(keys, k.ID)
				return ok && key.Expiration != nil && key.Expiration.Before(time.Now()), nil
			},
		}
	})
}

// deleteKey removes the key; the request must carry confirm=1 from the confirmation page, because
// deleting an API key cannot be undone (R2 karar 7).
func (h *APIKeysHandler) deleteKey(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != "1" {
		http.Error(w, "silme onaylanmadı; işlem geri alınamaz, onay sayfasından geçin", http.StatusBadRequest)
		return
	}
	h.write(w, r, func(k admin.APIKey) hsadmin.Op {
		return hsadmin.Op{
			Kind: hsadmin.KindAPIKeyDelete,
			Diff: apiKeyDiff(k),
			Apply: func(ctx context.Context) error {
				return h.cfg.Writer.DeleteApiKey(ctx, k.ID)
			},
			Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
				keys, err := rd.ListApiKeys(ctx)
				if err != nil {
					return false, err
				}
				_, ok := findAPIKey(keys, k.ID)
				return !ok, nil
			},
		}
	})
}

// write is the shared expire/delete flow: actor, id, version, fresh read for the diff, executor,
// redirect. The fresh read never writes; the executor's staleness check guards the race.
func (h *APIKeysHandler) write(w http.ResponseWriter, r *http.Request, build func(admin.APIKey) hsadmin.Op) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "kimlik gerekli", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	version := strings.TrimSpace(r.PostFormValue("version"))
	if version == "" {
		http.Error(w, "form sürüm alanı eksik; sayfayı yenileyin", http.StatusBadRequest)
		return
	}
	key, err := h.lookup(r.Context(), id)
	if errors.Is(err, errAPIKeyNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Headscale okunamadı; işlem apply edilmedi", http.StatusServiceUnavailable)
		return
	}
	op := build(key)
	op.Actor = actor
	op.ID = id
	op.Target = fmt.Sprintf("apikey:%d", id)
	op.Expected = version
	if _, err := h.cfg.Executor.Do(r.Context(), op); err != nil {
		switch {
		case errors.Is(err, hsadmin.ErrStale):
			http.Error(w, "key sayfa gösterildikten sonra değişti; sayfayı yenileyip yeniden deneyin", http.StatusConflict)
		default:
			http.Error(w, "API key işlemi apply edilemedi; sonucu audit kaydından görün", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/headscale/keys/api", http.StatusSeeOther)
}

// lookup reads the key with the id fresh from Headscale.
func (h *APIKeysHandler) lookup(ctx context.Context, id uint64) (admin.APIKey, error) {
	keys, err := h.cfg.Reader.ListApiKeys(ctx)
	if err != nil {
		return admin.APIKey{}, fmt.Errorf("web: list headscale api keys: %w", err)
	}
	key, ok := findAPIKey(keys, id)
	if !ok {
		return admin.APIKey{}, errAPIKeyNotFound
	}
	return key, nil
}

func findAPIKey(keys []admin.APIKey, id uint64) (admin.APIKey, bool) {
	i := slices.IndexFunc(keys, func(k admin.APIKey) bool { return k.ID == id })
	if i < 0 {
		return admin.APIKey{}, false
	}
	return keys[i], true
}

// errAPIKeyNotFound says the id has no API key in Headscale.
var errAPIKeyNotFound = errors.New("web: api key not found")

// apiKeyRowView maps a key to its list row with the display state labels.
func apiKeyRowView(k admin.APIKey, now time.Time) APIKeyRowView {
	row := APIKeyRowView{
		ID:         k.ID,
		Prefix:     k.Prefix,
		CreatedAt:  formatDeviceTime(k.CreatedAt),
		Expiration: "—",
		LastSeen:   "—",
		Version:    hsadmin.APIKeyVersion(k),
	}
	if k.Expiration != nil {
		row.Expiration = formatDeviceTime(*k.Expiration)
		row.Expired = k.Expiration.Before(now)
	} else {
		row.NoExpiry = true
	}
	if k.LastSeen != nil {
		row.LastSeen = formatDeviceTime(*k.LastSeen)
	} else {
		row.NeverUsed = true
	}
	return row
}

// apiKeyDiff is the audit summary: the key's stable identity (id and non-secret prefix). The
// surface never sees the secret, so none can leak into the audit log.
func apiKeyDiff(k admin.APIKey) audit.Diff {
	return audit.Diff{{Field: "api_key", After: fmt.Sprintf("id=%d prefix=%s", k.ID, k.Prefix)}}
}

// cmpID is the id sort used by the list snapshots.
func cmpID(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
