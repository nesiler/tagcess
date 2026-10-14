package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/vpnuser"
)

// The personal-device reopen (F3-021, H-01/Y-04): an expired personal device is reopened only
// when a fresh Zitadel read proves its owner eligible (active account, at least one vpn role) and
// only with an explicit confirm step. The eligibility proof and the expiry write run under the
// same writer lock (the executor's Guard), so a role lost between the confirm page and the apply
// is seen before anything is written. There is no automatic reopen: when the roles come back, the
// reconcile only fixes the policy, never the device.

// hsUserLister is the Headscale user read the owner lookup needs (F1 client).
type hsUserLister interface {
	ListUsers(ctx context.Context) ([]headscale.User, error)
}

// eligibilityFunc is the vpnuser resolver's fresh eligibility read.
type eligibilityFunc func(ctx context.Context, u headscale.User) (vpnuser.Eligibility, error)

// reconcileTrigger queues a reconcile; sync.Trigger satisfies it. The reopen asks for a manual
// run right after a successful apply (R2 karar 20).
type reconcileTrigger interface {
	RequestManual()
}

// DeviceReopenService builds the reopen operations.
type DeviceReopenService struct {
	hs    deviceAdminClient
	users hsUserLister
	elig  eligibilityFunc
	ex    *hsadmin.Executor
	trig  reconcileTrigger
}

// NewDeviceReopenService validates the wiring.
func NewDeviceReopenService(hs deviceAdminClient, users hsUserLister, elig eligibilityFunc, ex *hsadmin.Executor, trig reconcileTrigger) (*DeviceReopenService, error) {
	switch {
	case hs == nil:
		return nil, errors.New("web: device reopen needs a Headscale admin client")
	case users == nil:
		return nil, errors.New("web: device reopen needs a Headscale user reader")
	case elig == nil:
		return nil, errors.New("web: device reopen needs an eligibility check")
	case ex == nil:
		return nil, errors.New("web: device reopen needs an hsadmin executor")
	case trig == nil:
		return nil, errors.New("web: device reopen needs a reconcile trigger")
	}
	return &DeviceReopenService{hs: hs, users: users, elig: elig, ex: ex, trig: trig}, nil
}

// reopenable reports whether the detail page may offer the action: personal (untagged) and
// expired devices only. It is presentation; the guard refuses everything else again.
func reopenable(row DeviceRowView) bool { return !row.Tagged && row.Expired }

// confirm reads the device and its owner's current eligibility and returns the confirm page's
// view. No write happens here; an ineligible or unreadable owner comes back as Err (the reason to
// show) and the page then renders no form.
func (s *DeviceReopenService) confirm(ctx context.Context, id uint64) (DeviceReopenConfirmView, error) {
	nodes, err := s.hs.ListNodes(ctx)
	if err != nil {
		return DeviceReopenConfirmView{}, fmt.Errorf("web: list headscale nodes: %w", err)
	}
	var node admin.AdminNode
	found := false
	for _, n := range nodes {
		if n.ID == id {
			node, found = n, true
			break
		}
	}
	if !found {
		return DeviceReopenConfirmView{}, errDeviceNotFound
	}
	if len(node.Tags) > 0 {
		return DeviceReopenConfirmView{}, errReopenNotPersonal
	}
	view := DeviceReopenConfirmView{
		Row:     deviceRowView(node, time.Now()),
		Version: hsadmin.NodeVersion(node),
	}
	users, err := s.users.ListUsers(ctx)
	if err != nil {
		return view, fmt.Errorf("headscale kullanıcıları okunamadı: %w", err)
	}
	for _, u := range users {
		if u.ID == node.UserID {
			e, err := s.elig(ctx, u)
			if err != nil {
				return view, err
			}
			view.Evidence = e
			return view, nil
		}
	}
	return view, fmt.Errorf("cihazın sahibi (headscale kullanıcı %d) bulunamadı", node.UserID)
}

// errReopenNotPersonal marks a tagged device; reopen is personal-only (AC3).
var errReopenNotPersonal = errors.New("yeniden açma yalnız kişisel (tag'siz) cihazlarda yapılabilir")

// DeviceReopenConfirmView is the confirm page: the device, the owner's eligibility evidence and
// the version the confirmed apply must carry. Err != nil means the reopen may not proceed; the
// error text is the reason to show and Evidence stays zero.
type DeviceReopenConfirmView struct {
	Row      DeviceRowView
	Version  string
	Evidence vpnuser.Eligibility
	Err      error
}

// DeviceReopenHandler serves the reopen routes: the GET confirm page and the POST apply.
type DeviceReopenHandler struct {
	svc  *DeviceReopenService
	csrf *CSRF
}

// NewDeviceReopenHandler validates the wiring.
func NewDeviceReopenHandler(svc *DeviceReopenService, csrf *CSRF) (*DeviceReopenHandler, error) {
	switch {
	case svc == nil:
		return nil, errors.New("web: device reopen routes need a service")
	case csrf == nil:
		return nil, errors.New("web: device reopen routes need a CSRF signer")
	}
	return &DeviceReopenHandler{svc: svc, csrf: csrf}, nil
}

// Register adds the reopen routes.
func (h *DeviceReopenHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/devices/{id}/reopen", h.confirmPage)
	mux.HandleFunc("POST /headscale/devices/{id}/reopen/apply", h.apply)
}

// confirmPage shows the eligibility result and the two-step confirm form (AC4).
func (h *DeviceReopenHandler) confirmPage(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	view, err := h.svc.confirm(r.Context(), id)
	switch {
	case errors.Is(err, errDeviceNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, errReopenNotPersonal):
		http.Error(w, errReopenNotPersonal.Error(), http.StatusConflict)
		return
	case err != nil:
		view.Err = err // the reason is the page's content; no form is drawn
	}
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "headscale", "Yeniden açma onayı",
		DeviceReopenConfirmPage(view, h.csrf.Token())).Render(r.Context(), w)
}

// apply performs the guarded reopen (AC1, AC2, AC5): under the writer lock the guard re-reads the
// eligibility and refuses everything but eligible personal devices, then the expiry is moved to
// the chosen future instant and read back. A success asks the scheduler for a manual reconcile
// (AC6).
func (h *DeviceReopenHandler) apply(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != confirmWord {
		http.Error(w, "yeniden açma onayı yok; önce onay sayfasını açın", http.StatusBadRequest)
		return
	}
	expected := r.PostFormValue("expected")
	if expected == "" {
		http.Error(w, "form sürümü yok; sayfayı yenileyin", http.StatusBadRequest)
		return
	}
	expiry, err := parseDeviceExpiry(r.PostFormValue("expiry"))
	if err != nil || !expiry.After(time.Now()) {
		http.Error(w, "geçerli ve gelecekte bir expire tarihi gerekli", http.StatusBadRequest)
		return
	}

	guard := func(ctx context.Context, target admin.AdminNode) (audit.Diff, error) {
		if len(target.Tags) > 0 {
			return nil, errReopenNotPersonal
		}
		users, err := h.svc.users.ListUsers(ctx)
		if err != nil {
			return nil, fmt.Errorf("headscale kullanıcıları okunamadı: %w", err)
		}
		for _, u := range users {
			if u.ID != target.UserID {
				continue
			}
			e, err := h.svc.elig(ctx, u)
			if err != nil {
				return nil, err
			}
			return audit.Diff{
				{Field: "zitadel_kullanıcı", After: e.UserID},
				{Field: "hesap_durumu", After: e.State.String()},
				{Field: "roller", After: strings.Join(e.Roles, ",")},
			}, nil
		}
		return nil, fmt.Errorf("cihazın sahibi (headscale kullanıcı %d) bulunamadı", target.UserID)
	}

	actor, _ := ActorFrom(r.Context())
	op := hsadmin.Op{
		Actor:    actor.Email,
		Kind:     hsadmin.KindNodeReopen,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: expiryDiff(expiry.UTC().Format(time.RFC3339)),
		Guard:    guard,
		Apply: func(ctx context.Context) error {
			_, err := h.svc.hs.ExpireNode(ctx, id, expiry)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return n.Expiry != nil && n.Expiry.Sub(expiry).Abs() < time.Second, nil
				}
			}
			return false, nil
		},
	}
	res, err := h.svc.ex.Do(r.Context(), op)
	view := DeviceReopenResultView{
		DeviceActionResultView: DeviceActionResultView{
			DeviceID:   id,
			DeviceName: r.PostFormValue("current_name"),
			Action:     "Cihazı yeniden açma",
			Status:     res.Status,
			Note:       res.Note,
		},
	}
	switch {
	case err == nil:
		view.Status = hsadmin.StatusApplied
		view.ReconcileTriggered = true
		h.svc.trig.RequestManual()
	case errors.Is(err, hsadmin.ErrStale), errors.Is(err, hsadmin.ErrBlocked), errors.Is(err, hsadmin.ErrGuard):
		w.WriteHeader(http.StatusConflict)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "headscale", "İşlem sonucu",
		DeviceReopenResultPage(view)).Render(r.Context(), w)
}

// deviceID parses the path's device id; anything malformed is 404.
func (h *DeviceReopenHandler) deviceID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

// DeviceReopenResultView is the reopen outcome screen.
type DeviceReopenResultView struct {
	DeviceActionResultView
	// ReconcileTriggered: a manual reconcile was queued after the apply.
	ReconcileTriggered bool
}
