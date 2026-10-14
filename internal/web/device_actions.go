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
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
)

// The device actions (F3-014, H-01 write side): rename, expire now, set or disable the expiry and
// the two-step delete. Every action is an hsadmin Op: the executor owns the fresh read, the
// server-node protection, the staleness refusal, the audit trail and the read-back; this file only
// validates the form, builds the Op and renders the outcome.

// deviceAdminClient is the write surface the actions need. *admin.AdminClient satisfies it.
type deviceAdminClient interface {
	ListNodes(ctx context.Context) ([]admin.AdminNode, error)
	RenameNode(ctx context.Context, id uint64, newName string) (admin.AdminNode, error)
	DeleteNode(ctx context.Context, id uint64) error
	ExpireNode(ctx context.Context, id uint64, expiry time.Time) (admin.AdminNode, error)
	EnableNode(ctx context.Context, id uint64) (admin.AdminNode, error)
}

// deviceNamePattern is documented on validDeviceName; the check is hand-rolled so a bad name is
// refused without compiling a regexp per request.
// confirmWord is the delete/reopen confirmation field value the confirm page renders. A POST
// without it never reaches an RPC.
const confirmWord = "evet"

// DeviceActionsService builds device-action operations and the detail page's action panel.
type DeviceActionsService struct {
	hs deviceAdminClient
	ex *hsadmin.Executor
}

// NewDeviceActionsService validates the wiring.
func NewDeviceActionsService(hs deviceAdminClient, ex *hsadmin.Executor) (*DeviceActionsService, error) {
	switch {
	case hs == nil:
		return nil, errors.New("web: device actions need a Headscale admin client")
	case ex == nil:
		return nil, errors.New("web: device actions need an hsadmin executor")
	}
	return &DeviceActionsService{hs: hs, ex: ex}, nil
}

// DeviceActionsPanel is the detail page's write panel: the forms hide themselves on a protected
// node (the badge is shown instead) and while the protected list cannot be read. Hiding is
// presentation only; the executor refuses the same writes again (R2 karar: UI hiding is not
// security).
type DeviceActionsPanel struct {
	// Protected: the node carries a protected tag; only renaming stays available.
	Protected bool
	// Reopenable: an expired personal device may be reopened (F3-021). The reopen form lives on
	// its own confirm page.
	Reopenable bool
	// Warning explains why destructive forms are hidden (unreadable protected list). Empty when
	// the forms may be drawn.
	Warning string
}

// Panel builds the panel state for a device. A protected-list read failure fails safe: every
// tagged node counts as protected and the destructive forms stay hidden for every node.
func (s *DeviceActionsService) Panel(ctx context.Context, row DeviceRowView) *DeviceActionsPanel {
	tags, err := s.ex.ProtectedTags(ctx)
	p := &DeviceActionsPanel{Reopenable: reopenable(row)}
	if err != nil {
		p.Warning = "korumalı tag listesi okunamadı; silme ve expire işlemleri gizli. Neden: " + err.Error()
		p.Protected = len(row.Tags) > 0
		return p
	}
	for _, t := range row.Tags {
		if slices.Contains(tags, t) {
			p.Protected = true
			break
		}
	}
	return p
}

// device returns the live node for the confirm page.
func (s *DeviceActionsService) device(ctx context.Context, id uint64) (DeviceRowView, string, error) {
	nodes, err := s.hs.ListNodes(ctx)
	if err != nil {
		return DeviceRowView{}, "", fmt.Errorf("web: list headscale nodes: %w", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return deviceRowView(n, time.Now()), hsadmin.NodeVersion(n), nil
		}
	}
	return DeviceRowView{}, "", errDeviceNotFound
}

// DeviceActionsHandler serves the device action routes.
type DeviceActionsHandler struct {
	svc  *DeviceActionsService
	csrf *CSRF
}

// NewDeviceActionsHandler validates the wiring.
func NewDeviceActionsHandler(svc *DeviceActionsService, csrf *CSRF) (*DeviceActionsHandler, error) {
	switch {
	case svc == nil:
		return nil, errors.New("web: device action routes need a service")
	case csrf == nil:
		return nil, errors.New("web: device action routes need a CSRF signer")
	}
	return &DeviceActionsHandler{svc: svc, csrf: csrf}, nil
}

// Register adds the action routes. Every write is a POST (NFR-03); the delete has a GET confirm
// page before it.
func (h *DeviceActionsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /headscale/devices/{id}/rename", h.rename)
	mux.HandleFunc("POST /headscale/devices/{id}/expire", h.expireNow)
	mux.HandleFunc("POST /headscale/devices/{id}/expiry", h.setExpiry)
	mux.HandleFunc("POST /headscale/devices/{id}/expiry/disable", h.disableExpiry)
	mux.HandleFunc("GET /headscale/devices/{id}/delete", h.deleteConfirm)
	mux.HandleFunc("POST /headscale/devices/{id}/delete", h.delete)
}

// action names the operation on the result screen.
const (
	actionRename        = "Ad değiştirme"
	actionExpireNow     = "Şimdi expire etme"
	actionSetExpiry     = "Expire süresi ayarlama"
	actionDisableExpiry = "Expire kapatma"
	actionDelete        = "Cihaz silme"
)

// DeviceActionResultView is the outcome screen: what was attempted, the executor's status and the
// read-back note. The status is shown explicitly (applied/failed/unknown and the refusals).
type DeviceActionResultView struct {
	DeviceID   uint64
	DeviceName string
	// NewName is the name a successful rename set; the outcome shows it next to the old one.
	NewName string
	Action  string
	Status  hsadmin.Status
	Note    string
}

// DeviceDeleteConfirmView is the delete confirm page: the device as shown and the version its
// confirmed POST must carry.
type DeviceDeleteConfirmView struct {
	Row     DeviceRowView
	Version string
	Err     error
}

// rename applies a name change; an invalid name is refused before any RPC (AC1).
func (h *DeviceActionsHandler) rename(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !validDeviceName(name) {
		http.Error(w, "geçersiz ad: küçük harf, rakam ve tire; tire ile başlayıp bitemez (2-63 karakter)", http.StatusBadRequest)
		return
	}
	expected, ok := h.expected(w, r)
	if !ok {
		return
	}
	op := hsadmin.Op{
		Kind:     hsadmin.KindNodeRename,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: func(n admin.AdminNode) audit.Diff {
			return audit.Diff{{Field: "given_name", Before: n.GivenName, After: name}}
		},
		Apply: func(ctx context.Context) error {
			_, err := h.svc.hs.RenameNode(ctx, id, name)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return n.GivenName == name, nil
				}
			}
			return false, nil
		},
	}
	h.applyNamed(w, r, op, actionRename, name)
}

// expireNow cuts the node off immediately (AC2).
func (h *DeviceActionsHandler) expireNow(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	expected, ok := h.expected(w, r)
	if !ok {
		return
	}
	now := time.Now()
	op := hsadmin.Op{
		Kind:     hsadmin.KindNodeExpire,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: expiryDiff("şimdi"),
		Apply: func(ctx context.Context) error {
			_, err := h.svc.hs.ExpireNode(ctx, id, now)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return n.Expiry != nil && !n.Expiry.After(now), nil
				}
			}
			return false, nil
		},
	}
	h.apply(w, r, op, actionExpireNow)
}

// setExpiry schedules a future expiry; a past or unparseable instant is refused before any RPC
// (AC3). "Expiry açma" is the same write: an admin always names the date.
func (h *DeviceActionsHandler) setExpiry(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	expected, ok := h.expected(w, r)
	if !ok {
		return
	}
	expiry, err := parseDeviceExpiry(r.PostFormValue("expiry"))
	if err != nil {
		http.Error(w, "geçersiz expire tarihi", http.StatusBadRequest)
		return
	}
	if !expiry.After(time.Now()) {
		http.Error(w, "expire tarihi gelecekte olmalı; geçmiş için \"şimdi expire et\" eylemini kullanın", http.StatusBadRequest)
		return
	}
	op := hsadmin.Op{
		Kind:     hsadmin.KindNodeExpiry,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: expiryDiff(expiry.UTC().Format(time.RFC3339)),
		// Under maintenance only a shorter expiry may run (ADR 0021 d). A node with no expiry counts
		// as widening (F3b-014 rule), the safe side.
		Widens: func(n admin.AdminNode) bool { return n.Expiry == nil || expiry.After(*n.Expiry) },
		Guard:  refuseExpiredPersonal,
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
	h.apply(w, r, op, actionSetExpiry)
}

// disableExpiry clears the expiry so the node never expires by time (AC4). It never touches Y-04:
// the reconcile still expires a roleless user's device.
func (h *DeviceActionsHandler) disableExpiry(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	expected, ok := h.expected(w, r)
	if !ok {
		return
	}
	op := hsadmin.Op{
		Kind:     hsadmin.KindNodeExpiry,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: expiryDiff(""),
		// Removing the expiry always widens.
		Widens: func(admin.AdminNode) bool { return true },
		Guard:  refuseExpiredPersonal,
		Apply: func(ctx context.Context) error {
			_, err := h.svc.hs.EnableNode(ctx, id)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return n.Expiry == nil, nil
				}
			}
			return false, nil
		},
	}
	h.apply(w, r, op, actionDisableExpiry)
}

// expiryDiff is the audit diff of an expiry change; the "before" is the fresh node's expiry.
func expiryDiff(after string) func(admin.AdminNode) audit.Diff {
	return func(n admin.AdminNode) audit.Diff {
		before := ""
		if n.Expiry != nil {
			before = n.Expiry.UTC().Format(time.RFC3339)
		}
		return audit.Diff{{Field: "expiry", Before: before, After: after}}
	}
}

// refuseExpiredPersonal is the guard of the expiry actions: an expired personal device is brought
// back only through "Yeniden aç" (F3-021: confirm page and the fresh Zitadel eligibility read), so
// setting or disabling its expiry here would bypass that check. It runs under the writer lock on
// the freshly read node; the detail page hides the same forms, hiding is not the control.
func refuseExpiredPersonal(_ context.Context, n admin.AdminNode) (audit.Diff, error) {
	if len(n.Tags) == 0 && n.Expiry != nil && n.Expiry.Before(time.Now()) {
		return nil, errors.New("süresi dolmuş kişisel cihaz; \"Yeniden aç\" eylemini kullanın")
	}
	return nil, nil
}

// deleteConfirm shows the two-step delete page (AC5). The form it renders is the only way to POST
// the delete.
func (h *DeviceActionsHandler) deleteConfirm(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	row, version, err := h.svc.device(r.Context(), id)
	if errors.Is(err, errDeviceNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "cihaz okunamadı: "+err.Error(), http.StatusInternalServerError)
		return
	}
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "headscale", "Silme onayı",
		DeviceDeleteConfirmPage(DeviceDeleteConfirmView{Row: row, Version: version}, h.csrf.Token())).Render(r.Context(), w)
}

// delete removes the node after the confirm page (AC5). A POST without the confirmation field is
// refused before anything happens.
func (h *DeviceActionsHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := h.deviceID(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != confirmWord {
		http.Error(w, "silme onayı yok; önce onay sayfasını açın", http.StatusBadRequest)
		return
	}
	expected, ok := h.expected(w, r)
	if !ok {
		return
	}
	op := hsadmin.Op{
		Kind:     hsadmin.KindNodeDelete,
		ID:       id,
		Target:   "node:" + strconv.FormatUint(id, 10),
		Expected: expected,
		DiffFrom: func(n admin.AdminNode) audit.Diff {
			return audit.Diff{{Field: "device", Before: n.GivenName, After: ""}}
		},
		Apply: func(ctx context.Context) error {
			return h.svc.hs.DeleteNode(ctx, id)
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, n := range nodes {
				if n.ID == id {
					return false, nil
				}
			}
			return true, nil
		},
	}
	h.apply(w, r, op, actionDelete)
}

// apply runs the op through the executor and renders the outcome. Stale and blocked refusals get
// 409; the other outcomes are result screens (the status is shown explicitly, AC8).
func (h *DeviceActionsHandler) apply(w http.ResponseWriter, r *http.Request, op hsadmin.Op, action string) {
	h.applyNamed(w, r, op, action, "")
}

// applyNamed is apply for a rename: newName is shown on the outcome once the rename is applied.
func (h *DeviceActionsHandler) applyNamed(w http.ResponseWriter, r *http.Request, op hsadmin.Op, action, newName string) {
	actor, _ := ActorFrom(r.Context())
	op.Actor = actor.Email
	res, err := h.svc.ex.Do(r.Context(), op)
	view := DeviceActionResultView{
		DeviceID:   op.ID,
		DeviceName: r.PostFormValue("current_name"),
		Action:     action,
		Status:     res.Status,
		Note:       res.Note,
	}
	switch {
	case err == nil:
		view.Status = hsadmin.StatusApplied
		view.NewName = newName
	case errors.Is(err, hsadmin.ErrStale), errors.Is(err, hsadmin.ErrBlocked), errors.Is(err, hsadmin.ErrGuard):
		w.WriteHeader(http.StatusConflict)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.csrf.Token(), "headscale", "İşlem sonucu",
		DeviceActionResultPage(view)).Render(r.Context(), w)
}

// deviceID parses the path's device id; anything malformed is 404.
func (h *DeviceActionsHandler) deviceID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

// expected reads the form's version stamp; without it the executor could not refuse a stale form.
func (h *DeviceActionsHandler) expected(w http.ResponseWriter, r *http.Request) (string, bool) {
	expected := r.PostFormValue("expected")
	if expected == "" {
		http.Error(w, "form sürümü yok; sayfayı yenileyin", http.StatusBadRequest)
		return "", false
	}
	return expected, true
}

// validDeviceName reports whether name is a Headscale given name (dns label): lowercase letters,
// digits and hyphens, 1-63 characters, not starting or ending with a hyphen — the rule
// ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ with the single-character case allowed.
func validDeviceName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	for i, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// parseDeviceExpiry reads the datetime-local value (UTC, the form says so) or an RFC3339 instant.
func parseDeviceExpiry(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04", value)
}
