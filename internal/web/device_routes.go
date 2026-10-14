package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
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

// The device routes screen (F3-015, H-01): approve and revoke a node's advertised subnet routes
// and exit node. The write is a full-set read-modify-write through the F3-009 executor (lock,
// staleness, audit, read-back); this page only turns the form into the desired full set and
// refuses routes the node does not advertise before any RPC runs.

// The exit node's prefix pair; Headscale stores both once one is approved.
const (
	routeExitForm = "exit"
	exitNodeV4    = "0.0.0.0/0"
	exitNodeV6    = "::/0"
)

// routeApprovalNote is the promise the page makes next to every approval control.
const routeApprovalNote = "Route onayı erişim garantisi değildir; ACL ve autoApprovers etkisi ayrıca belirleyicidir."

// DeviceRoutesReader is the read surface of the routes page.
type DeviceRoutesReader interface {
	ListNodes(ctx context.Context) ([]admin.AdminNode, error)
}

// DeviceRoutesWriter is the write surface of the routes page; the production writer is
// *admin.AdminClient. It is an interface so tests can record the full-set calls.
type DeviceRoutesWriter interface {
	SetApprovedRoutes(ctx context.Context, id uint64, routes []string) (admin.AdminNode, error)
}

// DeviceRoutesPolicy is the policy read for the autoApprovers display; the production reader is
// the narrow F1 client (R2 T-02). A nil policy source is shown as a warning, not a blocker.
type DeviceRoutesPolicy interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
}

// DeviceRoutesHandlerConfig wires the routes screen. Every field except Policy is required.
type DeviceRoutesHandlerConfig struct {
	Reader   DeviceRoutesReader
	Writer   DeviceRoutesWriter
	Policy   DeviceRoutesPolicy
	Executor *hsadmin.Executor
	DryRun   change.DryRun
	CSRF     *CSRF
}

// DeviceRoutesHandler serves GET and POST /headscale/devices/{id}/routes.
type DeviceRoutesHandler struct {
	cfg DeviceRoutesHandlerConfig
}

// NewDeviceRoutesHandler validates the wiring.
func NewDeviceRoutesHandler(cfg DeviceRoutesHandlerConfig) (*DeviceRoutesHandler, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("web: routes page needs a reader")
	case cfg.Writer == nil:
		return nil, errors.New("web: routes page needs a writer")
	case cfg.Executor == nil:
		return nil, errors.New("web: routes page needs the admin executor")
	case cfg.DryRun == nil:
		return nil, errors.New("web: routes page needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: routes page needs a CSRF signer")
	}
	return &DeviceRoutesHandler{cfg: cfg}, nil
}

// Register adds the routes page routes.
func (h *DeviceRoutesHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/devices/{id}/routes", h.page)
	mux.HandleFunc("POST /headscale/devices/{id}/routes", h.apply)
}

// RouteRowView is one advertised subnet route: its checkbox state and where it stands.
type RouteRowView struct {
	Prefix        string
	Approved      bool
	Active        bool
	AutoApprovers string
}

// ExitRouteView is the exit node row: one checkbox for the /0 pair.
type ExitRouteView struct {
	Approved      bool
	Active        bool
	AutoApprovers string
}

// DeviceRoutesView is the /headscale/devices/{id}/routes snapshot.
type DeviceRoutesView struct {
	Row DeviceRowView
	// Version is the node version the form posts back as Expected.
	Version         string
	AvailableRoutes []string
	ApprovedRoutes  []string
	ActiveRoutes    []string
	SubnetRows      []RouteRowView
	Exit            *ExitRouteView
	// PolicyErr says the policy could not be read or parsed; the autoApprovers match is then
	// unknown and the page says so (fail safe: warn, never widen).
	PolicyErr bool
	DryRun    bool
	Err       error
}

// page renders the routes screen.
func (h *DeviceRoutesHandler) page(w http.ResponseWriter, r *http.Request) {
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
	view, err := h.snapshot(r.Context(), id)
	switch {
	case errors.Is(err, errDeviceNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		view = DeviceRoutesView{Err: err}
	}
	view.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Cihaz route'ları",
		DeviceRoutesPage(view, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// snapshot reads the node and the policy and builds the view.
func (h *DeviceRoutesHandler) snapshot(ctx context.Context, id uint64) (DeviceRoutesView, error) {
	nodes, err := h.cfg.Reader.ListNodes(ctx)
	if err != nil {
		return DeviceRoutesView{}, fmt.Errorf("web: list headscale nodes: %w", err)
	}
	i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == id })
	if i < 0 {
		return DeviceRoutesView{}, errDeviceNotFound
	}
	node := nodes[i]

	aa := policydoc.AutoApprovers{Routes: map[string][]string{}}
	policyErr := false
	if h.cfg.Policy != nil {
		p, perr := h.cfg.Policy.GetPolicy(ctx)
		if perr == nil {
			aa, perr = policydoc.ReadAutoApprovers(p.Text)
		}
		if perr != nil {
			// Warn, never block: approval stays possible, only the match hint is unknown.
			policyErr = true
		}
	}

	view := DeviceRoutesView{
		Row:             deviceRowView(node, time.Now()),
		Version:         hsadmin.NodeVersion(node),
		AvailableRoutes: node.AvailableRoutes,
		ApprovedRoutes:  node.ApprovedRoutes,
		ActiveRoutes:    node.SubnetRoutes,
		PolicyErr:       policyErr,
	}
	exitAdvertised := false
	for _, prefix := range node.AvailableRoutes {
		if isExitPrefix(prefix) {
			exitAdvertised = true
			continue
		}
		view.SubnetRows = append(view.SubnetRows, RouteRowView{
			Prefix:        prefix,
			Approved:      slices.Contains(node.ApprovedRoutes, prefix),
			Active:        slices.Contains(node.SubnetRoutes, prefix),
			AutoApprovers: strings.Join(approverMatch(aa, prefix), ", "),
		})
	}
	if exitAdvertised {
		approved := slices.ContainsFunc(node.ApprovedRoutes, isExitPrefix)
		active := slices.ContainsFunc(node.SubnetRoutes, isExitPrefix)
		var approvers []string
		if len(aa.ExitNode) > 0 {
			approvers = aa.ExitNode
		}
		view.Exit = &ExitRouteView{Approved: approved, Active: active, AutoApprovers: strings.Join(approvers, ", ")}
	}
	return view, nil
}

// apply turns the posted checkboxes into the desired full set and runs it through the executor.
func (h *DeviceRoutesHandler) apply(w http.ResponseWriter, r *http.Request) {
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

	// Fresh read for the advertished check (a read, not the write): an unadvertised route is
	// refused before any RPC. A node that vanished answers 404 like the page.
	nodes, err := h.cfg.Reader.ListNodes(r.Context())
	if err != nil {
		http.Error(w, "Headscale okunamadı; onay apply edilmedi", http.StatusServiceUnavailable)
		return
	}
	i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == id })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	node := nodes[i]
	desired, err := desiredRoutes(r.PostForm["route"], node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	op := hsadmin.Op{
		Actor:    actor,
		Kind:     hsadmin.KindNodeRoutes,
		ID:       id,
		Target:   fmt.Sprintf("node:%d", id),
		Expected: version,
		Diff:     auditRoutesDiff(node, desired),
		Apply: func(ctx context.Context) error {
			_, err := h.cfg.Writer.SetApprovedRoutes(ctx, id, desired)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			j := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == id })
			if j < 0 {
				return false, nil
			}
			return sameRoutes(nodes[j].ApprovedRoutes, desired), nil
		},
	}
	if _, err := h.cfg.Executor.Do(r.Context(), op); err != nil {
		switch {
		case errors.Is(err, hsadmin.ErrStale):
			http.Error(w, "node sayfa gösterildikten sonra değişti; sayfayı yenileyip yeniden onaylayın", http.StatusConflict)
		case errors.Is(err, hsadmin.ErrBlocked):
			http.Error(w, "işlem koruma kuralı tarafından engellendi", http.StatusConflict)
		default:
			http.Error(w, "route onayı apply edilemedi; sonucu audit kaydından görün", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/headscale/devices/%d/routes", id), http.StatusSeeOther)
}

// desiredRoutes turns the posted checkboxes into the full approved set to send. Every subnet
// route must be advertised (exact match, Headscale's own canonical form); exit is allowed only
// when the node advertises a /0 and expands to the IPv4+IPv6 pair (R2 B-04: the server adds the
// missing half, both are sent so the read-back is exact). Approved routes the node no longer
// advertises are kept in the set.
func desiredRoutes(posted []string, node admin.AdminNode) ([]string, error) {
	advertised := make(map[string]bool, len(node.AvailableRoutes))
	exitAdvertised := false
	for _, p := range node.AvailableRoutes {
		advertised[p] = true
		if isExitPrefix(p) {
			exitAdvertised = true
		}
	}
	seen := make(map[string]bool)
	desired := make([]string, 0, len(posted))
	wantExit := false
	for _, v := range posted {
		if v == routeExitForm {
			wantExit = true
			continue
		}
		if !advertised[v] {
			return nil, fmt.Errorf("route %s node tarafından ilan edilmiyor", v)
		}
		if !seen[v] {
			seen[v] = true
			desired = append(desired, v)
		}
	}
	// Approvals Headscale still holds for routes the node no longer advertises have no checkbox
	// (the page lists them under "Onaylı" only); the full-set replace must not revoke them silently.
	// An exit /0 is carried over only when the node does not advertise exit (otherwise the exit
	// checkbox owns both halves).
	for _, p := range node.ApprovedRoutes {
		if advertised[p] || seen[p] || (isExitPrefix(p) && exitAdvertised) {
			continue
		}
		seen[p] = true
		desired = append(desired, p)
	}
	if wantExit {
		if !exitAdvertised {
			return nil, errors.New("node exit node ilan etmiyor")
		}
		for _, e := range []string{exitNodeV4, exitNodeV6} {
			if !seen[e] {
				seen[e] = true
				desired = append(desired, e)
			}
		}
	}
	slices.Sort(desired)
	return desired, nil
}

// auditRoutesDiff is the audit summary: the approved set before/after, the advertised and active
// primary sets recorded separately (R2 B-04 audit row).
func auditRoutesDiff(node admin.AdminNode, desired []string) audit.Diff {
	return audit.Diff{
		{Field: "approved_routes", Before: routeList(node.ApprovedRoutes), After: routeList(desired)},
		{Field: "available_routes", After: routeList(node.AvailableRoutes)},
		{Field: "active_routes", After: routeList(node.SubnetRoutes)},
	}
}

// isExitPrefix says whether the CIDR is one of the exit node prefixes.
func isExitPrefix(p string) bool { return p == exitNodeV4 || p == exitNodeV6 }

// sameRoutes compares two route sets ignoring order.
func sameRoutes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// approverMatch returns the autoApprovers entries that cover an advertised route: every entry
// whose CIDR equals the route or contains it (a broader entry auto-approves the narrower route).
// An unparseable entry is skipped: this is a display hint, not a decision.
func approverMatch(aa policydoc.AutoApprovers, route string) []string {
	pr, err := netip.ParsePrefix(route)
	if err != nil {
		return nil
	}
	var out []string
	for cidr, approvers := range aa.Routes {
		pc, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if pc.Bits() <= pr.Bits() && pc.Contains(pr.Addr()) {
			out = append(out, approvers...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
