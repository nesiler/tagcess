package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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
	"github.com/nesiler/tagcess/internal/web/ui"
)

// The device tag screens (F3-016, H-01/H-05). A tagged device's tag set changes through the
// F3-009 executor (node.tags): the full new set goes to SetTags, the read-back decides. A personal
// device becomes tagged only through two steps (warning page, then the device name and a checkbox)
// because the change is irreversible and bypasses Y-04 (R2 karar 11). Options come only from the
// policy's tagOwners keys; protected server tags are never offered or assignable (R2 karar 6).

// tagPattern is the accepted shape of a tag (task F3-016).
var tagPattern = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)

// errEmptyTags is the reason shown when no tag is chosen.
const errEmptyTags = "En az bir tag seçilmeli: kişisel cihaza dönüş yok; cihazı silip OIDC ile yeniden kaydedin."

// The states of the tag page.
const (
	tagsModeError     = "error"
	tagsModeProtected = "protected"
	tagsModeEdit      = "edit"
	tagsModeWarn      = "warn"
	tagsModeConfirm   = "confirm"
	tagsModeDone      = "done"
)

// DevicePolicyReader reads the live Headscale policy (for the tagOwners keys). *headscale.Client
// satisfies it.
type DevicePolicyReader interface {
	GetPolicy(ctx context.Context) (headscale.Policy, error)
}

// DeviceTagSetter is the one write RPC the tag screens use. *admin.AdminClient satisfies it.
type DeviceTagSetter interface {
	SetTags(ctx context.Context, id uint64, tags []string) (admin.AdminNode, error)
}

// DeviceTagExecutor is the admin operation pipeline. *hsadmin.Executor satisfies it.
type DeviceTagExecutor interface {
	Do(ctx context.Context, op hsadmin.Op) (hsadmin.Result, error)
	ProtectedTags(ctx context.Context) ([]string, error)
}

// DeviceTagsConfig wires the tag screens.
type DeviceTagsConfig struct {
	Nodes    hsAdminLister
	Policy   DevicePolicyReader
	Setter   DeviceTagSetter
	Executor DeviceTagExecutor
	DryRun   change.DryRun
	CSRF     *CSRF
}

// DeviceTagsHandler serves GET and POST /headscale/devices/{id}/tags.
type DeviceTagsHandler struct {
	cfg DeviceTagsConfig
}

// NewDeviceTagsHandler validates the wiring.
func NewDeviceTagsHandler(cfg DeviceTagsConfig) (*DeviceTagsHandler, error) {
	switch {
	case cfg.Nodes == nil:
		return nil, errors.New("web: device tags needs a node reader")
	case cfg.Policy == nil:
		return nil, errors.New("web: device tags needs a policy reader")
	case cfg.Setter == nil:
		return nil, errors.New("web: device tags needs a tag setter")
	case cfg.Executor == nil:
		return nil, errors.New("web: device tags needs the admin executor")
	case cfg.DryRun == nil:
		return nil, errors.New("web: device tags needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: device tags needs a CSRF signer")
	}
	return &DeviceTagsHandler{cfg: cfg}, nil
}

// Register adds the tag page routes.
func (h *DeviceTagsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/devices/{id}/tags", h.page)
	mux.HandleFunc("POST /headscale/devices/{id}/tags", h.submit)
}

type tagOption struct {
	Name    string
	Checked bool
}

// deviceTagsView is the data of one rendering of the tag page.
type deviceTagsView struct {
	DryRun    bool
	NodeID    uint64
	Name      string
	Mode      string
	Notice    string
	Version   string
	Current   []string
	Options   []tagOption
	Selected  []string
	OwnerNow  string
	ExpiryNow string
}

func tagsPath(id uint64) string { return "/headscale/devices/" + strconv.FormatUint(id, 10) + "/tags" }

func routesPath(id uint64) string {
	return "/headscale/devices/" + strconv.FormatUint(id, 10) + "/routes"
}

// tagHiddenFields lists the selected tags as hidden form fields so the last conversion step posts
// the set the operator saw (ui.HiddenFields). Presentation only.
func tagHiddenFields(tags []string) []ui.Hidden {
	out := make([]ui.Hidden, 0, len(tags))
	for _, t := range tags {
		out = append(out, ui.Hidden{Name: "tag", Value: t})
	}
	return out
}

// tagsState is what a request reads fresh: the node, the offered tags and the protection list.
type tagsState struct {
	node      admin.AdminNode
	allowed   map[string]bool // policy tagOwners keys minus protected tags
	options   []string
	protected []string
	isServer  bool // the node carries a protected tag
}

// load reads the node, the policy and the protected list. Any failure returns an error and a
// status; nothing is offered or written then (rule 7).
func (h *DeviceTagsHandler) load(ctx context.Context, id uint64) (tagsState, int, error) {
	var st tagsState
	nodes, err := h.cfg.Nodes.ListNodes(ctx)
	if err != nil {
		return st, http.StatusServiceUnavailable, fmt.Errorf("headscale cihazları okunamadı: %w", err)
	}
	i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == id })
	if i < 0 {
		return st, http.StatusNotFound, errDeviceNotFound
	}
	st.node = nodes[i]
	st.protected, err = h.cfg.Executor.ProtectedTags(ctx)
	if err != nil {
		return st, http.StatusServiceUnavailable, fmt.Errorf("korumalı tag listesi okunamadı: %w", err)
	}
	pol, err := h.cfg.Policy.GetPolicy(ctx)
	if err != nil {
		return st, http.StatusServiceUnavailable, fmt.Errorf("headscale policy okunamadı: %w", err)
	}
	owners, err := policydoc.TagOwners(pol.Text)
	if err != nil {
		return st, http.StatusServiceUnavailable, fmt.Errorf("policy tagOwners okunamadı: %w", err)
	}
	st.allowed = map[string]bool{}
	for tag := range owners {
		if !slices.Contains(st.protected, tag) && tagPattern.MatchString(tag) {
			st.allowed[tag] = true
			st.options = append(st.options, tag)
		}
	}
	slices.Sort(st.options)
	for _, t := range st.node.Tags {
		if slices.Contains(st.protected, t) {
			st.isServer = true
		}
	}
	return st, 0, nil
}

// view builds the base view of a node: the options with the node's current tags (or the given
// selection) checked.
func (h *DeviceTagsHandler) view(r *http.Request, st tagsState, selected []string) deviceTagsView {
	dryRun, _ := h.cfg.DryRun.DryRun(r.Context())
	v := deviceTagsView{
		DryRun: dryRun, NodeID: st.node.ID, Name: st.node.GivenName,
		Version: hsadmin.NodeVersion(st.node), Current: sortedCopy(st.node.Tags), Selected: selected,
	}
	check := st.node.Tags
	if selected != nil {
		check = selected
	}
	for _, o := range st.options {
		v.Options = append(v.Options, tagOption{Name: o, Checked: slices.Contains(check, o)})
	}
	return v
}

func (h *DeviceTagsHandler) render(w http.ResponseWriter, r *http.Request, status int, v deviceTagsView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Cihaz tag'leri", DeviceTagsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderErr shows a refusal with its reason; the page offers nothing to submit.
func (h *DeviceTagsHandler) renderErr(w http.ResponseWriter, r *http.Request, status int, id uint64, msg string) {
	dryRun, _ := h.cfg.DryRun.DryRun(r.Context())
	h.render(w, r, status, deviceTagsView{DryRun: dryRun, NodeID: id, Mode: tagsModeError, Notice: msg})
}

func pathID(r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// page renders the form: the tag editor for a tagged node, the warning page (step 1) for a
// personal one, a notice for a protected server node.
func (h *DeviceTagsHandler) page(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	st, status, err := h.load(r.Context(), id)
	if errors.Is(err, errDeviceNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.renderErr(w, r, status, id, err.Error())
		return
	}
	v := h.view(r, st, nil)
	switch {
	case st.isServer:
		v.Mode = tagsModeProtected
	case len(st.node.Tags) == 0:
		v.Mode = tagsModeWarn
	default:
		v.Mode = tagsModeEdit
	}
	h.render(w, r, http.StatusOK, v)
}

// submit validates the chosen set and either shows the next conversion step or runs the change.
func (h *DeviceTagsHandler) submit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	st, status, err := h.load(r.Context(), id)
	if errors.Is(err, errDeviceNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.renderErr(w, r, status, id, err.Error())
		return
	}
	if st.isServer {
		h.renderErr(w, r, http.StatusForbidden, id, "korumalı sunucu node'unun tag'leri değiştirilemez")
		return
	}
	personal := len(st.node.Tags) == 0
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tags := normalizeTags(r.PostForm["tag"])
	mode := tagsModeEdit
	if personal {
		mode = tagsModeWarn
	}
	fail := func(status int, msg string) {
		v := h.view(r, st, tags)
		v.Mode, v.Notice = mode, msg
		h.render(w, r, status, v)
	}

	if len(tags) == 0 {
		fail(http.StatusBadRequest, errEmptyTags)
		return
	}
	for _, t := range tags {
		switch {
		case !tagPattern.MatchString(t):
			fail(http.StatusBadRequest, fmt.Sprintf("%q geçerli bir tag biçimi değil (tag:küçük-harf-rakam-tire).", t))
			return
		case slices.Contains(st.protected, t):
			fail(http.StatusForbidden, fmt.Sprintf("%s korumalı bir sunucu tag'i; arayüzden atanamaz.", t))
			return
		case !st.allowed[t]:
			fail(http.StatusBadRequest, fmt.Sprintf("%s policy tagOwners içinde tanımlı değil.", t))
			return
		}
	}
	if r.PostFormValue("version") != hsadmin.NodeVersion(st.node) {
		fail(http.StatusConflict, "Cihaz sayfa açıldıktan sonra değişti; sayfayı yenileyip yeniden deneyin.")
		return
	}

	if personal {
		if r.PostFormValue("step") != "convert" {
			v := h.view(r, st, tags)
			v.Mode = tagsModeConfirm
			h.render(w, r, http.StatusOK, v)
			return
		}
		if r.PostFormValue("confirm_name") != st.node.GivenName || r.PostFormValue("confirm") != "on" {
			v := h.view(r, st, tags)
			v.Mode = tagsModeConfirm
			v.Notice = "Cihaz adı yanlış veya onay kutusu işaretli değil; dönüştürülmedi."
			h.render(w, r, http.StatusBadRequest, v)
			return
		}
	}

	h.apply(w, r, st, actor, tags)
}

// apply runs node.tags through the executor and renders the read-back result.
func (h *DeviceTagsHandler) apply(w http.ResponseWriter, r *http.Request, st tagsState, actor string, tags []string) {
	node := st.node
	var seen *admin.AdminNode
	op := hsadmin.Op{
		Actor: actor, Kind: hsadmin.KindNodeTags, ID: node.ID,
		Target: "node:" + strconv.FormatUint(node.ID, 10), Expected: hsadmin.NodeVersion(node),
		Tags: tags,
		Diff: tagsDiff(node, tags),
		Apply: func(ctx context.Context) error {
			_, err := h.cfg.Setter.SetTags(ctx, node.ID, tags)
			return err
		},
		Verify: func(ctx context.Context, rd hsadmin.Reader) (bool, error) {
			nodes, err := rd.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			i := slices.IndexFunc(nodes, func(n admin.AdminNode) bool { return n.ID == node.ID })
			if i < 0 {
				return false, nil
			}
			seen = &nodes[i]
			return slices.Equal(sortedCopy(nodes[i].Tags), tags), nil
		},
		Observed: func() audit.Diff { return observedDiff(node, seen) },
	}
	_, err := h.cfg.Executor.Do(r.Context(), op)
	switch {
	case err == nil:
		v := h.view(r, st, nil)
		v.Mode, v.Current = tagsModeDone, sortedCopy(seen.Tags)
		v.OwnerNow = ownershipKind(*seen)
		v.ExpiryNow, _, _ = expiryText(seen.Expiry, time.Now())
		h.render(w, r, http.StatusOK, v)
	case errors.Is(err, hsadmin.ErrBlocked):
		h.renderErr(w, r, http.StatusForbidden, node.ID, err.Error())
	case errors.Is(err, hsadmin.ErrStale):
		h.renderErr(w, r, http.StatusConflict, node.ID, "Cihaz sayfa açıldıktan sonra değişti; sayfayı yenileyip yeniden deneyin.")
	default:
		h.renderErr(w, r, http.StatusBadGateway, node.ID, "Tag değişikliği doğrulanamadı veya başarısız oldu; durumu cihaz sayfasından kontrol edin (audit kaydı yazıldı): "+err.Error())
	}
}

// normalizeTags trims, de-duplicates and sorts the submitted tags.
func normalizeTags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func ownershipKind(n admin.AdminNode) string {
	if len(n.Tags) > 0 {
		return "tagged"
	}
	return "personal"
}

func joinTags(t []string) string { return strings.Join(sortedCopy(t), ",") }

// expiryAudit renders a node expiry for the audit log: RFC 3339 UTC, "none" when it never expires.
func expiryAudit(t *time.Time) string {
	if t == nil {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

// tagsDiff is the intent: ownership kind, owner id, the tag set and its added/removed parts.
func tagsDiff(node admin.AdminNode, tags []string) audit.Diff {
	d := audit.Diff{
		{Field: "ownership", Before: ownershipKind(node), After: "tagged"},
		{Field: "user_id", Before: strconv.FormatUint(node.UserID, 10)},
		{Field: "tags", Before: joinTags(node.Tags), After: strings.Join(tags, ",")},
	}
	var added, removed []string
	for _, t := range tags {
		if !slices.Contains(node.Tags, t) {
			added = append(added, t)
		}
	}
	for _, t := range sortedCopy(node.Tags) {
		if !slices.Contains(tags, t) {
			removed = append(removed, t)
		}
	}
	if len(added) > 0 {
		d = append(d, audit.Change{Field: "tags_added", After: strings.Join(added, ",")})
	}
	if len(removed) > 0 {
		d = append(d, audit.Change{Field: "tags_removed", Before: strings.Join(removed, ",")})
	}
	return d
}

// observedDiff is what the read-back showed: the ownership kind, owner id and expiry the node
// ended up with (R2 B-04: SetTags does not touch the expiry; the real value is observed here).
func observedDiff(before admin.AdminNode, after *admin.AdminNode) audit.Diff {
	if after == nil {
		return nil
	}
	return audit.Diff{
		{Field: "observed.ownership", Before: ownershipKind(before), After: ownershipKind(*after)},
		{Field: "observed.user_id", Before: strconv.FormatUint(before.UserID, 10), After: strconv.FormatUint(after.UserID, 10)},
		{Field: "observed.expiry", Before: expiryAudit(before.Expiry), After: expiryAudit(after.Expiry)},
	}
}
