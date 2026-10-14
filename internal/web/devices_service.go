package web

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
)

// The devices service (F3-012, H-01 read side) builds the list and detail snapshots from the
// admin client's node list. It writes nothing: the write paths arrive with F3-014/015/016 and go
// through the F3-009 executor, never through this page.

// hsAdminLister is the Headscale read surface the devices screens need. *admin.AdminClient
// satisfies it; the pages stay read-only by construction because no other method is reachable
// here.
type hsAdminLister interface {
	ListNodes(ctx context.Context) ([]admin.AdminNode, error)
}

// deviceTimeLayout is the display format of every instant on the Headscale screens.
const deviceTimeLayout = "2006-01-02 15:04"

// errDeviceNotFound says the id has no node in Headscale; the detail page answers 404.
var errDeviceNotFound = errors.New("web: device not found")

// DeviceRowView is one row of the device list: name, owner (personal) or tag'li with the tags,
// addresses, online state, last seen and expiry. The display texts are ready to render; ExpiryRaw
// is the expiry as RFC3339 ("" when unset) for the action forms' before-values.
type DeviceRowView struct {
	ID        uint64
	Name      string
	Owner     string
	Tagged    bool
	Tags      []string
	IPs       []string
	Online    bool
	LastSeen  string
	Expiry    string
	ExpiryRaw string
	Expired   bool
}

// DevicesView is the /headscale/devices snapshot. Err != nil means Headscale could not be read:
// the page shows the reason and no rows (fail safe, AC5). DryRun carries the section note.
type DevicesView struct {
	Rows   []DeviceRowView
	DryRun bool
	Err    error
}

// DeviceDetailView is the /headscale/devices/{id} snapshot: the list fields plus the three route
// sets and the registration time. Version is the node's state stamp (hsadmin.NodeVersion) the
// action forms carry back so a changed node is refused as stale (F3-014); it is empty while the
// page carries Err.
type DeviceDetailView struct {
	Row             DeviceRowView
	CreatedAt       string
	AvailableRoutes []string
	ApprovedRoutes  []string
	ActiveRoutes    []string
	Version         string
	// Actions is the write panel (F3-014); nil keeps the page read-only.
	Actions *DeviceActionsPanel
	DryRun  bool
	Err     error
}

// DevicesService builds the devices screens from the admin read. Use NewDevicesService.
type DevicesService struct {
	hs hsAdminLister
}

// NewDevicesService validates the wiring.
func NewDevicesService(hs hsAdminLister) (*DevicesService, error) {
	if hs == nil {
		return nil, errors.New("web: devices page needs a Headscale admin reader")
	}
	return &DevicesService{hs: hs}, nil
}

// Devices reads every node and maps it to a list row. Rows are ordered by node id so the page is
// deterministic.
func (s *DevicesService) Devices(ctx context.Context) (DevicesView, error) {
	nodes, err := s.hs.ListNodes(ctx)
	if err != nil {
		return DevicesView{}, fmt.Errorf("web: list headscale nodes: %w", err)
	}
	now := time.Now()
	rows := make([]DeviceRowView, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, deviceRowView(n, now))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return DevicesView{Rows: rows}, nil
}

// Device reads one node for the detail page. An unknown id is errDeviceNotFound.
func (s *DevicesService) Device(ctx context.Context, id uint64) (DeviceDetailView, error) {
	nodes, err := s.hs.ListNodes(ctx)
	if err != nil {
		return DeviceDetailView{}, fmt.Errorf("web: list headscale nodes: %w", err)
	}
	for _, n := range nodes {
		if n.ID == id {
			return deviceDetailView(n, time.Now()), nil
		}
	}
	return DeviceDetailView{}, errDeviceNotFound
}

// deviceRowView maps a node to its list row. A tagged node is owned by its tag even when a user
// id is set (stack-notes, Y-04): the owner column says "tag'li" and the tags render as badges.
func deviceRowView(n admin.AdminNode, now time.Time) DeviceRowView {
	row := DeviceRowView{
		ID: n.ID, Name: n.GivenName,
		Tagged: len(n.Tags) > 0, Tags: n.Tags, IPs: n.IPs, Online: n.Online,
		LastSeen: lastSeenText(n.LastSeen),
	}
	if row.Tagged {
		row.Owner = "tag'li"
	} else {
		row.Owner = n.UserName
	}
	row.Expiry, row.ExpiryRaw, row.Expired = expiryText(n.Expiry, now)
	return row
}

func deviceDetailView(n admin.AdminNode, now time.Time) DeviceDetailView {
	return DeviceDetailView{
		Row:             deviceRowView(n, now),
		CreatedAt:       formatDeviceTime(n.CreatedAt),
		AvailableRoutes: n.AvailableRoutes,
		ApprovedRoutes:  n.ApprovedRoutes,
		ActiveRoutes:    n.SubnetRoutes,
		Version:         hsadmin.NodeVersion(n),
	}
}

// formatDeviceTime renders an instant in the screens' fixed layout.
func formatDeviceTime(t time.Time) string { return t.Format(deviceTimeLayout) }

// expiryText maps the node expiry to its display text and raw value: "yok"/"" (never expires),
// "geçmiş"/RFC3339 (already cut off) or the moment/"…"/RFC3339. The bool says whether the node is
// expired.
func expiryText(expiry *time.Time, now time.Time) (string, string, bool) {
	switch {
	case expiry == nil:
		return "yok", "", false
	case expiry.Before(now):
		return "geçmiş", expiry.UTC().Format(time.RFC3339), true
	default:
		return formatDeviceTime(*expiry), expiry.UTC().Format(time.RFC3339), false
	}
}

// lastSeenText renders the last seen instant; a node never seen shows "—".
func lastSeenText(lastSeen *time.Time) string {
	if lastSeen == nil {
		return "—"
	}
	return formatDeviceTime(*lastSeen)
}

// routeList renders a route list or a dash when nothing is set.
func routeList(routes []string) string {
	if len(routes) == 0 {
		return "—"
	}
	return strings.Join(routes, ", ")
}
