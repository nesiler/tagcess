package web

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/vpnuser"
)

// hsUserNodes is the Headscale read surface the users page needs. *headscale.Client satisfies it;
// the narrow surface keeps the page read-only by construction (no user, node or key write exists
// on it).
type hsUserNodes interface {
	ListUsers(ctx context.Context) ([]headscale.User, error)
	ListNodes(ctx context.Context) ([]headscale.Node, error)
}

// UsersService builds the users page snapshot (H-02) from the Headscale reads and the vpnuser
// match. It writes nothing.
type UsersService struct {
	hs       hsUserNodes
	resolver *vpnuser.Resolver
}

// NewUsersService validates the wiring.
func NewUsersService(hs hsUserNodes, resolver *vpnuser.Resolver) (*UsersService, error) {
	switch {
	case hs == nil:
		return nil, errors.New("web: users page needs a Headscale reader")
	case resolver == nil:
		return nil, errors.New("web: users page needs a vpnuser resolver")
	}
	return &UsersService{hs: hs, resolver: resolver}, nil
}

// UsersRowView is one row of the users page (H-02).
type UsersRowView struct {
	ID              uint64
	Name            string
	DisplayName     string
	Email           string
	ProviderID      string
	Matched         bool
	Verified        bool
	ZitadelID       string
	Roles           []string
	State           string
	PersonalDevices int
	TaggedDevices   int
}

// UsersView is the read-only users page snapshot. ZitadelErr != nil means the role and state
// columns are unverified; the page shows the reason instead of failing (AC3). DryRun carries the
// section tab bar's note (F3-012).
type UsersView struct {
	Rows       []UsersRowView
	ZitadelErr error
	DryRun     bool
}

// Users reads the Headscale users and nodes and matches them against Zitadel. A failed Headscale
// read fails the snapshot (there is no page without the Headscale side); a failed Zitadel read is
// carried in the view, so the page still lists the users and says why roles and states are missing.
func (s *UsersService) Users(ctx context.Context) (UsersView, error) {
	users, err := s.hs.ListUsers(ctx)
	if err != nil {
		return UsersView{}, fmt.Errorf("web: list headscale users: %w", err)
	}
	nodes, err := s.hs.ListNodes(ctx)
	if err != nil {
		return UsersView{}, fmt.Errorf("web: list headscale nodes: %w", err)
	}

	// Device counts per owner, split into personal (untagged) and tagged. A tagged node is owned
	// by its tag even when a user id is set (Y-04), but it still counts for its owner's tagged
	// column; an ownerless node has no row to attach to and is skipped.
	type devices struct{ personal, tagged int }
	counts := make(map[uint64]*devices, len(users))
	for _, n := range nodes {
		if n.UserID == 0 {
			continue
		}
		d := counts[n.UserID]
		if d == nil {
			d = &devices{}
			counts[n.UserID] = d
		}
		if len(n.Tags) > 0 {
			d.tagged++
		} else {
			d.personal++
		}
	}

	snap := s.resolver.List(ctx, users)
	rows := make([]UsersRowView, 0, len(snap.Rows))
	for _, row := range snap.Rows {
		view := UsersRowView{
			ID:          row.User.ID,
			Name:        row.User.Name,
			DisplayName: row.User.DisplayName,
			Email:       row.User.Email,
			ProviderID:  row.User.ProviderID,
			Matched:     row.Matched,
			Verified:    row.Verified,
			ZitadelID:   row.ZitadelID,
			Roles:       row.Roles,
		}
		if row.Verified && row.Matched {
			view.State = row.State.String()
		}
		if d := counts[row.User.ID]; d != nil {
			view.PersonalDevices, view.TaggedDevices = d.personal, d.tagged
		}
		rows = append(rows, view)
	}
	// Rows are ordered by Headscale user id so the page is deterministic.
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return UsersView{Rows: rows, ZitadelErr: snap.ZitadelErr}, nil
}
