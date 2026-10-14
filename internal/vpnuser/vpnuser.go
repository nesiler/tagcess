// Package vpnuser matches Headscale users with Zitadel users (H-02, ADR 0002) and decides
// personal-access eligibility (H-03, R2 T-02): a fresh Zitadel read, an active account and at
// least one role in the vpn project. The package is read-only: it never writes anywhere (rule 3).
package vpnuser

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// ZitadelReader is the read-only Zitadel surface the resolver needs. It is satisfied by
// *zitadel.Client, whose lists are proven complete or fail (rule 7).
type ZitadelReader interface {
	ListGrants(ctx context.Context) ([]zitadel.Grant, error)
	UserStates(ctx context.Context, ids []string) (map[string]zitadel.UserState, error)
}

// Row is one Headscale user with its Zitadel match (H-02). Matched is only ever true when a
// complete Zitadel read proved it: the provider identifier carries the issuer, and the Zitadel
// user exists and is not deleted. An unverified row (Zitadel unreadable) keeps the provider id's
// user id in ZitadelID so the page can still show the correspondence.
type Row struct {
	User      headscale.User
	ZitadelID string
	Matched   bool
	Verified  bool // the Zitadel side was read completely
	Roles     []string
	State     zitadel.UserState // meaningful only when Matched && Verified
}

// Snapshot is the outcome of one List: the rows plus the Zitadel read error, if any. With an
// error the rows still carry the Headscale side, unverified, so the page can show it (AC3).
type Snapshot struct {
	Rows       []Row
	ZitadelErr error
}

// Resolver answers "who is this Headscale user in Zitadel" (List) and "may this user get
// personal access" (Eligible).
type Resolver struct {
	z      ZitadelReader
	issuer string
}

// NewResolver validates the wiring.
func NewResolver(z ZitadelReader, issuer string) (*Resolver, error) {
	switch {
	case z == nil:
		return nil, errors.New("vpnuser: a Zitadel reader is required")
	case strings.TrimSpace(issuer) == "":
		return nil, errors.New("vpnuser: an issuer is required")
	}
	return &Resolver{z: z, issuer: issuer}, nil
}

// List matches every given Headscale user against the vpn project's grants and user states
// (H-02). Zitadel is read once per call; a failed or incomplete read marks every row unverified
// instead of failing the list, so the page keeps showing the Headscale side and the reason (AC3).
func (r *Resolver) List(ctx context.Context, users []headscale.User) Snapshot {
	snap := Snapshot{Rows: make([]Row, 0, len(users))}

	grants, gerr := r.z.ListGrants(ctx)
	roles := map[string][]string{}
	ids := map[string]bool{}
	for _, g := range grants {
		roles[g.UserID] = append(roles[g.UserID], g.Role)
		ids[g.UserID] = true
	}
	for _, u := range users {
		if id, ok := render.MatchUserID(u.ProviderID, r.issuer); ok {
			ids[id] = true
		}
	}
	// The real client sorts its grants, but the row must not depend on that.
	sortRoles(roles)
	var states map[string]zitadel.UserState
	var serr error
	if gerr == nil {
		states, serr = r.z.UserStates(ctx, sortedIDs(ids))
		if serr != nil {
			serr = fmt.Errorf("kullanıcı durumları: %w", serr)
		}
	}
	snap.ZitadelErr = errors.Join(gerr, serr)

	for _, u := range users {
		row := Row{User: u}
		row.ZitadelID, _ = render.MatchUserID(u.ProviderID, r.issuer)
		if snap.ZitadelErr != nil {
			// Nothing about the Zitadel side is proven; the row stays unmatched and unverified.
			snap.Rows = append(snap.Rows, row)
			continue
		}
		row.Verified = true
		if st, ok := states[row.ZitadelID]; row.ZitadelID != "" && ok && st != zitadel.UserDeleted {
			row.Matched = true
			row.Roles = roles[row.ZitadelID]
			row.State = st
		}
		snap.Rows = append(snap.Rows, row)
	}
	sort.Slice(snap.Rows, func(i, j int) bool { return snap.Rows[i].User.ID < snap.Rows[j].User.ID })
	return snap
}

// Eligibility is the outcome of one fresh eligibility read: the verdict's proof — the Zitadel
// user id, the account state and the sorted vpn roles (no secrets) — ready for the audit log
// (F3-021 AC1).
type Eligibility struct {
	UserID string
	State  zitadel.UserState
	Roles  []string
}

// Eligibility answers "may this user get personal access" and returns the evidence in the same
// fresh read (personal pre-auth key, personal device reopen; H-03, R2 T-02): the provider
// identifier resolves to an existing Zitadel user whose account is active and who holds at least
// one role in the vpn project (the same "lost all roles" definition as Y-04). Zitadel is re-read
// on every call. A user that cannot be proven eligible gets the zero value and the error is the
// reason to show (fail closed, rule 7).
func (r *Resolver) Eligibility(ctx context.Context, u headscale.User) (Eligibility, error) {
	id, ok := render.MatchUserID(u.ProviderID, r.issuer)
	if !ok {
		return Eligibility{}, fmt.Errorf("eşleşmedi: provider identifier %q %q issuer biçiminde değil", u.ProviderID, r.issuer)
	}
	grants, err := r.z.ListGrants(ctx)
	if err != nil {
		return Eligibility{}, fmt.Errorf("zitadel okunamadı: %w", err)
	}
	states, err := r.z.UserStates(ctx, []string{id})
	if err != nil {
		return Eligibility{}, fmt.Errorf("zitadel okunamadı: %w", err)
	}
	st, known := states[id]
	if !known {
		// The real client proves every id it is asked for; this branch stays fail closed.
		return Eligibility{}, fmt.Errorf("zitadel kullanıcısı %s okunamadı", id)
	}
	var roles []string
	for _, g := range grants {
		if g.UserID == id {
			roles = append(roles, g.Role)
		}
	}
	if st != zitadel.UserActive {
		return Eligibility{}, fmt.Errorf("zitadel kullanıcısı %s aktif değil (durum: %s)", id, st.String())
	}
	if len(roles) == 0 {
		return Eligibility{}, fmt.Errorf("zitadel kullanıcısı %s vpn projesinde rolü yok", id)
	}
	sort.Strings(roles)
	return Eligibility{UserID: id, State: st, Roles: roles}, nil
}

// Eligible reports whether the user may receive personal access; the reason is the error text.
func (r *Resolver) Eligible(ctx context.Context, u headscale.User) (bool, error) {
	_, err := r.Eligibility(ctx, u)
	return err == nil, err
}

// sortedIDs returns the set's members sorted, so the state read is deterministic.
func sortedIDs(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// roles are appended in grant order; sort each user's roles so rows are deterministic.
func sortRoles(roles map[string][]string) {
	for id := range roles {
		slices.Sort(roles[id])
	}
}
