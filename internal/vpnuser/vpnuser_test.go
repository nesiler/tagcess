package vpnuser

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const testIssuer = "https://auth.example.com"

// fakeZitadel is a fixed Zitadel read surface. UserStates mimics the real client's proven
// behaviour: an id absent from the states map is a proven deletion.
type fakeZitadel struct {
	grants     []zitadel.Grant
	gerr       error
	states     map[string]zitadel.UserState
	serr       error
	calls      int
	stateCalls int
}

func (f *fakeZitadel) ListGrants(context.Context) ([]zitadel.Grant, error) {
	f.calls++
	return f.grants, f.gerr
}

func (f *fakeZitadel) UserStates(_ context.Context, ids []string) (map[string]zitadel.UserState, error) {
	f.stateCalls++
	if f.serr != nil {
		return nil, f.serr
	}
	out := make(map[string]zitadel.UserState, len(ids))
	for _, id := range ids {
		if st, ok := f.states[id]; ok {
			out[id] = st
			continue
		}
		out[id] = zitadel.UserDeleted
	}
	return out, nil
}

func newTestResolver(t *testing.T, z ZitadelReader) *Resolver {
	t.Helper()
	r, err := NewResolver(z, testIssuer)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// AC1: every Headscale user is matched by its provider identifier and listed with the Zitadel
// user id, its vpn project roles and its account state.
func TestVPNUsers_MatchesByProviderID(t *testing.T) {
	users := []headscale.User{
		{ID: 2, Name: "bob", Email: "bob@example.com", ProviderID: testIssuer + "/102"},
		{ID: 1, Name: "alice", DisplayName: "Alice", Email: "alice@example.com", ProviderID: testIssuer + "/101"},
	}
	z := &fakeZitadel{
		grants: []zitadel.Grant{
			{UserID: "101", Role: "vpn-user"},
			{UserID: "101", Role: "vpn-admin"},
			{UserID: "102", Role: "vpn-user"},
		},
		states: map[string]zitadel.UserState{"101": zitadel.UserActive, "102": zitadel.UserActive},
	}
	snap := newTestResolver(t, z).List(context.Background(), users)

	want := Snapshot{
		Rows: []Row{
			{User: users[1], ZitadelID: "101", Matched: true, Verified: true,
				Roles: []string{"vpn-admin", "vpn-user"}, State: zitadel.UserActive},
			{User: users[0], ZitadelID: "102", Matched: true, Verified: true,
				Roles: []string{"vpn-user"}, State: zitadel.UserActive},
		},
	}
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("List() =\n%+v\nwant\n%+v", snap, want)
	}
}

// AC2: a user without a match (no provider id, another issuer, empty id, Zitadel user gone) is
// flagged unmatched and shows no roles.
func TestVPNUsers_UnmatchedFlagged(t *testing.T) {
	users := []headscale.User{
		{ID: 3, Name: "carol"}, // no provider id
		{ID: 4, Name: "dave", ProviderID: "https://other.example.com/104"}, // different issuer
		{ID: 5, Name: "erin", ProviderID: testIssuer + "/"},                // empty id behind the prefix
		{ID: 6, Name: "eve", ProviderID: testIssuer + "/105"},              // Zitadel user deleted
	}
	// Eve still holds a stale grant; the deleted account must not surface it as a match.
	z := &fakeZitadel{
		grants: []zitadel.Grant{{UserID: "105", Role: "vpn-user"}},
		states: map[string]zitadel.UserState{},
	}
	snap := newTestResolver(t, z).List(context.Background(), users)

	if snap.ZitadelErr != nil {
		t.Fatalf("ZitadelErr = %v, want nil", snap.ZitadelErr)
	}
	if len(snap.Rows) != len(users) {
		t.Fatalf("got %d rows, want %d", len(snap.Rows), len(users))
	}
	for _, row := range snap.Rows {
		if row.Matched {
			t.Errorf("%s: Matched = true, want false", row.User.Name)
		}
		if !row.Verified {
			t.Errorf("%s: Verified = false, want true (Zitadel was readable)", row.User.Name)
		}
		if len(row.Roles) != 0 {
			t.Errorf("%s: Roles = %v, want none", row.User.Name, row.Roles)
		}
		if row.State != 0 {
			t.Errorf("%s: State = %v, want zero", row.User.Name, row.State)
		}
	}
	if got := snap.Rows[3].ZitadelID; got != "105" {
		t.Errorf("eve: ZitadelID = %q, want 105 (the deleted id stays visible)", got)
	}
}

// AC3: when Zitadel cannot be read (or the read is incomplete) the Headscale side is still
// listed, unverified with no roles, and the read error is returned for the page.
func TestVPNUsers_ZitadelUnreadable(t *testing.T) {
	users := []headscale.User{
		{ID: 1, Name: "alice", ProviderID: testIssuer + "/101"},
		{ID: 2, Name: "bob", ProviderID: testIssuer + "/102"},
	}
	cases := []struct {
		name   string
		mutate func(z *fakeZitadel)
	}{
		{"grants read fails", func(z *fakeZitadel) {
			z.grants = []zitadel.Grant{{UserID: "101", Role: "vpn-user"}}
			z.gerr = errors.New("zitadel: down")
		}},
		{"states read fails", func(z *fakeZitadel) {
			z.grants = []zitadel.Grant{{UserID: "101", Role: "vpn-user"}}
			z.serr = errors.New("zitadel: slow")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := &fakeZitadel{states: map[string]zitadel.UserState{"101": zitadel.UserActive}}
			tc.mutate(z)
			snap := newTestResolver(t, z).List(context.Background(), users)

			if snap.ZitadelErr == nil {
				t.Fatal("ZitadelErr = nil, want the read failure")
			}
			if len(snap.Rows) != len(users) {
				t.Fatalf("got %d rows, want %d (the Headscale side must still be listed)", len(snap.Rows), len(users))
			}
			for _, row := range snap.Rows {
				if row.Verified {
					t.Errorf("%s: Verified = true, want false", row.User.Name)
				}
				if row.Matched {
					t.Errorf("%s: Matched = true, want false (nothing was proven)", row.User.Name)
				}
				if len(row.Roles) != 0 {
					t.Errorf("%s: Roles = %v, want none", row.User.Name, row.Roles)
				}
				if row.State != 0 {
					t.Errorf("%s: State = %v, want zero", row.User.Name, row.State)
				}
			}
			if snap.Rows[0].User.Name != "alice" || snap.Rows[1].User.Name != "bob" {
				t.Errorf("rows lost the Headscale side: %+v", snap.Rows)
			}
		})
	}
}

// AC4: Eligible is true only for a matched, active user with at least one vpn role; every other
// case is false with a displayable reason.
func TestEligible_Table(t *testing.T) {
	cases := []struct {
		name    string
		user    headscale.User
		grants  []zitadel.Grant
		states  map[string]zitadel.UserState
		gerr    error
		serr    error
		want    bool
		wantSub string // substring of the reason; empty when want
	}{
		{
			name:   "matched active with role",
			user:   headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants: []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states: map[string]zitadel.UserState{"101": zitadel.UserActive},
			want:   true,
		},
		{
			name:    "active without roles",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "999", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserActive},
			wantSub: "rol",
		},
		{
			name:    "inactive",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserInactive},
			wantSub: "inactive",
		},
		{
			name:    "locked",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserLocked},
			wantSub: "locked",
		},
		{
			name:    "deleted",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{}, // absent: the real client proves deletion
			wantSub: "deleted",
		},
		{
			name:    "initial (not set up)",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserInitial},
			wantSub: "initial",
		},
		{
			name:    "no provider id",
			user:    headscale.User{ID: 1},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserActive},
			wantSub: "eşleşmedi",
		},
		{
			name:    "other issuer",
			user:    headscale.User{ID: 1, ProviderID: "https://other.example.com/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			states:  map[string]zitadel.UserState{"101": zitadel.UserActive},
			wantSub: "eşleşmedi",
		},
		{
			name:    "grants unreadable",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			gerr:    errors.New("zitadel: down"),
			wantSub: "okunamadı",
		},
		{
			name:    "states unreadable",
			user:    headscale.User{ID: 1, ProviderID: testIssuer + "/101"},
			grants:  []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
			serr:    errors.New("zitadel: slow"),
			wantSub: "okunamadı",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := &fakeZitadel{grants: tc.grants, gerr: tc.gerr, states: tc.states, serr: tc.serr}
			got, err := newTestResolver(t, z).Eligible(context.Background(), tc.user)
			if got != tc.want {
				t.Errorf("Eligible() = %v, want %v (err: %v)", got, tc.want, err)
			}
			if !tc.want {
				if err == nil {
					t.Fatal("error = nil, want a reason")
				}
				if !strings.Contains(err.Error(), tc.wantSub) {
					t.Errorf("reason %q does not mention %q", err, tc.wantSub)
				}
			} else if err != nil {
				t.Errorf("error = %v, want nil", err)
			}
		})
	}
}

// The eligibility check is a fresh Zitadel read on every call: a role removed after the first
// call is seen by the second, so a cached verdict can never outlive its Zitadel read.
func TestEligible_FreshRead(t *testing.T) {
	z := &fakeZitadel{
		grants: []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
		states: map[string]zitadel.UserState{"101": zitadel.UserActive},
	}
	r := newTestResolver(t, z)
	u := headscale.User{ID: 1, ProviderID: testIssuer + "/101"}

	if ok, err := r.Eligible(context.Background(), u); !ok || err != nil {
		t.Fatalf("first Eligible() = %v, %v; want true, nil", ok, err)
	}
	z.grants = nil // all roles removed between the two reads
	if ok, err := r.Eligible(context.Background(), u); ok || err == nil {
		t.Fatalf("second Eligible() = %v, %v; want false with a reason", ok, err)
	}
	if z.calls != 2 {
		t.Errorf("ListGrants calls = %d, want 2 (a fresh read per call)", z.calls)
	}
}

// F3-021 AC1: Eligibility returns the verdict together with its proof (Zitadel user id, account
// state, sorted role list) in one fresh read; an ineligible or unreadable user is an error with
// the reason and no evidence.
func TestEligibility_Evidence(t *testing.T) {
	z := &fakeZitadel{
		grants: []zitadel.Grant{{UserID: "101", Role: "vpn-user"}, {UserID: "101", Role: "vpn-admin"}},
		states: map[string]zitadel.UserState{"101": zitadel.UserActive},
	}
	r := newTestResolver(t, z)
	u := headscale.User{ID: 1, ProviderID: testIssuer + "/101"}

	e, err := r.Eligibility(context.Background(), u)
	if err != nil {
		t.Fatalf("Eligibility(): %v", err)
	}
	if e.UserID != "101" || e.State != zitadel.UserActive {
		t.Errorf("evidence = %+v, want user 101 active", e)
	}
	if !reflect.DeepEqual(e.Roles, []string{"vpn-admin", "vpn-user"}) {
		t.Errorf("roles = %v, want sorted [vpn-admin vpn-user]", e.Roles)
	}

	// Ineligible: the reason comes back, the evidence does not.
	z.grants = nil
	e, err = r.Eligibility(context.Background(), u)
	if err == nil || !strings.Contains(err.Error(), "rolü yok") {
		t.Fatalf("ineligible user: e = %+v, err = %v; want a reason", e, err)
	}
	if e.UserID != "" || len(e.Roles) != 0 {
		t.Errorf("ineligible user carries evidence: %+v", e)
	}

	// Eligible and Eligibility agree.
	ok, err := r.Eligible(context.Background(), u)
	if ok || err == nil {
		t.Errorf("Eligible() = %v, %v; want false with the same reason", ok, err)
	}
}

// NewResolver refuses an incomplete wiring.
func TestNewResolver_Wiring(t *testing.T) {
	if _, err := NewResolver(nil, testIssuer); err == nil {
		t.Error("nil reader accepted")
	}
	if _, err := NewResolver(&fakeZitadel{}, " "); err == nil {
		t.Error("empty issuer accepted")
	}
	if _, err := NewResolver(&fakeZitadel{}, testIssuer); err != nil {
		t.Errorf("valid wiring refused: %v", err)
	}
}
