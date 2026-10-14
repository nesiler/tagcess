package web

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// fakeUsersReader returns a fixed users page snapshot.
type fakeUsersReader struct {
	view UsersView
	err  error
}

func (f *fakeUsersReader) Users(context.Context) (UsersView, error) { return f.view, f.err }

// usersHarness wires the users handler behind the production identity + CSRF chain with a fake
// reader, so the tests exercise the same trust boundary as main.go.
type usersHarness struct {
	reader *fakeUsersReader
	csrf   *CSRF
	chain  http.Handler
}

func newUsersHarness(t *testing.T, view UsersView) *usersHarness {
	t.Helper()
	h := &usersHarness{reader: &fakeUsersReader{view: view}, csrf: testCSRF(t)}
	handler, err := NewUsersHandler(UsersHandlerConfig{Reader: h.reader, DryRun: &fakeDryRunReader{}, CSRF: h.csrf})
	if err != nil {
		t.Fatalf("NewUsersHandler: %v", err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	h.chain = WithShell(nil, RequireDevops(h.csrf.Protect(mux)))
	return h
}

// do issues a request with the given groups header ("" sends none). Unsafe methods carry a valid
// CSRF token, so a refusal can only come from the handler, never from the CSRF middleware.
func (h *usersHarness) do(t *testing.T, method, target, groups string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(""))
	if groups != "" {
		req.Header.Set(headerUser, "devops-user")
		req.Header.Set(headerEmail, "devops@example.com")
		req.Header.Set(headerGroups, groups)
	}
	if !isSafeMethod(method) {
		req.Header.Set(CSRFHeader, h.csrf.Token())
	}
	rec := httptest.NewRecorder()
	h.chain.ServeHTTP(rec, req)
	return rec
}

func (h *usersHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodGet, target, "devops")
}

// AC5: the page shows the personal and tagged device counts of every user separately.
func TestUsersPage_ShowsDeviceCounts(t *testing.T) {
	h := newUsersHarness(t, UsersView{Rows: []UsersRowView{
		{
			ID: 1, Name: "alice", DisplayName: "Alice", Email: "alice@example.com",
			ProviderID: "https://auth.example.com/101", Matched: true, Verified: true,
			ZitadelID: "101", Roles: []string{"vpn-user"}, State: "active",
			PersonalDevices: 2, TaggedDevices: 1,
		},
		{
			ID: 2, Name: "bob", ProviderID: "https://auth.example.com/102",
			ZitadelID: "102", Verified: true,
			PersonalDevices: 0, TaggedDevices: 3,
		},
	}})

	rec := h.get(t, "/headscale/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"alice", "Alice", "alice@example.com",
		"eşleşti", "vpn-user", "active",
		"eşleşmedi",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	for _, re := range []string{
		`<td>2</td>\s*<td>1</td>`, // alice: personal, tagged
		`<td>0</td>\s*<td>3</td>`, // bob: personal, tagged
	} {
		if !regexp.MustCompile(re).MatchString(body) {
			t.Errorf("page does not match device counts %q", re)
		}
	}
}

// AC3 (page side): an unreadable Zitadel is a warning banner with the reason, and the role and
// state columns say they could not be verified.
func TestUsersPage_ShowsZitadelFailure(t *testing.T) {
	h := newUsersHarness(t, UsersView{
		ZitadelErr: errors.New("zitadel: list grants: unavailable"),
		Rows: []UsersRowView{
			{ID: 1, Name: "alice", ProviderID: "https://auth.example.com/101", ZitadelID: "101"},
		},
	})

	rec := h.get(t, "/headscale/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"alice", "doğrulanamadı", "zitadel: list grants: unavailable"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if strings.Contains(body, "vpn-user") {
		t.Error("page shows roles although Zitadel was unreadable")
	}
}

// AC6: the users screen is read-only: POST/PUT/DELETE get 405 (Allow: GET), unknown subpaths 404,
// and the page carries no form and no create/delete/rename action.
func TestUsersPage_NoMutations(t *testing.T) {
	h := newUsersHarness(t, UsersView{Rows: []UsersRowView{{ID: 1, Name: "alice"}}})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := h.do(t, method, "/headscale/users", "devops")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /headscale/users = %d, want 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s Allow = %q, want GET", method, allow)
		}
	}
	if rec := h.do(t, http.MethodPost, "/headscale/users/create", "devops"); rec.Code != http.StatusNotFound {
		t.Errorf("POST /headscale/users/create = %d, want 404", rec.Code)
	}

	body := h.get(t, "/headscale/users").Body.String()
	if strings.Contains(body, "<form") {
		t.Error("page contains a form; the users screen must be read-only")
	}
	for _, action := range []string{"Oluştur", "Sil", "Yeniden adlandır"} {
		if strings.Contains(body, action) {
			t.Errorf("page offers a %q action", action)
		}
	}
}

// AC7: the page is behind the devops middleware; no group or a foreign group gets 403.
func TestUsersPage_RequiresDevops(t *testing.T) {
	h := newUsersHarness(t, UsersView{})

	if rec := h.do(t, http.MethodGet, "/headscale/users", ""); rec.Code != http.StatusForbidden {
		t.Errorf("no identity = %d, want 403", rec.Code)
	}
	if rec := h.do(t, http.MethodGet, "/headscale/users", "viewer"); rec.Code != http.StatusForbidden {
		t.Errorf("non-devops group = %d, want 403", rec.Code)
	}
	if rec := h.get(t, "/headscale/users"); rec.Code != http.StatusOK {
		t.Errorf("devops = %d, want 200", rec.Code)
	}
}

// A failed snapshot read fails the page, like the sync page.
func TestUsersPage_ReaderError(t *testing.T) {
	h := newUsersHarness(t, UsersView{})
	h.reader.err = errors.New("headscale: ListUsers: down")

	if rec := h.get(t, "/headscale/users"); rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// fakeHS is a fixed Headscale read surface for the production service.
type fakeHS struct {
	users []headscale.User
	nodes []headscale.Node
	err   error
}

func (f fakeHS) ListUsers(context.Context) ([]headscale.User, error) { return f.users, f.err }
func (f fakeHS) ListNodes(context.Context) ([]headscale.Node, error) { return f.nodes, f.err }

// fakeZitadelReader is a fixed Zitadel read surface for the production service.
type fakeZitadelReader struct {
	grants []zitadel.Grant
	states map[string]zitadel.UserState
}

func (f *fakeZitadelReader) ListGrants(context.Context) ([]zitadel.Grant, error) {
	return f.grants, nil
}

func (f *fakeZitadelReader) UserStates(_ context.Context, ids []string) (map[string]zitadel.UserState, error) {
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

// The service builds the page snapshot: rows sorted by id, match data carried over from the
// resolver, and the node counts split into personal (untagged) and tagged per owner.
func TestUsersService_BuildsView(t *testing.T) {
	resolver, err := vpnuser.NewResolver(&fakeZitadelReader{
		grants: []zitadel.Grant{{UserID: "101", Role: "vpn-user"}},
		// 102 is absent: the client proves a missing user deleted, so bob stays unmatched.
		states: map[string]zitadel.UserState{"101": zitadel.UserActive},
	}, "https://auth.example.com")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	svc, err := NewUsersService(fakeHS{
		users: []headscale.User{
			{ID: 2, Name: "bob", ProviderID: "https://auth.example.com/102"},
			{ID: 1, Name: "alice", Email: "alice@example.com", ProviderID: "https://auth.example.com/101"},
		},
		nodes: []headscale.Node{
			{ID: 10, UserID: 1},                            // alice, personal
			{ID: 11, UserID: 1},                            // alice, personal
			{ID: 12, UserID: 1, Tags: []string{"tag:k8s"}}, // alice, tagged
			{ID: 13, UserID: 2, Tags: []string{"tag:k8s"}}, // bob, tagged
			{ID: 14, UserID: 2, Tags: []string{"tag:k8s"}}, // bob, tagged
			{ID: 15, UserID: 2, Tags: []string{"tag:k8s"}}, // bob, tagged
			{ID: 16}, // ownerless: no row to attach to
		},
	}, resolver)
	if err != nil {
		t.Fatalf("NewUsersService: %v", err)
	}

	view, err := svc.Users(context.Background())
	if err != nil {
		t.Fatalf("Users(): %v", err)
	}
	if view.ZitadelErr != nil {
		t.Fatalf("ZitadelErr = %v, want nil", view.ZitadelErr)
	}
	if len(view.Rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(view.Rows))
	}
	alice, bob := view.Rows[0], view.Rows[1]
	if alice.ID != 1 || bob.ID != 2 {
		t.Fatalf("rows are not sorted by id: %d, %d", alice.ID, bob.ID)
	}
	if !alice.Matched || !alice.Verified || alice.ZitadelID != "101" || alice.State != "active" {
		t.Errorf("alice row = %+v, want matched/verified/101/active", alice)
	}
	if len(alice.Roles) != 1 || alice.Roles[0] != "vpn-user" {
		t.Errorf("alice roles = %v, want [vpn-user]", alice.Roles)
	}
	if alice.Email != "alice@example.com" {
		t.Errorf("alice email = %q", alice.Email)
	}
	if alice.PersonalDevices != 2 || alice.TaggedDevices != 1 {
		t.Errorf("alice devices = %d/%d, want 2/1", alice.PersonalDevices, alice.TaggedDevices)
	}
	if !bob.Verified || bob.Matched {
		t.Errorf("bob row = %+v, want verified but unmatched (deleted in Zitadel)", bob)
	}
	if bob.PersonalDevices != 0 || bob.TaggedDevices != 3 {
		t.Errorf("bob devices = %d/%d, want 0/3", bob.PersonalDevices, bob.TaggedDevices)
	}
}

// A failed Headscale read fails the snapshot; the handler turns that into a 500.
func TestUsersService_HeadscaleReadFails(t *testing.T) {
	resolver, err := vpnuser.NewResolver(&fakeZitadelReader{}, "https://auth.example.com")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	svc, err := NewUsersService(fakeHS{err: errors.New("down")}, resolver)
	if err != nil {
		t.Fatalf("NewUsersService: %v", err)
	}
	if _, err := svc.Users(context.Background()); err == nil {
		t.Fatal("Users() = nil error, want the Headscale read failure")
	}
}

// NewUsersService and NewUsersHandler refuse an incomplete wiring.
func TestUsersWiring(t *testing.T) {
	if _, err := NewUsersService(nil, nil); err == nil {
		t.Error("NewUsersService accepted a nil Headscale reader")
	}
	if _, err := NewUsersHandler(UsersHandlerConfig{}); err == nil {
		t.Error("NewUsersHandler accepted an empty config")
	}
}

// F5 E2: an unmatched Headscale user that owns only tagged devices (router, k8s) gets an
// informational note; an unmatched user with personal devices does not (it needs attention).
func TestUsersPage_TaggedOnlyUnmatchedUserIsExplained(t *testing.T) {
	const note = "tag'li cihazların kurulum sahibi"
	h := newUsersHarness(t, UsersView{Rows: []UsersRowView{
		{ID: 1, Name: "router", Verified: true, PersonalDevices: 0, TaggedDevices: 2},
		{ID: 2, Name: "mallory", Verified: true, PersonalDevices: 1, TaggedDevices: 0},
	}})
	// The note is a tooltip now (2026-10-06); its text is escaped like any other text.
	body := html.UnescapeString(h.get(t, "/headscale/users").Body.String())
	if strings.Count(body, note) != 1 {
		t.Fatalf("note %q appears %d times, want once (router only)", note, strings.Count(body, note))
	}
	router := body[strings.Index(body, "router"):strings.Index(body, "mallory")]
	if !strings.Contains(router, note) {
		t.Error("the note is not on the tagged-only row")
	}
}
