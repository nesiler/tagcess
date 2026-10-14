package sync

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const issuer = "https://auth.example.com"

var now = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func member(id string) string { return issuer + "/" + id + "@" }

func hsUser(hsID uint64, zid string) headscale.User {
	return headscale.User{ID: hsID, Name: "u" + zid, ProviderID: issuer + "/" + zid}
}

func node(id, userID uint64, tags ...string) headscale.Node {
	return headscale.Node{ID: id, Name: "n", UserID: userID, Tags: tags}
}

func policyWith(groups string) []byte {
	return []byte(`{
  "groups": {` + groups + `},
  "acls": [{"action": "accept", "src": ["group:dev"], "dst": ["*:*"]}],
  "tagOwners": {"tag:shared": ["group:ops"]}
}`)
}

func baseInput() Input {
	return Input{
		Read: Read{
			Complete: true,
			Grants: []zitadel.Grant{
				{UserID: "1", Role: "dev"},
				{UserID: "2", Role: "dev"},
			},
			States: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
		},
		Policy: policyWith(`"group:dev": ["` + member("1") + `", "` + member("2") + `"], "group:ops": []`),
		Roles:  []string{"dev", "ops"},
		Users:  []headscale.User{hsUser(11, "1"), hsUser(12, "2")},
		Format: render.ProviderIDFormat(issuer),
		Issuer: issuer,
		Now:    now,
	}
}

func TestPlan_IncompleteReadNoop(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Input)
	}{
		{"not complete", func(in *Input) { in.Read.Complete = false }},
		{"read error", func(in *Input) { in.Read.Err = errors.New("timeout") }},
		{"no state for a granted user", func(in *Input) { delete(in.Read.States, "2") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			// Would otherwise empty the groups and expire everything.
			in.Read.Grants = nil
			in.Nodes = []headscale.Node{node(1, 11), node(2, 12)}
			tt.mut(&in)
			if tt.name == "no state for a granted user" {
				in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"}}
			}
			p := Compute(in)
			if len(p.GroupDiff.Groups) != 0 || len(p.ExpireNodes) != 0 || p.NeedsApproval || p.WillApply {
				t.Fatalf("plan must be empty and not applied: %+v", p)
			}
			if !strings.Contains(p.Reason, "okuma hatası") {
				t.Fatalf("reason = %q, want it to mention okuma hatası", p.Reason)
			}
		})
	}
}

func TestPlan_ThresholdNeedsApproval(t *testing.T) {
	mk := func(total, removed int) Input {
		in := baseInput()
		in.Read.Grants = nil
		in.Read.States = map[string]zitadel.UserState{}
		in.Users = nil
		var members []string
		for i := 1; i <= total; i++ {
			id := fmt.Sprintf("u%d", i)
			members = append(members, `"`+member(id)+`"`)
			in.Read.States[id] = zitadel.UserActive
			in.Users = append(in.Users, hsUser(uint64(100+i), id)) // F3-031: holders need a Headscale user
			if i > removed {
				in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: id, Role: "dev"})
			}
		}
		in.Policy = policyWith(`"group:dev": [` + strings.Join(members, ",") + `], "group:ops": []`)
		return in
	}
	tests := []struct {
		name           string
		total, removed int
		want           bool
	}{
		{"none removed", 10, 0, false},
		{"exactly 3 of 20 (15%)", 20, 3, false},
		{"4 of 40 (10%) is over the count limit", 40, 4, true},
		{"exactly 30% (3 of 10)", 10, 3, false},
		{"2 of 5 is over 30% but under count", 5, 2, true},
		{"1 of 3 is over 30%", 3, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Compute(mk(tt.total, tt.removed))
			if p.NeedsApproval != tt.want {
				t.Fatalf("NeedsApproval = %v, want %v (reason %q)", p.NeedsApproval, tt.want, p.Reason)
			}
			if tt.want && (p.WillApply || p.Reason == "") {
				t.Fatalf("held plan must not apply and needs a reason: %+v", p)
			}
			if !tt.want && tt.removed > 0 && !p.WillApply {
				t.Fatalf("plan under the threshold should apply: %+v", p)
			}
		})
	}
}

func TestPlan_ExpireOnAllRolesLost(t *testing.T) {
	tests := []struct {
		name  string
		state zitadel.UserState
		roles bool
		want  bool
	}{
		{"no roles left", zitadel.UserActive, false, true},
		{"inactive", zitadel.UserInactive, true, true},
		{"locked", zitadel.UserLocked, true, true},
		{"deleted", zitadel.UserDeleted, false, true},
		{"active with role", zitadel.UserActive, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			in.Read.States["2"] = tt.state
			if !tt.roles {
				in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
			}
			in.Nodes = []headscale.Node{node(100, 11), node(200, 12), node(201, 12)}
			p := Compute(in)
			var got []uint64
			for _, e := range p.ExpireNodes {
				got = append(got, e.NodeID)
			}
			want := []uint64(nil)
			if tt.want {
				want = []uint64{200, 201}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("expire = %v, want %v", got, want)
			}
		})
	}

	t.Run("already expired nodes are skipped", func(t *testing.T) {
		in := baseInput()
		in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
		past := now.Add(-time.Hour)
		n := node(200, 12)
		n.Expiry = &past
		in.Nodes = []headscale.Node{n, node(201, 12)}
		p := Compute(in)
		if len(p.ExpireNodes) != 1 || p.ExpireNodes[0].NodeID != 201 {
			t.Fatalf("expire = %+v", p.ExpireNodes)
		}
	})

	t.Run("user without a known state is not expired", func(t *testing.T) {
		in := baseInput()
		in.Users = append(in.Users, hsUser(13, "3"))
		in.Nodes = []headscale.Node{node(300, 13)}
		p := Compute(in)
		if len(p.ExpireNodes) != 0 {
			t.Fatalf("unknown state must not expire: %+v", p.ExpireNodes)
		}
	})
}

func TestPlan_RoleChangeNoExpire(t *testing.T) {
	in := baseInput()
	// User 2 was dev and ops in policy; now only ops. User 1 unchanged.
	in.Policy = policyWith(`"group:dev": ["` + member("1") + `", "` + member("2") + `"], "group:ops": ["` + member("2") + `"]`)
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "ops"}}
	in.Nodes = []headscale.Node{node(100, 11), node(200, 12)}
	p := Compute(in)
	if len(p.ExpireNodes) != 0 {
		t.Fatalf("expire must be empty: %+v", p.ExpireNodes)
	}
	want := []GroupChange{{Group: "group:dev", Removed: []string{member("2")}}}
	if !reflect.DeepEqual(p.GroupDiff.Groups, want) {
		t.Fatalf("diff = %+v, want %+v", p.GroupDiff.Groups, want)
	}
	// User 2 loses its group:dev membership (it keeps group:ops). The threshold counts every
	// user who loses at least one membership, so 1 of 2 (50%) is over the 30% default.
	if !p.NeedsApproval || p.WillApply {
		t.Fatalf("losing 1 of 2 memberships (50%%) needs approval: %+v", p)
	}
}

func TestPlan_TaggedNodesNeverExpired(t *testing.T) {
	in := baseInput()
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	in.Read.States["2"] = zitadel.UserDeleted
	// Node 200 carries a tag and still has the creating user's UserID.
	in.Nodes = []headscale.Node{node(200, 12, "tag:shared"), node(201, 12)}
	p := Compute(in)
	if len(p.ExpireNodes) != 1 || p.ExpireNodes[0].NodeID != 201 {
		t.Fatalf("only the untagged node may be expired: %+v", p.ExpireNodes)
	}
}

func TestPlan_DryRunMarked(t *testing.T) {
	in := baseInput()
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	in.Nodes = []headscale.Node{node(200, 12)}
	in.Settings.DryRun = true
	p := Compute(in)
	if len(p.GroupDiff.Groups) == 0 || len(p.ExpireNodes) != 1 {
		t.Fatalf("dry run must still compute the plan: %+v", p)
	}
	if !p.DryRun || p.WillApply {
		t.Fatalf("dry run plan must be marked not applied: %+v", p)
	}
}

func TestPlan_DroppedReferencedGroupBlocked(t *testing.T) {
	in := baseInput()
	// group:ops is referenced by tagOwners; its role vanished from the project.
	in.Roles = []string{"dev"}
	p := Compute(in)
	if !p.Blocked || p.WillApply {
		t.Fatalf("plan must be blocked: %+v", p)
	}
	if !strings.Contains(p.Reason, "group:ops") {
		t.Fatalf("reason must name the group: %q", p.Reason)
	}
	if len(p.GroupDiff.RemovedGroups) != 1 || p.GroupDiff.RemovedGroups[0] != "group:ops" {
		t.Fatalf("removed groups = %v", p.GroupDiff.RemovedGroups)
	}
}

func TestPlan_DroppedUnreferencedGroupNeedsApproval(t *testing.T) {
	in := baseInput()
	in.Policy = policyWith(`"group:dev": ["` + member("1") + `", "` + member("2") + `"], "group:ops": [], "group:old": []`)
	p := Compute(in)
	if p.Blocked || !p.NeedsApproval || p.WillApply {
		t.Fatalf("unreferenced removal needs approval: %+v", p)
	}
	if !strings.Contains(p.Reason, "group:old") {
		t.Fatalf("reason = %q", p.Reason)
	}
}

func TestPlan_NoChange(t *testing.T) {
	p := Compute(baseInput())
	if len(p.GroupDiff.Groups) != 0 || len(p.GroupDiff.RemovedGroups) != 0 || len(p.ExpireNodes) != 0 || p.NeedsApproval || p.Blocked {
		t.Fatalf("expected an empty plan: %+v", p)
	}
}

func TestPlan_Deterministic(t *testing.T) {
	in := baseInput()
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "ops"}}
	in.Nodes = []headscale.Node{node(200, 12), node(201, 12)}
	first := Compute(in)
	for range 20 {
		if got := Compute(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("plan differs between runs:\n%+v\n%+v", first, got)
		}
	}
}

func TestPlan_DroppedGroupReferencedWithPortBlocked(t *testing.T) {
	in := baseInput()
	in.Roles = []string{"dev"}
	in.Policy = []byte(`{
  "groups": {"group:dev": ["` + member("1") + `", "` + member("2") + `"], "group:ops": []},
  "acls": [{"action": "accept", "src": ["group:dev"], "dst": ["group:ops:443"]}]
}`)
	p := Compute(in)
	if !p.Blocked || p.WillApply {
		t.Fatalf("a group used as dst with a port must block: %+v", p)
	}
}

func TestPlan_ForeignIssuerUserNotMapped(t *testing.T) {
	in := baseInput()
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	in.Read.States["2"] = zitadel.UserDeleted
	in.Users[1].ProviderID = "https://other.example.com/2"
	in.Nodes = []headscale.Node{node(200, 12)}
	p := Compute(in)
	if len(p.ExpireNodes) != 0 || len(p.Warnings) == 0 {
		t.Fatalf("foreign issuer must not map: %+v", p)
	}
}

func TestPlan_MassExpireNeedsApproval(t *testing.T) {
	in := baseInput()
	// Policy groups are empty (or not yet written), grants come back empty: everyone would be expired.
	in.Policy = policyWith(`"group:dev": [], "group:ops": []`)
	in.Read.Grants = nil
	in.Users = nil
	in.Read.States = map[string]zitadel.UserState{}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("u%d", i)
		in.Users = append(in.Users, hsUser(uint64(i), id))
		in.Read.States[id] = zitadel.UserActive
		in.Nodes = append(in.Nodes, node(uint64(100+i), uint64(i)))
	}
	p := Compute(in)
	if !p.NeedsApproval || p.WillApply {
		t.Fatalf("expiring 5/5 users must need approval: %+v", p)
	}
}

func TestPlan_ThresholdSettings(t *testing.T) {
	mk := func(total, removed int, s Settings) Input {
		in := baseInput()
		in.Read.Grants = nil
		in.Read.States = map[string]zitadel.UserState{}
		in.Users = nil
		var members []string
		for i := 1; i <= total; i++ {
			id := fmt.Sprintf("u%d", i)
			members = append(members, `"`+member(id)+`"`)
			in.Read.States[id] = zitadel.UserActive
			in.Users = append(in.Users, hsUser(uint64(100+i), id)) // F3-031: holders need a Headscale user
			if i > removed {
				in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: id, Role: "dev"})
			}
		}
		in.Policy = policyWith(`"group:dev": [` + strings.Join(members, ",") + `], "group:ops": []`)
		in.Settings = s
		return in
	}
	tests := []struct {
		name           string
		total, removed int
		set            Settings
		want           bool
	}{
		// A zero value falls back to the default threshold (30% or 3 users).
		{"zero settings below default", 10, 3, Settings{}, false},
		{"zero settings over default count", 40, 4, Settings{}, true},
		// Explicit defaults must behave exactly like zero values.
		{"explicit defaults below", 10, 3, Settings{MaxRemovedPercent: DefaultMaxRemovedPercent, MaxRemovedUsers: DefaultMaxRemovedUsers}, false},
		{"explicit defaults over count", 40, 4, Settings{MaxRemovedPercent: DefaultMaxRemovedPercent, MaxRemovedUsers: DefaultMaxRemovedUsers}, true},
		// Custom thresholds; a zero field still falls back to its default.
		{"custom user limit 1 exceeded", 10, 2, Settings{MaxRemovedUsers: 1}, true},
		{"custom user limit 5 not exceeded", 10, 4, Settings{MaxRemovedUsers: 5, MaxRemovedPercent: 90}, false},
		{"custom percent 10 exceeded", 10, 2, Settings{MaxRemovedPercent: 10, MaxRemovedUsers: 50}, true},
		{"custom percent 50 not exceeded", 10, 4, Settings{MaxRemovedPercent: 50, MaxRemovedUsers: 50}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Compute(mk(tt.total, tt.removed, tt.set))
			if p.NeedsApproval != tt.want {
				t.Fatalf("NeedsApproval = %v, want %v (settings %+v, reason %q)", p.NeedsApproval, tt.want, tt.set, p.Reason)
			}
		})
	}
}

func TestPlan_ExpireCandidateFormatErrorBlocked(t *testing.T) {
	in := baseInput()
	format := in.Format
	in.Format = func(id string) (string, error) {
		if id == "2" {
			return "", errors.New("cannot format")
		}
		return format(id)
	}
	// Empty policy groups, user 2 has no role and an untagged node: it would be expired unless the
	// formatting error fails the whole plan safe.
	in.Policy = policyWith(`"group:dev": [], "group:ops": []`)
	in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}}
	in.Nodes = []headscale.Node{node(200, 12)}
	p := Compute(in)
	if !p.Blocked || p.WillApply {
		t.Fatalf("a formatting error on an expire candidate must block: %+v", p)
	}
	if !strings.Contains(p.Reason, "2") {
		t.Fatalf("reason should name the user: %q", p.Reason)
	}
}

func TestPlan_DuplicateNamesInGroupsBlocked(t *testing.T) {
	tests := []struct {
		name   string
		groups string
	}{
		{"same member listed twice", `"group:dev": ["` + member("1") + `", "` + member("1") + `"], "group:ops": []`},
		{"same group defined twice", `"group:dev": ["` + member("1") + `"], "group:dev": ["` + member("2") + `"], "group:ops": []`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			in.Policy = policyWith(tt.groups)
			first := Compute(in)
			if !first.Blocked || first.WillApply {
				t.Fatalf("duplicate names must block the plan: %+v", first)
			}
			if !strings.Contains(first.Reason, "policy") {
				t.Fatalf("reason = %q, want it to mention the policy", first.Reason)
			}
			// Same input, same plan: no map-iteration-dependent guess about which name wins.
			if got := Compute(in); !reflect.DeepEqual(got, first) {
				t.Fatalf("plan differs between runs:\n%+v\n%+v", first, got)
			}
		})
	}
}

func TestPlan_BadPolicyRootBlocked(t *testing.T) {
	tests := []struct {
		name   string
		policy []byte
	}{
		{"null root", []byte(`null`)},
		{"array root", []byte(`[]`)},
		{"string root", []byte(`"nope"`)},
		{"duplicate groups", []byte(`{"groups": {}, "groups": {"group:stale": ["stale@example.com"]}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			in.Policy = tt.policy
			p := Compute(in)
			if !p.Blocked || p.WillApply {
				t.Fatalf("policy %s must block: %+v", tt.policy, p)
			}
			if !strings.Contains(p.Reason, "policy") {
				t.Fatalf("reason = %q, want it to mention the policy", p.Reason)
			}
		})
	}
}

// F3-016 AC9: a personal device that was turned into a tagged one (R2 karar 11) is not expired
// when its former owner loses every role; that is the Y-04 bypass the conversion page warns about.
// The control row shows the same node would have been expired while still personal.
func TestTags_ConvertedNodeNotExpiredByReconcile(t *testing.T) {
	for name, converted := range map[string]headscale.Node{
		// Headscale v0.29.4 moves a converted node to its built-in tagged-devices user (observed in
		// the F3-016 integration test); a node that kept its old owner is covered as well.
		"tagged-devices user": {ID: 300, Name: "n", UserID: 2147455555, Tags: []string{"tag:shared"}},
		"owner kept":          {ID: 300, Name: "n", UserID: 12, Tags: []string{"tag:shared"}},
	} {
		t.Run(name, func(t *testing.T) {
			in := baseInput()
			in.Read.Grants = []zitadel.Grant{{UserID: "1", Role: "dev"}} // user 2 lost every role

			in.Nodes = []headscale.Node{node(300, 12)}
			if p := Compute(in); len(p.ExpireNodes) != 1 || p.ExpireNodes[0].NodeID != 300 {
				t.Fatalf("control: the personal node must be expired: %+v", p.ExpireNodes)
			}

			in.Nodes = []headscale.Node{converted}
			if p := Compute(in); len(p.ExpireNodes) != 0 {
				t.Fatalf("converted node must not be expired: %+v", p.ExpireNodes)
			}
		})
	}
}

// Compute reads the policy but must not change the bytes it was given: the same slice is rendered into
// the target afterwards, and its comments must survive (F3-010 AC6).
func TestCompute_DoesNotMutatePolicy(t *testing.T) {
	in := baseInput()
	in.Policy = []byte("// header comment\n{\n  \"groups\": {\"group:dev\": [\"" + member("1") + "\", \"" + member("2") + "\"], \"group:ops\": []}, // trailing\n" +
		"  \"acls\": [], /* block */\n}\n")
	want := string(in.Policy)
	Compute(in)
	if got := string(in.Policy); got != want {
		t.Errorf("Compute changed the policy bytes:\n got %q\nwant %q", got, want)
	}
	target, err := Target(in)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	for _, c := range []string{"// header comment", "// trailing", "/* block */"} {
		if !strings.Contains(string(target), c) {
			t.Errorf("the rendered target lost %q:\n%s", c, target)
		}
	}
}

// F3-031 AC1: an active role holder without a Headscale user is not written into the role group
// and the plan says so (Headscale's locked tests cannot resolve such a member).
func TestCompute_SkipsHoldersWithoutHeadscaleUser(t *testing.T) {
	in := baseInput()
	in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: "3", Role: "dev"}, zitadel.Grant{UserID: "3", Role: "ops"})
	in.Read.States["3"] = zitadel.UserActive

	p := Compute(in)
	if len(p.GroupDiff.Groups) != 0 {
		t.Fatalf("holder 3 has no Headscale user and must not be added: %+v", p.GroupDiff)
	}
	var found []string
	for _, w := range p.Warnings {
		if strings.Contains(w, "3") && strings.Contains(w, "Headscale") {
			found = append(found, w)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one note for holder 3 (two roles), got warnings %q", p.Warnings)
	}
	if strings.Contains(strings.Join(p.Warnings, " "), member("3")) {
		t.Errorf("the note must not carry the policy member string: %q", p.Warnings)
	}
}

// F3-031 AC2: once the same person has a Headscale user the next reconcile adds them.
func TestCompute_AddsHolderAfterFirstLogin(t *testing.T) {
	in := baseInput()
	in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: "3", Role: "dev"})
	in.Read.States["3"] = zitadel.UserActive
	if p := Compute(in); len(p.GroupDiff.Groups) != 0 {
		t.Fatalf("before the first login: %+v", p.GroupDiff)
	}

	in.Users = append(in.Users, hsUser(13, "3"))
	p := Compute(in)
	want := []GroupChange{{Group: "group:dev", Added: []string{member("3")}}}
	if !reflect.DeepEqual(p.GroupDiff.Groups, want) {
		t.Fatalf("after the first login: %+v, want %+v", p.GroupDiff.Groups, want)
	}
	if !p.WillApply {
		t.Errorf("a single addition should apply: %+v", p)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "Headscale kullanıcısı yok") {
			t.Errorf("no skip note expected once the user exists: %q", w)
		}
	}
}

// F3-031 AC3: a member the policy lists whose Headscale user is gone is removed again, and the
// removal counts against the usual threshold and approval gate.
func TestCompute_RemovesMemberWithoutHeadscaleUser(t *testing.T) {
	t.Run("removed from the group", func(t *testing.T) {
		in := baseInput()
		in.Read.Grants = nil
		in.Read.States = map[string]zitadel.UserState{}
		in.Users = nil
		var members []string
		for i := 1; i <= 10; i++ {
			id := fmt.Sprintf("u%d", i)
			members = append(members, `"`+member(id)+`"`)
			in.Read.States[id] = zitadel.UserActive
			in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: id, Role: "dev"})
			if i != 10 {
				in.Users = append(in.Users, hsUser(uint64(100+i), id))
			}
		}
		in.Policy = policyWith(`"group:dev": [` + strings.Join(members, ",") + `], "group:ops": []`)

		p := Compute(in)
		want := []GroupChange{{Group: "group:dev", Removed: []string{member("u10")}}}
		if !reflect.DeepEqual(p.GroupDiff.Groups, want) {
			t.Fatalf("groups = %+v, want %+v", p.GroupDiff.Groups, want)
		}
		if !p.WillApply || p.NeedsApproval {
			t.Errorf("1 of 10 is under the threshold and applies: %+v", p)
		}
		if len(p.ExpireNodes) != 0 {
			t.Errorf("a missing Headscale user has no nodes to expire: %+v", p.ExpireNodes)
		}
	})
	t.Run("threshold still holds the plan", func(t *testing.T) {
		in := baseInput()
		in.Users = []headscale.User{hsUser(11, "1")} // user 2 lost its Headscale user: 1 of 2 members
		p := Compute(in)
		if !p.NeedsApproval || p.WillApply {
			t.Fatalf("removing 1 of 2 members must wait for approval: %+v", p)
		}
		want := []GroupChange{{Group: "group:dev", Removed: []string{member("2")}}}
		if !reflect.DeepEqual(p.GroupDiff.Groups, want) {
			t.Errorf("groups = %+v, want %+v", p.GroupDiff.Groups, want)
		}
	})
	t.Run("count limit", func(t *testing.T) {
		in := baseInput()
		in.Read.Grants = nil
		in.Read.States = map[string]zitadel.UserState{}
		in.Users = nil
		var members []string
		for i := 1; i <= 40; i++ {
			id := fmt.Sprintf("u%d", i)
			members = append(members, `"`+member(id)+`"`)
			in.Read.States[id] = zitadel.UserActive
			in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: id, Role: "dev"})
			if i > 4 {
				in.Users = append(in.Users, hsUser(uint64(100+i), id))
			}
		}
		in.Policy = policyWith(`"group:dev": [` + strings.Join(members, ",") + `], "group:ops": []`)
		if p := Compute(in); !p.NeedsApproval {
			t.Fatalf("4 of 40 removals are over MaxRemovedUsers and need approval: %+v", p)
		}
	})
}

// F5 E3: the skip note says what to do, not only what happened.
func TestCompute_SkipNoteSaysWhatToDo(t *testing.T) {
	in := baseInput()
	in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: "3", Role: "dev"})
	in.Read.States["3"] = zitadel.UserActive
	p := Compute(in)
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"Headscale kullanıcısı yok", "Ne yapmalı", "VPN'e (Tailscale ile) bir kez giriş yapsın"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q: %q", want, joined)
		}
	}
}
