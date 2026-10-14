package sync

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// g03Input is a policy still written in the pre-G-03 e-mail form, with matching Headscale users
// that carry both the e-mail and the OIDC provider identifier.
func g03Input() Input {
	in := baseInput()
	in.Read = Read{
		Complete: true,
		Grants:   []zitadel.Grant{{UserID: "1", Role: "dev"}, {UserID: "2", Role: "dev"}},
		States:   map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserActive},
	}
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com"], "group:ops": []`)
	in.Users = []headscale.User{
		{ID: 11, Name: "user1", Email: "user1@example.com", ProviderID: issuer + "/1"},
		{ID: 12, Name: "user2", Email: "user2@example.com", ProviderID: issuer + "/2"},
	}
	return in
}

// AC1: the first real sync sees e-mail members and offers the conversion as one pending change,
// listing old and new identity per person, without reading the rename as an access change.
func TestG03_PendingWithMapping(t *testing.T) {
	in := g03Input()
	p := Compute(in)

	if p.Identity == nil {
		t.Fatalf("no identity conversion detected: %+v", p)
	}
	want := []IdentityMapping{
		{Old: "user1@example.com", New: member("1"), UserID: "1"},
		{Old: "user2@example.com", New: member("2"), UserID: "2"},
	}
	if !reflect.DeepEqual(p.Identity.Mappings, want) {
		t.Fatalf("mappings = %+v, want %+v", p.Identity.Mappings, want)
	}
	if len(p.Identity.Unmatched) != 0 || len(p.Identity.Dropped) != 0 {
		t.Fatalf("unexpected unmatched/dropped: %+v", p.Identity)
	}
	if !p.NeedsApproval || p.Blocked || p.WillApply {
		t.Fatalf("conversion must be a single pending change: %+v", p)
	}
	// The rename is not an access change: no member is added or removed and no node expires.
	if len(p.GroupDiff.Groups) != 0 || len(p.GroupDiff.RemovedGroups) != 0 || len(p.ExpireNodes) != 0 {
		t.Fatalf("conversion must not change membership: %+v", p)
	}
	if !strings.Contains(p.Reason, "Kimlik dönüşümü") {
		t.Fatalf("reason must describe the conversion: %q", p.Reason)
	}
}

// AC2: an e-mail with no Zitadel user blocks approval; once the operator explicitly drops it the
// conversion may be approved and the drop reaches the change/audit reason.
func TestG03_UnmatchedBlocksUnlessDropped(t *testing.T) {
	in := g03Input()
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com", "ghost@example.com"], "group:ops": []`)

	p := Compute(in)
	if !p.Blocked || p.WillApply {
		t.Fatalf("an unmatched e-mail must block: %+v", p)
	}
	if len(p.Identity.Unmatched) != 1 || p.Identity.Unmatched[0] != "ghost@example.com" {
		t.Fatalf("unmatched = %v, want [ghost@example.com]", p.Identity.Unmatched)
	}
	if !strings.Contains(p.Reason, "ghost@example.com") {
		t.Fatalf("reason must name the unmatched e-mail: %q", p.Reason)
	}

	in.DroppedEmails = []string{"ghost@example.com"}
	p = Compute(in)
	if p.Blocked || !p.NeedsApproval || p.WillApply {
		t.Fatalf("an explicitly dropped e-mail must allow approval: %+v", p)
	}
	if len(p.Identity.Dropped) != 1 || p.Identity.Dropped[0] != "ghost@example.com" {
		t.Fatalf("dropped = %v, want [ghost@example.com]", p.Identity.Dropped)
	}

	req, err := Request(in, p, SystemActor, "manual", planSummary(p))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !req.NeedsApproval || req.Blocked {
		t.Fatalf("request = %+v, want pending approval", req)
	}
	// The drop must be visible in the reason, which the pipeline writes to the audit log.
	if !strings.Contains(req.Reason, "ghost@example.com") {
		t.Fatalf("request reason must record the drop: %q", req.Reason)
	}
	if strings.Contains(string(req.Target), "ghost@example.com") {
		t.Fatalf("a dropped e-mail must not survive in the rendered policy:\n%s", req.Target)
	}
}

// A policy already in provider-id form has nothing to convert.
func TestG03_CanonicalPolicyNoConversion(t *testing.T) {
	p := Compute(baseInput())
	if p.Identity != nil {
		t.Fatalf("canonical policy must not trigger a conversion: %+v", p.Identity)
	}
}

// A Headscale user whose provider identifier is foreign (or absent) cannot be tied to a Zitadel
// user, so its e-mail does not resolve.
func TestG03_ForeignProviderUnmatched(t *testing.T) {
	in := g03Input()
	in.Users[0].ProviderID = "https://other.example.com/1"
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a foreign provider identifier must not resolve: %+v", p)
	}
	if len(p.Identity.Unmatched) != 1 || p.Identity.Unmatched[0] != "user1@example.com" {
		t.Fatalf("unmatched = %v, want [user1@example.com]", p.Identity.Unmatched)
	}
}

// A legacy member whose Headscale user resolves to a Zitadel id without an active role is not a
// rename: the rendered target has no membership for it, so converting would remove the member. It
// must block until the operator explicitly drops it (G-03.1, rule 7).
func TestG03_NoActiveZitadelUserBlocks(t *testing.T) {
	in := g03Input()
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com", "ghost@example.com"], "group:ops": []`)
	// ghost has a Headscale user and an active Zitadel account, but no role grant.
	in.Users = append(in.Users, headscale.User{ID: 13, Name: "ghost", Email: "ghost@example.com", ProviderID: issuer + "/3"})
	in.Read.States["3"] = zitadel.UserActive
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a member without an active role must not be called a rename: %+v", p)
	}
	if len(p.Identity.Unmatched) != 1 || p.Identity.Unmatched[0] != "ghost@example.com" {
		t.Fatalf("unmatched = %v, want [ghost@example.com]", p.Identity.Unmatched)
	}
}

// A legacy member of a group the user does not hold the role for is not a rename: the converted
// policy would drop that membership. It must not be listed as a rename and the plan must block until
// the operator explicitly drops it, otherwise an access removal hides under the conversion.
func TestG03_MembershipLossBlocks(t *testing.T) {
	in := g03Input()
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com"], "group:ops": ["user1@example.com"]`)
	// user1 holds only dev; the legacy user1@example.com in group:ops has no matching role.
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a legacy member without the group's role must block: %+v", p)
	}
	if len(p.Identity.Unmatched) != 1 || p.Identity.Unmatched[0] != "user1@example.com" {
		t.Fatalf("unmatched = %v, want [user1@example.com]", p.Identity.Unmatched)
	}
	// The rename in group:dev is legitimate and listed once per person.
	if len(p.Identity.Mappings) != 2 {
		t.Fatalf("mappings = %+v, want user1 and user2", p.Identity.Mappings)
	}
}

// A conversion must be the only change in its plan: a concurrent membership diff (here a canonical
// member no longer wanted) would ride on the conversion's approval and change access, so it blocks.
func TestG03_ConcurrentGroupDiffBlocks(t *testing.T) {
	in := g03Input()
	in.Policy = policyWith(`"group:dev": ["user1@example.com", "user2@example.com", "` + member("9") + `"], "group:ops": []`)
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a concurrent group diff must block the conversion: %+v", p)
	}
	if p.Identity == nil || len(p.Identity.Mappings) != 2 {
		t.Fatalf("the conversion itself should still be detected: %+v", p.Identity)
	}
	if !strings.Contains(p.Reason, "tek başına") {
		t.Fatalf("reason must explain the conversion is held back: %q", p.Reason)
	}
}

// A conversion must not carry a node expiry: an unrelated node expiring in the same plan would be
// applied under the conversion's approval. It blocks instead.
func TestG03_ConcurrentExpiryBlocks(t *testing.T) {
	in := g03Input()
	in.Users = append(in.Users, headscale.User{ID: 13, Name: "gone", ProviderID: issuer + "/3"})
	in.Read.States["3"] = zitadel.UserActive
	in.Nodes = []headscale.Node{{ID: 200, UserID: 13}}
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a concurrent node expiry must block the conversion: %+v", p)
	}
	if len(p.ExpireNodes) != 1 {
		t.Fatalf("expire nodes = %+v, want one", p.ExpireNodes)
	}
	if !strings.Contains(p.Reason, "tek başına") {
		t.Fatalf("reason must explain the conversion is held back: %q", p.Reason)
	}
}

// The conversion must resolve only what Headscale itself would resolve: an e-mail that differs from
// the stored one only in case does not (Headscale matches exactly), so converting it would widen
// access. It must block instead.
func TestG03_CaseMismatchBlocks(t *testing.T) {
	in := g03Input()
	in.Users[0].Email = "User1@example.com"
	p := Compute(in)
	if !p.Blocked {
		t.Fatalf("a case-mismatched e-mail must not resolve: %+v", p)
	}
	if len(p.Identity.Unmatched) != 1 || p.Identity.Unmatched[0] != "user1@example.com" {
		t.Fatalf("unmatched = %v, want [user1@example.com]", p.Identity.Unmatched)
	}
}
