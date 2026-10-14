package sync

import (
	"slices"
	"strings"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// IdentityMapping is one person's policy identity before and after the G-03 conversion (ADR 0002):
// the legacy member that used to be written into a group and the provider identifier that replaces
// it. UserID is the Zitadel user id both forms point at.
type IdentityMapping struct {
	Old    string // the legacy group member (an e-mail address)
	New    string // the canonical provider identifier ("<issuer>/<id>@")
	UserID string // the Zitadel user id behind both
}

// IdentityConversion is the G-03 e-mail-to-provider-id migration the first real sync detects. It is
// always offered as a single approval change and never changes who can reach what: a member that
// resolves is renamed, not removed (G-03.1).
type IdentityConversion struct {
	// Mappings are the resolvable legacy members, one per person, sorted by the old member.
	Mappings []IdentityMapping
	// Unmatched are legacy members Headscale would not resolve to exactly one mappable user. As long
	// as one of them is not explicitly dropped the conversion must not be approved (G-03.1).
	Unmatched []string
	// Dropped is the subset of Unmatched the operator explicitly marked to drop; it reaches the
	// plan reason, which is written to the audit log.
	Dropped []string
}

// resolveIdentities rewrites the policy's legacy group members into their provider identifier form
// and returns what it changed, or nil when the policy already uses provider ids. It mutates current
// in place: a member that resolves and still belongs to its own group is replaced by its canonical
// form, so the later diff does not read the rename as an access change. A member that does not
// resolve, or that resolves to a user with no active role in the group it is listed in, is left in
// place (the diff drops it) and reported as unmatched; in.DroppedEmails lists the unmatched members
// the operator explicitly allowed to drop.
func resolveIdentities(current map[string]map[string]bool, in Input) *IdentityConversion {
	issuer := strings.TrimRight(in.Issuer, "/")
	dropped := map[string]bool{}
	for _, e := range in.DroppedEmails {
		dropped[strings.ToLower(strings.TrimSpace(e))] = true
	}
	// A rename preserves access only if the person holds an active role in the very group the legacy
	// member sits in: the rendered target only contains active holders of that role, so a member whose
	// user holds some other role would be removed, not renamed. Requiring the matching role keeps a
	// "conversion" from hiding an access removal (rule 7, G-03).
	activeRoles := map[string]map[string]bool{}
	for _, g := range in.Read.Grants {
		if in.Read.States[g.UserID] != zitadel.UserActive {
			continue
		}
		if activeRoles[g.UserID] == nil {
			activeRoles[g.UserID] = map[string]bool{}
		}
		activeRoles[g.UserID][g.Role] = true
	}

	conv := &IdentityConversion{}
	mappedUser := map[string]bool{}
	unmatched := map[string]bool{}
	names := map[string]bool{}
	for n := range current {
		names[n] = true
	}
	for _, name := range sortedKeys(names) {
		role, _ := strings.CutPrefix(name, groupPrefix)
		for _, m := range sortedKeys(current[name]) {
			if !isLegacyMember(m) {
				continue
			}
			newMember, id, ok := resolveLegacyMember(m, in.Users, issuer, in.Format)
			if ok && activeRoles[id][role] {
				if !mappedUser[id] {
					conv.Mappings = append(conv.Mappings, IdentityMapping{Old: m, New: newMember, UserID: id})
					mappedUser[id] = true
				}
				delete(current[name], m)
				current[name][newMember] = true
				continue
			}
			if !unmatched[m] {
				conv.Unmatched = append(conv.Unmatched, m)
				unmatched[m] = true
				if dropped[strings.ToLower(m)] {
					conv.Dropped = append(conv.Dropped, m)
				}
			}
		}
	}
	if len(conv.Mappings) == 0 && len(conv.Unmatched) == 0 {
		return nil
	}
	slices.SortFunc(conv.Mappings, func(a, b IdentityMapping) int { return strings.Compare(a.Old, b.Old) })
	slices.Sort(conv.Unmatched)
	slices.Sort(conv.Dropped)
	return conv
}

// conversionConflicts lists the parts of a plan that a G-03 conversion must not carry: the conversion
// is a rename plus the explicitly dropped members and nothing else. Any added member, any removal not
// explained by a drop, any removed group or any node expiry would apply a real access change under
// the conversion's single approval, so it holds the plan back (rule 7, G-03).
func conversionConflicts(p Plan, conv *IdentityConversion) []string {
	dropped := map[string]bool{}
	for _, d := range conv.Dropped {
		dropped[strings.ToLower(strings.TrimSpace(d))] = true
	}
	var out []string
	for _, ch := range p.GroupDiff.Groups {
		if len(ch.Added) > 0 {
			out = append(out, ch.Group+" grubuna üye ekleniyor")
		}
		for _, m := range ch.Removed {
			if !dropped[strings.ToLower(strings.TrimSpace(m))] {
				out = append(out, ch.Group+" grubundan "+m+" çıkarılıyor")
			}
		}
	}
	for _, g := range p.GroupDiff.RemovedGroups {
		out = append(out, "grup siliniyor: "+g)
	}
	if len(p.ExpireNodes) > 0 {
		out = append(out, "node expire edilecek")
	}
	return out
}

// isLegacyMember reports whether a policy group member still uses the pre-G-03 form. The canonical
// form is a provider identifier URI ("<issuer>/<id>@", ADR 0002); anything without a URI scheme is
// legacy (today an e-mail), which resolveIdentities rewrites.
func isLegacyMember(m string) bool {
	return !strings.Contains(m, "://")
}

// resolveLegacyMember mirrors Headscale's own user resolution (hscontrol/policy/v2 types.go
// resolveUser, v0.29.4) so the conversion never grants access Headscale would not already grant:
// drop one trailing "@", then an exact provider-identifier match wins, otherwise exactly one exact
// e-mail or name match. It returns false when no user matches, when several do, or when the matched
// user cannot be written as a provider identifier (a foreign/absent provider id, or a formatting
// error). A legacy e-mail that differs from the stored e-mail only in case therefore does not
// resolve, because Headscale would not resolve it either.
func resolveLegacyMember(m string, users []headscale.User, issuer string, format render.MemberFormat) (string, string, bool) {
	key := strings.TrimSuffix(m, "@")
	var matched *headscale.User
	count := 0
	for i := range users {
		u := &users[i]
		if u.ProviderID != "" && u.ProviderID == key {
			matched, count = u, 1
			break
		}
		if u.Email == key || u.Name == key {
			matched, count = u, count+1
		}
	}
	if count != 1 || matched == nil {
		return "", "", false
	}
	id, ok := strings.CutPrefix(matched.ProviderID, issuer+"/")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", "", false
	}
	newMember, err := format(id)
	if err != nil {
		return "", "", false
	}
	return newMember, id, true
}
