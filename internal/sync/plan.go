// Package sync decides what a reconcile should change. Compute is a pure function of what was read
// from Zitadel and Headscale: it does no I/O and applies nothing (applying is the change pipeline's job).
package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// Default protection thresholds (Y-03.4, [Ö]).
const (
	DefaultMaxRemovedPercent = 30
	DefaultMaxRemovedUsers   = 3
)

const (
	groupPrefix     = "group:"
	policyGroupsKey = "groups"
)

// Read is what the caller got from Zitadel. Complete means every page was read and the counts matched
// (Y-04.5); Err is any read error. Anything else than Complete with a nil Err yields an empty plan.
type Read struct {
	Complete bool
	Err      error
	Grants   []zitadel.Grant
	// States holds the account state of every user that has a grant or owns a Headscale node.
	States map[string]zitadel.UserState
}

// Settings are the reconcile settings.
type Settings struct {
	DryRun bool
	// Zero values mean the defaults.
	MaxRemovedPercent int
	MaxRemovedUsers   int
}

// Input is everything Compute looks at.
type Input struct {
	Read Read
	// Policy is the current Headscale policy text.
	Policy []byte
	// Roles lists every role of the vpn project, including roles nobody holds. A role missing here
	// (and without a grant) makes its existing group count as removed.
	Roles  []string
	Users  []headscale.User
	Nodes  []headscale.Node
	Format render.MemberFormat
	// Issuer is the OIDC issuer of the Zitadel instance. Only Headscale users whose provider ID is
	// "<Issuer>/<id>" map to a Zitadel user; any other provider ID is left alone.
	Issuer   string
	Settings Settings
	// DroppedEmails lists legacy (e-mail) group members the operator explicitly chose to drop
	// during the G-03 conversion. Each is written into the plan reason, which reaches the audit log.
	DroppedEmails []string
	Now           time.Time
}

// GroupChange is the membership change of one policy group. Members are policy strings
// (provider identifier form), sorted.
type GroupChange struct {
	Group   string
	Added   []string
	Removed []string
}

// GroupDiff is the change to the policy `groups` section.
type GroupDiff struct {
	Groups []GroupChange
	// RemovedGroups are groups in the policy that no role explains; regenerating `groups` would drop them.
	RemovedGroups []string
}

// NodeExpiry is a node to expire and why.
type NodeExpiry struct {
	NodeID uint64
	Node   string
	UserID string // Zitadel user ID
	Why    string
}

// Plan is the outcome of one reconcile decision.
type Plan struct {
	GroupDiff   GroupDiff
	ExpireNodes []NodeExpiry
	// NeedsApproval: the plan is held until a devops approves it (Y-03.4, or a group removal).
	NeedsApproval bool
	// Blocked: the plan cannot be applied even with approval, because writing it would make Headscale
	// reject the whole policy (a removed group is still referenced).
	Blocked bool
	// DryRun: the plan is only reported (Y-06).
	DryRun bool
	// WillApply is true only when nothing holds the plan back.
	WillApply bool
	Reason    string
	// Warnings are non-blocking notes, e.g. users skipped because their state is unknown.
	Warnings []string
	// Identity is the G-03 e-mail to provider-id conversion, nil when the policy already uses
	// provider ids (or has no legacy members).
	Identity *IdentityConversion
}

// Compute builds the plan. It never returns an error: anything it cannot trust becomes an empty or
// blocked plan with a Reason (fail safe, never widen access, never expire on doubt).
func Compute(in Input) Plan {
	if in.Read.Err != nil {
		return Plan{Reason: "okuma hatası: " + in.Read.Err.Error()}
	}
	if !in.Read.Complete {
		return Plan{Reason: "okuma hatası: Zitadel okuması eksik"}
	}
	for _, g := range in.Read.Grants {
		if _, ok := in.Read.States[g.UserID]; !ok {
			return Plan{Reason: fmt.Sprintf("okuma hatası: %s kullanıcısının durumu okunamadı", g.UserID)}
		}
	}
	if in.Format == nil || in.Issuer == "" {
		return Plan{Blocked: true, Reason: "üye biçimi veya issuer tanımlı değil"}
	}

	current, referenced, err := parsePolicy(in.Policy)
	if err != nil {
		return Plan{Blocked: true, Reason: "policy okunamadı: " + err.Error()}
	}

	// G-03: rewrite legacy e-mail members into provider identifiers before diffing, so the identity
	// rename is not counted as an access change.
	identity := resolveIdentities(current, in)

	var p Plan
	p.DryRun = in.Settings.DryRun
	p.Identity = identity

	// Headscale users by Zitadel user ID. A role holder only enters a group once Headscale knows
	// them (R2 decision 27): Headscale's locked tests resolve every group member and reject the
	// whole policy on a member without a user. The next reconcile adds them after their first login.
	zitadelID, hasHSUser := headscaleIdentities(in)

	// Wanted membership: active users holding the role who have a Headscale user.
	wanted := map[string]map[string]bool{} // group -> members
	for _, r := range in.Roles {
		wanted[groupPrefix+r] = map[string]bool{}
	}
	hasRole := map[string]bool{}
	noHSUser := map[string]bool{}
	for _, g := range in.Read.Grants {
		hasRole[g.UserID] = true
		name := groupPrefix + g.Role
		if wanted[name] == nil {
			wanted[name] = map[string]bool{}
		}
		if in.Read.States[g.UserID] != zitadel.UserActive {
			continue
		}
		m, err := in.Format(g.UserID)
		if err != nil {
			return Plan{Blocked: true, Reason: fmt.Sprintf("kullanıcı %s biçimlenemedi: %v", g.UserID, err)}
		}
		if !hasHSUser[g.UserID] {
			noHSUser[g.UserID] = true
			continue
		}
		wanted[name][m] = true
	}
	for _, id := range sortedKeys(noHSUser) {
		p.Warnings = append(p.Warnings, fmt.Sprintf("kullanıcı %s: Headscale kullanıcısı yok, rol gruplarına yazılmadı. Ne yapmalı: kullanıcı VPN'e (Tailscale ile) bir kez giriş yapsın; giriş sonrası sync kendiliğinden çalışır ve kullanıcı eklenir, sonra Headscale > Kullanıcılar sayfasında doğrulayın", id))
	}

	// Group diff.
	names := map[string]bool{}
	for n := range current {
		names[n] = true
	}
	for n := range wanted {
		names[n] = true
	}
	sortedNames := sortedKeys(names)
	// losing holds every member that loses at least one group membership (a member of a removed
	// group, or of a group it is no longer wanted in). currentMembers is the union of every member
	// the policy currently lists.
	losing := map[string]bool{}
	currentMembers := map[string]bool{}
	var droppedRef, droppedFree []string
	var reasons []string
	for _, n := range sortedNames {
		cur, inCurrent := current[n]
		want, inWanted := wanted[n]
		if inCurrent {
			for m := range cur {
				currentMembers[m] = true
				if !want[m] {
					losing[m] = true
				}
			}
		}
		if inCurrent && !inWanted {
			p.GroupDiff.RemovedGroups = append(p.GroupDiff.RemovedGroups, n)
			if referenced[n] {
				droppedRef = append(droppedRef, n)
			} else {
				droppedFree = append(droppedFree, n)
			}
			continue
		}
		var ch GroupChange
		ch.Group = n
		for m := range want {
			if !cur[m] {
				ch.Added = append(ch.Added, m)
			}
		}
		for m := range cur {
			if !want[m] {
				ch.Removed = append(ch.Removed, m)
			}
		}
		if len(ch.Added) > 0 || len(ch.Removed) > 0 {
			slices.Sort(ch.Added)
			slices.Sort(ch.Removed)
			p.GroupDiff.Groups = append(p.GroupDiff.Groups, ch)
		}
	}

	// Node expiry (Y-04): untagged nodes of users who lost all roles or whose account is unusable.
	for _, n := range in.Nodes {
		if len(n.Tags) > 0 { // tagged nodes are owned by their tag even when UserID is set
			continue
		}
		zid, ok := zitadelID[n.UserID]
		if !ok {
			p.Warnings = append(p.Warnings, fmt.Sprintf("node %d: Headscale kullanıcısı %d Zitadel kullanıcısıyla eşleşmiyor, expire edilmedi", n.ID, n.UserID))
			continue
		}
		state, known := in.Read.States[zid]
		var why string
		switch {
		case known && (state == zitadel.UserInactive || state == zitadel.UserLocked || state == zitadel.UserDeleted):
			why = "kullanıcı " + state.String()
		case known && !hasRole[zid]:
			why = "hiç rol kalmadı"
		case !known && !hasRole[zid]:
			p.Warnings = append(p.Warnings, fmt.Sprintf("node %d: kullanıcı %s durumu bilinmiyor, expire edilmedi", n.ID, zid))
			continue
		default:
			continue
		}
		if n.Expiry != nil && !n.Expiry.After(in.Now) {
			continue
		}
		p.ExpireNodes = append(p.ExpireNodes, NodeExpiry{NodeID: n.ID, Node: n.Name, UserID: zid, Why: why})
	}
	sort.Slice(p.ExpireNodes, func(i, j int) bool { return p.ExpireNodes[i].NodeID < p.ExpireNodes[j].NodeID })

	// Protection threshold: unique users who lose at least one group membership, plus the users whose
	// devices get expired. Counting the expiring users even when the policy did not list them keeps a
	// bad "complete but empty" read from expiring everyone without approval. The denominator is the
	// union of the current members and the expire candidates, so a user is only ever counted once.
	denominator := map[string]bool{}
	for m := range currentMembers {
		denominator[m] = true
	}
	for _, e := range p.ExpireNodes {
		m, err := in.Format(e.UserID)
		if err != nil {
			// We cannot tell how many users this affects; fail safe instead of applying silently.
			return Plan{Blocked: true, Reason: fmt.Sprintf("expire edilecek kullanıcı %s biçimlenemedi: %v", e.UserID, err)}
		}
		losing[m] = true
		denominator[m] = true
	}
	left := len(losing)
	maxPct, maxUsers := in.Settings.MaxRemovedPercent, in.Settings.MaxRemovedUsers
	if maxPct == 0 {
		maxPct = DefaultMaxRemovedPercent
	}
	if maxUsers == 0 {
		maxUsers = DefaultMaxRemovedUsers
	}
	if left > maxUsers || left*100 > maxPct*len(denominator) {
		p.NeedsApproval = true
		reasons = append(reasons, fmt.Sprintf("%d/%d kullanıcı gruplardan çıkarılacak (threshold: %%%d veya %d kullanıcı); onay gerekli",
			left, len(denominator), maxPct, maxUsers))
	}
	if len(droppedFree) > 0 {
		p.NeedsApproval = true
		reasons = append(reasons, "role karşılık gelmeyen grup silinecek: "+strings.Join(droppedFree, ", ")+"; onay gerekli")
	}
	if len(droppedRef) > 0 {
		p.Blocked = true
		reasons = append(reasons, "silinecek grup policy'de hâlâ kullanılıyor (Headscale tüm policy'yi reddederdi): "+
			strings.Join(droppedRef, ", ")+"; önce kuralları düzeltin veya rolü geri ekleyin")
	}

	// G-03 gate: a conversion is always a single approval change. An unmatched member that the
	// operator has not explicitly dropped blocks approval; once every unmatched member is dropped
	// the change may be approved and the drop is named in the reason (and so in the audit log).
	if identity != nil {
		dropped := map[string]bool{}
		for _, d := range identity.Dropped {
			dropped[strings.ToLower(d)] = true
		}
		var unresolved []string
		for _, m := range identity.Unmatched {
			if !dropped[strings.ToLower(m)] {
				unresolved = append(unresolved, m)
			}
		}
		if len(unresolved) > 0 {
			p.Blocked = true
			reasons = append(reasons, "Kimlik dönüşümü: eşleşmeyen üyeler onayı engelliyor: "+
				strings.Join(unresolved, ", ")+"; eşleştirin veya açıkça düşürün")
		} else {
			p.NeedsApproval = true
			conv := fmt.Sprintf("Kimlik dönüşümü: %d kişi e-posta yerine provider id ile yazılacak (%d eşleşmeyen düşürülecek)",
				len(identity.Mappings), len(identity.Dropped))
			if len(identity.Dropped) > 0 {
				conv += ": " + strings.Join(identity.Dropped, ", ")
			}
			reasons = append(reasons, conv)
		}
		// A conversion must be the only change in its plan; anything else holds it back so no real
		// access change can ride on the rename's single approval.
		if !p.Blocked {
			if extra := conversionConflicts(p, identity); len(extra) > 0 {
				p.Blocked = true
				reasons = append(reasons, "Kimlik dönüşümü tek başına apply edilmeli: "+strings.Join(extra, ", "))
			}
		}
	}

	p.Reason = strings.Join(reasons, "; ")
	p.WillApply = !p.DryRun && !p.NeedsApproval && !p.Blocked
	return p
}

// headscaleIdentities maps the Headscale users whose provider ID is "<Issuer>/<id>" to their Zitadel
// user ID (by Headscale user ID) and lists those Zitadel IDs. It is the one place that decides which
// role holders Headscale knows: Compute and Target must agree, or the plan and the written groups drift.
func headscaleIdentities(in Input) (byHSID map[uint64]string, known map[string]bool) {
	byHSID = map[uint64]string{}
	known = map[string]bool{}
	for _, u := range in.Users {
		if id, ok := render.MatchUserID(u.ProviderID, in.Issuer); ok {
			byHSID[u.ID] = id
			known[id] = true
		}
	}
	return byHSID, known
}

// parsePolicy returns the current groups (name -> members) and the set of group names referenced
// anywhere outside the top-level "groups" section.
func parsePolicy(policy []byte) (map[string]map[string]bool, map[string]bool, error) {
	// Standardize rewrites the buffer in place (comments become blanks). The caller renders the same
	// bytes into the target afterwards, so work on a copy.
	root, err := hujson.Parse(bytes.Clone(policy))
	if err != nil {
		return nil, nil, err
	}
	root.Standardize()
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return nil, nil, fmt.Errorf("policy root is not a JSON object")
	}
	current := map[string]map[string]bool{}
	referenced := map[string]bool{}
	groupsSeen := 0
	for i := range obj.Members {
		m := obj.Members[i]
		lit, ok := m.Name.Value.(hujson.Literal)
		if !ok {
			return nil, nil, fmt.Errorf("policy has a non-string key")
		}
		key := lit.String()
		if key != policyGroupsKey {
			var v any
			if err := json.Unmarshal(m.Value.Pack(), &v); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", key, err)
			}
			collectRefs(v, referenced)
			continue
		}
		// Headscale would reject the whole policy on a duplicate key; do not guess which one wins.
		groupsSeen++
		if groupsSeen > 1 {
			return nil, nil, fmt.Errorf("policy has duplicate top-level %q sections", policyGroupsKey)
		}
		groupsObj, ok := m.Value.Value.(*hujson.Object)
		if !ok {
			return nil, nil, fmt.Errorf("groups: not a JSON object")
		}
		for i := range groupsObj.Members {
			gm := groupsObj.Members[i]
			lit, ok := gm.Name.Value.(hujson.Literal)
			if !ok {
				return nil, nil, fmt.Errorf("groups: has a non-string key")
			}
			name := lit.String()
			// A JSON decoder silently keeps only the last duplicate key (here a group name), and a
			// member listed twice collapses the same way; either would undercount removals. Fail
			// safe like a duplicate top-level section instead of guessing which name wins.
			if _, dup := current[name]; dup {
				return nil, nil, fmt.Errorf("groups: duplicate group %q", name)
			}
			var members []string
			if err := json.Unmarshal(gm.Value.Pack(), &members); err != nil {
				return nil, nil, fmt.Errorf("groups: %q: %w", name, err)
			}
			set := map[string]bool{}
			for _, mm := range members {
				if set[mm] {
					return nil, nil, fmt.Errorf("groups: %q lists %q more than once", name, mm)
				}
				set[mm] = true
			}
			current[name] = set
		}
	}
	return current, referenced, nil
}

func collectRefs(v any, out map[string]bool) {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, groupPrefix) {
			out[groupRef(t)] = true
		}
	case []any:
		for _, e := range t {
			collectRefs(e, out)
		}
	case map[string]any:
		for k, e := range t {
			if strings.HasPrefix(k, groupPrefix) {
				out[groupRef(k)] = true
			}
			collectRefs(e, out)
		}
	}
}

// groupRef strips a destination port ("group:ops:443" -> "group:ops").
func groupRef(s string) string {
	if i := strings.Index(s[len(groupPrefix):], ":"); i >= 0 {
		return s[:len(groupPrefix)+i]
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
