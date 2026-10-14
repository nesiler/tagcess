// Package render produces tagcess's generated artifacts deterministically.
// It only ever touches the sections tagcess owns and leaves the rest of the
// source byte-for-byte unchanged.
package render

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/tailscale/hujson"
)

const groupsKey = "groups"

// Indentation used for the regenerated groups value. The rest of the policy is
// never reformatted, so the groups section is emitted in a canonical 2-space
// style (the style Headscale writes today).
const (
	topMemberIndent = "\n  "
	groupsClose     = "\n  "
	groupNameIndent = "\n    "
	memberIndent    = "\n      "
	arrayClose      = "\n    "
)

// roleNameRE is the role allow-list from security.md §5.
var roleNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// MemberFormat converts a user's matching key (the Zitadel user ID) into the
// string written into a policy group. See ProviderIDFormat for the canonical
// (ADR 0002) implementation.
type MemberFormat func(userID string) (string, error)

// ProviderIDFormat returns a MemberFormat that writes users as the OIDC
// provider identifier with a trailing "@", i.e. "<issuer>/<userID>@" (ADR 0002).
func ProviderIDFormat(issuer string) MemberFormat {
	return func(userID string) (string, error) {
		return FormatProviderIdentifier(issuer, userID)
	}
}

// FormatProviderIdentifier returns the policy representation of a user: the
// provider identifier with a trailing "@" (ADR 0002). The issuer must be an
// http(s) URI and the Zitadel user ID a single path segment; the result then
// contains exactly one "@" (at the end), so it cannot be mistaken for an
// e-mail or username when Headscale resolves it.
func FormatProviderIdentifier(issuer, userID string) (string, error) {
	issuer = strings.TrimRight(issuer, "/")
	if issuer == "" {
		return "", fmt.Errorf("issuer is empty")
	}
	if strings.ContainsAny(issuer, " \t\r\n\"@\\") {
		return "", fmt.Errorf("issuer %q contains an unsafe character", issuer)
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("issuer %q: %w", issuer, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not an http(s) URI", issuer)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("issuer %q must not have a query, fragment or user part", issuer)
	}
	if userID == "" {
		return "", fmt.Errorf("user id is empty")
	}
	if userID == "." || userID == ".." {
		return "", fmt.Errorf("user id %q is not allowed", userID)
	}
	if strings.ContainsAny(userID, "@ \t\r\n\"/?#") || strings.IndexFunc(userID, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("user id %q contains an unsafe character", userID)
	}
	return issuer + "/" + userID + "@", nil
}

// MatchUserID extracts the Zitadel user ID carried by a Headscale user's provider identifier,
// "<issuer>/<id>" (ADR 0002; the read direction of the identifier format FormatProviderIdentifier
// writes into policies). ok is false when the identifier does not start with the issuer, is empty
// behind the issuer prefix, or continues with another path segment; such a user never matches.
func MatchUserID(providerID, issuer string) (string, bool) {
	id, ok := strings.CutPrefix(providerID, issuer+"/")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// RenderGroups returns policy with its top-level "groups" section regenerated
// from roles. A group is written for every role as "group:<role>"; its members
// are the formatted matching keys, sorted and deduplicated. A role with no
// members keeps an empty list (never removed, so ACL references stay valid).
// The section is fully replaced, so a group without a matching role is removed;
// deciding whether that removal is allowed (Y-03.4) belongs to the caller.
// Every other section and comment is left byte-for-byte unchanged.
func RenderGroups(policy []byte, roles map[string][]string, format MemberFormat) ([]byte, error) {
	if format == nil {
		return nil, fmt.Errorf("member format is nil")
	}

	roleNames := make([]string, 0, len(roles))
	for name := range roles {
		if !roleNameRE.MatchString(name) {
			return nil, fmt.Errorf("invalid role name %q", name)
		}
		roleNames = append(roleNames, name)
	}
	slices.Sort(roleNames)

	groups := make([]group, 0, len(roleNames))
	for _, name := range roleNames {
		members := make([]string, 0, len(roles[name]))
		for _, id := range roles[name] {
			m, err := format(id)
			if err != nil {
				return nil, fmt.Errorf("role %q member %q: %w", name, id, err)
			}
			if m == "" {
				return nil, fmt.Errorf("role %q member %q formatted to an empty string", name, id)
			}
			members = append(members, m)
		}
		slices.Sort(members)
		groups = append(groups, group{name: name, members: slices.Compact(members)})
	}

	root, err := hujson.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return nil, fmt.Errorf("policy root is not a JSON object")
	}

	value := buildGroups(groups)
	switch matches := memberIndexes(obj, groupsKey); len(matches) {
	case 0:
		obj.Members = append(obj.Members, hujson.ObjectMember{
			Name:  hujson.Value{BeforeExtra: hujson.Extra(topMemberIndent), Value: hujson.String(groupsKey)},
			Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: value},
		})
		if obj.AfterExtra == nil {
			obj.AfterExtra = hujson.Extra("\n")
		}
	case 1:
		obj.Members[matches[0]].Value.Value = value
	default:
		// Duplicate top-level keys are invalid JSON; Headscale would reject the
		// whole policy. Do not guess which one wins.
		return nil, fmt.Errorf("policy has %d top-level %q sections", len(matches), groupsKey)
	}
	return root.Pack(), nil
}

type group struct {
	name    string
	members []string
}

func buildGroups(groups []group) *hujson.Object {
	obj := &hujson.Object{}
	if len(groups) == 0 {
		return obj
	}
	obj.AfterExtra = hujson.Extra(groupsClose)
	for _, g := range groups {
		arr := &hujson.Array{}
		for _, m := range g.members {
			arr.Elements = append(arr.Elements, hujson.Value{
				BeforeExtra: hujson.Extra(memberIndent),
				Value:       hujson.String(m),
			})
		}
		if len(g.members) > 0 {
			arr.AfterExtra = hujson.Extra(arrayClose)
		}
		obj.Members = append(obj.Members, hujson.ObjectMember{
			Name: hujson.Value{
				BeforeExtra: hujson.Extra(groupNameIndent),
				Value:       hujson.String("group:" + g.name),
			},
			Value: hujson.Value{
				BeforeExtra: hujson.Extra(" "),
				Value:       arr,
			},
		})
	}
	return obj
}

func memberIndexes(obj *hujson.Object, name string) []int {
	var matches []int
	for i := range obj.Members {
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == name {
			matches = append(matches, i)
		}
	}
	return matches
}
