package policydoc

import (
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// AutoApprovers is the parsed autoApprovers section: the routes map (CIDR to its approver list)
// and the exitNode approver list. Routes is never nil, so readers can range it unconditionally.
type AutoApprovers struct {
	Routes   map[string][]string
	ExitNode []string
}

// ReadAutoApprovers reads the autoApprovers section for display (F3-015). A missing section
// gives an empty result; a malformed document or section gives an error, and callers show a
// warning instead of guessing a match. It is read-only, like TagOwners.
func ReadAutoApprovers(raw string) (AutoApprovers, error) {
	_, obj, err := parseRoot(raw)
	if err != nil {
		return AutoApprovers{}, err
	}
	out := AutoApprovers{Routes: map[string][]string{}}
	switch idx := memberIndexes(obj, autoApproversKey); len(idx) {
	case 0:
		return out, nil
	case 1:
		section, ok := obj.Members[idx[0]].Value.Value.(*hujson.Object)
		if !ok {
			return AutoApprovers{}, fmt.Errorf("%s must be an object", autoApproversKey)
		}
		for _, m := range section.Members {
			name, ok := literalString(m.Name)
			if !ok {
				return AutoApprovers{}, fmt.Errorf("%s: member name is not a string", autoApproversKey)
			}
			switch {
			case isMetadata(name):
				continue
			case strings.EqualFold(name, routesKey):
				routes, ok := m.Value.Value.(*hujson.Object)
				if !ok {
					return AutoApprovers{}, fmt.Errorf("%s.%s must be an object", autoApproversKey, routesKey)
				}
				for _, rm := range routes.Members {
					cidr, ok := literalString(rm.Name)
					if !ok {
						return AutoApprovers{}, fmt.Errorf("%s.%s: member name is not a string", autoApproversKey, routesKey)
					}
					if isMetadata(cidr) {
						continue
					}
					if _, dup := out.Routes[cidr]; dup {
						return AutoApprovers{}, fmt.Errorf("%s.%s: duplicate route %q", autoApproversKey, routesKey, cidr)
					}
					approvers, err := stringArray(rm.Value, fmt.Sprintf("%s.%s[%s]", autoApproversKey, routesKey, cidr))
					if err != nil {
						return AutoApprovers{}, err
					}
					out.Routes[cidr] = approvers
				}
			case strings.EqualFold(name, exitNodeKey):
				approvers, err := stringArray(m.Value, autoApproversKey+"."+exitNodeKey)
				if err != nil {
					return AutoApprovers{}, err
				}
				out.ExitNode = approvers
			default:
				return AutoApprovers{}, fmt.Errorf("%s: unknown member %q", autoApproversKey, name)
			}
		}
		return out, nil
	default:
		return AutoApprovers{}, fmt.Errorf("document has %d %s sections", len(idx), autoApproversKey)
	}
}

// stringArray reads a JSON array of strings.
func stringArray(v hujson.Value, what string) ([]string, error) {
	arr, ok := v.Value.(*hujson.Array)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", what)
	}
	out := make([]string, 0, len(arr.Elements))
	for _, e := range arr.Elements {
		s, ok := literalString(e)
		if !ok {
			return nil, fmt.Errorf("%s: element is not a string", what)
		}
		out = append(out, s)
	}
	return out, nil
}
