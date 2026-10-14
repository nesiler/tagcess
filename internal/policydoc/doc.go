// Package policydoc works on the Headscale policy document as text: it validates a draft in
// layers before it may be saved (validate.go), owns the locked mandatory policy tests
// (locked.go) and reads the tagOwners section (TagOwners). The document stays raw HuJSON; code
// here parses it for reading and changes it only by editing the syntax tree, so comments and
// formatting survive (ADR 0020).
package policydoc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// topFields are the top-level sections Headscale v0.29.4 knows (R2 B-02), in canonical spelling.
// Headscale matches names case-insensitively; a document with any other section is not saved.
var topFields = []string{
	"groups", "tagOwners", "hosts", "acls", "grants", "ssh", "autoApprovers",
	"nodeAttrs", "tests", "sshTests", "randomizeClientPort",
}

const (
	aclsKey       = "acls"
	grantsKey     = "grants"
	testsKey      = "tests"
	tagOwnersKey  = "tagOwners"
	metadataFirst = '#' // members whose name starts with '#' are metadata (Headscale strips them)
)

// parseRoot parses raw HuJSON and requires an object at the root.
func parseRoot(raw string) (*hujson.Value, *hujson.Object, error) {
	root, err := hujson.Parse([]byte(raw))
	if err != nil {
		return nil, nil, err
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return nil, nil, errors.New("the policy root must be a JSON object")
	}
	return &root, obj, nil
}

// literalString returns the unescaped text of a string literal.
func literalString(v hujson.Value) (string, bool) {
	lit, ok := v.Value.(hujson.Literal)
	if !ok || lit.Kind() != '"' {
		return "", false
	}
	return lit.String(), true
}

func isMetadata(name string) bool { return name != "" && name[0] == metadataFirst }

// memberIndexes returns the members whose name equals name, ignoring case like Headscale does.
func memberIndexes(obj *hujson.Object, name string) []int {
	var idx []int
	for i := range obj.Members {
		if n, ok := literalString(obj.Members[i].Name); ok && strings.EqualFold(n, name) {
			idx = append(idx, i)
		}
	}
	return idx
}

// TagOwners reads the tagOwners section: tag name to its owner list. A missing section gives an
// empty map; a malformed document or section gives an error. It is read-only and the one reader
// every task shares (F3-016/017/024).
func TagOwners(raw string) (map[string][]string, error) {
	_, obj, err := parseRoot(raw)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	switch idx := memberIndexes(obj, tagOwnersKey); len(idx) {
	case 0:
		return out, nil
	case 1:
		section, ok := obj.Members[idx[0]].Value.Value.(*hujson.Object)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", tagOwnersKey)
		}
		for _, m := range section.Members {
			tag, ok := literalString(m.Name)
			if !ok {
				return nil, fmt.Errorf("%s: member name is not a string", tagOwnersKey)
			}
			if isMetadata(tag) {
				continue
			}
			if _, dup := out[tag]; dup {
				return nil, fmt.Errorf("%s: duplicate tag %q", tagOwnersKey, tag)
			}
			arr, ok := m.Value.Value.(*hujson.Array)
			if !ok {
				return nil, fmt.Errorf("%s: owners of %q must be an array", tagOwnersKey, tag)
			}
			owners := make([]string, 0, len(arr.Elements))
			for _, e := range arr.Elements {
				owner, ok := literalString(e)
				if !ok {
					return nil, fmt.Errorf("%s: owner of %q is not a string", tagOwnersKey, tag)
				}
				owners = append(owners, owner)
			}
			out[tag] = owners
		}
		return out, nil
	default:
		return nil, fmt.Errorf("document has %d %s sections", len(idx), tagOwnersKey)
	}
}
