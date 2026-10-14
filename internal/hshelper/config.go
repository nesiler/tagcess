// Package hshelper is the logic of the Headscale host helper (ADR 0008, ADR 0021). This file reads
// the live Headscale config.yaml into the secret-free projection hostpatch.BaseRev hashes, and
// builds the candidate config that differs from it only in oidc.allowed_groups. It does no file
// I/O: the caller reads and writes the bytes, so ownership, mode and atomic replacement stay in
// the apply flow (F3b-008).
//
// The config is edited through the yaml.Node tree, so every other value, secret reference and
// comment is carried over untouched. Anything this file cannot map onto the projection with
// certainty (bad YAML, several documents, anchors or merge keys around oidc, duplicate keys,
// values outside the supported group set) is config_unreadable and no candidate is produced.
// Errors are static reasons: they never echo config content.
package hshelper

import (
	"bytes"
	"errors"
	"io"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

// ErrConfigUnreadable is matched (errors.Is) by every ConfigError.
var ErrConfigUnreadable = errors.New(string(hostpatch.CodeConfigUnreadable))

// ConfigError is a config_unreadable failure with a static reason.
type ConfigError struct{ reason string }

func (e *ConfigError) Error() string { return string(hostpatch.CodeConfigUnreadable) + ": " + e.reason }

// Is makes errors.Is(err, ErrConfigUnreadable) true.
func (e *ConfigError) Is(target error) bool { return target == ErrConfigUnreadable }

// Code is the result.json error code for this failure.
func (e *ConfigError) Code() hostpatch.ErrorCode { return hostpatch.CodeConfigUnreadable }

func unreadable(reason string) error { return &ConfigError{reason: reason} }

const (
	keyOIDC          = "oidc"
	keyAllowedGroups = "allowed_groups"
)

// Project returns the current oidc.allowed_groups (canonical order, never nil; a missing or null
// field is empty) and the matching base_rev.
func Project(src []byte) (groups []string, baseRev string, err error) {
	doc, err := parse(src)
	if err != nil {
		return nil, "", err
	}
	oidc, err := oidcNode(doc)
	if err != nil {
		return nil, "", err
	}
	return projectOIDC(oidc)
}

// Candidate returns src with oidc.allowed_groups set to groups (written as a block list in
// canonical order) and nothing else changed. groups is validated by hostpatch.ValidateGroups; a
// failure there wraps hostpatch.ErrInvalidRequest, not ErrConfigUnreadable.
func Candidate(src []byte, groups []string) ([]byte, error) {
	doc, err := parse(src)
	if err != nil {
		return nil, err
	}
	if err := hostpatch.ValidateGroups(groups); err != nil {
		return nil, err
	}
	oidc, err := oidcNode(doc)
	if err != nil {
		return nil, err
	}
	// The current value must be understood before it is replaced.
	if _, _, err := projectOIDC(oidc); err != nil {
		return nil, err
	}
	want := canonical(groups)
	setAllowedGroups(oidc, want)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, unreadable("cannot encode the candidate")
	}
	if err := enc.Close(); err != nil {
		return nil, unreadable("cannot encode the candidate")
	}

	// Self-check: the bytes we hand out project to exactly what was asked.
	got, _, err := Project(buf.Bytes())
	if err != nil || !slices.Equal(got, want) {
		return nil, unreadable("candidate does not project to the requested groups")
	}
	return buf.Bytes(), nil
}

// parse decodes exactly one YAML document whose root is a mapping, and rejects duplicate keys and
// merge keys anywhere in it.
func parse(src []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, unreadable("empty config")
		}
		return nil, unreadable("not valid YAML")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, unreadable("more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, unreadable("top level is not a mapping")
	}
	if err := checkKeys(doc.Content[0]); err != nil {
		return nil, err
	}
	return &doc, nil
}

// checkKeys rejects duplicate mapping keys and merge keys at any depth. Headscale itself would
// resolve both in a way this file does not model, so it does not guess.
func checkKeys(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return unreadable("non-scalar mapping key")
			}
			if k.Tag == "!!merge" {
				return unreadable("merge key")
			}
			if seen[k.Value] {
				return unreadable("duplicate key")
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkKeys(c); err != nil {
			return err
		}
	}
	return nil
}

// oidcNode returns the oidc mapping. It must exist, be a mapping, and contain no anchor or alias.
func oidcNode(doc *yaml.Node) (*yaml.Node, error) {
	oidc := mapValue(doc.Content[0], keyOIDC)
	if oidc == nil {
		return nil, unreadable("no oidc block")
	}
	if oidc.Kind != yaml.MappingNode {
		return nil, unreadable("oidc is not a mapping")
	}
	if hasAnchorOrAlias(oidc) {
		return nil, unreadable("anchor or alias in oidc")
	}
	return oidc, nil
}

func hasAnchorOrAlias(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return true
	}
	for _, c := range n.Content {
		if hasAnchorOrAlias(c) {
			return true
		}
	}
	return false
}

// mapValue returns the value node for key in a mapping, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func projectOIDC(oidc *yaml.Node) ([]string, string, error) {
	groups := []string{}
	if n := mapValue(oidc, keyAllowedGroups); n != nil && !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, "", unreadable("allowed_groups is not a list")
		}
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode || item.ShortTag() != "!!str" {
				return nil, "", unreadable("allowed_groups has a non-string item")
			}
			groups = append(groups, item.Value)
		}
	}
	rev, err := hostpatch.BaseRev(groups)
	if err != nil {
		return nil, "", unreadable("allowed_groups outside the supported set")
	}
	return canonical(groups), rev, nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" }

// canonical returns groups in hostpatch's canonical order. Callers pass validated values.
func canonical(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper, hostpatch.GroupStandart} {
		if slices.Contains(groups, g) {
			out = append(out, g)
		}
	}
	return out
}

// setAllowedGroups replaces (or adds) the allowed_groups list as a block sequence. Items that
// stay keep their node, and with it their comments; the key and the old value's head and foot
// comments stay too. A line comment on the old value (`allowed_groups: [..] # why`) would be
// emitted after the last item of the new block list, so it moves onto the key line.
func setAllowedGroups(oidc *yaml.Node, groups []string) {
	idx := -1
	for i := 0; i+1 < len(oidc.Content); i += 2 {
		if oidc.Content[i].Value == keyAllowedGroups {
			idx = i
		}
	}
	keep := map[string]*yaml.Node{}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if idx >= 0 {
		key, old := oidc.Content[idx], oidc.Content[idx+1]
		if old.Kind == yaml.SequenceNode {
			for _, item := range old.Content {
				keep[item.Value] = item
			}
		}
		seq.HeadComment, seq.FootComment = old.HeadComment, old.FootComment
		if key.LineComment == "" {
			key.LineComment = old.LineComment
		}
	}
	for _, g := range groups {
		item, ok := keep[g]
		if !ok {
			item = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: g}
		}
		seq.Content = append(seq.Content, item)
	}
	if idx < 0 {
		oidc.Content = append(oidc.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: keyAllowedGroups}, seq)
		return
	}
	oidc.Content[idx+1] = seq
}
