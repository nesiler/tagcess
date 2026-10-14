package policydoc

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// Targeted edits for the form view (ADR 0020). A Doc holds the HuJSON syntax tree; every
// operation changes only its own entry, so comments, order, grants, ssh, tests, nodeAttrs, hosts,
// groups and unknown fields stay as they are. There is deliberately no operation on "groups":
// the role groups belong to the Zitadel sync (F3-010). Saving and validating the result is the
// writer's job (F3-010/006); here the result is just new text.
//
// Input is checked against allow-lists (security.md §5): bad values are rejected, never fixed,
// and a failed operation leaves the Doc unchanged.

var (
	// ErrInvalidInput: a value is outside the allow-list.
	ErrInvalidInput = errors.New("invalid input")
	// ErrStaleRule: the rule at the index is not the rule the form was showing.
	ErrStaleRule = errors.New("the rule changed since it was read")
	// ErrNotFound: no such rule index, tag or route.
	ErrNotFound = errors.New("not found")
)

const (
	autoApproversKey = "autoApprovers"
	routesKey        = "routes"
	exitNodeKey      = "exitNode"
	actionAccept     = "accept"
)

// Rule is one ACL rule as the form edits it. An empty Action means "accept"; an empty Proto
// means the field is left out.
type Rule struct {
	Action string
	Proto  string
	Src    []string
	Dst    []string
}

// Doc is a policy document open for targeted edits.
type Doc struct {
	root hujson.Value
}

// Parse opens raw HuJSON. The root must be an object.
func Parse(raw string) (*Doc, error) {
	root, _, err := parseRoot(raw)
	if err != nil {
		return nil, err
	}
	return &Doc{root: *root}, nil
}

// Text returns the document; before any edit it is byte for byte the text given to Parse.
func (d *Doc) Text() string { return string(d.root.Pack()) }

// edit runs fn on a copy and keeps the copy only when fn succeeds. The copy is made by parsing
// the text again: hujson's Clone turns an empty non-nil Extra (the trailing comma marker) into
// nil and would drop trailing commas.
func (d *Doc) edit(fn func(obj *hujson.Object) error) error {
	c, err := hujson.Parse(d.root.Pack())
	if err != nil {
		return err
	}
	if err := fn(c.Value.(*hujson.Object)); err != nil {
		return err
	}
	d.root = c
	return nil
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, a...))
}

// ---- reading ----

// ACLRules returns the acls entries in order. A rule with a field the form does not know is an
// error: the form never rewrites what it cannot show (the raw editor handles those).
func (d *Doc) ACLRules() ([]Rule, error) {
	obj := d.root.Value.(*hujson.Object)
	idx, err := uniqueMember(obj, aclsKey)
	if err != nil || idx < 0 {
		return nil, err
	}
	arr, ok := obj.Members[idx].Value.Value.(*hujson.Array)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", aclsKey)
	}
	rules := make([]Rule, len(arr.Elements))
	for i, el := range arr.Elements {
		if rules[i], err = readRule(el); err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", aclsKey, i, err)
		}
	}
	return rules, nil
}

func readRule(el hujson.Value) (Rule, error) {
	o, ok := el.Value.(*hujson.Object)
	if !ok {
		return Rule{}, errors.New("not an object")
	}
	var r Rule
	seen := map[string]bool{}
	for _, m := range o.Members {
		name, ok := literalString(m.Name)
		if !ok {
			return Rule{}, errors.New("member name is not a string")
		}
		if isMetadata(name) {
			continue
		}
		if seen[name] {
			return Rule{}, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		switch name {
		case "action", "proto":
			s, ok := literalString(m.Value)
			if !ok {
				return Rule{}, fmt.Errorf("%s is not a string", name)
			}
			if name == "action" {
				r.Action = s
			} else {
				r.Proto = s
			}
		case "src", "dst":
			list, err := stringList(m.Value)
			if err != nil {
				return Rule{}, fmt.Errorf("%s: %w", name, err)
			}
			if name == "src" {
				r.Src = list
			} else {
				r.Dst = list
			}
		default:
			return Rule{}, fmt.Errorf("unsupported field %q", name)
		}
	}
	return r, nil
}

func stringList(v hujson.Value) ([]string, error) {
	arr, ok := v.Value.(*hujson.Array)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]string, 0, len(arr.Elements))
	for _, e := range arr.Elements {
		s, ok := literalString(e)
		if !ok {
			return nil, errors.New("an element is not a string")
		}
		out = append(out, s)
	}
	return out, nil
}

// sameRule compares rules after defaulting the action; nil and empty lists are equal.
func sameRule(a, b Rule) bool {
	norm := func(r Rule) Rule {
		if r.Action == "" {
			r.Action = actionAccept
		}
		return r
	}
	a, b = norm(a), norm(b)
	return a.Action == b.Action && a.Proto == b.Proto && slices.Equal(a.Src, b.Src) && slices.Equal(a.Dst, b.Dst)
}

// ---- ACL rules ----

// AddACLRule appends a rule to acls (creating the section when absent).
func (d *Doc) AddACLRule(r Rule) error {
	if err := validateRule(&r); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		arr, err := ensureArray(obj, aclsKey, 1)
		if err != nil {
			return err
		}
		v, err := ruleValue(r)
		if err != nil {
			return err
		}
		appendElement(arr, v, 2)
		return nil
	})
}

// UpdateACLRule replaces the rule at index with r, keeping the comments around it. expected is
// the rule the form was showing: when the live rule differs, nothing changes (ErrStaleRule).
func (d *Doc) UpdateACLRule(index int, expected, r Rule) error {
	if err := validateRule(&r); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		arr, err := aclTarget(obj, index, expected)
		if err != nil {
			return err
		}
		old := arr.Elements[index]
		live, _ := readRule(old)
		if sameRule(live, r) {
			return nil
		}
		v, err := ruleValue(r)
		if err != nil {
			return err
		}
		// Metadata members ("#...") of the old rule survive the rewrite.
		o := v.Value.(*hujson.Object)
		for _, m := range old.Value.(*hujson.Object).Members {
			if n, _ := literalString(m.Name); isMetadata(n) {
				m = cloneMember(m)
				m.Name.BeforeExtra, m.Value.BeforeExtra, m.Value.AfterExtra = hujson.Extra(" "), hujson.Extra(" "), nil
				o.Members = append(o.Members, m)
			}
		}
		v.BeforeExtra, v.AfterExtra = old.BeforeExtra, old.AfterExtra
		arr.Elements[index] = v
		return nil
	})
}

// DeleteACLRule removes the rule at index together with the comment lines right above it and
// the note on its own line. expected works as in UpdateACLRule.
func (d *Doc) DeleteACLRule(index int, expected Rule) error {
	return d.edit(func(obj *hujson.Object) error {
		arr, err := aclTarget(obj, index, expected)
		if err != nil {
			return err
		}
		removeSlot(arraySeq(arr), index)
		arr.Elements = slices.Delete(arr.Elements, index, index+1)
		return nil
	})
}

func aclTarget(obj *hujson.Object, index int, expected Rule) (*hujson.Array, error) {
	idx, err := uniqueMember(obj, aclsKey)
	if err != nil {
		return nil, err
	}
	var arr *hujson.Array
	if idx >= 0 {
		var ok bool
		if arr, ok = obj.Members[idx].Value.Value.(*hujson.Array); !ok {
			return nil, fmt.Errorf("%s must be an array", aclsKey)
		}
	}
	if arr == nil || index < 0 || index >= len(arr.Elements) {
		return nil, fmt.Errorf("%w: acls rule %d", ErrNotFound, index)
	}
	live, err := readRule(arr.Elements[index])
	if err != nil {
		return nil, fmt.Errorf("%s[%d]: %w", aclsKey, index, err)
	}
	if !sameRule(live, expected) {
		return nil, ErrStaleRule
	}
	return arr, nil
}

func ruleValue(r Rule) (hujson.Value, error) {
	var b strings.Builder
	b.WriteString(`{ "action": "accept"`)
	if r.Proto != "" {
		b.WriteString(`, "proto": ` + quote(r.Proto))
	}
	b.WriteString(`, "src": ` + quoteList(r.Src) + `, "dst": ` + quoteList(r.Dst) + ` }`)
	return hujson.Parse([]byte(b.String()))
}

func quote(s string) string { return string(hujson.String(s)) }

func quoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = quote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func cloneMember(m hujson.ObjectMember) hujson.ObjectMember {
	return hujson.ObjectMember{Name: m.Name.Clone(), Value: m.Value.Clone()}
}

// ---- tagOwners ----

// SetTagOwners sets the owners of tag, creating the tag (and the tagOwners section) when absent.
// Setting the value that is already there changes nothing.
func (d *Doc) SetTagOwners(tag string, owners []string) error {
	if err := validateTag(tag); err != nil {
		return err
	}
	if err := validateOwners(owners); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		sec, err := ensureObject(obj, tagOwnersKey, 1)
		if err != nil {
			return err
		}
		return setStringList(sec, tag, owners, 2)
	})
}

// DeleteTag removes the tag and the comment lines right above it. An emptied tagOwners section
// stays.
func (d *Doc) DeleteTag(tag string) error {
	if err := validateTag(tag); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		sec, err := findObject(obj, tagOwnersKey)
		if err != nil {
			return err
		}
		return deleteMember(sec, tag)
	})
}

// ---- autoApprovers ----

// SetRouteApprovers sets who may auto-approve the subnet route cidr (autoApprovers.routes),
// creating the route, "routes" and "autoApprovers" as needed.
func (d *Doc) SetRouteApprovers(cidr string, approvers []string) error {
	if err := validateCIDR(cidr); err != nil {
		return err
	}
	if err := validateOwners(approvers); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		aa, err := ensureObject(obj, autoApproversKey, 1)
		if err != nil {
			return err
		}
		routes, err := ensureObject(aa, routesKey, 2)
		if err != nil {
			return err
		}
		return setStringList(routes, cidr, approvers, 3)
	})
}

// DeleteRoute removes one route from autoApprovers.routes; emptied sections stay.
func (d *Doc) DeleteRoute(cidr string) error {
	if err := validateCIDR(cidr); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		aa, err := findObject(obj, autoApproversKey)
		if err != nil {
			return err
		}
		routes, err := findObject(aa, routesKey)
		if err != nil {
			return err
		}
		return deleteMember(routes, cidr)
	})
}

// SetExitNodeApprovers sets autoApprovers.exitNode.
func (d *Doc) SetExitNodeApprovers(approvers []string) error {
	if err := validateOwners(approvers); err != nil {
		return err
	}
	return d.edit(func(obj *hujson.Object) error {
		aa, err := ensureObject(obj, autoApproversKey, 1)
		if err != nil {
			return err
		}
		return setStringList(aa, exitNodeKey, approvers, 2)
	})
}

// ---- tree helpers ----

// uniqueMember returns the index of the member called name (any case), -1 when absent.
func uniqueMember(obj *hujson.Object, name string) (int, error) {
	switch idx := memberIndexes(obj, name); len(idx) {
	case 0:
		return -1, nil
	case 1:
		return idx[0], nil
	default:
		return -1, fmt.Errorf("document has %d %s sections", len(idx), name)
	}
}

// findObject returns the object member called name, or ErrNotFound when it is absent.
func findObject(obj *hujson.Object, name string) (*hujson.Object, error) {
	idx, err := uniqueMember(obj, name)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	o, ok := obj.Members[idx].Value.Value.(*hujson.Object)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return o, nil
}

// ensureObject returns the object member called name, appending an empty one at the given depth
// (1 = top level) when absent.
func ensureObject(obj *hujson.Object, name string, depth int) (*hujson.Object, error) {
	idx, err := uniqueMember(obj, name)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		o := &hujson.Object{}
		appendMember(obj, name, o, depth)
		return o, nil
	}
	o, ok := obj.Members[idx].Value.Value.(*hujson.Object)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return o, nil
}

func ensureArray(obj *hujson.Object, name string, depth int) (*hujson.Array, error) {
	idx, err := uniqueMember(obj, name)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		a := &hujson.Array{}
		appendMember(obj, name, a, depth)
		return a, nil
	}
	a, ok := obj.Members[idx].Value.Value.(*hujson.Array)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", name)
	}
	return a, nil
}

// setStringList sets obj[key] to a one-line string array, appending the member at depth when it
// is absent. An equal existing list is left alone, whatever its formatting.
func setStringList(obj *hujson.Object, key string, list []string, depth int) error {
	var matches []int
	for i := range obj.Members {
		if n, ok := literalString(obj.Members[i].Name); ok && n == key {
			matches = append(matches, i)
		}
	}
	if len(matches) > 1 {
		return fmt.Errorf("duplicate entry %q", key)
	}
	v, err := hujson.Parse([]byte(quoteList(list)))
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		appendMember(obj, key, v.Value, depth)
		return nil
	}
	m := &obj.Members[matches[0]]
	cur, err := stringList(m.Value)
	if err != nil {
		return fmt.Errorf("%q: %w", key, err)
	}
	if slices.Equal(cur, list) {
		return nil
	}
	m.Value.Value = v.Value // the space after the colon and the trailing comma/comment stay
	return nil
}

func deleteMember(obj *hujson.Object, key string) error {
	for i := range obj.Members {
		if n, ok := literalString(obj.Members[i].Name); ok && n == key {
			removeSlot(objectSeq(obj), i)
			obj.Members = slices.Delete(obj.Members, i, i+1)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, key)
}

// ---- layout: gaps between items ----
//
// In the syntax tree the text between one item's comma and the next item (a note on the previous
// item's line, comment lines, indentation) is the next item's BeforeExtra; the text before the
// closing bracket is the container's AfterExtra. seq exposes those gaps for arrays and objects.

type seq struct {
	gaps  []*hujson.Extra // gaps[i]: text before item i
	close *hujson.Extra   // text before the closing bracket
	tail  []*hujson.Extra // tail[i]: AfterExtra of item i's value; non-nil on the last = trailing comma
}

func arraySeq(a *hujson.Array) seq {
	s := seq{close: &a.AfterExtra}
	for i := range a.Elements {
		s.gaps = append(s.gaps, &a.Elements[i].BeforeExtra)
		s.tail = append(s.tail, &a.Elements[i].AfterExtra)
	}
	return s
}

func objectSeq(o *hujson.Object) seq {
	s := seq{close: &o.AfterExtra}
	for i := range o.Members {
		s.gaps = append(s.gaps, &o.Members[i].Name.BeforeExtra)
		s.tail = append(s.tail, &o.Members[i].Value.AfterExtra)
	}
	return s
}

func indentOf(depth int) string { return strings.Repeat("  ", depth) }

// splitLine splits at the first newline: the rest of the previous item's line, and what follows.
func splitLine(g string) (head, rest string) {
	if i := strings.IndexByte(g, '\n'); i >= 0 {
		return g[:i], g[i:]
	}
	return g, ""
}

// appendSlot prepares the gaps for a new last item at depth and returns its BeforeExtra and
// whether the list uses a trailing comma. The note on the old last item's line stays there.
func appendSlot(s seq, depth int) (gap hujson.Extra, trailing bool) {
	indent := "\n" + indentOf(depth)
	if n := len(s.gaps); n > 0 {
		g := string(*s.gaps[n-1])
		if i := strings.LastIndexByte(g, '\n'); i >= 0 && strings.TrimLeft(g[i+1:], " \t") == "" {
			indent = g[i:]
		}
		trailing = *s.tail[n-1] != nil
	}
	head, rest := splitLine(string(*s.close))
	if rest == "" {
		rest = "\n" + indentOf(depth-1)
	}
	*s.close = hujson.Extra(rest)
	return hujson.Extra(head + indent), trailing
}

func appendElement(a *hujson.Array, v hujson.Value, depth int) {
	gap, trailing := appendSlot(arraySeq(a), depth)
	v.BeforeExtra = gap
	if trailing {
		v.AfterExtra = hujson.Extra{}
	}
	a.Elements = append(a.Elements, v)
}

func appendMember(o *hujson.Object, name string, v hujson.ValueTrimmed, depth int) {
	gap, trailing := appendSlot(objectSeq(o), depth)
	m := hujson.ObjectMember{
		Name:  hujson.Value{BeforeExtra: gap, Value: hujson.String(name)},
		Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: v},
	}
	if trailing {
		m.Value.AfterExtra = hujson.Extra{}
	}
	o.Members = append(o.Members, m)
}

func isCommentLine(l string) bool {
	t := strings.TrimSpace(l)
	if strings.HasPrefix(t, "//") {
		return true
	}
	return len(t) >= 4 && strings.HasPrefix(t, "/*") && strings.HasSuffix(t, "*/") && !strings.Contains(t[2:len(t)-2], "*/")
}

// removeSlot fixes the gaps for the removal of item i; the caller removes the item itself. What
// goes with it: the comment lines directly above it (no blank line between) and the note after
// it on its own line. Everything else stays, including a note on the previous item's line.
func removeSlot(s seq, i int) {
	lines := strings.Split(string(*s.gaps[i]), "\n")
	keep := lines[:1] // the rest of the previous item's line (or of the opening bracket's)
	if last := len(lines) - 1; last > 0 && strings.TrimSpace(lines[last]) == "" {
		j := last
		for j-1 >= 1 && isCommentLine(lines[j-1]) {
			j--
		}
		keep = lines[:j]
	}
	prefix := strings.Join(keep, "\n")

	next := s.close
	if i+1 < len(s.gaps) {
		next = s.gaps[i+1]
	}
	// The first line of the next gap is D's own trailing note: it goes with D.
	_, rest := splitLine(string(*next))
	if rest == "" && strings.TrimSpace(string(*next)) != "" {
		rest = string(*next) // a comment with no newline: keep it
	}
	if strings.TrimSpace(prefix) == "" {
		prefix = ""
	}
	*next = hujson.Extra(prefix + rest)

	if i == len(s.gaps)-1 && i > 0 { // the previous item becomes the last one
		hadTrailing := *s.tail[i] != nil
		switch prev := s.tail[i-1]; {
		case hadTrailing && *prev == nil:
			*prev = hujson.Extra{}
		case !hadTrailing:
			*prev = nil
		}
	}
}

// ---- validation (allow-lists) ----

var (
	tagRE       = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)
	groupRE     = regexp.MustCompile(`^group:[a-z0-9_-]{1,32}$`)
	aliasCharRE = regexp.MustCompile(`^[A-Za-z0-9@:._/*-]{1,256}$`)
	dstCharRE   = regexp.MustCompile(`^[A-Za-z0-9@:._/*,-]{1,300}$`)
	portRE      = regexp.MustCompile(`^[0-9]{1,5}$`)

	autogroups = []string{"member", "tagged", "internet", "self"}
	protocols  = []string{"tcp", "udp", "icmp", "sctp", "igmp", "ipv4", "ip-in-ip", "egp", "igp", "gre", "esp", "ah"}
)

func validateRule(r *Rule) error {
	switch r.Action {
	case "":
		r.Action = actionAccept
	case actionAccept:
	default:
		return invalid("action %q (only %q is allowed)", r.Action, actionAccept)
	}
	if r.Proto != "" && !slices.Contains(protocols, r.Proto) {
		return invalid("proto %q", r.Proto)
	}
	if len(r.Src) == 0 || len(r.Dst) == 0 {
		return invalid("a rule needs at least one src and one dst")
	}
	for _, a := range r.Src {
		if err := validateAlias(a, true); err != nil {
			return invalid("src %q", a)
		}
	}
	for _, a := range r.Dst {
		if err := validateDst(a); err != nil {
			return invalid("dst %q: %v", a, err)
		}
	}
	return nil
}

// validateAlias accepts "*" (when allowStar), group:, tag:, an allowed autogroup:, an IP or CIDR
// and a user identifier (anything with an "@" and no "*").
func validateAlias(a string, wide bool) error {
	if !aliasCharRE.MatchString(a) {
		return errors.New("bad characters or length")
	}
	switch {
	case a == "*":
		if !wide {
			return errors.New("* is not allowed here")
		}
		return nil
	case strings.HasPrefix(a, "group:"):
		if !groupRE.MatchString(a) {
			return errors.New("bad group name")
		}
		return nil
	case strings.HasPrefix(a, "tag:"):
		if !tagRE.MatchString(a) {
			return errors.New("bad tag name")
		}
		return nil
	case strings.HasPrefix(a, "autogroup:"):
		if !wide || !slices.Contains(autogroups, strings.TrimPrefix(a, "autogroup:")) {
			return errors.New("autogroup not allowed")
		}
		return nil
	}
	if wide {
		if _, err := netip.ParseAddr(a); err == nil {
			return nil
		}
		if _, err := netip.ParsePrefix(a); err == nil {
			return nil
		}
	}
	if strings.Contains(a, "@") && !strings.Contains(a, "*") {
		return nil
	}
	return errors.New("not an allowed alias")
}

func validateDst(s string) error {
	if !dstCharRE.MatchString(s) {
		return errors.New("bad characters or length")
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return errors.New("alias:ports expected")
	}
	if err := validateAlias(s[:i], true); err != nil {
		return err
	}
	return validatePorts(s[i+1:])
}

// validatePorts accepts "*" or a comma list of ports and ranges, each within 1-65535.
func validatePorts(p string) error {
	if p == "*" {
		return nil
	}
	for _, part := range strings.Split(p, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		if !portRE.MatchString(lo) || (isRange && !portRE.MatchString(hi)) {
			return fmt.Errorf("bad ports %q", p)
		}
		a, _ := strconv.Atoi(lo)
		b := a
		if isRange {
			b, _ = strconv.Atoi(hi)
		}
		if a < 1 || b > 65535 || a > b {
			return fmt.Errorf("bad ports %q", p)
		}
	}
	return nil
}

func validateTag(tag string) error {
	if !tagRE.MatchString(tag) {
		return invalid("tag name %q", tag)
	}
	return nil
}

func validateOwners(owners []string) error {
	seen := map[string]bool{}
	for _, o := range owners {
		if err := validateAlias(o, false); err != nil {
			return invalid("owner %q", o)
		}
		if seen[o] {
			return invalid("owner %q appears twice", o)
		}
		seen[o] = true
	}
	return nil
}

// validateCIDR wants the canonical form of a prefix: masked, no zone, not IPv4-mapped.
func validateCIDR(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.String() != s {
		return invalid("route %q is not a canonical CIDR", s)
	}
	return nil
}
