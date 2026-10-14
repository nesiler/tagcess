package policydoc

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/headscale"
)

// Locked tests are policy `tests` entries tagcess owns (R2 decision 5): devops reach the tagcess
// UI, the k8s host reaches the webhook port, devops reach SSH. Headscale runs the tests inside
// CheckPolicy, so an edit that breaks one of these rules is rejected there. Each entry carries a
// /* tagcess:locked */ comment before its first member. Comments are HuJSON syntax, so Headscale
// never sees the marker (F5 L1: an extra "#tagcess" member is "unknown field" in 0.29.3).
// Entries written with the old "#tagcess": "locked" member are still recognised and rewritten.
const (
	lockedComment = "/* tagcess:locked */"

	legacyMarkerKey   = "#tagcess"
	legacyMarkerValue = "locked"

	// Rule names, used in change reports and LockedTestError.
	RuleUI      = "ui"
	RuleWebhook = "webhook"
	RuleSSH     = "ssh"

	entryIndent = "\n    "
)

// LockedConfig parameterises the locked tests. DefaultLockedConfig holds the defaults; F3-020
// lets the settings screen change them (the JSON tags are the stored form, see locked_setting.go).
type LockedConfig struct {
	DevopsGroup string   `json:"devops_group"` // source of the UI rule, "group:devops"
	ServerTag   string   `json:"server_tag"`   // the tag the UI and webhook live on, "tag:vpn-server"
	UIPort      int      `json:"ui_port"`      // tagcess UI port, 443
	K8sTag      string   `json:"k8s_tag"`      // webhook caller, "tag:k8s"
	WebhookPort int      `json:"webhook_port"` // hook.listen port on ServerTag
	SSHSrc      string   `json:"ssh_src"`      // SSH source, "group:devops"
	SSHDst      []string `json:"ssh_dst"`      // SSH destinations, "tag:vpn-server", "tag:k8s"
	SSHPort     int      `json:"ssh_port"`     // 22
}

// DefaultLockedConfig returns the production defaults; the webhook port comes from hook.listen.
func DefaultLockedConfig(webhookPort int) LockedConfig {
	return LockedConfig{
		DevopsGroup: "group:devops",
		ServerTag:   "tag:vpn-server",
		UIPort:      443,
		K8sTag:      "tag:k8s",
		WebhookPort: webhookPort,
		SSHSrc:      "group:devops",
		SSHDst:      []string{"tag:vpn-server", "tag:k8s"},
		SSHPort:     22,
	}
}

type lockedRule struct {
	Name   string
	Src    string
	Accept []string
}

func (r lockedRule) entry() string {
	acc := make([]string, len(r.Accept))
	for i, a := range r.Accept {
		acc[i] = string(hujson.String(a))
	}
	return fmt.Sprintf(`{ %s "src": %s, "accept": [%s] }`,
		lockedComment, string(hujson.String(r.Src)), strings.Join(acc, ", "))
}

func validAlias(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\\'
	})
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// rules returns the canonical locked entries in a fixed order, or an error for a bad config.
func (c LockedConfig) rules() ([]lockedRule, error) {
	for name, v := range map[string]string{
		"DevopsGroup": c.DevopsGroup, "ServerTag": c.ServerTag, "K8sTag": c.K8sTag, "SSHSrc": c.SSHSrc,
	} {
		if !validAlias(v) {
			return nil, fmt.Errorf("locked tests: %s %q is empty or has an unsafe character", name, v)
		}
	}
	for name, p := range map[string]int{"UIPort": c.UIPort, "WebhookPort": c.WebhookPort, "SSHPort": c.SSHPort} {
		if !validPort(p) {
			return nil, fmt.Errorf("locked tests: %s %d is not a port", name, p)
		}
	}
	if len(c.SSHDst) == 0 {
		return nil, errors.New("locked tests: SSHDst is empty")
	}
	ssh := lockedRule{Name: RuleSSH, Src: c.SSHSrc}
	for _, d := range c.SSHDst {
		if !validAlias(d) {
			return nil, fmt.Errorf("locked tests: SSHDst %q is empty or has an unsafe character", d)
		}
		ssh.Accept = append(ssh.Accept, fmt.Sprintf("%s:%d", d, c.SSHPort))
	}
	return []lockedRule{
		{Name: RuleUI, Src: c.DevopsGroup, Accept: []string{fmt.Sprintf("%s:%d", c.ServerTag, c.UIPort)}},
		{Name: RuleWebhook, Src: c.K8sTag, Accept: []string{fmt.Sprintf("%s:%d", c.ServerTag, c.WebhookPort)}},
		ssh,
	}, nil
}

// ChangeKind says what Inject did to a locked entry.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "added"    // the entry was missing
	ChangeReplaced ChangeKind = "replaced" // a marked entry differed from the canonical one
	ChangeRemoved  ChangeKind = "removed"  // a marked entry outside the canonical set
)

// Change is one Inject action. Rule is empty for ChangeRemoved.
type Change struct {
	Kind ChangeKind
	Rule string
}

// InjectResult is the document after Inject and what it changed.
type InjectResult struct {
	Text    string
	Changes []Change
}

// Changed reports whether Inject altered the document.
func (r InjectResult) Changed() bool { return len(r.Changes) > 0 }

// Inject rebuilds the locked tests: every locked entry (marked, legacy-marked or with canonical
// content) becomes the canonical set. Missing entries
// are added, marked entries that differ from the canonical one are replaced (the user's version
// is not kept), marked entries beyond the set are removed. The rest of the document is kept byte
// for byte, and a second call changes nothing.
func Inject(raw string, cfg LockedConfig) (InjectResult, error) {
	root, obj, err := parseRoot(raw)
	if err != nil {
		return InjectResult{}, err
	}
	changes, err := reconcileLocked(obj, cfg)
	if err != nil {
		return InjectResult{}, err
	}
	if len(changes) == 0 {
		return InjectResult{Text: raw}, nil
	}
	return InjectResult{Text: string(root.Pack()), Changes: changes}, nil
}

// reconcileLocked edits obj in place and returns what it did.
func reconcileLocked(obj *hujson.Object, cfg LockedConfig) ([]Change, error) {
	rules, err := cfg.rules()
	if err != nil {
		return nil, err
	}
	var arr *hujson.Array
	idx := memberIndexes(obj, testsKey)
	switch len(idx) {
	case 0:
	case 1:
		a, ok := obj.Members[idx[0]].Value.Value.(*hujson.Array)
		if !ok {
			return nil, fmt.Errorf("%s must be an array", testsKey)
		}
		arr = a
	default:
		return nil, fmt.Errorf("document has %d %s sections", len(idx), testsKey)
	}

	canon := map[string]string{} // minimized entry -> rule name
	for _, r := range rules {
		v, err := hujson.Parse([]byte(r.entry()))
		if err != nil {
			return nil, err
		}
		canon[minimized(v)] = r.Name
	}

	kept := map[string]bool{}
	var stale []int
	if arr != nil {
		for i, el := range arr.Elements {
			name, isCanon := canon[minimized(el)]
			marked := hasLockedComment(el)
			if !marked && !isCanon && !isLegacyEntry(el) {
				continue
			}
			if isCanon && marked && !kept[name] {
				kept[name] = true
				continue
			}
			stale = append(stale, i)
		}
	}
	var missing []lockedRule
	for _, r := range rules {
		if !kept[r.Name] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 && len(stale) == 0 {
		return nil, nil
	}

	var changes []Change
	drop := map[int]bool{}
	for j, i := range stale {
		if j >= len(missing) {
			drop[i] = true
			changes = append(changes, Change{Kind: ChangeRemoved})
			continue
		}
		v, err := hujson.Parse([]byte(missing[j].entry()))
		if err != nil {
			return nil, err
		}
		arr.Elements[i].Value = v.Value // keep the old element's surrounding whitespace and comma
		changes = append(changes, Change{Kind: ChangeReplaced, Rule: missing[j].Name})
	}
	var add []lockedRule
	if len(stale) < len(missing) {
		add = missing[len(stale):]
	}

	if len(drop) > 0 {
		rest := arr.Elements[:0]
		for i, el := range arr.Elements {
			if !drop[i] {
				rest = append(rest, el)
			}
		}
		arr.Elements = rest
	}
	if len(add) == 0 {
		return changes, nil
	}

	wasEmpty := arr == nil || len(arr.Elements) == 0
	if arr == nil {
		arr = &hujson.Array{}
		obj.Members = append(obj.Members, hujson.ObjectMember{
			Name:  hujson.Value{BeforeExtra: hujson.Extra("\n  "), Value: hujson.String(testsKey)},
			Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: arr},
		})
		if obj.AfterExtra == nil {
			obj.AfterExtra = hujson.Extra("\n")
		}
		// A trailing comma on the previous member means the new one gets one too.
		if n := len(obj.Members); n >= 2 && obj.Members[n-2].Value.AfterExtra != nil {
			obj.Members[n-1].Value.AfterExtra = hujson.Extra{}
		}
	}
	trailing := len(arr.Elements) > 0 && arr.Elements[len(arr.Elements)-1].AfterExtra != nil
	for _, r := range add {
		v, err := hujson.Parse([]byte(r.entry()))
		if err != nil {
			return nil, err
		}
		v.BeforeExtra = hujson.Extra(entryIndent)
		arr.Elements = append(arr.Elements, v)
		changes = append(changes, Change{Kind: ChangeAdded, Rule: r.Name})
	}
	if trailing {
		arr.Elements[len(arr.Elements)-1].AfterExtra = hujson.Extra{}
	}
	if wasEmpty && strings.TrimSpace(string(arr.AfterExtra)) == "" {
		arr.AfterExtra = hujson.Extra("\n  ")
	}
	return changes, nil
}

// hasLockedComment reports whether the text before a tests element's first member is exactly the
// marker comment tagcess writes (whitespace aside). A comment that merely contains the marker text
// belongs to the user and does not make the entry tagcess-owned.
func hasLockedComment(el hujson.Value) bool {
	o, ok := el.Value.(*hujson.Object)
	return ok && len(o.Members) > 0 && strings.TrimSpace(string(o.Members[0].Name.BeforeExtra)) == lockedComment
}

// isLegacyEntry reports whether a tests element carries the old "#tagcess": "locked" member.
func isLegacyEntry(el hujson.Value) bool {
	o, ok := el.Value.(*hujson.Object)
	if !ok {
		return false
	}
	for _, m := range o.Members {
		if n, ok := literalString(m.Name); ok && n == legacyMarkerKey {
			v, ok := literalString(m.Value)
			return ok && v == legacyMarkerValue
		}
	}
	return false
}

// minimized is a whitespace-, comment- and comma-free form for comparing entries.
func minimized(v hujson.Value) string {
	c := v.Clone()
	c.BeforeExtra, c.AfterExtra = nil, nil
	c.Minimize()
	return string(c.Pack())
}

// LockedTestError means CheckPolicy rejected the document because a locked test failed.
type LockedTestError struct {
	Rule   string // ui, webhook or ssh
	Detail string // Headscale's line for the failing test
}

func (e *LockedTestError) Error() string {
	return fmt.Sprintf("locked test failed: %s: %s", e.Rule, e.Detail)
}

var (
	// "src -> dst (proto): expected ALLOWED, got DENIED"
	failDstRE = regexp.MustCompile(`^(\S+) -> (\S+?)(?: \([^)]*\))?: expected `)
	// `src: error testing "dst": ...`
	failErrRE = regexp.MustCompile(`^(\S+)(?: \([^)]*\))?: error testing "([^"]+)"`)
	// `src: failed to resolve source ...` / `src: source "x" resolved to no IP addresses`
	failSrcRE = regexp.MustCompile(`^(\S+)(?: \([^)]*\))?: (?:failed to resolve source|source )`)
)

// ClassifyCheckError turns a CheckPolicy rejection that names a locked test into a
// *LockedTestError. Any other error comes back unchanged.
func ClassifyCheckError(cfg LockedConfig, err error) error {
	var pe *headscale.PolicyError
	if !errors.As(err, &pe) {
		return err
	}
	rules, rerr := cfg.rules()
	if rerr != nil {
		return err
	}
	for _, line := range strings.Split(pe.Message, "\n") {
		line = strings.TrimSpace(line)
		var src, dst string
		switch {
		case failDstRE.MatchString(line):
			m := failDstRE.FindStringSubmatch(line)
			src, dst = m[1], m[2]
		case failErrRE.MatchString(line):
			m := failErrRE.FindStringSubmatch(line)
			src, dst = m[1], m[2]
		case failSrcRE.MatchString(line):
			src = failSrcRE.FindStringSubmatch(line)[1]
		default:
			continue
		}
		var bySrc *lockedRule
		for i, r := range rules {
			if r.Src != src {
				continue
			}
			if bySrc == nil {
				bySrc = &rules[i]
			}
			for _, a := range r.Accept {
				if a == dst {
					return &LockedTestError{Rule: r.Name, Detail: line}
				}
			}
		}
		if dst == "" && bySrc != nil {
			return &LockedTestError{Rule: bySrc.Name, Detail: line}
		}
	}
	return err
}
