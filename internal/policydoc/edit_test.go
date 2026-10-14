package policydoc

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func richFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/rich-policy.hujson")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustParse(t *testing.T, text string) *Doc {
	t.Helper()
	d, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return d
}

// editFixtures are the documents every edit runs against: the anonymised production policy and
// a rich one with the sections the form does not own.
func editFixtures(t *testing.T) map[string]string {
	return map[string]string{"prod": fixture(t), "rich": richFixture(t)}
}

type editOp struct {
	name    string
	section string // the top-level section the operation may change
	only    string // restrict to one fixture ("" = both)
	apply   func(d *Doc) error
}

func ruleAt(t *testing.T, d *Doc, i int) Rule {
	t.Helper()
	rules, err := d.ACLRules()
	if err != nil || i >= len(rules) {
		t.Fatalf("ACLRules: %v (%d rules)", err, len(rules))
	}
	return rules[i]
}

func allOps(t *testing.T) []editOp {
	newRule := Rule{Action: "accept", Proto: "tcp", Src: []string{"group:developer", "10.1.0.0/16"}, Dst: []string{"tag:k8s:443", "autogroup:internet:*"}}
	return []editOp{
		{name: "AddACLRule", section: "acls", apply: func(d *Doc) error { return d.AddACLRule(newRule) }},
		{name: "UpdateACLRule", section: "acls", apply: func(d *Doc) error {
			return d.UpdateACLRule(1, ruleAt(t, d, 1), newRule)
		}},
		{name: "DeleteACLRule first", section: "acls", apply: func(d *Doc) error { return d.DeleteACLRule(0, ruleAt(t, d, 0)) }},
		{name: "DeleteACLRule middle", section: "acls", apply: func(d *Doc) error { return d.DeleteACLRule(1, ruleAt(t, d, 1)) }},
		{name: "DeleteACLRule last", section: "acls", apply: func(d *Doc) error { return d.DeleteACLRule(2, ruleAt(t, d, 2)) }},
		{name: "SetTagOwners new", section: "tagOwners", apply: func(d *Doc) error {
			return d.SetTagOwners("tag:new-one", []string{"group:devops", "user@example.com"})
		}},
		{name: "SetTagOwners replace", section: "tagOwners", apply: func(d *Doc) error {
			return d.SetTagOwners("tag:vpn-server", []string{"group:developer"})
		}},
		{name: "DeleteTag", section: "tagOwners", apply: func(d *Doc) error { return d.DeleteTag("tag:k8s") }},
		{name: "SetRouteApprovers new", section: "autoApprovers", apply: func(d *Doc) error {
			return d.SetRouteApprovers("172.16.0.0/12", []string{"group:devops"})
		}},
		{name: "SetRouteApprovers replace", section: "autoApprovers", only: "rich", apply: func(d *Doc) error {
			return d.SetRouteApprovers("10.20.0.0/16", []string{"tag:k8s", "group:developer"})
		}},
		{name: "DeleteRoute", section: "autoApprovers", only: "rich", apply: func(d *Doc) error { return d.DeleteRoute("192.168.1.0/24") }},
		{name: "SetExitNodeApprovers", section: "autoApprovers", apply: func(d *Doc) error {
			return d.SetExitNodeApprovers([]string{"tag:k8s"})
		}},
	}
}

// onlyTouches fails unless every changed byte lies inside the value of the named top-level
// section (or, when the section is absent, after the last top-level member): the smallest
// window between the common prefix and suffix of the two texts.
func onlyTouches(t *testing.T, before, after, section string) {
	t.Helper()
	root, err := hujson.Parse([]byte(before))
	if err != nil {
		t.Fatal(err)
	}
	obj := root.Value.(*hujson.Object)
	p := 0
	for p < len(before) && p < len(after) && before[p] == after[p] {
		p++
	}
	s := 0
	for s < len(before)-p && s < len(after)-p && before[len(before)-1-s] == after[len(after)-1-s] {
		s++
	}
	q := len(before) - s // the changed window in before is [p, q)
	lo, hi := 0, 0
	if idx := memberIndexes(obj, section); len(idx) == 1 {
		v := obj.Members[idx[0]].Value
		lo, hi = v.StartOffset, v.EndOffset
	} else {
		last := obj.Members[len(obj.Members)-1].Value
		lo, hi = last.EndOffset, root.EndOffset-1
	}
	if p < lo || q > hi {
		t.Errorf("changed bytes [%d,%d) leave the %s section [%d,%d)\nbefore: %q\nafter:  %q",
			p, q, section, lo, hi, before[max(0, p-20):min(len(before), q+20)], after[max(0, p-20):min(len(after), len(after)-s+20)])
	}
}

// TestPolicyDoc_EditPreservesEverythingElse is AC1: every operation, on both fixtures, changes
// bytes only inside its own section.
func TestPolicyDoc_EditPreservesEverythingElse(t *testing.T) {
	for fname, text := range editFixtures(t) {
		for _, op := range allOps(t) {
			if op.only != "" && op.only != fname {
				continue
			}
			t.Run(fname+"/"+op.name, func(t *testing.T) {
				d := mustParse(t, text)
				if got := d.Text(); got != text {
					t.Fatal("Parse then Text is not byte-identical")
				}
				if err := op.apply(d); err != nil {
					t.Fatal(err)
				}
				after := d.Text()
				if after == text {
					t.Fatal("the operation changed nothing")
				}
				onlyTouches(t, text, after, op.section)
				if _, err := hujson.Parse([]byte(after)); err != nil {
					t.Fatalf("result is not valid HuJSON: %v\n%s", err, after)
				}
			})
		}
	}
}

const aclsDoc = `{
  "acls": [
    // one
    { "action": "accept", "src": ["*"], "dst": ["tag:a:1"] }, // t1
    // two
    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] } // t2
  ]
}`

// TestPolicyDoc_ACLRuleEdits is AC2: order, indentation, comments.
func TestPolicyDoc_ACLRuleEdits(t *testing.T) {
	rule := func(src, dst string) Rule { return Rule{Action: "accept", Src: []string{src}, Dst: []string{dst}} }
	tests := []struct {
		name string
		doc  string
		do   func(d *Doc) error
		want string
	}{
		{
			name: "add appends at the end, indented, comments untouched",
			doc:  aclsDoc,
			do:   func(d *Doc) error { return d.AddACLRule(rule("group:x", "tag:a:3")) },
			want: `{
  "acls": [
    // one
    { "action": "accept", "src": ["*"], "dst": ["tag:a:1"] }, // t1
    // two
    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] }, // t2
    { "action": "accept", "src": ["group:x"], "dst": ["tag:a:3"] }
  ]
}`,
		},
		{
			name: "add with proto keeps the field order action, proto, src, dst",
			doc:  `{"acls": []}`,
			do: func(d *Doc) error {
				return d.AddACLRule(Rule{Proto: "udp", Src: []string{"*"}, Dst: []string{"tag:a:53", "tag:b:1000-2000"}})
			},
			want: `{"acls": [
    { "action": "accept", "proto": "udp", "src": ["*"], "dst": ["tag:a:53", "tag:b:1000-2000"] }
  ]}`,
		},
		{
			name: "add keeps a trailing comma style",
			doc:  "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:1\"] },\n  ],\n}",
			do:   func(d *Doc) error { return d.AddACLRule(rule("group:x", "tag:a:3")) },
			want: "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:1\"] },\n    { \"action\": \"accept\", \"src\": [\"group:x\"], \"dst\": [\"tag:a:3\"] },\n  ],\n}",
		},
		{
			name: "add creates a missing acls section",
			doc:  "{\n  \"grants\": []\n}\n",
			do:   func(d *Doc) error { return d.AddACLRule(rule("group:x", "tag:a:3")) },
			want: "{\n  \"grants\": [],\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"group:x\"], \"dst\": [\"tag:a:3\"] }\n  ]\n}\n",
		},
		{
			name: "update rewrites the rule in place, comments stay",
			doc:  aclsDoc,
			do: func(d *Doc) error {
				return d.UpdateACLRule(0, rule("*", "tag:a:1"), rule("group:y", "tag:a:9"))
			},
			want: `{
  "acls": [
    // one
    { "action": "accept", "src": ["group:y"], "dst": ["tag:a:9"] }, // t1
    // two
    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] } // t2
  ]
}`,
		},
		{
			name: "delete the first rule takes its comment and its trailing note",
			doc:  aclsDoc,
			do:   func(d *Doc) error { return d.DeleteACLRule(0, rule("*", "tag:a:1")) },
			want: `{
  "acls": [
    // two
    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] } // t2
  ]
}`,
		},
		{
			name: "delete the last rule takes its comment, keeps the previous trailing note",
			doc:  aclsDoc,
			do:   func(d *Doc) error { return d.DeleteACLRule(1, rule("*", "tag:a:2")) },
			want: `{
  "acls": [
    // one
    { "action": "accept", "src": ["*"], "dst": ["tag:a:1"] } // t1
  ]
}`,
		},
		{
			name: "delete only takes the adjacent comment lines, not a block above a blank line",
			doc: `{
  "acls": [
    // about the whole list

    // about the rule
    { "action": "accept", "src": ["*"], "dst": ["tag:a:1"] },
    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] },
  ]
}`,
			do: func(d *Doc) error { return d.DeleteACLRule(0, rule("*", "tag:a:1")) },
			want: `{
  "acls": [
    // about the whole list

    { "action": "accept", "src": ["*"], "dst": ["tag:a:2"] },
  ]
}`,
		},
		{
			name: "delete the only rule leaves an empty array",
			doc:  "{\n  \"acls\": [\n    // r\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:1\"] }\n  ],\n  \"grants\": []\n}",
			do:   func(d *Doc) error { return d.DeleteACLRule(0, rule("*", "tag:a:1")) },
			want: "{\n  \"acls\": [\n  ],\n  \"grants\": []\n}",
		},
		{
			name: "delete in a trailing-comma list keeps the trailing comma",
			doc:  "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:1\"] },\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:2\"] },\n  ]\n}",
			do:   func(d *Doc) error { return d.DeleteACLRule(1, rule("*", "tag:a:2")) },
			want: "{\n  \"acls\": [\n    { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:a:1\"] },\n  ]\n}",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, tc.doc)
			if err := tc.do(d); err != nil {
				t.Fatal(err)
			}
			if got := d.Text(); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}

	t.Run("rule order is kept and the new rule is last", func(t *testing.T) {
		d := mustParse(t, richFixture(t))
		before, err := d.ACLRules()
		if err != nil {
			t.Fatal(err)
		}
		if err := d.AddACLRule(rule("group:x", "tag:a:3")); err != nil {
			t.Fatal(err)
		}
		after, err := d.ACLRules()
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before)+1 || !reflect.DeepEqual(after[:len(before)], before) || after[len(before)].Dst[0] != "tag:a:3" {
			t.Errorf("rules before %v after %v", before, after)
		}
	})
	t.Run("rich fixture: the multi-line rule and its two comment lines go together", func(t *testing.T) {
		d := mustParse(t, richFixture(t))
		if err := d.DeleteACLRule(2, ruleAt(t, d, 2)); err != nil {
			t.Fatal(err)
		}
		got := d.Text()
		for _, gone := range []string{"devops ssh and icmp", "two comment lines", `"proto": "tcp"`} {
			if strings.Contains(got, gone) {
				t.Errorf("%q survived the delete", gone)
			}
		}
		for _, kept := range []string{"// everyone reaches the gate", "// gate", "// Caddy to k8s only on the internal port", "// access rules"} {
			if !strings.Contains(got, kept) {
				t.Errorf("comment %q was lost", kept)
			}
		}
	})
}

const tagDoc = `{
  "tagOwners": {
    // the server
    "tag:s": ["group:devops"], // note
    "tag:k": []
  },
  "acls": []
}`

// TestPolicyDoc_TagOwnersAndAutoApprovers is AC3.
func TestPolicyDoc_TagOwnersAndAutoApprovers(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		do   func(d *Doc) error
		want string
	}{
		{
			name: "new tag is appended with the same indentation",
			doc:  tagDoc,
			do:   func(d *Doc) error { return d.SetTagOwners("tag:new", []string{"group:a", "u@x"}) },
			want: `{
  "tagOwners": {
    // the server
    "tag:s": ["group:devops"], // note
    "tag:k": [],
    "tag:new": ["group:a", "u@x"]
  },
  "acls": []
}`,
		},
		{
			name: "existing tag: only its value changes",
			doc:  tagDoc,
			do:   func(d *Doc) error { return d.SetTagOwners("tag:s", []string{"group:b"}) },
			want: `{
  "tagOwners": {
    // the server
    "tag:s": ["group:b"], // note
    "tag:k": []
  },
  "acls": []
}`,
		},
		{
			name: "missing tagOwners section is created with fixed indentation",
			doc:  "{\n  \"acls\": []\n}\n",
			do:   func(d *Doc) error { return d.SetTagOwners("tag:a", []string{"group:x"}) },
			want: "{\n  \"acls\": [],\n  \"tagOwners\": {\n    \"tag:a\": [\"group:x\"]\n  }\n}\n",
		},
		{
			name: "a section name in another case is the same section",
			doc:  `{"TAGOWNERS": {"tag:a": []}, "acls": []}`,
			do:   func(d *Doc) error { return d.SetTagOwners("tag:b", nil) },
			want: "{\"TAGOWNERS\": {\"tag:a\": [],\n    \"tag:b\": []\n  }, \"acls\": []}",
		},
		{
			name: "delete the last tag keeps the empty section",
			doc:  "{\n  \"tagOwners\": {\n    \"tag:a\": []\n  },\n  \"acls\": []\n}",
			do:   func(d *Doc) error { return d.DeleteTag("tag:a") },
			want: "{\n  \"tagOwners\": {\n  },\n  \"acls\": []\n}",
		},
		{
			name: "delete takes the tag's comment line, not the others",
			doc:  tagDoc,
			do:   func(d *Doc) error { return d.DeleteTag("tag:s") },
			want: `{
  "tagOwners": {
    "tag:k": []
  },
  "acls": []
}`,
		},
		{
			name: "route approvers: autoApprovers and routes are created",
			doc:  "{\n  \"acls\": []\n}\n",
			do:   func(d *Doc) error { return d.SetRouteApprovers("10.0.0.0/8", []string{"group:x"}) },
			want: "{\n  \"acls\": [],\n  \"autoApprovers\": {\n    \"routes\": {\n      \"10.0.0.0/8\": [\"group:x\"]\n    }\n  }\n}\n",
		},
		{
			name: "route approvers: routes is added to an existing autoApprovers",
			doc:  "{\n  \"autoApprovers\": {\n    \"exitNode\": [\"tag:e\"]\n  },\n  \"acls\": []\n}",
			do:   func(d *Doc) error { return d.SetRouteApprovers("10.0.0.0/8", []string{"group:x"}) },
			want: "{\n  \"autoApprovers\": {\n    \"exitNode\": [\"tag:e\"],\n    \"routes\": {\n      \"10.0.0.0/8\": [\"group:x\"]\n    }\n  },\n  \"acls\": []\n}",
		},
		{
			name: "delete the last route keeps routes and autoApprovers",
			doc:  "{\n  \"autoApprovers\": {\n    \"routes\": {\n      \"10.0.0.0/8\": [\"group:x\"]\n    }\n  },\n  \"acls\": []\n}",
			do:   func(d *Doc) error { return d.DeleteRoute("10.0.0.0/8") },
			want: "{\n  \"autoApprovers\": {\n    \"routes\": {\n    }\n  },\n  \"acls\": []\n}",
		},
		{
			name: "exit node approvers: created, then replaced",
			doc:  "{\n  \"acls\": []\n}\n",
			do: func(d *Doc) error {
				if err := d.SetExitNodeApprovers([]string{"tag:a"}); err != nil {
					return err
				}
				return d.SetExitNodeApprovers([]string{"tag:b", "group:c"})
			},
			want: "{\n  \"acls\": [],\n  \"autoApprovers\": {\n    \"exitNode\": [\"tag:b\", \"group:c\"]\n  }\n}\n",
		},
		{
			name: "exit node approvers can be emptied",
			doc:  "{\"autoApprovers\": {\"exitNode\": [\"tag:a\"]}, \"acls\": []}",
			do:   func(d *Doc) error { return d.SetExitNodeApprovers(nil) },
			want: "{\"autoApprovers\": {\"exitNode\": []}, \"acls\": []}",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, tc.doc)
			if err := tc.do(d); err != nil {
				t.Fatal(err)
			}
			if got := d.Text(); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// TestPolicyDoc_RejectsInvalidInput is AC4: every bad value is refused with ErrInvalidInput and
// leaves the document exactly as it was.
func TestPolicyDoc_RejectsInvalidInput(t *testing.T) {
	ok := Rule{Action: "accept", Src: []string{"group:devops"}, Dst: []string{"tag:k8s:22"}}
	with := func(f func(r *Rule)) Rule {
		r := Rule{Action: ok.Action, Src: slicesClone(ok.Src), Dst: slicesClone(ok.Dst)}
		f(&r)
		return r
	}
	bad := map[string]func(d *Doc) error{}
	addRule := func(name string, r Rule) {
		bad["add/"+name] = func(d *Doc) error { return d.AddACLRule(r) }
		bad["update/"+name] = func(d *Doc) error { return d.UpdateACLRule(0, ruleAt(t, d, 0), r) }
	}
	addRule("action deny", with(func(r *Rule) { r.Action = "deny" }))
	addRule("action upper case", with(func(r *Rule) { r.Action = "ACCEPT" }))
	addRule("no src", with(func(r *Rule) { r.Src = nil }))
	addRule("no dst", with(func(r *Rule) { r.Dst = nil }))
	for _, a := range []string{
		"", " ", "bad alias", "a\"b", "a\nb", "a\\b", "x\x00y", "grüp@x", "group:", "group:Dev", "group:dev ops", "group:" + strings.Repeat("a", 33),
		"tag:", "tag:Bad", "tag:-x", "tag:" + strings.Repeat("a", 64), "tag:a_b", "autogroup:danger-all", "autogroup:", "autogroup:foo",
		"10.0.0.0/33", "999.1.1.1", "10.0.0.0/", "fe80::1%eth0", "nobody", "a,b", "*,*", "group:a@b",
	} {
		addRule("src "+a, with(func(r *Rule) { r.Src = []string{a} }))
	}
	for _, a := range []string{
		"tag:a", "tag:a:", "tag:a:0", "tag:a:65536", "tag:a:22-", "tag:a:-22", "tag:a:80-20", "tag:a:80,,81", "tag:a:80,", "tag:a:22,*", "tag:a:x", "tag:a:1-2-3",
		"tag:A:22", "group:x\n:22", "tag:a:22\"", "*:*\n", ":22", "autogroup:foo:22", "10.0.0.0/33:22", "tag:a:99999999999999999999", "tag:a: 22",
	} {
		addRule("dst "+a, with(func(r *Rule) { r.Dst = []string{a} }))
	}
	for _, p := range []string{"bogus", "TCP", "tcp\n", "tcp\"", "6", " tcp", "tcp,udp"} {
		addRule("proto "+p, with(func(r *Rule) { r.Proto = p }))
	}
	for _, tag := range []string{"", "vpn", "tag:", "tag:A", "tag:" + strings.Repeat("a", 64), "tag:a\"", "tag:a\n", "group:x", "tag:-a"} {
		bad["tag/"+tag] = func(d *Doc) error { return d.SetTagOwners(tag, []string{"group:x"}) }
		bad["deltag/"+tag] = func(d *Doc) error { return d.DeleteTag(tag) }
	}
	for _, o := range []string{"", "*", "autogroup:member", "autogroup:self", "x", "10.0.0.1", "10.0.0.0/8", "g\"x@", "a\nb@", "group:", "tag:Bad", "group:x y", "u@x*"} {
		bad["owner/"+o] = func(d *Doc) error { return d.SetTagOwners("tag:new", []string{o}) }
		bad["routeowner/"+o] = func(d *Doc) error { return d.SetRouteApprovers("10.0.0.0/8", []string{o}) }
		bad["exitowner/"+o] = func(d *Doc) error { return d.SetExitNodeApprovers([]string{o}) }
	}
	bad["owner/duplicate"] = func(d *Doc) error { return d.SetTagOwners("tag:new", []string{"group:x", "group:x"}) }
	for _, c := range []string{"", "bad", "10.0.0.0", "10.0.0.1/8", "10.0.0.0/33", "10.0.0.0/-1", "::ffff:10.0.0.0/104", "fe80::%eth0/64", "010.0.0.0/8", "10.0.0.0/8\n", " 10.0.0.0/8", "10.0.0.0/08", "*"} {
		bad["route/"+c] = func(d *Doc) error { return d.SetRouteApprovers(c, []string{"group:x"}) }
		bad["delroute/"+c] = func(d *Doc) error { return d.DeleteRoute(c) }
	}

	for fname, text := range editFixtures(t) {
		for name, op := range bad {
			t.Run(fname+"/"+name, func(t *testing.T) {
				d := mustParse(t, text)
				err := op(d)
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("err = %v, want ErrInvalidInput", err)
				}
				if d.Text() != text {
					t.Error("the document changed")
				}
			})
		}
	}

	t.Run("accepted forms", func(t *testing.T) {
		for _, a := range []string{
			"*", "group:devops", "tag:vpn-server", "autogroup:member", "autogroup:tagged", "user@example.com",
			"https://idp.example.com/oauth/12345@", "10.0.0.1", "10.0.0.0/8", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::/48",
		} {
			d := mustParse(t, fixture(t))
			if err := d.AddACLRule(with(func(r *Rule) { r.Src = []string{a} })); err != nil {
				t.Errorf("src %q: %v", a, err)
			}
		}
		for _, a := range []string{"*:*", "tag:a:22", "tag:a:80,443", "tag:a:1000-2000", "tag:a:22,80-90", "10.0.0.0/8:443", "autogroup:internet:*", "group:devops:1-65535", "u@x.com:22"} {
			d := mustParse(t, fixture(t))
			if err := d.AddACLRule(with(func(r *Rule) { r.Dst = []string{a} })); err != nil {
				t.Errorf("dst %q: %v", a, err)
			}
		}
		for _, p := range []string{"", "tcp", "udp", "icmp", "sctp"} {
			d := mustParse(t, fixture(t))
			if err := d.AddACLRule(with(func(r *Rule) { r.Proto = p })); err != nil {
				t.Errorf("proto %q: %v", p, err)
			}
		}
		d := mustParse(t, fixture(t))
		if err := d.AddACLRule(Rule{Src: []string{"*"}, Dst: []string{"*:*"}}); err != nil {
			t.Errorf("empty action defaults to accept: %v", err)
		}
		if !strings.Contains(d.Text(), `"action": "accept", "src": ["*"]`) {
			t.Errorf("the action was not written as accept:\n%s", d.Text())
		}
	})
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// TestPolicyDoc_NoGroupsMutation is AC5: no method touches groups, and a rule or owner list may
// still name a role group.
func TestPolicyDoc_NoGroupsMutation(t *testing.T) {
	typ := reflect.TypeOf(&Doc{})
	for i := 0; i < typ.NumMethod(); i++ {
		if name := typ.Method(i).Name; strings.Contains(strings.ToLower(name), "group") {
			t.Errorf("Doc has a method %q that names groups", name)
		}
	}
	// The group name syntax in a tag or route key is refused, so no operation can address a group.
	d := mustParse(t, fixture(t))
	for _, err := range []error{
		d.SetTagOwners("group:devops", []string{"group:devops"}),
		d.DeleteTag("group:devops"),
		d.SetRouteApprovers("group:devops", nil),
	} {
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	}
	// Role groups are fine as rule and owner values, and the groups section stays byte for byte.
	if err := d.AddACLRule(Rule{Src: []string{"group:developer"}, Dst: []string{"tag:k8s:443"}}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetTagOwners("tag:new", []string{"group:standart"}); err != nil {
		t.Fatal(err)
	}
	if groupsSection(t, d.Text()) != groupsSection(t, fixture(t)) {
		t.Error("the groups section changed")
	}
}

func groupsSection(t *testing.T, text string) string {
	t.Helper()
	root, obj, err := parseRoot(text)
	if err != nil {
		t.Fatal(err)
	}
	idx := memberIndexes(obj, "groups")
	if len(idx) != 1 {
		t.Fatalf("%d groups sections", len(idx))
	}
	v := obj.Members[idx[0]].Value
	return string(root.Pack()[v.StartOffset:v.EndOffset])
}

// TestPolicyDoc_StaleRuleRejected is AC6.
func TestPolicyDoc_StaleRuleRejected(t *testing.T) {
	text := fixture(t)
	other := Rule{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}}
	nr := Rule{Src: []string{"group:x"}, Dst: []string{"tag:a:1"}}
	t.Run("update", func(t *testing.T) {
		d := mustParse(t, text)
		if err := d.UpdateACLRule(0, other, nr); !errors.Is(err, ErrStaleRule) {
			t.Fatalf("err = %v, want ErrStaleRule", err)
		}
		if d.Text() != text {
			t.Error("the document changed")
		}
	})
	t.Run("delete", func(t *testing.T) {
		d := mustParse(t, text)
		if err := d.DeleteACLRule(0, other); !errors.Is(err, ErrStaleRule) {
			t.Fatalf("err = %v, want ErrStaleRule", err)
		}
		if d.Text() != text {
			t.Error("the document changed")
		}
	})
	t.Run("the rule moved: the index now points at another rule", func(t *testing.T) {
		d := mustParse(t, text)
		first := ruleAt(t, d, 0)
		if err := d.DeleteACLRule(0, first); err != nil {
			t.Fatal(err)
		}
		before := d.Text()
		if err := d.DeleteACLRule(0, first); !errors.Is(err, ErrStaleRule) {
			t.Fatalf("err = %v, want ErrStaleRule", err)
		}
		if d.Text() != before {
			t.Error("the document changed")
		}
	})
	t.Run("an empty action in expected means accept", func(t *testing.T) {
		d := mustParse(t, text)
		exp := ruleAt(t, d, 0)
		exp.Action = ""
		if err := d.DeleteACLRule(0, exp); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("index out of range", func(t *testing.T) {
		d := mustParse(t, text)
		for _, i := range []int{-1, 3, 99} {
			if err := d.DeleteACLRule(i, other); !errors.Is(err, ErrNotFound) {
				t.Errorf("DeleteACLRule(%d) = %v, want ErrNotFound", i, err)
			}
			if err := d.UpdateACLRule(i, other, nr); !errors.Is(err, ErrNotFound) {
				t.Errorf("UpdateACLRule(%d) = %v, want ErrNotFound", i, err)
			}
		}
	})
	t.Run("missing tag and route", func(t *testing.T) {
		d := mustParse(t, text)
		if err := d.DeleteTag("tag:nope"); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteTag = %v, want ErrNotFound", err)
		}
		if err := d.DeleteRoute("10.9.0.0/16"); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteRoute = %v, want ErrNotFound", err)
		}
	})
	t.Run("a rule with a field the form does not know cannot be read or edited", func(t *testing.T) {
		raw := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"], "srcPosture": ["x"]}]}`
		d := mustParse(t, raw)
		if _, err := d.ACLRules(); err == nil {
			t.Error("ACLRules read a rule with an unknown field")
		}
		if err := d.DeleteACLRule(0, Rule{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}}); err == nil {
			t.Error("DeleteACLRule accepted a rule with an unknown field")
		}
		if d.Text() != raw {
			t.Error("the document changed")
		}
	})
	t.Run("metadata members in a rule are kept by an update", func(t *testing.T) {
		raw := `{"acls": [{"#why": "because", "action": "accept", "src": ["*"], "dst": ["tag:a:1"]}]}`
		d := mustParse(t, raw)
		if err := d.UpdateACLRule(0, ruleAt(t, d, 0), Rule{Src: []string{"*"}, Dst: []string{"tag:a:2"}}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.Text(), `"#why": "because"`) || !strings.Contains(d.Text(), "tag:a:2") {
			t.Errorf("got %s", d.Text())
		}
	})
}

// TestPolicyDoc_EditsPassValidation is AC7 (local stages): the output of every operation passes
// the input, syntax, structure and locked stages of F3-006. The real CheckPolicy part is the
// integration test.
func TestPolicyDoc_EditsPassValidation(t *testing.T) {
	for fname, text := range editFixtures(t) {
		res, err := Inject(text, testCfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range allOps(t) {
			if op.only != "" && op.only != fname {
				continue
			}
			t.Run(fname+"/"+op.name, func(t *testing.T) {
				d := mustParse(t, res.Text)
				if err := op.apply(d); err != nil {
					t.Fatal(err)
				}
				r := Validate(context.Background(), d.Text(), testCfg, &fakeChecker{})
				if !r.Valid() {
					t.Fatalf("report not valid: %+v\n%s", r.Stages, d.Text())
				}
			})
		}
	}
}

// TestPolicyDoc_IdempotentSets is AC8: setting what is already there changes nothing, even when
// the existing value is formatted differently.
func TestPolicyDoc_IdempotentSets(t *testing.T) {
	text := richFixture(t)
	d := mustParse(t, text)
	sets := map[string]func() error{
		"SetTagOwners":         func() error { return d.SetTagOwners("tag:vpn-server", []string{"group:devops"}) },
		"SetTagOwners empty":   func() error { return d.SetTagOwners("tag:k8s", nil) },
		"SetRouteApprovers":    func() error { return d.SetRouteApprovers("10.20.0.0/16", []string{"group:devops"}) },
		"SetExitNodeApprovers": func() error { return d.SetExitNodeApprovers([]string{"tag:vpn-server"}) },
		"UpdateACLRule same": func() error {
			return d.UpdateACLRule(2, ruleAt(t, d, 2), ruleAt(t, d, 2))
		},
	}
	for name, set := range sets {
		t.Run(name, func(t *testing.T) {
			for range 2 {
				if err := set(); err != nil {
					t.Fatal(err)
				}
				if d.Text() != text {
					t.Fatal("the document changed")
				}
			}
		})
	}
	t.Run("a created entry is stable on the second call", func(t *testing.T) {
		d := mustParse(t, fixture(t))
		if err := d.SetTagOwners("tag:new", []string{"group:a"}); err != nil {
			t.Fatal(err)
		}
		once := d.Text()
		if err := d.SetTagOwners("tag:new", []string{"group:a"}); err != nil {
			t.Fatal(err)
		}
		if d.Text() != once {
			t.Error("the second call changed the document")
		}
	})
}

func TestPolicyDoc_ParseErrors(t *testing.T) {
	for name, raw := range map[string]string{
		"syntax":    `{"acls": `,
		"not obj":   `[]`,
		"dup acls":  `{"acls": [], "acls": []}`,
		"acls type": `{"acls": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			d, err := Parse(raw)
			if err == nil {
				err = d.AddACLRule(Rule{Src: []string{"*"}, Dst: []string{"*:*"}})
			}
			if err == nil {
				t.Error("no error")
			}
		})
	}
}
