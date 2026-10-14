//go:build integration

// Integration test for F3-011 AC7: the output of every edit operation is accepted by a real
// Headscale CheckPolicy. It uses its own disposable Headscale (hsstack), so it does not touch the
// shared compose stack: `go test -tags=integration ./internal/policydoc/...`.
package policydoc_test

import (
	"context"
	"os"
	"testing"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

func TestPolicyDoc_Integration_HeadscaleAccepts(t *testing.T) {
	raw, err := os.ReadFile("testdata/rich-policy.hujson")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	c := hsstack.Start(t).Client()
	check := func(t *testing.T, doc string) {
		t.Helper()
		if err := c.CheckPolicy(context.Background(), doc); err != nil {
			t.Fatalf("Headscale rejected the document: %v\n%s", err, doc)
		}
	}
	// The control: the untouched fixture is accepted, so a rejection below is the edit's fault.
	check(t, text)

	rule := policydoc.Rule{Proto: "tcp", Src: []string{"group:developer", "10.1.0.0/16"}, Dst: []string{"tag:k8s:443", "autogroup:internet:*"}}
	rule2 := policydoc.Rule{Src: []string{"*"}, Dst: []string{"tag:k8s:1000-2000,22"}}
	ops := map[string]func(d *policydoc.Doc) error{
		"AddACLRule":    func(d *policydoc.Doc) error { return d.AddACLRule(rule) },
		"AddACLRule 2":  func(d *policydoc.Doc) error { return d.AddACLRule(rule2) },
		"UpdateACLRule": func(d *policydoc.Doc) error { return d.UpdateACLRule(1, mustRule(t, d, 1), rule) },
		"DeleteACLRule": func(d *policydoc.Doc) error { return d.DeleteACLRule(1, mustRule(t, d, 1)) },
		"SetTagOwners new": func(d *policydoc.Doc) error {
			return d.SetTagOwners("tag:new-one", []string{"group:devops", "user@example.com"})
		},
		"SetTagOwners replace": func(d *policydoc.Doc) error {
			return d.SetTagOwners("tag:vpn-server", []string{"group:developer"})
		},
		"DeleteTag": func(d *policydoc.Doc) error {
			if err := d.SetTagOwners("tag:tmp", nil); err != nil {
				return err
			}
			return d.DeleteTag("tag:tmp")
		},
		"SetRouteApprovers": func(d *policydoc.Doc) error {
			return d.SetRouteApprovers("172.16.0.0/12", []string{"group:devops", "tag:k8s"})
		},
		"DeleteRoute":          func(d *policydoc.Doc) error { return d.DeleteRoute("192.168.1.0/24") },
		"SetExitNodeApprovers": func(d *policydoc.Doc) error { return d.SetExitNodeApprovers([]string{"tag:k8s"}) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			d, err := policydoc.Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			if err := op(d); err != nil {
				t.Fatal(err)
			}
			check(t, d.Text())
		})
	}
	// Removing a tag that rules still use is the caller's mistake; CheckPolicy is what catches it.
	t.Run("deleting a referenced tag is rejected by Headscale", func(t *testing.T) {
		d, _ := policydoc.Parse(text)
		if err := d.DeleteTag("tag:k8s"); err != nil {
			t.Fatal(err)
		}
		if err := c.CheckPolicy(context.Background(), d.Text()); err == nil {
			t.Error("Headscale accepted a policy with a dangling tag")
		}
	})
	// Edits stacked on each other, plus the section-creating path on a document without them.
	t.Run("all edits together", func(t *testing.T) {
		d, _ := policydoc.Parse(text)
		for name, op := range ops {
			if name == "AddACLRule 2" {
				continue
			}
			if err := op(d); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		check(t, d.Text())
	})
	t.Run("sections created from nothing", func(t *testing.T) {
		d, err := policydoc.Parse(`{ "groups": { "group:devops": [] }, "acls": [] }`)
		if err != nil {
			t.Fatal(err)
		}
		for _, err := range []error{
			d.SetTagOwners("tag:a", []string{"group:devops"}),
			d.SetRouteApprovers("10.0.0.0/8", []string{"tag:a"}),
			d.SetExitNodeApprovers([]string{"tag:a"}),
			d.AddACLRule(policydoc.Rule{Src: []string{"group:devops"}, Dst: []string{"tag:a:443"}}),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
		check(t, d.Text())
	})
}

func mustRule(t *testing.T, d *policydoc.Doc, i int) policydoc.Rule {
	t.Helper()
	rules, err := d.ACLRules()
	if err != nil || i >= len(rules) {
		t.Fatalf("ACLRules: %v", err)
	}
	return rules[i]
}
