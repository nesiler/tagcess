//go:build integration

// Integration tests for F3-006 against the local compose Headscale (`make lab-up`, then
// `go test -tags=integration ./internal/policydoc/...`). They only call CheckPolicy, which does
// not change anything, and need no registered node: the locked rules are parameterised with
// `hosts` aliases, which resolve to fixed addresses. The same rules with real groups, tags and
// nodes are proved in F3-026 and F3-028.
package policydoc_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/policydoc"
)

func target() string {
	if t := os.Getenv("TAGCESS_HEADSCALE_TARGET"); t != "" {
		return t
	}
	return "127.0.0.1:50444"
}

func newClient(t *testing.T) *headscale.Client {
	t.Helper()
	c, err := headscale.New(headscale.Config{Target: target(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var cfg = policydoc.LockedConfig{
	DevopsGroup: "devops-host",
	ServerTag:   "vpn-host",
	UIPort:      443,
	K8sTag:      "k8s-host",
	WebhookPort: 9000,
	SSHSrc:      "devops-host",
	SSHDst:      []string{"vpn-host", "k8s-host"},
	SSHPort:     22,
}

const base = `{
  "hosts": {
    "devops-host": "100.64.9.1",
    "vpn-host": "100.64.9.2",
    "k8s-host": "100.64.9.3"
  },
  "acls": [
    { "action": "accept", "src": ["devops-host"], "dst": ["vpn-host:443,22", "k8s-host:22"] },
    { "action": "accept", "src": ["k8s-host"], "dst": ["vpn-host:9000"] }
  ]
}`

func injected(t *testing.T, doc string) string {
	t.Helper()
	res, err := policydoc.Inject(doc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return res.Text
}

// TestLockedTests_Integration_MarkerAccepted: Headscale ignores the /* tagcess:locked */ comment and runs the
// entries as ordinary tests, so a document carrying them is accepted.
func TestLockedTests_Integration_MarkerAccepted(t *testing.T) {
	c := newClient(t)
	doc := injected(t, base)
	if !strings.Contains(doc, `/* tagcess:locked */`) {
		t.Fatal("no marker in the injected document")
	}
	r := policydoc.Validate(context.Background(), doc, cfg, c)
	if !r.Valid() {
		t.Fatalf("report not valid: %+v", r.Stages)
	}
}

// TestLockedTests_Integration_RuleRemovalRejected: the locked tests are really executed, so a
// document that lost the rule behind one of them is rejected, naming that rule.
func TestLockedTests_Integration_RuleRemovalRejected(t *testing.T) {
	c := newClient(t)
	cases := map[string]struct {
		drop string // text removed from the document
		rule string
	}{
		"ui":      {`"vpn-host:443,22"`, "ui"},
		"webhook": {`    { "action": "accept", "src": ["k8s-host"], "dst": ["vpn-host:9000"] }`, "webhook"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc := injected(t, base)
			broken := strings.Replace(doc, tc.drop, `"vpn-host:22"`, 1)
			if tc.rule == "webhook" {
				broken = strings.Replace(doc, tc.drop, "", 1)
				broken = strings.Replace(broken, "\"k8s-host:22\"] },\n", "\"k8s-host:22\"] }\n", 1)
			}
			if broken == doc {
				t.Fatal("test bug: nothing was removed")
			}
			// The control: the intact document passes with the same checker.
			if err := c.CheckPolicy(context.Background(), doc); err != nil {
				t.Fatalf("intact document rejected: %v", err)
			}
			err := policydoc.ClassifyCheckError(cfg, c.CheckPolicy(context.Background(), broken))
			var le *policydoc.LockedTestError
			if !errors.As(err, &le) {
				t.Fatalf("CheckPolicy(broken) = %v, want a LockedTestError", err)
			}
			t.Logf("Headscale: %s", le.Detail)
			if le.Rule != tc.rule {
				t.Errorf("rule = %q, want %q (%s)", le.Rule, tc.rule, le.Detail)
			}
			r := policydoc.Validate(context.Background(), broken, cfg, c)
			if r.Valid() || r.Locked == nil {
				t.Errorf("Validate: valid=%v locked=%v", r.Valid(), r.Locked)
			}
		})
	}
}
