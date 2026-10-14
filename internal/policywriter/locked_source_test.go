package policywriter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
)

// F3-020 AC5: a LockedSource is read on every save/preview, so changed locked test parameters apply
// to the next operation without a restart; an unreadable source stops the operation (rule 7).
func TestPolicyWriter_LockedSourceReadPerOperation(t *testing.T) {
	e := newEnv(t)
	cfg := policydoc.DefaultLockedConfig(9000)
	var srcErr error
	w, err := New(Config{
		Evaluator: e.rec, Pipeline: e.pipe, Revisions: e.revs, Checker: e.hs,
		LockedSource: func(context.Context) (policydoc.LockedConfig, error) { return cfg, srcErr },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := SaveRequest{Actor: devops, Text: e.live, BaseHash: policyrev.HashRaw(e.live)}

	res, err := w.Preview(context.Background(), req)
	if err != nil || !strings.Contains(res.Text, `"tag:vpn-server:443"] }`) {
		t.Fatalf("first preview = %v, text lacks the 443 rule:\n%s", err, res.Text)
	}

	cfg.UIPort = 8443
	res, err = w.Preview(context.Background(), req)
	if err != nil {
		t.Fatalf("second preview: %v", err)
	}
	if !strings.Contains(res.Text, `{ /* tagcess:locked */ "src": "group:devops", "accept": ["tag:vpn-server:8443"] }`) {
		t.Errorf("new UI port not injected:\n%s", res.Text)
	}

	srcErr = errors.New("settings unreadable")
	before := len(e.hs.Sets())
	if _, err := w.Save(context.Background(), req); err == nil {
		t.Fatal("Save succeeded with an unreadable locked source")
	}
	if len(e.hs.Sets()) != before {
		t.Error("a policy was written although the locked source failed")
	}
}

func TestPolicyWriter_LockedConfigRequired(t *testing.T) {
	e := newEnv(t)
	_, err := New(Config{Evaluator: e.rec, Pipeline: e.pipe, Revisions: e.revs, Checker: e.hs})
	if err == nil {
		t.Fatal("New accepted a config with neither Locked nor LockedSource")
	}
}
