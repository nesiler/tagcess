//go:build integration

// Integration test for F1-010 (AC1) against the local compose Headscale, reached through the relay
// (see internal/headscale/client_integration_test.go). Run `make lab-up` first, then
// `go test -tags=integration ./internal/change/...` or `make lab-integration`.
package change_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/store"
)

func target() string {
	if t := os.Getenv("TAGCESS_HEADSCALE_TARGET"); t != "" {
		return t
	}
	return "127.0.0.1:50444"
}

func canonical(t *testing.T, policy string) any {
	t.Helper()
	root, err := hujson.Parse([]byte(policy))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	root.Standardize()
	var v any
	if err := json.Unmarshal(root.Pack(), &v); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return v
}

// TestApply_HappyPath drives a real policy through CheckPolicy -> SetPolicy -> GetPolicy on the
// compose Headscale and records the change, the audit event and the sync run.
func TestApply_HappyPath(t *testing.T) {
	ctx := context.Background()
	hs, err := headscale.New(headscale.Config{Target: target(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Close() })

	before, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}

	// Apply needs policy.mode=database; the shared compose stack runs in file mode until the G-02
	// runbook is applied (F1-023). Probe once and skip instead of failing the whole suite.
	if _, err := hs.SetPolicy(ctx, before.Text); err != nil {
		if strings.Contains(err.Error(), "update is disabled for modes other than") {
			t.Skipf("compose Headscale runs in policy file mode: %v", err)
		}
		t.Fatalf("SetPolicy probe: %v", err)
	}
	t.Cleanup(func() {
		if _, err := hs.SetPolicy(context.Background(), before.Text); err != nil {
			t.Errorf("restore policy: %v", err)
		}
	})

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.DB().ExecContext(ctx, `UPDATE settings SET value = 'false' WHERE key = 'dry_run'`); err != nil {
		t.Fatalf("turn off dry run: %v", err)
	}
	p := change.New(hs, s.Queries(), audit.New(s.Queries()), s)

	// The same policy with a trailing comment: a real byte change that stays semantically valid.
	target := before.Text + "\n// tagcess integration\n"
	res, err := p.Submit(ctx, change.Request{
		Kind:    change.KindPolicy,
		Actor:   "system:sync",
		Trigger: "manual",
		Summary: "integration",
		Target:  []byte(target),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !res.Applied || res.Status != change.StatusApplied {
		t.Fatalf("result = %+v, want applied", res)
	}

	got, err := hs.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy after apply: %v", err)
	}
	if !reflect.DeepEqual(canonical(t, got.Text), canonical(t, target)) {
		t.Fatalf("policy not applied:\n got %s\nwant %s", got.Text, target)
	}

	// The run is recorded: an applied change, an applied sync run and the apply audit event.
	for _, tc := range []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM changes WHERE status = 'applied'`, 1},
		{`SELECT count(*) FROM sync_runs WHERE result = 'applied'`, 1},
		{`SELECT count(*) FROM audit_events WHERE event = 'policy.apply'`, 1},
	} {
		var n int
		if err := s.DB().QueryRowContext(ctx, tc.query).Scan(&n); err != nil {
			t.Fatalf("count %q: %v", tc.query, err)
		}
		if n != tc.want {
			t.Errorf("%s = %d, want %d", tc.query, n, tc.want)
		}
	}
}
