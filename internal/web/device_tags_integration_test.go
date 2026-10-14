//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// AC10 (F3-016): the personal → tagged conversion against real database-mode Headscale v0.29.4
// (disposable hsstack fixture), driven through the production handler and executor. The test
// asserts what was observed (see the Kanıt of the task and stack-notes): SetTags replaces the set,
// the read-back is in the audit row, and the node ends up tagged, which is what the reconcile's
// expiry rule keys on (AC9).
func TestTags_Integration_OwnershipAfterSetTags(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()
	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	auditor := audit.New(s.Queries())
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: auditor, Store: s.Queries()})
	csrf := testCSRF(t)
	handler, err := NewDeviceTagsHandler(DeviceTagsConfig{
		Nodes: c, Policy: h.Client(), Setter: c, Executor: ex, DryRun: &fakeDryRunReader{}, CSRF: csrf,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	chain := RequireDevops(csrf.Protect(mux))
	tags := &tagsHarness{csrf: csrf, chain: chain}

	h.CreateUser(t, "ops")
	id := h.NewNode(t, "ops", "laptop", "")
	node := func() admin.AdminNode {
		nodes, err := c.ListNodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nodes {
			if n.ID == id {
				return n
			}
		}
		t.Fatalf("node %d missing", id)
		return admin.AdminNode{}
	}
	// Give the node a real expiry so "SetTags leaves the expiry alone" is observed on a value.
	if _, err := c.ExpireNode(ctx, id, time.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("ExpireNode: %v", err)
	}
	before := node()
	if before.Expiry == nil {
		t.Fatal("fixture node has no expiry after setting one")
	}
	t.Logf("before: user=%d/%q tags=%v expiry=%v", before.UserID, before.UserName, before.Tags, before.Expiry)
	if len(before.Tags) != 0 || before.UserID == 0 {
		t.Fatalf("fixture node is not personal: %+v", before)
	}

	form := func(step string) url.Values {
		v := url.Values{}
		v.Set("version", hsadmin.NodeVersion(before))
		v.Add("tag", "tag:server")
		if step != "" {
			v.Set("step", step)
			v.Set("confirm_name", before.GivenName)
			v.Set("confirm", "on")
		}
		return v
	}
	if rec := tags.get(id); rec.Code != http.StatusOK {
		t.Fatalf("warning page status = %d", rec.Code)
	}
	if rec := tags.post(id, form("")); rec.Code != http.StatusOK || node().UserID != before.UserID || len(node().Tags) != 0 {
		t.Fatalf("step 1 must not convert: status %d, node %+v", rec.Code, node())
	}
	if rec := tags.post(id, form("convert")); rec.Code != http.StatusOK {
		t.Fatalf("convert status = %d: %s", rec.Code, rec.Body)
	}

	after := node()
	t.Logf("after: user=%d/%q tags=%v expiry=%v", after.UserID, after.UserName, after.Tags, after.Expiry)
	if !slices.Equal(after.Tags, []string{"tag:server"}) {
		t.Errorf("tags = %v, want [tag:server]", after.Tags)
	}
	// What the reconcile's Y-04 rule and the device list key on: tagged means tag'li.
	if len(after.Tags) == 0 {
		t.Errorf("node is not tagged after the conversion")
	}
	if (before.Expiry == nil) != (after.Expiry == nil) || (before.Expiry != nil && !before.Expiry.Equal(*after.Expiry)) {
		t.Errorf("expiry changed: %v → %v (R2 B-04 says SetTags leaves it alone)", before.Expiry, after.Expiry)
	}

	evs, err := auditor.List(ctx, audit.Filter{Limit: 10})
	if err != nil || len(evs) != 2 {
		t.Fatalf("audit rows = %d, %v", len(evs), err)
	}
	applied := evs[0] // newest first
	if applied.Result != "applied" {
		t.Fatalf("result = %q", applied.Result)
	}
	for field, want := range map[string]string{
		"observed.user_id": itoa(after.UserID),
		"observed.expiry":  expiryAudit(after.Expiry),
	} {
		if c, ok := diffField(applied.Diff, field); !ok || c.After != want {
			t.Errorf("audit %s = %+v (present %v), want after %q", field, c, ok, want)
		}
	}
	if c, _ := diffField(applied.Diff, "observed.ownership"); c.Before != "personal" || c.After != "tagged" {
		t.Errorf("audit observed.ownership = %+v", c)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
