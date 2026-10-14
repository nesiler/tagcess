//go:build integration

package hsadmin_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// TestExecutor_Integration_ProtectedNode runs the executor against real Headscale v0.29.4 in the
// disposable hsstack fixture: a rename goes through with a verified read-back, deleting a server
// tagged node is refused without touching it, and deleting a personal node works.
func TestExecutor_Integration_ProtectedNode(t *testing.T) {
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
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(s.Queries()), Store: s.Queries()})
	// The fixture policy only knows tag:server, so that is the protected tag here.
	if err := s.Queries().UpsertSetting(ctx, db.UpsertSettingParams{Key: hsadmin.ProtectedTagsKey, Value: `["tag:server"]`, UpdatedAt: "2026-10-01T00:00:00.000Z"}); err != nil {
		t.Fatal(err)
	}

	h.CreateUser(t, "ops")
	server := h.NewNode(t, "ops", "gw", "")
	personal := h.NewNode(t, "ops", "laptop", "")
	if _, err := c.SetTags(ctx, server, []string{"tag:server"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}

	version := func(id uint64) admin.AdminNode {
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
	gone := func(ctx context.Context, r hsadmin.Reader, id uint64) (bool, error) {
		nodes, err := r.ListNodes(ctx)
		if err != nil {
			return false, err
		}
		for _, n := range nodes {
			if n.ID == id {
				return false, nil
			}
		}
		return true, nil
	}

	// Rename the protected node: allowed, verified by read-back.
	n := version(server)
	res, err := ex.Do(ctx, hsadmin.Op{
		Actor: "devops@example.com", Kind: hsadmin.KindNodeRename, ID: server, Target: "node:gw",
		Expected: hsadmin.NodeVersion(n),
		Apply:    func(ctx context.Context) error { _, err := c.RenameNode(ctx, server, "gw-renamed"); return err },
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) {
			nodes, err := r.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, x := range nodes {
				if x.ID == server {
					return x.GivenName == "gw-renamed", nil
				}
			}
			return false, nil
		},
	})
	if err != nil || res.Status != hsadmin.StatusApplied {
		t.Fatalf("rename: %+v, %v", res, err)
	}

	// Delete the protected node: refused, node untouched.
	n = version(server)
	_, err = ex.Do(ctx, hsadmin.Op{
		Actor: "devops@example.com", Kind: hsadmin.KindNodeDelete, ID: server, Target: "node:gw-renamed",
		Expected: hsadmin.NodeVersion(n),
		Apply:    func(ctx context.Context) error { return c.DeleteNode(ctx, server) },
		Verify:   func(ctx context.Context, r hsadmin.Reader) (bool, error) { return gone(ctx, r, server) },
	})
	if !errors.Is(err, hsadmin.ErrBlocked) {
		t.Fatalf("delete protected: err = %v, want ErrBlocked", err)
	}
	version(server) // still there

	// Delete the personal node: applied.
	n = version(personal)
	res, err = ex.Do(ctx, hsadmin.Op{
		Actor: "devops@example.com", Kind: hsadmin.KindNodeDelete, ID: personal, Target: "node:laptop",
		Expected: hsadmin.NodeVersion(n),
		Apply:    func(ctx context.Context) error { return c.DeleteNode(ctx, personal) },
		Verify:   func(ctx context.Context, r hsadmin.Reader) (bool, error) { return gone(ctx, r, personal) },
	})
	if err != nil || res.Status != hsadmin.StatusApplied {
		t.Fatalf("delete personal: %+v, %v", res, err)
	}
}

// TestExecutor_Integration_MaintenanceGate (F3b-014 AC6): with the maintenance open, a pre-auth key
// create is refused and no key appears in the real Headscale, while an expire-now on a node still
// lands there.
func TestExecutor_Integration_MaintenanceGate(t *testing.T) {
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
	maint := maintenance.New(s.Queries())
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(s.Queries()), Store: s.Queries(), Maintenance: maint})

	userID := h.CreateUser(t, "ops")
	node := h.NewNode(t, "ops", "laptop", "")
	if _, err := maint.Start(ctx, "req-1", "devops@example.com"); err != nil {
		t.Fatal(err)
	}

	keysBefore, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Do(ctx, hsadmin.Op{
		Actor: "devops@example.com", Kind: hsadmin.KindPreAuthCreate, Target: "preauth:new",
		Apply: func(ctx context.Context) error {
			_, _, err := c.CreatePreAuthKey(ctx, userID, admin.PreAuthKeyOptions{})
			return err
		},
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) { return true, nil },
	})
	if !errors.Is(err, hsadmin.ErrMaintenance) || res.Status != hsadmin.StatusBlocked {
		t.Fatalf("preauth.create: %+v, %v; want blocked by maintenance", res, err)
	}
	keysAfter, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keysAfter) != len(keysBefore) {
		t.Fatalf("pre-auth keys %d -> %d; the refused create reached Headscale", len(keysBefore), len(keysAfter))
	}

	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var n admin.AdminNode
	for _, x := range nodes {
		if x.ID == node {
			n = x
		}
	}
	now := time.Now()
	res, err = ex.Do(ctx, hsadmin.Op{
		Actor: "devops@example.com", Kind: hsadmin.KindNodeExpire, ID: node, Target: "node:laptop",
		Expected: hsadmin.NodeVersion(n),
		Apply:    func(ctx context.Context) error { _, err := c.ExpireNode(ctx, node, now); return err },
		Verify: func(ctx context.Context, r hsadmin.Reader) (bool, error) {
			ns, err := r.ListNodes(ctx)
			if err != nil {
				return false, err
			}
			for _, x := range ns {
				if x.ID == node {
					return x.Expiry != nil && !x.Expiry.After(now.Add(time.Second)), nil
				}
			}
			return false, nil
		},
	})
	if err != nil || res.Status != hsadmin.StatusApplied {
		t.Fatalf("node.expire: %+v, %v; want applied", res, err)
	}
	if exp := h.NodeExpiry(t, node); exp == nil || exp.After(now.Add(time.Second)) {
		t.Fatalf("node expiry = %v, want expired", exp)
	}
}
