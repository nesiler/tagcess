//go:build integration

package web

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// keysStack is the key service over a disposable database-mode Headscale (hsstack).
type keysStack struct {
	hs  *hsstack.Stack
	c   *admin.AdminClient
	svc *KeysService
}

func newKeysStack(t *testing.T) *keysStack {
	t.Helper()
	h := hsstack.Start(t)
	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(s.Queries()), Store: s.Queries()})
	svc, err := NewKeysService(KeysServiceConfig{Admin: c, Policy: h.Client(), Exec: ex})
	if err != nil {
		t.Fatal(err)
	}
	return &keysStack{hs: h, c: c, svc: svc}
}

func (k *keysStack) key(t *testing.T, id uint64) (admin.PreAuthKey, bool) {
	t.Helper()
	keys, err := k.c.ListPreAuthKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key.ID == id {
			return key, true
		}
	}
	return admin.PreAuthKey{}, false
}

// AC3 on real Headscale: deleting a key through the confirmed flow removes the key and leaves the
// device that exists for its user alone.
func TestPreAuth_Integration_DeleteKeepsNodes(t *testing.T) {
	k := newKeysStack(t)
	ctx := context.Background()
	uid := k.hs.CreateUser(t, "alice")
	node := k.hs.NewNode(t, "alice", "alice-laptop", "")
	pk, _, err := k.c.CreatePreAuthKey(ctx, uid, admin.PreAuthKeyOptions{Expiration: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	confirm, err := k.svc.Confirm(ctx, pk.ID, "delete")
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	out := k.svc.Delete(ctx, "devops@example.com", pk.ID, confirm.Version)
	if out.Status != keyApplied {
		t.Fatalf("Delete = %+v", out)
	}
	if _, found := k.key(t, pk.ID); found {
		t.Error("key still listed after delete")
	}
	nodes, err := k.c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var kept bool
	for _, n := range nodes {
		kept = kept || n.ID == node
	}
	if !kept {
		t.Errorf("node %d was deleted with the key", node)
	}
}

// AC8 on real Headscale: a tagged key made through the service lists with its tags; the accepted
// user/tag combination is pinned: a tagged key needs no user (user 0, the nodes it registers are
// owned by their tags), a key with neither tags nor a user is refused by Headscale, and a user
// together with tags is accepted too.
func TestTagKey_Integration_AcceptedCombination(t *testing.T) {
	k := newKeysStack(t)
	ctx := context.Background()

	out := k.svc.CreateTagKey(ctx, "devops@example.com", TagKeyInput{Tags: []string{"tag:server"}, ExpiresIn: "2h"})
	if out.Status != keyApplied || !strings.HasPrefix(out.Secret, "hskey-auth-") {
		t.Fatalf("CreateTagKey = %+v", out)
	}
	key, found := k.key(t, out.KeyID)
	if !found {
		t.Fatalf("key %d not listed", out.KeyID)
	}
	if len(key.Tags) != 1 || key.Tags[0] != "tag:server" || key.UserID != 0 || key.Reusable || key.Ephemeral || key.Used {
		t.Errorf("listed key = %+v", key)
	}
	if key.Expiration == nil || time.Until(*key.Expiration) < time.Hour || time.Until(*key.Expiration) > 2*time.Hour+time.Minute {
		t.Errorf("expiration = %v, want about 2h from now", key.Expiration)
	}
	if v := k.svc.Keys(ctx); v.Err != nil || len(v.Rows) != 1 || v.Rows[0].Owner != "tag'li" || len(v.Rows[0].Tags) != 1 {
		t.Errorf("Keys view = %+v", v)
	}

	// A tag the policy does not own is refused before any RPC.
	if out := k.svc.CreateTagKey(ctx, "devops@example.com", TagKeyInput{Tags: []string{"tag:ghost"}}); out.Status != keyRefused {
		t.Errorf("unknown tag = %+v", out)
	}

	// The combinations Headscale itself accepts (documented in stack-notes).
	raw := k.hs.Raw()
	uid := k.hs.CreateUser(t, "ops")
	exp := timestamppb.New(time.Now().Add(time.Hour))
	if _, err := raw.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{User: uid, AclTags: []string{"tag:server"}, Expiration: exp}); err != nil {
		t.Errorf("user + tags refused: %v", err)
	}
	if _, err := raw.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{Expiration: exp}); err == nil {
		t.Error("no user and no tags accepted")
	}
}
