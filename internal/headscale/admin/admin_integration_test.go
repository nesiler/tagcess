//go:build integration

// Integration tests for F3-004 against the disposable database-mode Headscale fixture
// (test/compose/hsstack; Docker required). They verify the destructive RPCs against real
// Headscale v0.29.4: node rename, future expiry, expiry clearing, tags, deletion, and the
// pre-auth/API key lifecycle.
package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

func newAdminClient(t *testing.T, h *hsstack.Stack) *admin.AdminClient {
	t.Helper()
	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func findNode(nodes []admin.AdminNode, id uint64) *admin.AdminNode {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
	}
	return nil
}

func userID(t *testing.T, h *hsstack.Stack, name string) uint64 {
	t.Helper()
	users, err := h.Client().ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == name {
			return u.ID
		}
	}
	t.Fatalf("user %q not found", name)
	return 0
}

// TestAdminClient_Integration_NodeLifecycle is the integration half of AC7: rename, a future
// expiry, clearing the expiry, tags and deletion against real Headscale.
func TestAdminClient_Integration_NodeLifecycle(t *testing.T) {
	h := hsstack.Start(t)
	c := newAdminClient(t, h)
	ctx := context.Background()

	user := "lifecycle-user"
	h.CreateUser(t, user)
	id := h.NewNode(t, user, "lifecycle-node", "")

	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := findNode(nodes, id)
	if n == nil {
		t.Fatalf("node %d not in %+v", id, nodes)
	}
	if n.UserName != user || n.CreatedAt.IsZero() {
		t.Errorf("node = %+v", n)
	}

	// Rename (v0.29.4: RenameNode changes GivenName; Name stays the machine-registered name).
	if _, err := c.RenameNode(ctx, id, "lifecycle-node-2"); err != nil {
		t.Fatalf("RenameNode: %v", err)
	}
	if nodes, err = c.ListNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if n = findNode(nodes, id); n == nil || n.GivenName != "lifecycle-node-2" {
		t.Fatalf("after rename: %+v", n)
	}

	// Expiry at a future date.
	at := time.Now().Add(24 * time.Hour).Round(time.Second)
	if _, err := c.ExpireNode(ctx, id, at); err != nil {
		t.Fatalf("ExpireNode(+24h): %v", err)
	}
	nodes, err = c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n = findNode(nodes, id); n == nil || n.Expiry == nil || n.Expiry.Before(time.Now()) {
		t.Fatalf("after future expiry: expiry = %v, want in the future", n.Expiry)
	}

	// Clearing the expiry (disable_expiry).
	if _, err := c.EnableNode(ctx, id); err != nil {
		t.Fatalf("EnableNode: %v", err)
	}
	if got := h.NodeExpiry(t, id); got != nil {
		t.Fatalf("after EnableNode: expiry = %v, want nil", got)
	}

	// Tags (full list).
	if _, err := c.SetTags(ctx, id, []string{"tag:server"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	nodes, err = c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n = findNode(nodes, id); n == nil || strings.Join(n.Tags, ",") != "tag:server" {
		t.Fatalf("after SetTags: %+v", n)
	}

	// Deletion.
	if err := c.DeleteNode(ctx, id); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	nodes, err = c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if findNode(nodes, id) != nil {
		t.Fatalf("node %d still present after delete: %+v", id, nodes)
	}
}

// TestAdminClient_Integration_Keys is AC8: pre-auth and API keys go through
// create → list → expire → delete against real Headscale, the list never carries the created
// secret, and deleting keys does not delete nodes.
func TestAdminClient_Integration_Keys(t *testing.T) {
	h := hsstack.Start(t)
	c := newAdminClient(t, h)
	ctx := context.Background()

	user := "keys-user"
	h.CreateUser(t, user)
	nodeID := h.NewNode(t, user, "keys-node", "")

	// Pre-auth key: create, the secret comes back exactly once.
	created, secret, err := c.CreatePreAuthKey(ctx, userID(t, h, user), admin.PreAuthKeyOptions{
		Reusable:   true,
		Expiration: time.Now().Add(time.Hour).Round(time.Second),
		Tags:       []string{"tag:server"},
	})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if secret == "" || !strings.HasPrefix(secret, "hskey-auth-") {
		t.Fatalf("secret = %q", secret)
	}
	if created.ID == 0 || created.UserID == 0 || created.Expiration == nil || len(created.Tags) != 1 {
		t.Fatalf("created DTO = %+v", created)
	}

	// List: metadata comes back, the secret does not.
	keys, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("key list carries the secret: %s", blob)
	}
	var found *admin.PreAuthKey
	for i := range keys {
		if keys[i].ID == created.ID {
			found = &keys[i]
		}
	}
	if found == nil || !found.Reusable || found.Expiration == nil {
		t.Fatalf("created key not in the list: %+v", keys)
	}

	// Expire, then list.
	if err := c.ExpirePreAuthKey(ctx, created.ID); err != nil {
		t.Fatalf("ExpirePreAuthKey: %v", err)
	}
	keys, err = c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found = nil
	for i := range keys {
		if keys[i].ID == created.ID {
			found = &keys[i]
		}
	}
	if found == nil || found.Expiration == nil || !found.Expiration.Before(time.Now()) {
		t.Fatalf("after expire: %+v", found)
	}

	// Delete, then list.
	if err := c.DeletePreAuthKey(ctx, created.ID); err != nil {
		t.Fatalf("DeletePreAuthKey: %v", err)
	}
	keys, err = c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID == created.ID {
			t.Fatalf("key %d still listed after delete: %+v", created.ID, keys)
		}
	}

	// API key: created through the raw client (the admin client deliberately cannot create
	// keys), managed through the admin client. The raw response is the full secret string; the
	// fresh fixture holds no other keys, so the created one is identified through the list.
	raw := h.Raw()
	if _, err := raw.CreateApiKey(ctx, &v1.CreateApiKeyRequest{Expiration: timestamppb.New(time.Now().Add(time.Hour))}); err != nil {
		t.Fatalf("raw CreateApiKey: %v", err)
	}
	apiKeys, err := c.ListApiKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apiKeys) != 1 {
		t.Fatalf("api keys = %+v, want exactly the created one", apiKeys)
	}
	apiKey := &apiKeys[0]
	if apiKey.ID == 0 || apiKey.Prefix == "" || apiKey.Expiration == nil {
		t.Fatalf("created api key = %+v", apiKey)
	}
	if err := c.ExpireApiKey(ctx, apiKey.ID); err != nil {
		t.Fatalf("ExpireApiKey: %v", err)
	}
	apiKeys, err = c.ListApiKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apiKeys) != 1 {
		t.Fatalf("api keys after expire = %+v", apiKeys)
	}
	apiKey = &apiKeys[0]
	if apiKey.Expiration == nil || !apiKey.Expiration.Before(time.Now()) {
		t.Fatalf("api key after expire: %+v", apiKey)
	}
	if err := c.DeleteApiKey(ctx, apiKey.ID); err != nil {
		t.Fatalf("DeleteApiKey: %v", err)
	}
	apiKeys, err = c.ListApiKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apiKeys) != 0 {
		t.Fatalf("api keys after delete = %+v, want none", apiKeys)
	}

	// Deleting keys never touches nodes.
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if findNode(nodes, nodeID) == nil {
		t.Fatalf("node %d disappeared after key deletion: %+v", nodeID, nodes)
	}
}
