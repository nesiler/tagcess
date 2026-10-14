//go:build integration

// Integration tests for F1-006 against the local compose Headscale (`make lab-up`, then `make lab-integration` or
// `go test -tags=integration ./internal/headscale/...`).
//
// Headscale's gRPC unix socket lives in a container. On OrbStack a bind-mounted socket is visible on
// the macOS host but connect() is refused, so the stack runs a socat relay (`headscale-relay`,
// test/compose/compose.yaml) that publishes it on 127.0.0.1:50444; TAGCESS_HEADSCALE_TARGET
// overrides that address, for example with a real socket path on a Linux CI host.
package headscale_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/test/compose/seed"
)

const testPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

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

// rawAPI is the generated client, used only to set up and remove test nodes; the package under
// test deliberately cannot do either.
func rawAPI(t *testing.T) v1.HeadscaleServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(target(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return v1.NewHeadscaleServiceClient(conn)
}

// newNode registers a throwaway node under the seeded user and deletes it at cleanup.
func newNode(t *testing.T) uint64 {
	t.Helper()
	api := rawAPI(t)
	ctx := context.Background()
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	key := "hskey-authreq-" + hex.EncodeToString(buf) // 14 + 24 = the 38 characters Headscale requires
	name := "f1006-" + hex.EncodeToString(buf[:4])
	if _, err := api.DebugCreateNode(ctx, &v1.DebugCreateNodeRequest{User: seed.HeadscaleUserName, Key: key, Name: name}); err != nil {
		t.Fatalf("DebugCreateNode: %v", err)
	}
	resp, err := api.RegisterNode(ctx, &v1.RegisterNodeRequest{User: seed.HeadscaleUserName, Key: key})
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	id := resp.GetNode().GetId()
	t.Cleanup(func() { _, _ = api.DeleteNode(context.Background(), &v1.DeleteNodeRequest{NodeId: id}) })
	return id
}

// TestHeadscale_Read is AC1: policy, users and nodes come back from the compose Headscale.
func TestHeadscale_Read(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	id := newNode(t)

	if _, err := c.GetPolicy(ctx); err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundUser := false
	for _, u := range users {
		if u.Name == seed.HeadscaleUserName {
			foundUser = true
		}
	}
	if !foundUser {
		t.Errorf("seeded user %q not in %+v", seed.HeadscaleUserName, users)
	}
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundNode := false
	for _, n := range nodes {
		if n.ID == id {
			foundNode = true
			if n.UserName != seed.HeadscaleUserName {
				t.Errorf("node user = %q", n.UserName)
			}
		}
	}
	if !foundNode {
		t.Errorf("node %d not in %+v", id, nodes)
	}
}

// TestHeadscale_CheckPolicyRejects is AC2: Headscale's own message comes back, and SetPolicy is
// not reached. The stack runs Headscale in policy.mode=file, where a SetPolicy that got through the
// check would fail with a plain error; getting a *PolicyError from SetPolicy shows the check stopped
// it first, and the unchanged policy shows nothing was written.
func TestHeadscale_CheckPolicyRejects(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	if err := c.CheckPolicy(ctx, testPolicy); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	bad := `{"acls":[{"action":"accept","src":["group:nobody"],"dst":["*:*"]}]}`
	err := c.CheckPolicy(ctx, bad)
	var pe *headscale.PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("CheckPolicy(bad) = %v, want *PolicyError", err)
	}
	if !strings.Contains(pe.Message, "group:nobody") {
		t.Errorf("message does not carry Headscale's text: %q", pe.Message)
	}

	before, err := c.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SetPolicy(ctx, bad)
	if !errors.As(err, &pe) {
		t.Fatalf("SetPolicy(bad) = %v, want *PolicyError", err)
	}
	after, err := c.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("policy changed by a rejected SetPolicy: %+v -> %+v", before, after)
	}
}

// TestHeadscale_ExpireNode is AC3: after ExpireNode the node's expiry, read back with ListNodes, is
// in the past.
func TestHeadscale_ExpireNode(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	id := newNode(t)

	nodes, err := c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID == id && n.Expiry != nil && n.Expiry.Before(time.Now()) {
			t.Fatalf("node %d already expired before the call", id)
		}
	}
	if _, err := c.ExpireNode(ctx, id); err != nil {
		t.Fatalf("ExpireNode: %v", err)
	}
	nodes, err = c.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID != id {
			continue
		}
		if n.Expiry == nil || n.Expiry.After(time.Now()) {
			t.Fatalf("expiry after ExpireNode = %v, want in the past", n.Expiry)
		}
		return
	}
	t.Fatalf("node %d disappeared", id)
}
