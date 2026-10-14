// F3b-024: lab-only admin fixtures that create OIDC-linked Headscale users and nodes in the host
// lab, so the reconciler sees the same users the lab Zitadel holds. Headscale has no CLI/gRPC for
// the provider identifier or the advertised routes, so they are patched into the container's SQLite
// file (the method hsstack uses for a disposable Headscale, F1-005). These helpers never touch
// production (ADR 0014): the lab Zitadel is only an OIDC issuer here.
package hostlab

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// HeadscaleDBInLab is the lab Headscale SQLite file the provider-identifier and route patches open.
const HeadscaleDBInLab = "/var/lib/headscale/db.sqlite"

// CreateUser creates a Headscale user in the lab and deletes it (with any node that references it)
// when the test ends.
func (l *Lab) CreateUser(t testing.TB, name string) uint64 {
	t.Helper()
	resp, err := l.api.CreateUser(context.Background(), &v1.CreateUserRequest{Name: name})
	if err != nil {
		t.Fatalf("hostlab: CreateUser %s: %v", name, err)
	}
	id := resp.GetUser().GetId()
	t.Cleanup(func() { l.deleteUser(t, name) })
	return id
}

// deleteUser removes the user's nodes and the user itself; it reports (but does not fail) clean-up
// problems so a leaked lab user is visible rather than silently polluting the next scenario.
func (l *Lab) deleteUser(t testing.TB, name string) {
	ctx := context.Background()
	if nodes, err := l.api.ListNodes(ctx, &v1.ListNodesRequest{User: name}); err == nil {
		for _, n := range nodes.GetNodes() {
			if _, derr := l.api.DeleteNode(ctx, &v1.DeleteNodeRequest{NodeId: n.GetId()}); derr != nil {
				t.Logf("hostlab: delete node %d of %s: %v", n.GetId(), name, derr)
			}
		}
	} else {
		t.Logf("hostlab: list nodes of %s: %v", name, err)
	}
	if users, err := l.api.ListUsers(ctx, &v1.ListUsersRequest{}); err == nil {
		for _, u := range users.GetUsers() {
			if u.GetName() == name {
				if _, derr := l.api.DeleteUser(ctx, &v1.DeleteUserRequest{Id: u.GetId()}); derr != nil {
					t.Errorf("hostlab: delete user %s (%d): %v", name, u.GetId(), derr)
				}
			}
		}
	} else {
		t.Logf("hostlab: list users while deleting %s: %v", name, err)
	}
}

// SetProviderID stops Headscale, writes the user's provider identifier directly into its SQLite
// file (there is no CLI/gRPC for it) and starts it again; it waits for /health.
func (l *Lab) SetProviderID(t testing.TB, name, providerID string) {
	t.Helper()
	sql := fmt.Sprintf("UPDATE users SET provider='oidc', provider_identifier=%s WHERE name=%s;",
		sqlQuote(providerID), sqlQuote(name))
	l.patchDB(t, sql)
}

// SetNodeRoutableIPs stops Headscale, patches the node's hostinfo RoutableIPs directly in its
// SQLite file (a DebugCreateNode node announces no routes; the RPC's routes field only fills the
// echo response) and starts it again. Headscale derives available_routes from hostinfo at read time.
func (l *Lab) SetNodeRoutableIPs(t testing.TB, nodeName string, prefixes []string) {
	t.Helper()
	b, err := json.Marshal(prefixes)
	if err != nil {
		t.Fatalf("hostlab: marshal routes: %v", err)
	}
	sql := fmt.Sprintf(
		"UPDATE nodes SET host_info = json_set(COALESCE(NULLIF(host_info,''),'{}'), '$.RoutableIPs', json(%s)) WHERE given_name=%s OR hostname=%s;",
		sqlQuote(string(b)), sqlQuote(nodeName), sqlQuote(nodeName))
	l.patchDB(t, sql)
}

// patchDB stops Headscale, checkpoints, runs sql, starts it again and waits for /health. Even when
// sqlite3 fails Headscale is started again: a failed patch must not leave the lab without a control
// plane (F3b-027 AC6).
func (l *Lab) patchDB(t testing.TB, sql string) {
	t.Helper()
	if err := l.PatchDBErr(t, sql); err != nil {
		t.Fatalf("hostlab: patch DB: %v", err)
	}
}

// PatchDBErr is patchDB that returns the sqlite3 error instead of failing, so a test can drive the
// failure path: Headscale is restarted and healthy either way (F3b-027 AC6).
func (l *Lab) PatchDBErr(t testing.TB, sql string) error {
	t.Helper()
	l.Exec(t, "systemctl", "stop", "headscale.service")
	_, sqlErr := l.ExecErr("sqlite3", HeadscaleDBInLab, "PRAGMA wal_checkpoint(TRUNCATE);"+sql)
	// The root-run sqlite3 may leave root-owned WAL/journal files; Headscale runs as "headscale".
	l.Exec(t, "sh", "-c", "chown headscale:headscale "+HeadscaleDBInLab+"* ; chmod 0644 "+HeadscaleDBInLab)
	// A scenario restarts Headscale once per linked user; without clearing systemd's start rate-limit
	// counter the burst trips "start-limit-hit" (DefaultStartLimitBurst=5 per 10s). reset-failed clears
	// the counter, as WriteConfig already does for its own restart.
	l.Exec(t, "systemctl", "reset-failed", "headscale.service")
	l.Exec(t, "systemctl", "start", "headscale.service")
	WaitHealth(t, l)
	return sqlErr
}

// NewNode registers a throwaway node under a Headscale user in the lab, optionally tagged, and
// deletes it when the test ends.
func (l *Lab) NewNode(t testing.TB, userName, name, tag string) uint64 {
	t.Helper()
	ctx := context.Background()
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	key := "hskey-authreq-" + fmt.Sprintf("%x", buf)
	if _, err := l.api.DebugCreateNode(ctx, &v1.DebugCreateNodeRequest{User: userName, Key: key, Name: name}); err != nil {
		t.Fatalf("hostlab: DebugCreateNode: %v", err)
	}
	resp, err := l.api.RegisterNode(ctx, &v1.RegisterNodeRequest{User: userName, Key: key})
	if err != nil {
		t.Fatalf("hostlab: RegisterNode: %v", err)
	}
	id := resp.GetNode().GetId()
	if tag != "" {
		if _, err := l.api.SetTags(ctx, &v1.SetTagsRequest{NodeId: id, Tags: []string{tag}}); err != nil {
			t.Fatalf("hostlab: SetTags: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = l.api.DeleteNode(context.Background(), &v1.DeleteNodeRequest{NodeId: id}) })
	return id
}

// sqlQuote single-quotes a value for SQLite.
func sqlQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

// PreAuthKeyCount returns how many pre-auth keys the lab Headscale holds.
func (l *Lab) PreAuthKeyCount(t testing.TB) int {
	t.Helper()
	resp, err := l.api.ListPreAuthKeys(context.Background(), &v1.ListPreAuthKeysRequest{})
	if err != nil {
		t.Fatalf("hostlab: ListPreAuthKeys: %v", err)
	}
	return len(resp.GetPreAuthKeys())
}

// ApprovedRoutes returns the approved routes of the node.
func (l *Lab) ApprovedRoutes(t testing.TB, id uint64) []string {
	t.Helper()
	resp, err := l.api.ListNodes(context.Background(), &v1.ListNodesRequest{})
	if err != nil {
		t.Fatalf("hostlab: ListNodes: %v", err)
	}
	for _, n := range resp.GetNodes() {
		if n.GetId() == id {
			return n.GetApprovedRoutes()
		}
	}
	t.Fatalf("hostlab: node %d is gone", id)
	return nil
}
