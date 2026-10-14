// F3b-023: exported host-lab request/result helpers, so a test outside this package (the groups-claim
// matrix) can drive the helper over the bind-mounted directories the way F3b-003 does. They publish
// `requests/<UUID>.json` and `requests/request.ready` (ADR 0021 b) and read `results/result.json` /
// `results/status.json` back. Lab-only, like the rest of this package.
package hostlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/hshelper"
)

// NewRequestID returns a fresh lowercase (v4) UUID for a helper request.
func NewRequestID(t testing.TB) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("hostlab: uuid: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	id := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", id[0:8], id[8:12], id[12:16], id[16:20], id[20:32])
}

// PublishRequest writes a valid request for id with base_rev from the live config: the request file
// first, then requests/request.ready by atomic rename (ADR 0021 b). The live config must already have
// a helper installed and be readable.
func PublishRequest(t testing.TB, lab *Lab, id string, groups []string) {
	t.Helper()
	_, rev, err := hshelper.Project(ConfigBytes(t, lab))
	if err != nil {
		t.Fatalf("hostlab: project live config: %v", err)
	}
	doc, err := hostpatch.BuildRequest(id, rev, groups)
	if err != nil {
		t.Fatalf("hostlab: build request: %v", err)
	}
	if err := os.WriteFile(filepath.Join(lab.RequestsDir(), id+".json"), doc, 0o644); err != nil { //nolint:gosec // G306: the F3b-003 fixture publishes request files 0644
		t.Fatalf("hostlab: write request: %v", err)
	}
	marker := filepath.Join(lab.RequestsDir(), "request.ready")
	tmp := marker + ".tmp"
	if err := os.WriteFile(tmp, []byte(id), 0o644); err != nil { //nolint:gosec // G306: the F3b-003 fixture publishes the marker 0644
		t.Fatalf("hostlab: write marker: %v", err)
	}
	if err := os.Rename(tmp, marker); err != nil {
		t.Fatalf("hostlab: publish marker: %v", err)
	}
}

// WaitResult waits until results/result.json carries id and returns it.
func WaitResult(t testing.TB, lab *Lab, id string) hostpatch.Result {
	t.Helper()
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(lab.ResultsDir(), "result.json")); err == nil {
			if r, derr := hostpatch.DecodeResult(b); derr == nil && r.RequestID == id {
				return r
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("hostlab: no result.json for %s within 150s", id)
	return hostpatch.Result{}
}

// WaitStatusFor waits until results/status.json projects rev with no config_error and returns it.
func WaitStatusFor(t testing.TB, lab *Lab, rev string) hostpatch.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(lab.ResultsDir(), "status.json")); err == nil {
			if s, derr := hostpatch.DecodeStatus(b); derr == nil && s.BaseRev == rev && s.ConfigError == "" {
				return s
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("hostlab: status.json did not show base_rev %s within 30s", rev)
	return hostpatch.Status{}
}

// DeleteNodesWithPrefix deletes every lab node whose name or given name starts with prefix. It is the
// matrix's clean-up: the nodes are created by real OIDC logins, so nothing else removes them.
func (l *Lab) DeleteNodesWithPrefix(t testing.TB, prefix string) {
	t.Helper()
	ctx := context.Background()
	nodes, err := l.api.ListNodes(ctx, &v1.ListNodesRequest{})
	if err != nil {
		t.Logf("hostlab: list nodes for clean-up: %v", err)
		return
	}
	for _, n := range nodes.GetNodes() {
		if !strings.HasPrefix(n.GetName(), prefix) && !strings.HasPrefix(n.GetGivenName(), prefix) {
			continue
		}
		if _, err := l.api.DeleteNode(ctx, &v1.DeleteNodeRequest{NodeId: n.GetId()}); err != nil {
			t.Errorf("hostlab: delete node %d (%s): %v", n.GetId(), n.GetName(), err)
		}
	}
}
