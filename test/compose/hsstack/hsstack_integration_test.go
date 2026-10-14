//go:build integration

// Docker-backed tests of the hsstack fixture (F3-003 AC1–AC4). They need only local Docker; run
// them with `make lab-integration` or `go test -tags=integration ./test/compose/hsstack/...`.
package hsstack

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	"github.com/nesiler/tagcess/internal/headscale"
)

// TestHSStack_StartsDatabaseMode is AC1: Start brings up a database-mode Headscale v0.29.4 on
// loopback, waits until it is healthy, proves SetPolicy is accepted (refused in file mode) and
// hands out the narrow F1 client and the raw gRPC client.
func TestHSStack_StartsDatabaseMode(t *testing.T) {
	s := Start(t)

	if img := containerImage(t, s.name); img != Image {
		t.Errorf("headscale container runs %q, want %q", img, Image)
	}
	// SetPolicy was accepted while Start waited (file mode refuses it), and the policy is readable
	// back through the narrow client.
	groups := s.PolicyGroups(t)
	if _, ok := groups["group:devops"]; !ok {
		t.Errorf("applied baseline policy has no group:devops: %v", groups)
	}
	// Both clients work: the narrow one answered ListUsers, the raw one answers too.
	if _, err := s.Raw().ListUsers(context.Background(), &v1.ListUsersRequest{}); err != nil {
		t.Errorf("raw gRPC client ListUsers: %v", err)
	}
	if users, err := s.Client().ListUsers(context.Background()); err != nil || len(users) != 0 {
		t.Errorf("narrow client ListUsers = %v, %v; want no users", users, err)
	}
}

// TestHSStack_ParallelFixtures is AC2: two fixtures at the same time must not fight over ports or
// names and both must stay up with separate databases.
func TestHSStack_ParallelFixtures(t *testing.T) {
	a := Start(t)
	b := Start(t)

	if a.GRPCAddr() == b.GRPCAddr() {
		t.Errorf("both fixtures use relay address %s", a.GRPCAddr())
	}
	if a.name == b.name || a.relay == b.relay || a.volume == b.volume {
		t.Errorf("container/volume names collide: %s/%s vs %s/%s", a.name, a.volume, b.name, b.volume)
	}
	// Both are alive after the second one is up; the same-named user in each stays in its own DB.
	for _, s := range []*Stack{a, b} {
		s.CreateUser(t, "parallel-user")
		users, err := s.Client().ListUsers(context.Background())
		if err != nil {
			t.Fatalf("ListUsers on %s: %v", s.name, err)
		}
		if len(users) != 1 || users[0].Name != "parallel-user" {
			t.Errorf("fixture %s ListUsers = %+v, want exactly parallel-user", s.name, users)
		}
		if _, ok := s.PolicyGroups(t)["group:devops"]; !ok {
			t.Errorf("fixture %s lost its baseline policy", s.name)
		}
	}
}

// TestHSStack_Helpers is AC3: user creation, provider identifier patching, tagged/untagged node
// registration and pre-auth key generation all work and show up in ListUsers/ListNodes.
func TestHSStack_Helpers(t *testing.T) {
	s := Start(t)
	ctx := context.Background()

	id := s.CreateUser(t, "alice")
	if id == 0 {
		t.Fatal("CreateUser returned id 0")
	}
	s.SetProviderID(t, "alice", "https://zitadel.test/123456")
	users, err := s.Client().ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var alice *headscale.User
	for i := range users {
		if users[i].Name == "alice" {
			alice = &users[i]
		}
	}
	if alice == nil {
		t.Fatalf("user alice not in ListUsers: %+v", users)
	}
	if alice.Provider != "oidc" || alice.ProviderID != "https://zitadel.test/123456" {
		t.Errorf("alice = provider %q, provider id %q; want oidc / https://zitadel.test/123456",
			alice.Provider, alice.ProviderID)
	}

	untagged := s.NewNode(t, "alice", "hs-untagged", "")
	tagged := s.NewNode(t, "alice", "hs-tagged", "tag:server")
	nodes, err := s.Client().ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	byID := map[uint64]headscale.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	if n, ok := byID[untagged]; !ok {
		t.Errorf("untagged node %d not in ListNodes: %+v", untagged, nodes)
	} else if len(n.Tags) != 0 {
		t.Errorf("untagged node has tags %v", n.Tags)
	}
	if n, ok := byID[tagged]; !ok {
		t.Errorf("tagged node %d not in ListNodes: %+v", tagged, nodes)
	} else if len(n.Tags) != 1 || n.Tags[0] != "tag:server" {
		t.Errorf("tagged node has tags %v, want [tag:server]", n.Tags)
	}

	key := s.PreAuthKey(t, "alice", PreAuthKeyOptions{Reusable: true})
	if !strings.HasPrefix(key, "hskey-auth-") {
		t.Errorf("pre-auth key %q does not carry the hskey-auth- prefix", key)
	}
	list, err := s.Raw().ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
	if err != nil {
		t.Fatalf("ListPreAuthKeys: %v", err)
	}
	if len(list.GetPreAuthKeys()) == 0 {
		t.Error("ListPreAuthKeys shows no key after PreAuthKey")
	}
	// Tagged key generation is what the shared-device flow (F3-017) needs.
	if taggedKey := s.PreAuthKey(t, "alice", PreAuthKeyOptions{Tags: []string{"tag:server"}}); taggedKey == "" {
		t.Error("tagged pre-auth key is empty")
	}
}

// TestHSStack_Cleanup is AC4: when the test that started a fixture ends, its containers, relay,
// volume and temp directory are gone.
func TestHSStack_Cleanup(t *testing.T) {
	var s *Stack
	t.Run("start", func(t *testing.T) {
		s = Start(t)
	})
	if s == nil {
		t.Fatal("fixture did not start")
	}
	for _, name := range []string{s.name, s.relay} {
		if out := containersNamed(t, name); len(out) != 0 {
			t.Errorf("container %s still exists after cleanup: %v", name, out)
		}
	}
	if out := volumesNamed(t, s.volume); len(out) != 0 {
		t.Errorf("volume %s still exists after cleanup: %v", s.volume, out)
	}
	if _, err := os.Stat(s.dir); err == nil {
		t.Errorf("temp directory %s still exists after cleanup", s.dir)
	}
}

// Docker listing helpers ------------------------------------------------------

func containerImage(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "--format", "{{.Config.Image}}", name).CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect %s: %v: %s", name, err, out)
	}
	return strings.TrimSpace(string(out))
}

func containersNamed(t *testing.T, name string) []string {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}", "--filter", "name="+name).Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	return splitLines(out)
}

func volumesNamed(t *testing.T, name string) []string {
	t.Helper()
	out, err := exec.Command("docker", "volume", "ls", "--format", "{{.Name}}", "--filter", "name="+name).Output()
	if err != nil {
		t.Fatalf("docker volume ls: %v", err)
	}
	return splitLines(out)
}

func splitLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
