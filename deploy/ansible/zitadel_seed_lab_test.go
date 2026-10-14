//go:build integration

package installer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/nesiler/tagcess/test/adopttarget"
	"github.com/nesiler/tagcess/test/labenv"
)

// AC7 (F6-006), end to end: the zitadel_seed role builds and runs the real tool against the lab Zitadel (ADR 0014)
// with an isolated project, writes zitadel.json and the new client secret file; the test deletes its own project.
func TestZitadelSeedRoleLab_EndToEnd(t *testing.T) {
	pat := filepath.Join(adopttarget.RepoRoot(), "test", "compose", ".secrets", "lab", "bootstrap-pat")
	if _, err := os.Stat(pat); err != nil {
		t.Skip("lab Zitadel PAT missing: run make lab-up (a skip is not a PASS)")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	project := "vpn-f6test-" + hex.EncodeToString(b)
	home := t.TempDir()
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/zitadel_seed.yml", Inventories: []string{localInventory(t)}, ConfigHome: home,
		Vars: map[string]any{"install_env": "seedlab", "install_mode": "fresh", "tagcess_domain": "f6test.example.test", "vpn_tailnet_ip": "100.64.0.1",
			"zitadel_issuer": labenv.ZitadelIssuer(), "zitadel_admin_pat_file": pat, "zitadel_project_name": project,
			"zitadel_seed_apply": true}})
	var out struct {
		ProjectID   string            `json:"zitadel_project_id"`
		HSClient    string            `json:"headscale_oidc_client_id"`
		SecretFiles map[string]string `json:"secret_files"`
	}
	data, _ := os.ReadFile(filepath.Join(home, "tagcess-install", "seedlab", "zitadel.json")) // #nosec G304 -- test temp dir
	_ = json.Unmarshal(data, &out)
	t.Cleanup(func() {
		if out.ProjectID == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		raw, _ := os.ReadFile(pat) // #nosec G304 -- test file
		api, err := client.New(ctx, zitadel.New(labenv.ZitadelHost()), client.WithAuth(client.PAT(strings.TrimSpace(string(raw)))))
		if err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		defer func() { _ = api.Close() }()
		if _, err := api.ProjectServiceV2().DeleteProject(ctx, &projectv2.DeleteProjectRequest{ProjectId: out.ProjectID}); err != nil {
			t.Errorf("cleanup: delete %s: %v", out.ProjectID, err)
		}
	})
	if res.ExitCode != 0 || out.ProjectID == "" || out.HSClient == "" {
		t.Fatalf("exit %d zitadel.json %s\n%s", res.ExitCode, data, res.Output)
	}
	p := out.SecretFiles["headscale_oidc_client_secret"]
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("client secret file %s: %v", p, err)
	}
	secret, _ := os.ReadFile(p) // #nosec G304 -- test temp dir
	if len(secret) == 0 || strings.Contains(res.Output, string(secret)) {
		t.Fatal("the client secret is empty or reached the output")
	}
}
