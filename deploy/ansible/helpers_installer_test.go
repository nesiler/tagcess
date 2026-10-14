//go:build installer

package installer

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
	"github.com/nesiler/tagcess/test/labenv"
)

// randomSecret writes a random secret file (0600) for a test and returns its path and content.
func randomSecret(t *testing.T, name string) (string, string) {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := "F6TEST-" + hex.EncodeToString(b)
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, v
}

// labZitadel is the lab Zitadel (ADR 0014) a running tagcess in a test target talks to: issuer, project id and
// the tagcess service user's key that `make lab-up` left in test/compose (never in the repo).
type labZitadel struct{ Issuer, ProjectID, KeyFile, GateClientID string }

func needLabZitadel(t *testing.T) labZitadel {
	t.Helper()
	root := adopttarget.RepoRoot()
	key := filepath.Join(root, "test", "compose", ".secrets", "lab", "zitadel-key.json")
	env, err := os.ReadFile(filepath.Join(root, "test", "compose", ".env"))
	if _, kerr := os.Stat(key); err != nil || kerr != nil {
		t.Skip("lab Zitadel material missing (test/compose/.env, .secrets/lab/zitadel-key.json): run make lab-up; a skip is not a PASS")
	}
	z := labZitadel{Issuer: labenv.ZitadelIssuer(), KeyFile: key}
	sc := bufio.NewScanner(strings.NewReader(string(env)))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "ZITADEL_PROJECT_ID":
			z.ProjectID = strings.Trim(v, `"'`)
		case "OAUTH2_PROXY_CLIENT_ID":
			z.GateClientID = strings.Trim(v, `"'`)
		}
	}
	if z.ProjectID == "" {
		t.Skip("ZITADEL_PROJECT_ID not in test/compose/.env")
	}
	return z
}

var (
	imageMu    sync.Mutex
	imageCache = map[string][2]string{}
)

// imageArchive builds the tagcess image with the target's caddy/headscale GIDs on this machine (once per GID pair
// and test process) and returns a `docker save | gzip` archive for app_image_source: archive and the image tag.
func imageArchive(t *testing.T, tg *adopttarget.Target) (string, string) {
	t.Helper()
	gid := func(g string) string {
		out := tg.Sh(t, "getent group "+g)
		return strings.Split(strings.TrimSpace(out), ":")[2]
	}
	caddy, hs := gid("caddy"), gid("headscale")
	key := caddy + "-" + hs
	imageMu.Lock()
	defer imageMu.Unlock()
	if c, ok := imageCache[key]; ok {
		return c[0], c[1]
	}
	tag := "tagcess-f6test:" + key
	build := exec.Command("docker", "build", "-q", "-f", "deploy/Dockerfile", "--build-arg", "CADDY_GID="+caddy, "--build-arg", "HEADSCALE_GID="+hs,
		"-t", tag, ".")
	build.Dir = adopttarget.RepoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	dir, err := os.MkdirTemp("", "tagcess-f6-image-")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tagcess-"+key+".tar.gz")
	save := exec.Command("sh", "-c", fmt.Sprintf("docker save %s | gzip -1 > %q", tag, p))
	if out, err := save.CombinedOutput(); err != nil {
		t.Fatalf("docker save: %v\n%s", err, out)
	}
	imageCache[key] = [2]string{p, tag}
	return p, tag
}

// appVars are the adopt settings plus everything the host/hshelper/app phases need to run tagcess for real in the
// adopt-shaped target (lab Zitadel as the issuer; the hook on the target's tailnet IP).
func appVars(t *testing.T, tg *adopttarget.Target) map[string]any {
	t.Helper()
	z := needLabZitadel(t)
	w, _ := randomSecret(t, "webhook-signing-key")
	g, _ := randomSecret(t, "groups-signing-key")
	archive, tag := imageArchive(t, tg)
	return adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{
		"secret_files":           map[string]string{"webhook_signing_key": w, "groups_signing_key": g, "zitadel_key": z.KeyFile},
		"zitadel_issuer":         z.Issuer,
		"zitadel_project_id":     z.ProjectID,
		"oauth2_proxy_client_id": z.GateClientID,
		"site_seed_file":         filepath.Join(adopttarget.AnsibleDir(), "examples", "seed.example.json"),
		"app_image_source":       "archive",
		"app_image_archive":      archive,
		"tagcess_image":          tag,
		"app_zitadel_internal_sources": []string{"10.8.0.0/24", "127.0.0.1/32", "::1/128", "192.0.2.10/32", "192.0.2.20/32",
			"2001:db8:10::/64", "2001:db8:20::/64"},
	})
}

// mustRun runs phases and fails the test unless they succeed.
func mustRun(t *testing.T, tg *adopttarget.Target, home string, vars map[string]any, extra map[string]string, tags ...string) adopttarget.Result {
	t.Helper()
	res := runSite(t, tg, home, vars, extra, tags...)
	if res.ExitCode != 0 {
		t.Fatalf("phases %v failed:\n%s", tags, res.Output)
	}
	return res
}

// noChanges asserts a run reported changed=0 for the target.
func noChanges(t *testing.T, tg *adopttarget.Target, res adopttarget.Result) {
	t.Helper()
	if r := res.Recap[tg.Name]; r.Changed != 0 || r.Failed != 0 {
		t.Fatalf("second run: recap %+v, changed tasks %v", r, adopttarget.ChangedTasks(res.Output))
	}
}

// fullAdopt are the settings and environment of a whole adopt run on the adopt-shaped target: a real tagcess and
// oauth2-proxy (lab Zitadel issuer), the fake Zitadel adopt tool (it answers with the lab's ids; the lab instance's
// Actions are never touched) and the k8s namespace for the manifest.
type fullAdopt struct {
	Vars map[string]any
	Env  []string
}

func fullAdoptSetup(t *testing.T, tg *adopttarget.Target) fullAdopt {
	t.Helper()
	z := needLabZitadel(t)
	op := oauth2Vars(t)
	vars := adopttarget.Merge(appVars(t, tg), map[string]any{
		"zitadel_seed_tool":      filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-zitadel-adopt.sh"),
		"zitadel_admin_key_file": z.KeyFile, "zitadel_seed_apply": true, "k8s_namespaces": []string{"web"},
	})
	sf := vars["secret_files"].(map[string]string)
	sf["oauth2_proxy_client_secret"] = op["secret_files"].(map[string]string)["oauth2_proxy_client_secret"]
	logf := filepath.Join(t.TempDir(), "zitadel-args.log")
	return fullAdopt{Vars: vars, Env: []string{"FAKE_ZITADEL_LOG=" + logf, "FAKE_PROJECT_ID=" + z.ProjectID, "FAKE_OP_CLIENT=" + z.GateClientID}}
}

// confirmAll are the phase confirmations install.sh would pass one by one (g02 runs separately with the policy hash).
var confirmAll = map[string]string{"confirm_host_system": "yes", "confirm_hs_tags": "yes", "confirm_hs_hook_acl": "yes", "confirm_hs_dns_path": "yes"}

// runFull runs site.yml (all phases, or the given tags) with the full adopt settings.
func runFull(t *testing.T, tg *adopttarget.Target, home string, f fullAdopt, over map[string]any, extra map[string]string, tags ...string) adopttarget.Result {
	t.Helper()
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: adopttarget.Merge(f.Vars, over), ExtraVars: extra, Tags: tags, Env: f.Env})
}
