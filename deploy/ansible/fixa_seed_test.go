package installer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/test/adopttarget"
)

const (
	fixaOldKey = "OLD-SUPPLIED-SIGNING-KEY-aaaa1111"
	fixaNewKey = "NEW-TARGET-SIGNING-KEY-bbbb2222"
)

// fixaSeed runs testdata/zitadel_seed.yml (apply) in the controller home `home` with the fake tool; the home is shared
// between calls so a later call sees what an earlier one left in <env>/zitadel.json and <env>/secrets.
func fixaSeed(t *testing.T, home string, vars map[string]any, env ...string) adopttarget.Result {
	t.Helper()
	logf := filepath.Join(t.TempDir(), "args.log")
	admin := filepath.Join(t.TempDir(), "admin-key.json")
	if err := os.WriteFile(admin, []byte(`{"type":"serviceaccount","key":"ADMIN-KEY-MARKER-55c1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"install_env": "seedtest", "install_mode": "adopt", "tagcess_domain": "c.example.test", "vpn_tailnet_ip": "100.64.0.4",
		"zitadel_seed_tool": filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-zitadel-adopt.sh"), "zitadel_admin_key_file": admin,
		"zitadel_seed_apply": true,
	}
	adopttarget.RequireAnsible(t)
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/zitadel_seed.yml", Inventories: []string{localInventory(t)},
		ConfigHome: home, Vars: adopttarget.Merge(base, vars), Env: append([]string{"FAKE_ZITADEL_LOG=" + logf}, env...)})
}

// fixaLater runs a separate, later ansible-playbook call (config role only) in the same home.
func fixaLater(t *testing.T, home string, vars map[string]any) adopttarget.Result {
	t.Helper()
	adopttarget.RequireAnsible(t)
	base := map[string]any{"install_env": "seedtest", "install_mode": "adopt", "tagcess_domain": "c.example.test"}
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "testdata/zitadel_seed_later.yml", Inventories: []string{localInventory(t)},
		ConfigHome: home, Vars: adopttarget.Merge(base, vars)})
}

// fixaPath reads "<label>=<path>" out of a NEXT/LATER debug line.
func fixaPath(t *testing.T, out, line, label string) string {
	t.Helper()
	m := regexp.MustCompile(line + ` .*?\b` + label + `=(\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no %s %s in the output:\n%s", line, label, out)
	}
	return strings.TrimSuffix(m[1], `"`)
}

func fixaSecretFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixaZitadelSig signs like Zitadel (pkg/actions/signing.go): t=<ts>,v1=hex(HMAC-SHA256(key, "<ts>.<body>")).
func fixaZitadelSig(now time.Time, body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func fixaZitadelJSON(t *testing.T, home string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(envDir(home, "seedtest"), "zitadel.json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// H7: two seed runs, the second one reports no secret paths (an earlier tool, an interrupted run): zitadel.json keeps
// the paths of files that still exist and drops the ones whose file is gone (validated merge, never an empty overwrite);
// a new Ansible call afterwards uses the same paths.
func TestZitadelSeedRole_SecondRunKeepsSecretPaths(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	vars := map[string]any{"zitadel_seed_create_actions": true}
	first := fixaSeed(t, home, vars, "FAKE_WEBHOOK_KEY="+fixaNewKey, "FAKE_GROUPS_KEY=GROUPS-KEY-cccc3333")
	if first.ExitCode != 0 {
		t.Fatalf("first run:\n%s", first.Output)
	}
	wh := fixaPath(t, first.Output, "NEXT", "webhook")
	groups := fixaPath(t, first.Output, "NEXT", "groups")
	hs := fixaPath(t, first.Output, "NEXT", "hssecret")
	second := fixaSeed(t, home, vars, "FAKE_SECRETS_EMPTY=1")
	if second.ExitCode != 0 {
		t.Fatalf("second run:\n%s", second.Output)
	}
	for label, want := range map[string]string{"webhook": wh, "groups": groups, "hssecret": hs} {
		if got := fixaPath(t, second.Output, "NEXT", label); got != want {
			t.Errorf("second run: %s = %q, want %q", label, got, want)
		}
	}
	// A new ansible-playbook call (the next install.sh phase) reads the same paths from zitadel.json.
	later := fixaLater(t, home, nil)
	if later.ExitCode != 0 {
		t.Fatalf("later call:\n%s", later.Output)
	}
	for label, want := range map[string]string{"webhook": wh, "groups": groups, "hssecret": hs} {
		if got := fixaPath(t, later.Output, "LATER", label); got != want {
			t.Errorf("later call: %s = %q, want %q", label, got, want)
		}
	}
	// A secret file that is gone is dropped from zitadel.json, the others stay.
	if err := os.Remove(groups); err != nil {
		t.Fatal(err)
	}
	third := fixaSeed(t, home, vars, "FAKE_SECRETS_EMPTY=1")
	if third.ExitCode != 0 {
		t.Fatalf("third run:\n%s", third.Output)
	}
	sf, _ := fixaZitadelJSON(t, home)["secret_files"].(map[string]any)
	if _, ok := sf["groups_signing_key"]; ok || sf["webhook_signing_key"] != wh || sf["headscale_oidc_client_secret"] != hs {
		t.Fatalf("zitadel.json secret_files after the file was removed: %v", sf)
	}
}

// H7: objects the tool reports as created-but-missing stop the phase after the ids are saved, unless the settings supply
// that secret file.
func TestZitadelSeedRole_MissingSecretStopsUnlessSupplied(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	missing := `[{"key":"oauth2_proxy_client_secret","object":"app oauth2-proxy","path":"/x/oauth2_proxy_client_secret"}]`
	res := fixaSeed(t, home, nil, "FAKE_MISSING_JSON="+missing)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "secret dosyası eksik") || !strings.Contains(res.Output, "oauth2_proxy_client_secret") {
		t.Fatalf("want a stop naming the missing secret:\n%s", res.Output)
	}
	if fixaZitadelJSON(t, home)["zitadel_project_id"] != "p-777" {
		t.Fatal("the ids were not saved before the stop")
	}
	supplied := fixaSecretFile(t, "op-secret", "OP-CLIENT-SECRET-dddd4444")
	res = fixaSeed(t, t.TempDir(), map[string]any{"secret_files": map[string]string{"oauth2_proxy_client_secret": supplied}}, "FAKE_MISSING_JSON="+missing)
	if res.ExitCode != 0 {
		t.Fatalf("a supplied secret file must satisfy the missing one:\n%s", res.Output)
	}
}

// H8: the signing key of a newly created Actions target is the effective source. A different key the settings named
// earlier is not silently preferred (nor is the new one silently preferred over it): the run stops, naming the key,
// and no secret value reaches the output.
func TestZitadelSeedRole_NewTargetKeyConflictStops(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	old := fixaSecretFile(t, "old-webhook-key", fixaOldKey)
	res := fixaSeed(t, home, map[string]any{"zitadel_seed_create_actions": true, "secret_files": map[string]string{"webhook_signing_key": old}},
		"FAKE_WEBHOOK_KEY="+fixaNewKey)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "webhook_signing_key") || !strings.Contains(res.Output, "farklı") {
		t.Fatalf("want a conflict stop:\n%s", res.Output)
	}
	for _, k := range []string{fixaOldKey, fixaNewKey} {
		if strings.Contains(res.Output, k) {
			t.Fatalf("a signing key reached the output")
		}
	}
	// Every later call stops too while the settings still name the other key; with the stale entry removed it passes.
	if later := fixaLater(t, home, map[string]any{"secret_files": map[string]string{"webhook_signing_key": old}}); later.ExitCode == 0 ||
		!strings.Contains(later.Output, "farklı") {
		t.Fatalf("a later call must stop on the conflict:\n%s", later.Output)
	}
	if later := fixaLater(t, home, nil); later.ExitCode != 0 {
		t.Fatalf("without the stale entry the later call must pass:\n%s", later.Output)
	}
}

// H8: the effective key is the new target's: Zitadel's signature (computed with the target's real key) verifies with the
// file the next phases copy to the host, in this run, in a later call, and also when the settings name an identical
// copy of that key. The old key does not verify.
func TestZitadelSeedRole_EffectiveSigningKeyVerifiesZitadelSignature(t *testing.T) {
	t.Parallel()
	body := []byte(`{"aggregateID":"u1","sequence":1,"event_type":"user.grant.added"}`)
	now := time.Now()
	verifies := func(t *testing.T, path string) error {
		t.Helper()
		key, err := os.ReadFile(path) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatal(err)
		}
		return hook.VerifySignature(key, body, fixaZitadelSig(now, body, fixaNewKey), now)
	}
	t.Run("no key supplied", func(t *testing.T) {
		home := t.TempDir()
		res := fixaSeed(t, home, map[string]any{"zitadel_seed_create_actions": true}, "FAKE_WEBHOOK_KEY="+fixaNewKey)
		if res.ExitCode != 0 {
			t.Fatal(res.Output)
		}
		for _, p := range []string{fixaPath(t, res.Output, "NEXT", "webhook"), fixaPath(t, fixaLater(t, home, nil).Output, "LATER", "webhook")} {
			if err := verifies(t, p); err != nil {
				t.Errorf("Zitadel's signature does not verify with %s: %v", p, err)
			}
		}
	})
	t.Run("an identical copy supplied", func(t *testing.T) {
		copyPath := fixaSecretFile(t, "copy-of-new-key", fixaNewKey)
		res := fixaSeed(t, t.TempDir(), map[string]any{"zitadel_seed_create_actions": true, "secret_files": map[string]string{"webhook_signing_key": copyPath}},
			"FAKE_WEBHOOK_KEY="+fixaNewKey)
		if res.ExitCode != 0 {
			t.Fatal(res.Output)
		}
		if err := verifies(t, fixaPath(t, res.Output, "NEXT", "webhook")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the old key does not verify", func(t *testing.T) {
		old := fixaSecretFile(t, "old", fixaOldKey)
		if err := verifies(t, old); err == nil {
			t.Fatal("the old key verified a signature made with the new one")
		}
	})
}
