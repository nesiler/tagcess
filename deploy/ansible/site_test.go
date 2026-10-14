//go:build installer

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// AC8 (F6-008): site.yml --check --diff on the adopt shape changes no host file and shows each phase's plan.
func TestSiteYml_CheckModeWritesNothing(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	f := fullAdoptSetup(t, tg)
	before := tg.Checksums(t, hostRoots)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: t.TempDir(),
		Vars: f.Vars, ExtraVars: confirmAll, Env: f.Env, Check: true, Diff: true})
	if res.ExitCode != 0 {
		t.Fatalf("--check run:\n%s", tail(res.Output, 60))
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("--check changed the host:\n%s", strings.Join(d, "\n"))
	}
	for _, w := range []string{"--- before", "+++ after", "/etc/caddy/sites/tagcess.caddy", "/var/lib/tagcess", "Yedek --check kipinde alınmaz",
		"Zitadel planı (yazma yok)", "/etc/tagcess/config.yaml"} {
		if !strings.Contains(res.Output, w) {
			t.Errorf("the plan lacks %q", w)
		}
	}
}

// AC9 (F6-008): without confirmations host_system, hs_tags, hs_hook_acl, hs_dns_path and g02 are "waiting" and change
// nothing.
func TestSiteYml_GatedPhasesSkippedWithoutConfirm(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hs_k8s_node": "k8s-host-missing"})
	before := tg.Checksums(t, hostRoots)
	res := mustRun(t, tg, t.TempDir(), vars, nil, "host_system", "hs_tags", "hs_hook_acl", "hs_dns_path", "g02")
	for _, w := range []string{"host_system onay bekliyor", "hs_tags: eksik etiketler yalnız raporlandı; uygulama onay bekliyor",
		"hs_hook_acl onay bekliyor", "hs_dns_path onay bekliyor", "g02 onay bekliyor"} {
		if !strings.Contains(res.Output, w) {
			t.Errorf("%q missing", w)
		}
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("gated phases changed the host:\n%s", strings.Join(d, "\n"))
	}
}

// AC10 (F6-008): a preflight blocker stops the whole site.yml before any writing phase.
func TestSiteYml_PreflightBlocksWrites(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := tg.Checksums(t, hostRoots)
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"headscale_version": "0.29.3"})
	res := runSite(t, tg, t.TempDir(), vars, confirmAll)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Preflight engeli") {
		t.Fatalf("want a preflight stop:\n%s", tail(res.Output, 30))
	}
	if regexp.MustCompile(`TASK \[(host|backup|app|caddy_ui|hshelper|oauth2_proxy|host_system) :`).MatchString(res.Output) {
		t.Fatal("a writing phase ran")
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("host changed:\n%s", strings.Join(d, "\n"))
	}
}

// executedPhases lists the phases whose guide tasks ran (not skipped), in order.
func executedPhases(out string) []string {
	var phases []string
	re := regexp.MustCompile(`(?m)^TASK \[guide : Guide: controller directory \((\w+)\)\][^\n]*\n(ok|changed|skipping)`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		if m[2] != "skipping" && !slices.Contains(phases, m[1]) {
			phases = append(phases, m[1])
		}
	}
	return phases
}

// AC11, AC12, AC13 + verify AC1, AC3, AC4 + rollback AC14, AC15, AC16 (F6-008) on one installed adopt-shaped target.
func TestSiteYml_RunsPhasesOfSelectedMode(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	f := fullAdoptSetup(t, tg)
	home := t.TempDir()
	lax := map[string]any{"verify_strict": false}
	res := runFull(t, tg, home, f, lax, confirmAll)
	if res.ExitCode != 0 {
		t.Fatalf("install:\n%s", tail(res.Output, 60))
	}
	var want []string
	for _, p := range phasesYML(t) {
		if slices.Contains(p["modes"].([]any), any("adopt")) {
			want = append(want, p["name"].(string))
		}
	}
	if got := executedPhases(res.Output); !slices.Equal(got, want) {
		t.Fatalf("adopt ran phases\n %v\nwant (phases.yml, adopt)\n %v", got, want)
	}

	t.Run("TestSiteYml_GuideFilePerPhase", func(t *testing.T) {
		for _, p := range want {
			data, err := os.ReadFile(filepath.Join(envDir(home, "adopttest"), "guide", p+".json")) // #nosec G304 -- test temp dir
			var g struct {
				Items []any `json:"items"`
			}
			if err != nil || json.Unmarshal(data, &g) != nil || g.Items == nil {
				t.Errorf("guide/%s.json: %v %s", p, err, data)
			}
		}
	})
	t.Run("TestSiteYml_BackupBeforeEachWritingPhase", func(t *testing.T) {
		var st struct {
			Phases map[string]struct {
				BackupID string `json:"backup_id"`
			} `json:"phases"`
		}
		if err := json.Unmarshal([]byte(tg.ReadFile(t, "/var/lib/tagcess-install/state.json")), &st); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"host", "host_system", "hshelper", "oauth2_proxy", "caddy_ui", "app", "hs_hook_acl", "hs_dns_path"} {
			id := st.Phases[p].BackupID
			if id == "" || !strings.HasSuffix(id, "-"+p) {
				t.Errorf("%s: backup id %q", p, id)
				continue
			}
			tg.Sh(t, "test -f /var/backups/tagcess-install/"+id+"/manifest.json")
		}
	})
	t.Run("TestVerify_ReportAllChecks", func(t *testing.T) {
		reports, _ := filepath.Glob(filepath.Join(envDir(home, "adopttest"), "report-*.md"))
		if len(reports) == 0 {
			t.Fatal("no verify report")
		}
		r, _ := os.ReadFile(reports[len(reports)-1]) // #nosec G304 -- test temp dir
		for _, w := range []string{"[x] tagcess başladı, ERROR yok", "[x] ui.sock srw-rw---- 10001 caddy", "[x] Başlıksız soket isteği 403",
			"[x] İmzasız hook POST 401", "[x] oauth2-proxy /ping 200", "[x] headscale ve caddy çalışıyor", "## İlk içe aktarma paritesi"} {
			if !strings.Contains(string(r), w) {
				t.Errorf("report lacks %q:\n%s", w, r)
			}
		}
	})
	t.Run("TestVerify_ReadOnly", func(t *testing.T) {
		before := tg.Checksums(t, hostRoots)
		runFull(t, tg, home, f, lax, nil, "verify")
		if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
			t.Fatalf("verify changed the host:\n%s", strings.Join(d, "\n"))
		}
	})
	t.Run("TestVerify_NoSecretAndManualList", func(t *testing.T) {
		reports, _ := filepath.Glob(filepath.Join(envDir(home, "adopttest"), "report-*.md"))
		r, _ := os.ReadFile(reports[len(reports)-1]) // #nosec G304 -- test temp dir
		for _, s := range f.Vars["secret_files"].(map[string]string) {
			v, _ := os.ReadFile(s) // #nosec G304 -- test file
			if len(v) > 8 && strings.Contains(string(r), string(v)) {
				t.Fatal("a secret is in the report")
			}
		}
		if !strings.Contains(string(r), "(elle)") {
			t.Fatal("manual checks missing")
		}
	})
	t.Run("TestVerify_ParityDiffFails", func(t *testing.T) {
		broken := filepath.Join(t.TempDir(), "seed.json")
		seed, _ := os.ReadFile(f.Vars["site_seed_file"].(string)) // #nosec G304 -- repo file
		_ = os.WriteFile(broken, []byte(strings.Replace(string(seed), "monitor.c.example.test", "mon2.c.example.test", 1)), 0o600)
		mustRun(t, tg, home, adopttarget.Merge(f.Vars, map[string]any{"site_seed_file": broken}), nil, "app")
		res := runFull(t, tg, home, f, map[string]any{"site_seed_file": broken}, nil, "verify")
		if res.ExitCode == 0 || !strings.Contains(res.Output, "uygulamaya hazır değil") {
			t.Fatalf("want not ready:\n%s", tail(res.Output, 20))
		}
		mustRun(t, tg, home, f.Vars, nil, "app")
	})
	t.Run("TestRollback_G02BackToFileMode", func(t *testing.T) {
		sha := strings.Fields(tg.Sh(t, "sha256sum /etc/headscale/policy.hujson"))[0]
		if r := runFull(t, tg, home, f, lax, map[string]string{"confirm_g02": "yes", "expected_policy_sha256": sha}, "g02"); r.ExitCode != 0 {
			t.Fatalf("g02:\n%s", tail(r.Output, 30))
		}
		rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
			Vars: f.Vars, Tags: []string{"g02"}, Env: f.Env})
		if rb.ExitCode != 0 {
			t.Fatalf("rollback g02:\n%s", tail(rb.Output, 30))
		}
		tg.Sh(t, `set -e
			grep -Eq '^[[:space:]]+mode: file' /etc/headscale/config.yaml
			runuser -u headscale -- headscale policy check -f /etc/headscale/policy.hujson >/dev/null 2>&1
			systemctl is-active -q headscale`)
	})
	t.Run("TestRollback_ValidationFailStops", func(t *testing.T) {
		// The host_system backup carries a Caddy drop-in a later hand edit broke: restoring it must stop before reloads.
		var st struct {
			Phases map[string]struct {
				First string `json:"first_backup_id"`
			} `json:"phases"`
		}
		_ = json.Unmarshal([]byte(tg.ReadFile(t, "/var/lib/tagcess-install/state.json")), &st)
		id := st.Phases["caddy_ui"].First
		tg.Sh(t, `set -e
			b=/var/backups/tagcess-install/`+id+`
			echo 'broken {' >>$b/files/etc/caddy/Caddyfile
			new=$(sha256sum $b/files/etc/caddy/Caddyfile | cut -d' ' -f1)
			python3 - "$b/manifest.json" "$new" <<'PY'
import json,sys
p,new=sys.argv[1],sys.argv[2]
m=json.load(open(p))
for e in m["entries"]:
    if e["path"]=="/etc/caddy/Caddyfile": e["sha256"]=new
json.dump(m,open(p,"w"))
PY`)
		running := tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum")
		rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
			Vars: f.Vars, Tags: []string{"caddy_ui"}, Env: f.Env})
		if rb.ExitCode == 0 || !strings.Contains(rb.Output, "hiçbir servis yeniden yüklenmedi") {
			t.Fatalf("want a validation stop:\n%s", tail(rb.Output, 30))
		}
		if tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum") != running {
			t.Fatal("Caddy was reloaded")
		}
	})
	t.Run("TestRollback_CaddyPhasesRefusedAfterImport", func(t *testing.T) {
		tg.Sh(t, `sed -i '1i # Generated by tagcess. Do not edit; every apply rewrites this file from the site records.' /etc/caddy/Caddyfile`)
		before := tg.Checksums(t, caddyRoot)
		for _, tag := range []string{"caddy_ui", "caddy_install"} {
			rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
				Vars: f.Vars, Tags: []string{tag}, Env: f.Env})
			if tag == "caddy_ui" && (rb.ExitCode == 0 || !strings.Contains(rb.Output, "arayüzden geri al")) {
				t.Fatalf("%s: want a refusal:\n%s", tag, tail(rb.Output, 20))
			}
			if d := adopttarget.DiffChecksums(before, tg.Checksums(t, caddyRoot)); len(d) > 0 {
				t.Fatalf("%s: Caddy files changed:\n%s", tag, strings.Join(d, "\n"))
			}
		}
	})
}
