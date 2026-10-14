//go:build installer

package installer

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// freshFull are the settings of a whole fresh run on the empty target: the fresh roles with test certificates, the
// lab Zitadel as the issuer (real oauth2-proxy and tagcess), the fake Zitadel adopt tool (lab ids; nothing is created
// in the shared lab) and Zitadel not installed (zitadel_install_enabled false: the lab Zitadel exists).
func freshFull(t *testing.T) (map[string]any, []string) {
	t.Helper()
	z := needLabZitadel(t)
	op := oauth2Vars(t)
	w, _ := randomSecret(t, "webhook-signing-key")
	g, _ := randomSecret(t, "groups-signing-key")
	vars := freshVars(t)
	sf := vars["secret_files"].(map[string]string)
	sf["webhook_signing_key"], sf["groups_signing_key"], sf["zitadel_key"] = w, g, z.KeyFile
	sf["oauth2_proxy_client_secret"] = op["secret_files"].(map[string]string)["oauth2_proxy_client_secret"]
	vars = adopttarget.Merge(vars, map[string]any{
		"zitadel_issuer": z.Issuer, "zitadel_discovery_url": z.Issuer + "/.well-known/openid-configuration",
		"zitadel_seed_tool":      filepath.Join(adopttarget.AnsibleDir(), "testdata", "fake-zitadel-adopt.sh"),
		"zitadel_admin_key_file": z.KeyFile, "zitadel_seed_apply": true, "k8s_namespaces": []string{"web"},
		"app_image_source": "archive",
	})
	logf := filepath.Join(t.TempDir(), "zitadel-args.log")
	return vars, []string{"FAKE_ZITADEL_LOG=" + logf, "FAKE_PROJECT_ID=" + z.ProjectID, "FAKE_OP_CLIENT=" + z.GateClientID}
}

func runFresh(t *testing.T, tg *adopttarget.Target, home string, vars map[string]any, env []string, extra map[string]string, tags ...string) adopttarget.Result {
	t.Helper()
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: vars, ExtraVars: extra, Tags: tags, Env: env})
}

// AC26, AC27, AC28 (F6-012) on one empty target: site.yml in fresh mode runs exactly the fresh phases in order (the
// image is built once the component phases have made the caddy/headscale groups); the Headscale adopt steps find
// everything done; rollback leaves the components installed and says so.
func TestSiteYml_RunsPhasesOfSelectedModeFresh(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars, env := freshFull(t)
	home := t.TempDir()
	first := runFresh(t, tg, home, vars, env, nil, "certbot", "headscale_install", "caddy_install")
	if first.ExitCode != 0 {
		t.Fatalf("component phases:\n%s", tail(first.Output, 60))
	}
	archive, tag := imageArchive(t, tg)
	vars = adopttarget.Merge(vars, map[string]any{"app_image_archive": archive, "tagcess_image": tag})
	res := runFresh(t, tg, home, vars, env, confirmAll)
	if res.ExitCode != 0 {
		t.Fatalf("fresh run:\n%s", tail(res.Output, 80))
	}
	var want []string
	for _, p := range phasesYML(t) {
		if slices.Contains(p["modes"].([]any), any("fresh")) {
			want = append(want, p["name"].(string))
		}
	}
	if got := executedPhases(res.Output); !slices.Equal(got, want) {
		t.Fatalf("fresh ran phases\n %v\nwant (phases.yml, fresh)\n %v", got, want)
	}
	for _, w := range []string{"zitadel_install atlandı: zitadel_install_enabled false", "Parite: eşit (0 fark)"} {
		if !strings.Contains(res.Output, w) {
			t.Errorf("output lacks %q", w)
		}
	}

	t.Run("TestHeadscaleAdopt_FreshIsNoOp", func(t *testing.T) {
		for _, w := range []string{"Hook ACL kuralı (tag:k8s → tag:vpn-server:9443) zaten var", "Headscale DNS kayıt yolu zaten /var/lib/tagcess/dns/extra-records.json"} {
			if !strings.Contains(res.Output, w) {
				t.Errorf("output lacks %q", w)
			}
		}
		pid := mainPID(t, tg, "headscale")
		again := runFresh(t, tg, home, vars, env, confirmAll, "hs_tags", "hs_hook_acl", "hs_dns_path")
		if again.ExitCode != 0 {
			t.Fatalf("adopt steps:\n%s", tail(again.Output, 40))
		}
		noChanges(t, tg, again)
		if mainPID(t, tg, "headscale") != pid {
			t.Fatal("Headscale restarted")
		}
	})
	t.Run("TestRollback_FreshComponentsNotRemoved", func(t *testing.T) {
		rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
			Vars: vars, ExtraVars: map[string]string{"confirm_remove_data": "yes"}, Env: env})
		if rb.ExitCode != 0 {
			t.Fatalf("rollback:\n%s", tail(rb.Output, 60))
		}
		tg.Sh(t, `set -e
			dpkg-query -W headscale caddy certbot tailscale >/dev/null
			systemctl is-active -q headscale && systemctl is-active -q caddy
			test ! -e /etc/tagcess/config.yaml && test ! -e /etc/caddy/sites/tagcess.caddy
			! docker ps --format '{{.Names}}' | grep -qx tagcess`)
		for _, p := range []string{"certbot", "headscale_install", "caddy_install", "tailscale_join"} {
			if !strings.Contains(rb.Output, p+": ") || !strings.Contains(rb.Output, "kaldırılmadı; tamamen kaldırmak host'u kapatmaktır") {
				t.Errorf("rollback report does not list %s as not removed", p)
			}
		}
		if t.Failed() {
			t.Log(tail(rb.Output, 80))
		}
	})
}
