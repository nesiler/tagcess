//go:build installer

package installer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

var (
	fixB_taskHeader = regexp.MustCompile(`^TASK \[([^\]:]+?) ?: (.*)\] \*+$`)
	fixB_notPhase   = map[string]bool{"backup": true, "guide": true, "state": true, "config": true, "preflight": true}
)

// fixB_backupFirst proves from the ansible output that the phase's backup task ran (not skipped) before the first task
// that changed something on the host.
func fixB_backupFirst(out, phase string) error {
	task, role := "", ""
	backupAt, firstChange := -1, -1
	firstChangeTask := ""
	for i, line := range strings.Split(out, "\n") {
		if m := fixB_taskHeader.FindStringSubmatch(line); m != nil {
			role, task = m[1], m[2]
			continue
		}
		if role == "backup" && task == "Take the backup on the host" && backupAt < 0 && strings.HasPrefix(line, "ok:") {
			backupAt = i
		}
		if strings.HasPrefix(line, "changed:") && !fixB_notPhase[role] && firstChange < 0 {
			firstChange, firstChangeTask = i, role+" : "+task
		}
	}
	switch {
	case backupAt < 0:
		return fmt.Errorf("%s: no backup was taken", phase)
	case firstChange >= 0 && firstChange < backupAt:
		return fmt.Errorf("%s: %q changed the host before the backup", phase, firstChangeTask)
	}
	return nil
}

func fixB_backupIDs(t *testing.T, tg *adopttarget.Target, suffix string) []string {
	t.Helper()
	var ids []string
	for _, d := range strings.Fields(tg.Sh(t, "ls -1 "+backupRoot+" 2>/dev/null || true")) {
		if strings.HasSuffix(d, "-"+suffix) {
			ids = append(ids, d)
		}
	}
	return ids
}

// H2: on the empty target every writing fresh phase takes its backup before its first change, including
// headscale_install (before the package), tailscale_join and headscale_oidc.
func TestFixB_BackupBeforeFirstChange_FreshPhases(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	discoveryStub(t, tg)
	for _, p := range []string{"certbot", "headscale_install", "caddy_install", "tailscale_join"} {
		res := mustRun(t, tg, home, vars, nil, p)
		if err := fixB_backupFirst(res.Output, p); err != nil {
			t.Errorf("%v", err)
		}
	}
	sec, _ := randomSecret(t, "hs-oidc-secret")
	oidc := adopttarget.Merge(vars, map[string]any{"headscale_oidc_client_id": "339000000000000003",
		"secret_files": map[string]string{"cloudflare_token": vars["secret_files"].(map[string]string)["cloudflare_token"], "headscale_oidc_client_secret": sec}})
	res := mustRun(t, tg, home, oidc, nil, "headscale_oidc")
	if err := fixB_backupFirst(res.Output, "headscale_oidc"); err != nil {
		t.Error(err)
	}
	var st struct {
		Phases map[string]struct {
			First string `json:"first_backup_id"`
		} `json:"phases"`
	}
	if err := json.Unmarshal([]byte(tg.ReadFile(t, "/var/lib/tagcess-install/state.json")), &st); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"certbot", "headscale_install", "caddy_install", "tailscale_join", "headscale_oidc"} {
		id := st.Phases[p].First
		if id == "" || !strings.HasSuffix(id, "-"+p) {
			t.Errorf("%s: first backup id %q", p, id)
			continue
		}
		tg.Sh(t, "test -f "+backupRoot+"/"+id+"/manifest.json")
	}
	// The headscale_install backup is from before the package: Headscale's files did not exist then.
	var m manifest
	if err := json.Unmarshal([]byte(tg.ReadFile(t, backupRoot+"/"+st.Phases["headscale_install"].First+"/manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	if i, ok := m.entry("/etc/headscale/config.yaml"); !ok || m.Entries[i].Existed {
		t.Errorf("the headscale_install backup was taken after Headscale's config existed")
	}
}

// H2: a later credentials change is backed up too (not only the first install), and the backup holds the credentials
// as they were; the OIDC secret file is in the backup scope and the headscale_oidc rollback returns it.
func TestFixB_CredentialChangesAreBackedUp(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	vars := freshVars(t)
	home := t.TempDir()
	discoveryStub(t, tg)
	mustRun(t, tg, home, vars, nil, "certbot", "headscale_install")
	old := secretOf(t, vars, "cloudflare_token")
	if n := len(fixB_backupIDs(t, tg, "certbot")); n != 1 {
		t.Fatalf("%d certbot backups after the first run", n)
	}
	// A new credentials file: the second run backs up the old one first.
	tok2, _ := randomSecret(t, "cloudflare.ini")
	v2 := adopttarget.Merge(vars, map[string]any{"secret_files": map[string]string{"cloudflare_token": tok2}})
	res := mustRun(t, tg, home, v2, nil, "certbot")
	if err := fixB_backupFirst(res.Output, "certbot (second run)"); err != nil {
		t.Error(err)
	}
	ids := fixB_backupIDs(t, tg, "certbot")
	if len(ids) != 2 {
		t.Fatalf("certbot backups after a credentials change: %v", ids)
	}
	newest := ids[len(ids)-1]
	if got := tg.ReadFile(t, backupRoot+"/"+newest+"/files/root/.secrets/certbot/cloudflare.ini"); got != old {
		t.Fatalf("the second certbot backup does not hold the credentials from before the change")
	}
	tg.Sh(t, "test -d "+backupRoot+"/"+newest+"/files/etc/letsencrypt")

	// headscale_oidc: first pass writes the secret file; the second (new secret) backs up the first.
	s1, v1 := randomSecret(t, "hs-oidc-1")
	s2, _ := randomSecret(t, "hs-oidc-2")
	mk := func(sec string) map[string]any {
		return adopttarget.Merge(vars, map[string]any{"headscale_oidc_client_id": "339000000000000003",
			"secret_files": map[string]string{"cloudflare_token": vars["secret_files"].(map[string]string)["cloudflare_token"], "headscale_oidc_client_secret": sec}})
	}
	mustRun(t, tg, home, mk(s1), nil, "headscale_oidc")
	mustRun(t, tg, home, mk(s2), nil, "headscale_oidc")
	oids := fixB_backupIDs(t, tg, "headscale_oidc")
	if len(oids) != 2 {
		t.Fatalf("headscale_oidc backups: %v", oids)
	}
	if got := tg.ReadFile(t, backupRoot+"/"+oids[1]+"/files/etc/headscale/oidc_client_secret"); got != v1 {
		t.Fatal("the second headscale_oidc backup does not hold the OIDC secret file from before the change")
	}

	rb := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: mk(s2), Tags: []string{"headscale_oidc"}})
	if rb.ExitCode != 0 {
		t.Fatalf("rollback headscale_oidc:\n%s", tail(rb.Output, 40))
	}
	tg.Sh(t, `set -e
		! grep -Eq '^oidc:' /etc/headscale/config.yaml
		test ! -e /etc/headscale/oidc_client_secret
		test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = 200`)
	if n := len(fixB_backupIDs(t, tg, "rollback-headscale_oidc")); n != 1 {
		t.Fatalf("the rollback took %d backups of today's state first, want 1", n)
	}
}
