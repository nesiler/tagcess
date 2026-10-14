//go:build installer

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// Fix round 2 (F6 second review): the first-round fixes of H6, H3, H2 and M2 were partial in a few places.

// fixR2_failCp makes `cp` fail for any call that mentions needle (a disposable target: the wrapper shadows /usr/bin/cp
// through /usr/local/bin and is removed again by the returned func).
func fixR2_failCp(t *testing.T, tg *adopttarget.Target, needle string) func() {
	t.Helper()
	tg.Sh(t, `set -e
		real=$(command -v cp)
		printf '%s\n' '#!/bin/sh' 'case "$*" in *`+needle+`*) echo "injected cp failure" >&2; exit 1;; esac' 'exec '"$real"' "$@"' >/usr/local/bin/cp
		chmod 0755 /usr/local/bin/cp`)
	return func() { tg.Sh(t, "rm -f /usr/local/bin/cp") }
}

// R2-H1 (F6-006): when keeping today's files fails, the commit has not begun: the rescue must not touch the live
// config, the secrets or the service (it used to remove the files it thought did not exist and restart the service).
func TestFixR2_OAuthSaveFailurePreservesLiveFiles(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := oauth2Vars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "oauth2_proxy")
	before := fixD_state(t, tg)

	undo := fixR2_failCp(t, tg, "oauth2-proxy-prev")
	rot := fixD_withSecrets(vars, map[string]string{"oauth2_proxy_cookie_secret": fixD_secretFile(t, "cookie_secret", fixD_random(32))})
	res := runSite(t, tg, home, rot, nil, "oauth2_proxy")
	undo()
	if res.ExitCode == 0 {
		t.Fatalf("a failed save of today's files must stop the role:\n%s", tail(res.Output, 30))
	}
	if now := fixD_state(t, tg); now != before {
		t.Fatalf("the live files or the service changed although the commit never began:\n%s\n--- before\n%s", now, before)
	}
	fixD_noLeftovers(t, tg)
}

// fixR2_restoreVars is AdoptVars with the Headscale health URL pointed at a dead port: everything of the restore works
// up to the health check, which then fails after the files, the database and Caddy were already changed.
func fixR2_restoreVars() map[string]any {
	return adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"headscale_health_url": "http://127.0.0.1:4199/health"})
}

func fixR2_restore(t *testing.T, tg *adopttarget.Target, id string) adopttarget.Result {
	t.Helper()
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: fixR2_restoreVars(), ExtraVars: map[string]string{"backup_id": id, "restore_headscale_db": "yes"}})
}

// fixR2_editBackup appends text to one backed-up file and fixes its manifest hash (the backup stays "whole").
func fixR2_editBackup(t *testing.T, tg *adopttarget.Target, id, path, text string) {
	t.Helper()
	tg.Sh(t, `set -e
		b=`+backupRoot+`/`+id+`
		printf '%s\n' '`+text+`' >>$b/files`+path+`
		new=$(sha256sum $b/files`+path+` | cut -d' ' -f1)
		python3 - "$b/manifest.json" "`+path+`" "$new" <<'PY'
import json,sys
p,path,new=sys.argv[1],sys.argv[2],sys.argv[3]
m=json.load(open(p))
for e in m["entries"]:
    if e["path"]==path: e["sha256"]=new
json.dump(m,open(p,"w"))
PY`)
}

// R2-H2 (F6-003): Caddy was reloaded with the restored config and a later check failed: the undo puts the old file back
// AND reloads Caddy, so the running config is the one from before the restore (it used to keep serving the old
// backup's access rules).
func TestFixR2_RestoreFailureRestoresLiveCaddy(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	fixR2_editBackup(t, tg, m.ID, "/etc/caddy/Caddyfile", "http://127.0.0.1:18999 {\n\trespond \"from-the-old-backup\" 200\n}")
	tg.Sh(t, "headscale users create after-backup >/dev/null")
	disk := "sha256sum /etc/caddy/Caddyfile"
	live := "curl -fsS http://127.0.0.1:2019/config/ | sha256sum"
	diskBefore, liveBefore := tg.Sh(t, disk), tg.Sh(t, live)

	res := fixR2_restore(t, tg, m.ID)
	if res.ExitCode == 0 {
		t.Fatalf("want a failed restore (Headscale health):\n%s", tail(res.Output, 30))
	}
	if !strings.Contains(res.Output, "Caddy") {
		t.Fatalf("the restore did not even reach Caddy:\n%s", tail(res.Output, 40))
	}
	if got := tg.Sh(t, disk); got != diskBefore {
		t.Fatalf("the Caddyfile on disk was not put back:\n%s\n->\n%s", diskBefore, got)
	}
	if got := tg.Sh(t, live); got != liveBefore {
		t.Fatalf("the RUNNING Caddy config is not the one from before the restore:\n%s\n->\n%s\nplaybook:\n%s", liveBefore, got, tail(res.Output, 40))
	}
	if out := tg.Sh(t, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18999/ || true"); out == "200" {
		t.Fatal("the site of the old backup is still served")
	}
}

// R2-H3 (F6-003): the undo copies the database (and WAL/SHM) back: its owners are stopped for that, and started again
// afterwards. The wrapper records what systemd says about Headscale at the moment the undo script is called.
func TestFixR2_UndoRunsWithDatabaseOwnerStopped(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	tg.Sh(t, "headscale users create after-backup >/dev/null")
	usersBefore := tg.Sh(t, "headscale users list -o json | sha256sum")
	tg.Sh(t, `set -e
		real=$(command -v python3)
		cat >/usr/local/bin/python3 <<EOF
#!/bin/sh
for a in "\$@"; do
  if printf '%s' "\$a" | base64 -d 2>/dev/null | grep -Eq '"mode": ?"undo"'; then
    echo "headscale=\$(systemctl is-active headscale)" >>/run/undo-owner-state
  fi
done
exec $real "\$@"
EOF
		chmod 0755 /usr/local/bin/python3; rm -f /run/undo-owner-state`)
	res := fixR2_restore(t, tg, m.ID)
	tg.Sh(t, "rm -f /usr/local/bin/python3")
	if res.ExitCode == 0 {
		t.Fatalf("want a failed restore (Headscale health):\n%s", tail(res.Output, 30))
	}
	got := strings.TrimSpace(tg.Sh(t, "cat /run/undo-owner-state"))
	if got != "headscale=inactive" && got != "headscale=failed" {
		t.Fatalf("the undo ran while Headscale owned its database: %q\n%s", got, tail(res.Output, 40))
	}
	if got := tg.Sh(t, "headscale users list -o json | sha256sum"); got != usersBefore {
		t.Fatal("the Headscale database from before the restore is not back")
	}
	if out, err := tg.ShErr("systemctl is-active -q headscale && curl -fsS -o /dev/null http://127.0.0.1:8080/health"); err != nil {
		t.Fatalf("Headscale is not running again: %v %s", err, out)
	}
	// The health check of the rescue uses the same dead URL: a failed restart/health must not be reported as a success.
	// (ansible prints the task's template source too: only the final fatal line is the message.)
	fatal := ""
	for _, line := range strings.Split(res.Output, "\n") {
		if strings.HasPrefix(line, "fatal:") {
			fatal = line
		}
	}
	if fatal == "" || strings.Contains(fatal, "servisler önceki çalışma durumuna döndürüldü") {
		t.Fatalf("the failure message claims the services are back although the health check failed:\n%s", tail(res.Output, 40))
	}
	if !strings.Contains(fatal, "DİKKAT") || !strings.Contains(fatal, "Headscale sağlık kontrolü") {
		t.Fatalf("want a loud warning naming the unhealthy service:\n%s", fatal)
	}
}

// R2-M3 (F6-007/F6-008): a node that started without tags and got tag:k8s from the installer cannot be untagged (Headscale
// refuses to take the last tag off). The rollback must not pretend: it fails with the exact manual step; a node that
// had another tag before still goes back (TestFixB_NoopSecondRunKeepsTagRollback).
func TestFixR2_RollbackReportsOriginallyPersonalNode(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	tg.Sh(t, `set -e
		mkdir -p /var/lib/ts2
		systemd-run --unit=ts2 tailscaled --tun=userspace-networking --state=/var/lib/ts2/tailscaled.state --socket=/run/ts2.sock --port=41642
		headscale users create k8s >/dev/null
		uid=$(headscale users list -o json | python3 -c 'import json,sys;print([u["id"] for u in json.load(sys.stdin) if u["name"]=="k8s"][0])')
		key=$(headscale preauthkeys create --user "$uid" --expiration 10m 2>/dev/null | tail -1)
		sleep 2
		tailscale --socket=/run/ts2.sock up --login-server http://127.0.0.1:8080 --authkey "$key" --hostname k8s-host-like --accept-dns=false >/dev/null`)
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hs_k8s_node": "k8s-host-like"})
	home := t.TempDir()
	yes := map[string]string{"confirm_hs_tags": "yes"}
	mustRun(t, tg, home, vars, yes, "hs_tags")
	if !strings.Contains(tg.Sh(t, "headscale nodes list -o json"), `"tag:k8s"`) {
		t.Fatal("the confirmed tag was not applied")
	}
	rb := fixB_rollback(t, tg, home, vars, nil, "hs_tags")
	if rb.ExitCode == 0 {
		t.Fatalf("the rollback reported success although the node still carries the installer's tag:\n%s", tail(rb.Output, 30))
	}
	var nodes []struct {
		ID        json.Number `json:"id"`
		GivenName string      `json:"given_name"`
	}
	if err := json.Unmarshal([]byte(tg.Sh(t, "headscale nodes list -o json")), &nodes); err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, n := range nodes {
		if n.GivenName == "k8s-host-like" {
			id = n.ID.String()
		}
	}
	for _, want := range []string{"k8s-host-like", "tag:k8s", "headscale nodes delete -i " + id} {
		if !strings.Contains(rb.Output, want) {
			t.Fatalf("the failure must name the node, the tag and the exact manual command (%q):\n%s", want, tail(rb.Output, 30))
		}
	}
}

// R2-M2 (F6-012): the k8s host is not the installer's host. Tailscale leftovers there (repository key, source list: the
// binary may be gone while they stay) are never overwritten without a backup: such a host is left alone and left to the
// guide, like one with a working Tailscale.
func TestFixR2_TailscaleJoinLeavesK8sLeftoversAlone(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	k8s := adopttarget.Up(t, "bare")
	inv := filepath.Join(t.TempDir(), "k8s-inventory.yml")
	src, err := os.ReadFile(k8s.Inventory) // #nosec G304 -- the target's generated inventory
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(strings.Replace(string(src), "    vpn:", "    k8s:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := freshVars(t)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "headscale_install")
	const keyring, list = "/usr/share/keyrings/tailscale-archive-keyring.gpg", "/etc/apt/sources.list.d/tailscale.list"
	k8s.Sh(t, "mkdir -p /usr/share/keyrings /etc/apt/sources.list.d; echo 'existing keyring' >"+keyring+"; echo '# existing list' >"+list)
	files := "sha256sum " + keyring + " " + list
	before := k8s.Sh(t, files)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "site.yml", Inventories: []string{tg.Inventory, inv}, ConfigHome: home,
		Vars: vars, Tags: []string{"tailscale_join"}})
	if res.ExitCode != 0 {
		t.Fatalf("tailscale_join failed:\n%s", tail(res.Output, 40))
	}
	if after := k8s.Sh(t, files); after != before {
		t.Fatalf("Tailscale files on the k8s host were overwritten without a backup:\n%s\n->\n%s", before, after)
	}
	if out, _ := k8s.ShErr("command -v tailscale"); strings.TrimSpace(out) != "" {
		t.Fatalf("tailscale was installed on the k8s host: %s", out)
	}
}
