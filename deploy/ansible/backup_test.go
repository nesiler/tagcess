//go:build installer

package installer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

const backupRoot = "/var/backups/tagcess-install"

type manifest struct {
	ID      string `json:"id"`
	Phase   string `json:"phase"`
	Entries []struct {
		Path    string `json:"path"`
		Type    string `json:"type"`
		SHA256  string `json:"sha256"`
		Mode    string `json:"mode"`
		Owner   string `json:"owner"`
		Existed bool   `json:"existed"`
	} `json:"entries"`
	SQLite []struct {
		Path    string `json:"path"`
		Backup  string `json:"backup"`
		Existed bool   `json:"existed"`
	} `json:"sqlite"`
}

// takeBackup runs the backup phase and returns the new backup's manifest.
func takeBackup(t *testing.T, tg *adopttarget.Target, vars map[string]any) (manifest, adopttarget.Result) {
	t.Helper()
	before := strings.Fields(tg.Sh(t, "ls -1 "+backupRoot+" 2>/dev/null || true"))
	res := runSite(t, tg, t.TempDir(), vars, nil, "backup")
	if res.ExitCode != 0 {
		t.Fatalf("backup phase:\n%s", res.Output)
	}
	var id string
	for _, d := range strings.Fields(tg.Sh(t, "ls -1 "+backupRoot)) {
		if !strings.Contains(" "+strings.Join(before, " ")+" ", " "+d+" ") {
			id = d
		}
	}
	if id == "" {
		t.Fatalf("no new backup under %s", backupRoot)
	}
	var m manifest
	if err := json.Unmarshal([]byte(tg.ReadFile(t, backupRoot+"/"+id+"/manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	return m, res
}

func (m manifest) entry(path string) (int, bool) {
	for i, e := range m.Entries {
		if e.Path == path {
			return i, true
		}
	}
	return -1, false
}

// sha returns the sha256 of a file in the target.
func sha(t *testing.T, tg *adopttarget.Target, path string) string {
	t.Helper()
	return strings.Fields(tg.Sh(t, "sha256sum "+path))[0]
}

// AC1 (F6-003): manifest.json records the sha256 of every file; the backup directory is 0700 root.
func TestBackup_ManifestAndModes(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, res := takeBackup(t, tg, adopttarget.AdoptVars())
	if res.Recap[tg.Name].Changed != 0 {
		t.Errorf("the backup phase reported changes (backups are not managed state): %v", adopttarget.ChangedTasks(res.Output))
	}
	if got := tg.Sh(t, "stat -c '%a %U' "+backupRoot+" "+backupRoot+"/"+m.ID); strings.Count(got, "700 root") != 2 {
		t.Fatalf("backup dirs: %q, want 700 root", got)
	}
	files := 0
	for _, e := range m.Entries {
		if e.Type != "file" {
			continue
		}
		files++
		if got := sha(t, tg, backupRoot+"/"+m.ID+"/files"+e.Path); got != e.SHA256 {
			t.Errorf("%s: backup copy %s, manifest %s", e.Path, got, e.SHA256)
		}
		if got := sha(t, tg, e.Path); got != e.SHA256 {
			t.Errorf("%s: live %s, manifest %s", e.Path, got, e.SHA256)
		}
		if e.Mode == "" || e.Owner == "" {
			t.Errorf("%s: mode/owner missing in the manifest", e.Path)
		}
	}
	for _, p := range []string{"/etc/caddy/Caddyfile", "/etc/caddy/sites/monitor.c.example.test.caddy", "/etc/headscale/config.yaml",
		"/etc/headscale/policy.hujson", "/etc/headscale/extra-records.json", "/etc/oauth2-proxy/oauth2-proxy.cfg"} {
		if _, ok := m.entry(p); !ok {
			t.Errorf("%s is not in the manifest", p)
		}
	}
	if files < 25 {
		t.Fatalf("only %d files in the manifest", files)
	}
}

// AC2 (F6-003): the Headscale database copy taken while Headscale runs passes integrity_check and carries the same
// rows.
func TestBackup_HeadscaleDBConsistent(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	tg.Sh(t, "for u in alice bob carol; do headscale users create $u >/dev/null; done; "+
		"uid=$(headscale users list -o json | python3 -c 'import json,sys;print(json.load(sys.stdin)[1][\"id\"])'); "+
		"headscale preauthkeys create --user $uid --expiration 1h >/dev/null")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	var dbBackup string
	for _, d := range m.SQLite {
		if d.Path == "/var/lib/headscale/db.sqlite" && d.Existed {
			dbBackup = backupRoot + "/" + m.ID + "/" + d.Backup
		}
	}
	if dbBackup == "" {
		t.Fatalf("no Headscale database in the manifest: %+v", m.SQLite)
	}
	if got := strings.TrimSpace(tg.Sh(t, "sqlite3 "+dbBackup+" 'PRAGMA integrity_check'")); got != "ok" {
		t.Fatalf("integrity_check: %q", got)
	}
	q := "select (select count(*) from users)||','||(select count(*) from nodes)||','||(select count(*) from pre_auth_keys)||','||(select count(*) from policies)"
	live := strings.TrimSpace(tg.Sh(t, "runuser -u headscale -- sqlite3 /var/lib/headscale/db.sqlite \""+q+"\""))
	copied := strings.TrimSpace(tg.Sh(t, "sqlite3 "+dbBackup+" \""+q+"\""))
	if live != copied || !strings.HasPrefix(live, "4,1,") {
		t.Fatalf("rows live %q, backup %q (want users 4 incl. vpn-server, 1 node)", live, copied)
	}
	// No root-owned journal file appeared next to the live database.
	if out := tg.Sh(t, "find /var/lib/headscale -maxdepth 1 -name 'db.sqlite*' ! -user headscale"); strings.TrimSpace(out) != "" {
		t.Fatalf("files not owned by headscale next to the live database:\n%s", out)
	}
}

// AC3 (F6-003): after a phase changed files, restore.yml returns every file to its manifest sha256 (a file added
// later is moved aside), validates and leaves Caddy and Headscale running.
func TestRestore_RoundTrip(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	tg.Sh(t, `set -e
		echo '# changed' >>/etc/caddy/sites/monitor.c.example.test.caddy
		printf 'new.c.example.test {\n\timport vpn_only c.example.test\n}\n' >/etc/caddy/sites/new.c.example.test.caddy
		chgrp caddy /etc/caddy/Caddyfile && chmod 0640 /etc/caddy/Caddyfile
		echo '// changed' >>/etc/headscale/policy.hujson
		sed -i 's/cookie_expire = "12h"/cookie_expire = "1h"/' /etc/oauth2-proxy/oauth2-proxy.cfg
		systemctl reload caddy
		headscale users create dave >/dev/null`)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), ExtraVars: map[string]string{"backup_id": m.ID, "restore_headscale_db": "yes"}})
	if res.ExitCode != 0 {
		t.Fatalf("restore:\n%s", res.Output)
	}
	for _, e := range m.Entries {
		if e.Type == "file" {
			if got := sha(t, tg, e.Path); got != e.SHA256 {
				t.Errorf("%s: %s after restore, manifest %s", e.Path, got, e.SHA256)
			}
		}
	}
	if mode := strings.TrimSpace(tg.Sh(t, "stat -c '%a %G' /etc/caddy/Caddyfile")); mode != "644 root" {
		t.Errorf("Caddyfile mode/group %s after restore, want 644 root", mode)
	}
	if out, err := tg.ShErr("test ! -e /etc/caddy/sites/new.c.example.test.caddy && test -f " + backupRoot + "/" + m.ID +
		"/restore-removed/etc/caddy/sites/new.c.example.test.caddy"); err != nil {
		t.Errorf("the later file was not moved aside: %v %s", err, out)
	}
	if out := tg.Sh(t, "headscale users list -o json"); strings.Contains(out, "dave") {
		t.Errorf("the database was not restored (dave still exists)")
	}
	tg.Sh(t, "systemctl is-active -q caddy && systemctl is-active -q headscale && curl -fsS -o /dev/null http://127.0.0.1:8080/health "+
		"&& caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1")
	// The restore itself was backed up first (pre-restore) and a second restore changes nothing.
	tg.Sh(t, "ls "+backupRoot+" | grep -q -- -pre-restore")
	res = adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), ExtraVars: map[string]string{"backup_id": m.ID}})
	if res.ExitCode != 0 || !strings.Contains(res.Output, "Geri gelen: -") {
		t.Fatalf("second restore must change nothing:\n%s", res.Output)
	}
}

// AC4 (F6-003): a restored config that fails validation stops before any reload/restart and names the file.
func TestRestore_ValidationFailStops(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	// Damage the backup's Caddyfile consistently (copy + manifest), as if a broken file had been backed up.
	tg.Sh(t, `set -e
		b=`+backupRoot+`/`+m.ID+`
		echo 'this is { not caddy' >>$b/files/etc/caddy/Caddyfile
		new=$(sha256sum $b/files/etc/caddy/Caddyfile | cut -d' ' -f1)
		python3 - "$b/manifest.json" "$new" <<'PY'
import json,sys
p,new=sys.argv[1],sys.argv[2]
m=json.load(open(p))
for e in m["entries"]:
    if e["path"]=="/etc/caddy/Caddyfile": e["sha256"]=new
json.dump(m,open(p,"w"))
PY`)
	before := tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum; systemctl show caddy -p ExecMainPID --value")
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), ExtraVars: map[string]string{"backup_id": m.ID}})
	if res.ExitCode == 0 || !strings.Contains(res.Output, "hiçbir servis yeniden yüklenmedi") || !strings.Contains(res.Output, "/etc/caddy/Caddyfile") {
		t.Fatalf("want a validation stop naming the Caddyfile:\n%s", res.Output)
	}
	if strings.Contains(res.Output, "TASK [backup : Restore: reload Caddy]") && !strings.Contains(res.Output, "skipping") {
		t.Fatalf("Caddy was reloaded")
	}
	if after := tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum; systemctl show caddy -p ExecMainPID --value"); after != before {
		t.Fatalf("the running Caddy changed: %q -> %q", before, after)
	}
}

// AC5 (F6-003): backup and restore never show a secret file's content.
func TestBackup_NoSecretInOutput(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	first, second := "BACKUP-SECRET-MARKER-one-91c2", "BACKUP-SECRET-MARKER-two-4d7e"
	tg.WriteFile(t, "/etc/oauth2-proxy/client_secret", first, "0640", "root:oauth2-proxy")
	tg.WriteFile(t, "/etc/headscale/oidc_client_secret", first, "0640", "root:headscale")
	m, res := takeBackup(t, tg, adopttarget.AdoptVars())
	tg.WriteFile(t, "/etc/oauth2-proxy/client_secret", second, "0640", "root:oauth2-proxy")
	rres := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), ExtraVars: map[string]string{"backup_id": m.ID}})
	if rres.ExitCode != 0 {
		t.Fatalf("restore:\n%s", rres.Output)
	}
	for _, out := range []string{res.Output, rres.Output} {
		if strings.Contains(out, first) || strings.Contains(out, second) {
			t.Fatalf("a secret reached the Ansible output")
		}
	}
	if got := tg.ReadFile(t, "/etc/oauth2-proxy/client_secret"); got != first {
		t.Fatalf("the secret file was not restored byte for byte")
	}
}

// AC6 (F6-003): on the empty target the backup finishes and records every path as "did not exist".
func TestBackup_MissingPathsRecorded(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "bare")
	m, _ := takeBackup(t, tg, adopttarget.BareVars())
	if len(m.Entries) == 0 {
		t.Fatal("empty manifest")
	}
	for _, e := range m.Entries {
		if e.Existed || e.Type != "missing" {
			t.Errorf("%s: existed=%v type=%s on the bare target", e.Path, e.Existed, e.Type)
		}
	}
	for _, d := range m.SQLite {
		if d.Existed {
			t.Errorf("database %s recorded as existing on the bare target", d.Path)
		}
	}
}
