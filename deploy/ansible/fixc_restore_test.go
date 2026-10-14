//go:build installer

package installer

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// fixC_hsState is what must not change when a restore fails: Headscale's start time (never stopped or restarted),
// its answer to /health and its users.
func fixC_hsState(t *testing.T, tg *adopttarget.Target) string {
	t.Helper()
	return tg.Sh(t, `systemctl is-active headscale; systemctl show headscale -p ExecMainStartTimestamp --value;
		curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/health; headscale users list -o json | sha256sum`)
}

func fixC_restore(t *testing.T, tg *adopttarget.Target, id string, extra map[string]string) adopttarget.Result {
	t.Helper()
	ev := map[string]string{"backup_id": id, "restore_headscale_db": "yes"}
	for k, v := range extra {
		ev[k] = v
	}
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "restore.yml", Inventories: []string{tg.Inventory},
		Vars: adopttarget.AdoptVars(), ExtraVars: ev})
}

// Fix H3 (F6-003): a well-formed backup id that does not exist stops the restore before any service is stopped.
func TestRestore_MissingBackupKeepsServicesRunning(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	before := fixC_hsState(t, tg)
	res := fixC_restore(t, tg, "20200101T000000Z-aaaa-host", nil)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Geri yükleme yapılamadı") {
		t.Fatalf("want a restore stop:\n%s", res.Output)
	}
	if after := fixC_hsState(t, tg); after != before {
		t.Fatalf("Headscale was touched by a restore that could not even start:\n%s\n->\n%s", before, after)
	}
}

// Fix H3: a damaged database copy (does not match the manifest) stops the restore before Headscale is stopped.
func TestRestore_DamagedDatabaseCopyKeepsServicesRunning(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	tg.Sh(t, "echo damaged >>"+backupRoot+"/"+m.ID+"/db/headscale-db.sqlite")
	tg.Sh(t, "headscale users create after-backup >/dev/null")
	before := fixC_hsState(t, tg)
	res := fixC_restore(t, tg, m.ID, nil)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "damaged") {
		t.Fatalf("want a damaged-backup stop:\n%s", res.Output)
	}
	if after := fixC_hsState(t, tg); after != before {
		t.Fatalf("Headscale or its database changed:\n%s\n->\n%s", before, after)
	}
}

// Fix H3: a database copy that matches its manifest but is not a SQLite database any more is refused up front as well.
func TestRestore_UnreadableDatabaseCopyKeepsServicesRunning(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
	tg.Sh(t, `set -e
		b=`+backupRoot+`/`+m.ID+`
		echo 'not a database' >$b/db/headscale-db.sqlite
		new=$(sha256sum $b/db/headscale-db.sqlite | cut -d' ' -f1)
		python3 - "$b/manifest.json" "$new" <<'PY'
import json,sys
p,new=sys.argv[1],sys.argv[2]
m=json.load(open(p))
for d in m["sqlite"]:
    if d.get("existed"): d["sha256"]=new
json.dump(m,open(p,"w"))
PY`)
	before := fixC_hsState(t, tg)
	res := fixC_restore(t, tg, m.ID, nil)
	if res.ExitCode == 0 {
		t.Fatalf("want a stop:\n%s", res.Output)
	}
	if after := fixC_hsState(t, tg); after != before {
		t.Fatalf("Headscale or its database changed:\n%s\n->\n%s", before, after)
	}
}

// Fix H3: a validation failure after the restore began puts the files and the database back and starts Headscale again
// (it was stopped for its database).
func TestRestore_ValidationFailAfterStartPutsStateBack(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	m, _ := takeBackup(t, tg, adopttarget.AdoptVars())
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
PY
		headscale users create after-backup >/dev/null
		echo '// local edit' >>/etc/headscale/policy.hujson`)
	files := "sha256sum /etc/caddy/Caddyfile /etc/headscale/policy.hujson /etc/headscale/config.yaml"
	filesBefore := tg.Sh(t, files)
	usersBefore := tg.Sh(t, "headscale users list -o json | sha256sum")
	running := tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum")
	res := fixC_restore(t, tg, m.ID, nil)
	if res.ExitCode == 0 || !strings.Contains(res.Output, "hiçbir servis yeniden yüklenmedi") {
		t.Fatalf("want a validation stop:\n%s", res.Output)
	}
	if out, err := tg.ShErr("systemctl is-active -q headscale && curl -fsS -o /dev/null http://127.0.0.1:8080/health"); err != nil {
		t.Fatalf("Headscale is not running again: %v %s\nplaybook:\n%s", err, out, res.Output)
	}
	if got := tg.Sh(t, "headscale users list -o json | sha256sum"); got != usersBefore {
		t.Fatal("the Headscale database was not put back (the user created after the backup is gone)")
	}
	if got := tg.Sh(t, files); got != filesBefore {
		t.Fatalf("the files were not put back:\n%s\n->\n%s", filesBefore, got)
	}
	if got := tg.Sh(t, "curl -fsS http://127.0.0.1:2019/config/ | sha256sum"); got != running {
		t.Fatal("the running Caddy changed")
	}
	if out, err := tg.ShErr("find /etc /var/lib/headscale -name '*.tagcess-restore'"); err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("restore leftovers: %v %s", err, out)
	}
}
