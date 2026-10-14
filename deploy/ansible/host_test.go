//go:build installer

package installer

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// hostVars are the adopt settings with random secret files (the host phase only copies them).
func hostVars(t *testing.T) (map[string]any, map[string]string) {
	t.Helper()
	w, wv := randomSecret(t, "webhook-signing-key")
	g, gv := randomSecret(t, "groups-signing-key")
	z, zv := randomSecret(t, "zitadel-key.json")
	return adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{
		"secret_files": map[string]string{"webhook_signing_key": w, "groups_signing_key": g, "zitadel_key": z},
	}), map[string]string{"/etc/tagcess/secrets/webhook-signing-key": wv, "/etc/tagcess/secrets/groups-signing-key": gv,
		"/etc/tagcess/secrets/zitadel-key.json": zv}
}

// AC1, AC2, AC3, AC4 (F6-005): one host run on the adopt shape: modes and owners of the mount table, tmpfiles
// recreating /run/tagcess, the DNS file seeded from today's records and readable by headscale, secrets byte for
// byte and never shown; the second run changes nothing.
func TestHostRole_Idempotent(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars, secrets := hostVars(t)
	home := t.TempDir()
	first := mustRun(t, tg, home, vars, nil, "host")
	noChanges(t, tg, mustRun(t, tg, home, vars, nil, "host"))

	t.Run("TestHostRole_ModesAndOwners", func(t *testing.T) {
		want := map[string]string{
			"/var/lib/tagcess":                         "711 10001 10001",
			"/var/lib/tagcess/dns":                     "2750 10001 headscale",
			"/var/lib/tagcess-credentials":             "700 10001 10001",
			"/run/tagcess":                             "750 10001 caddy",
			"/etc/tagcess":                             "750 root 10001",
			"/etc/tagcess/secrets":                     "750 root 10001",
			"/etc/tagcess/secrets/webhook-signing-key": "640 root 10001",
			"/etc/tagcess/secrets/groups-signing-key":  "640 root 10001",
			"/etc/tagcess/secrets/zitadel-key.json":    "400 10001 10001",
			"/var/lib/tagcess/dns/extra-records.json":  "640 10001 headscale",
			"/etc/tmpfiles.d/tagcess.conf":             "644 root root",
		}
		// uid/gid 10001 has no name on the host (it is the container's tagcess user): compare numerically.
		num := strings.NewReplacer("caddy", strings.Split(tg.Sh(t, "getent group caddy"), ":")[2],
			"headscale", strings.Split(tg.Sh(t, "getent group headscale"), ":")[2], "root", "0")
		for p, w := range want {
			if got := strings.TrimSpace(tg.Sh(t, "stat -c '%a %u %g' "+p)); got != num.Replace(w) {
				t.Errorf("%s: %q, want %q", p, got, w)
			}
		}
		tg.Sh(t, "rm -rf /run/tagcess && systemd-tmpfiles --create /etc/tmpfiles.d/tagcess.conf")
		if got := strings.TrimSpace(tg.Sh(t, "stat -c '%a %u %G' /run/tagcess")); got != "750 10001 caddy" {
			t.Errorf("tmpfiles did not recreate /run/tagcess: %q", got)
		}
	})
	t.Run("TestHostRole_DNSSeedKeepsRecords", func(t *testing.T) {
		if a, b := tg.ReadFile(t, "/etc/headscale/extra-records.json"), tg.ReadFile(t, "/var/lib/tagcess/dns/extra-records.json"); a != b {
			t.Fatalf("records changed while seeding:\n%s\n%s", a, b)
		}
		tg.Sh(t, "runuser -u headscale -- cat /var/lib/tagcess/dns/extra-records.json >/dev/null")
		// An existing tagcess DNS file is never overwritten.
		tg.Sh(t, `echo '[]' > /var/lib/tagcess/dns/extra-records.json`)
		mustRun(t, tg, home, vars, nil, "host")
		if got := strings.TrimSpace(tg.ReadFile(t, "/var/lib/tagcess/dns/extra-records.json")); got != "[]" {
			t.Fatalf("the existing DNS file was overwritten: %s", got)
		}
	})
	t.Run("TestHostRole_SecretsByteExactNoLog", func(t *testing.T) {
		for p, v := range secrets {
			if got := tg.ReadFile(t, p); got != v {
				t.Errorf("%s is not byte-exact", p)
			}
			if strings.Contains(first.Output, v) {
				t.Errorf("the content of %s reached the output", p)
			}
		}
	})
}

// AC5 (F6-005): a missing secret file stops the phase before any directory on the host changes.
func TestHostRole_MissingSecretStopsEarly(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars, _ := hostVars(t)
	vars["secret_files"] = map[string]string{"webhook_signing_key": vars["secret_files"].(map[string]string)["webhook_signing_key"],
		"zitadel_key": "/nonexistent/zitadel-key.json"}
	before := tg.Checksums(t, hostRoots)
	res := runSite(t, tg, t.TempDir(), vars, nil, "host")
	if res.ExitCode == 0 || !strings.Contains(res.Output, "Secret dosyası yok: zitadel_key") {
		t.Fatalf("want a stop naming zitadel_key:\n%s", res.Output)
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("the host changed before the stop:\n%s", strings.Join(d, "\n"))
	}
}

// AC6 (F6-005): Docker is installed when missing in fresh mode and verified; in adopt mode only with
// confirm_add_missing=docker (else reported); an existing Docker package is not touched.
func TestHostRole_DockerAddedOnlyWhenMissing(t *testing.T) {
	t.Parallel()
	t.Run("fresh on bare", func(t *testing.T) {
		t.Parallel()
		tg := adopttarget.Up(t, "bare")
		// The fresh host phase needs the groups the fresh Caddy/Headscale packages create.
		tg.Sh(t, "groupadd -r caddy && groupadd -r headscale && useradd -r -g headscale headscale")
		vars, _ := hostVars(t)
		vars = adopttarget.Merge(adopttarget.BareVars(), map[string]any{"secret_files": vars["secret_files"]})
		res := mustRun(t, tg, t.TempDir(), vars, nil, "host")
		tg.Sh(t, "docker info >/dev/null && dpkg -s docker.io >/dev/null")
		if !strings.Contains(res.Output, "Install Docker (missing)") {
			t.Fatal("docker install task did not run")
		}
	})
	t.Run("adopt without docker", func(t *testing.T) {
		t.Parallel()
		tg := adopttarget.Up(t, "adopt")
		tg.Sh(t, "systemctl stop docker.socket docker.service containerd 2>/dev/null; DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq docker.io docker-compose-v2 >/dev/null")
		vars, _ := hostVars(t)
		home := t.TempDir()
		res := mustRun(t, tg, home, vars, nil, "host")
		if _, err := tg.ShErr("command -v docker"); err == nil {
			t.Fatal("docker was installed in adopt mode without confirmation")
		}
		if !strings.Contains(res.Output, "Docker yok ve adopt kipinde onaysız kurulmaz") {
			t.Fatalf("not reported:\n%s", res.Output)
		}
		mustRun(t, tg, home, vars, map[string]string{"confirm_add_missing": "docker"}, "host")
		tg.Sh(t, "docker info >/dev/null")
	})
	t.Run("adopt with docker", func(t *testing.T) {
		t.Parallel()
		tg := adopttarget.Up(t, "adopt")
		before := tg.Sh(t, "dpkg -s docker.io | grep -E '^(Version|Status)'")
		vars, _ := hostVars(t)
		res := mustRun(t, tg, t.TempDir(), vars, nil, "host")
		if after := tg.Sh(t, "dpkg -s docker.io | grep -E '^(Version|Status)'"); after != before || strings.Contains(res.Output, "TASK [host : Install Docker (missing)]\nchanged") {
			t.Fatal("the existing Docker package was touched")
		}
	})
}
