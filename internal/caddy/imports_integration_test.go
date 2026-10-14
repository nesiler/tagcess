//go:build integration

package caddy

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// adaptedHosts runs `caddy adapt` (pinned Caddy v2.8.4) on the text from stdin with the adopt-shaped fixture
// mounted at /etc/caddy and the working directory "/" (as the systemd unit runs Caddy), and returns the
// hosts of the server routes.
func adaptedHosts(t *testing.T, fixture, caddyfile string) []string {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm", "-i", "-w", "/", "-v", fixture+":/etc/caddy:ro", "caddy:2.8.4",
		"caddy", "adapt", "--adapter", "caddyfile", "--config", "/dev/stdin")
	cmd.Stdin = strings.NewReader(caddyfile)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("caddy adapt: %v: %s", err, errb.String())
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			for _, m := range r.Match {
				hosts = append(hosts, m.Host...)
			}
		}
	}
	slices.Sort(hosts)
	return hosts
}

// TestAbsImports_RealCaddySeesSiteFiles (F6 parity, M6): with today's relative `import sites/*.caddy` the
// pinned Caddy, reading the text from stdin, finds none of the 20 adopt-target site files (the glob is resolved
// against its working directory and an empty match is only a warning); after AbsImports it finds all of them.
func TestAbsImports_RealCaddySeesSiteFiles(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	fixture := filepath.Join(filepath.Dir(self), "..", "..", "test", "adopttarget", "fixtures", "adopt", "etc", "caddy")
	text, err := os.ReadFile(filepath.Join(fixture, "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(fixture, "sites", "*.caddy"))
	if err != nil || len(files) != 20 {
		t.Fatalf("fixture site files: %d, %v", len(files), err)
	}
	system := []string{"auth.c.example.test", "hs.c.example.test", "vpn.c.example.test"}
	if got := adaptedHosts(t, fixture, string(text)); !slices.Equal(got, system) {
		t.Fatalf("without AbsImports Caddy saw %v; the premise of the fix (only the system blocks) no longer holds", got)
	}
	want := slices.Clone(system)
	for _, f := range files {
		want = append(want, strings.TrimSuffix(filepath.Base(f), ".caddy"))
	}
	slices.Sort(want)
	if got := adaptedHosts(t, fixture, AbsImports(string(text), "/etc/caddy")); !slices.Equal(got, want) {
		t.Fatalf("with AbsImports Caddy saw %v, want %v", got, want)
	}
}
