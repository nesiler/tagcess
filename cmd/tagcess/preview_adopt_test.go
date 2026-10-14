//go:build installer

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// adoptPreviewConfig is a tagcess config for the adopt-shaped target (example.test names, F6-001 fixture).
const adoptPreviewConfig = `data_dir: /root/pv/data
ui: {socket: /root/pv/ui.sock, socket_group: caddy}
hook: {listen: 100.64.0.4:9443, signing_key_file: /root/pv/k}
headscale: {socket: /var/run/headscale/headscale.sock}
zitadel: {issuer: https://auth.c.example.test, project_id: "1", key_file: /root/pv/z, oauth2_proxy_app: oauth2-proxy}
caddy: {admin_url: http://127.0.0.1:2019, caddyfile_path: /etc/caddy/Caddyfile}
dns: {records_path: /etc/headscale/extra-records.json}
sites:
  allowed_domains: [c.example.test, b.example.test, internal.a.example.test]
  allowed_targets: [100.64.0.5]
  acme_email: admin@c.example.test
  certificates: [internal.a.example.test, b.example.test, c.example.test]
  vpn_address: 100.64.0.4
  k8s_upstream: https://100.64.0.5:8443
  tagcess_host: tagcess.c.example.test
  zitadel_internal_sources: [10.8.0.0/24, 127.0.0.1/32, "::1/128", 192.0.2.10/32, "2001:db8:10::/64", 192.0.2.20/32, "2001:db8:20::/64"]
  seed_file: /root/pv/seed.json
`

// AC3 (F6-004): with the adopt-shaped fixture (20 sites, 5 with @api) and the adopt seed example (sites
// open + transition), -import-preview against the real Caddy 2.8.4 reports parity 0 apart from the one accepted
// class (developer decision 2026-10-07, [K] F6): parity "accepted", no diff line, and s06_open_start exactly for
// the 20 open sites (18 transition, 2 intentional vpn_only), each with today's tailnet + free sources.
func TestCLIImportPreview_AdoptShapeOpenTransitionEqual(t *testing.T) {
	tg := adopttarget.Up(t, "adopt")
	bin := filepath.Join(t.TempDir(), "tagcess")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+dockerArch(t))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	seed, err := os.ReadFile(filepath.Join(adopttarget.RepoRoot(), "deploy", "ansible", "examples", "seed.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", bin, tg.Name+":/usr/local/bin/tagcess-cli").CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	tg.WriteFile(t, "/root/pv/config.yaml", adoptPreviewConfig, "0600", "root:root")
	tg.WriteFile(t, "/root/pv/seed.json", string(seed), "0600", "root:root")
	tg.Sh(t, "mkdir -p /root/pv/data")
	// stdout is the JSON report, stderr the S-06 warning: docker exec interleaves a combined stream in either order,
	// so the warning goes to a file and is checked on its own.
	out, err := tg.ShErr("tagcess-cli -config /root/pv/config.yaml -import-preview 2>/root/pv/stderr.txt")
	var p importPreview
	if jerr := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &p); jerr != nil {
		t.Fatalf("preview output: %v (%v)\n%s", jerr, err, out)
	}
	if warn := tg.Sh(t, "cat /root/pv/stderr.txt"); !strings.Contains(warn, "WARNING: accepted difference s06_open_start") {
		t.Errorf("the S-06 warning is missing on stderr:\n%s", warn)
	}
	if err != nil || p.Parity != "accepted" || p.DiffCount != 0 || len(p.FirstDiffs) != 0 || len(p.Narrower) != 0 {
		t.Fatalf("adopt shape parity is %q with %d differences (only s06_open_start is accepted):\n%s",
			p.Parity, p.DiffCount, strings.Join(p.FirstDiffs, "\n"))
	}
	var hosts []string
	for _, a := range p.Accepted {
		if a.Class != "s06_open_start" || !slices.Contains(a.TodaySources, "100.64.0.0/10") || !slices.Contains(a.TodaySources, "10.8.0.0/24") {
			t.Errorf("accepted %+v", a)
		}
		hosts = append(hosts, a.Hosts...)
	}
	var want []string
	for _, f := range []string{"issues", "blog", "blog-staging", "blog-admin", "dashboard", "dashboard-staging", "store", "store-staging"} {
		want = append(want, f+".internal.a.example.test")
	}
	want = append(want, "sandbox.b.example.test")
	for _, f := range []string{"docs", "k8s-api", "monitor", "dbmetrics", "dbadmin", "projects", "projects-auth", "storage-api", "errors", "partner-api", "tickets"} {
		want = append(want, f+".c.example.test")
	}
	slices.Sort(hosts)
	slices.Sort(want)
	if !slices.Equal(hosts, want) {
		t.Fatalf("accepted hosts = %v, want the 20 existing installation sites %v", hosts, want)
	}
}

func dockerArch(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.TrimSpace(string(out)); a == "x86_64" {
		return "amd64"
	}
	return "arm64"
}
