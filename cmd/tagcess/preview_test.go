package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// fakeCaddyAdmin answers POST /adapt with a stand-in JSON document derived from the text (so equal texts are
// equal JSON) and records every request; anything but POST /adapt is a write attempt.
type fakeCaddyAdmin struct {
	mu     sync.Mutex
	calls  []string
	bodies []string
	writes int
	// docFor, when set, answers /adapt with the document it returns for the text instead.
	docFor func(caddyfile string) any
}

func (f *fakeCaddyAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.bodies = append(f.bodies, string(body))
	if r.Method != http.MethodPost || r.URL.Path != "/adapt" {
		f.writes++
	}
	f.mu.Unlock()
	if r.URL.Path != "/adapt" {
		http.Error(w, "not here", http.StatusNotFound)
		return
	}
	doc := map[string]any{"result": map[string]any{"apps": map[string]any{"lines": strings.Split(strings.TrimSpace(string(body)), "\n")}}}
	if f.docFor != nil {
		doc = map[string]any{"result": f.docFor(string(body))}
	}
	_ = json.NewEncoder(w).Encode(doc)
}

// previewFixture is one config + seed + Caddyfile + DNS file set in a temp dir.
type previewFixture struct {
	dir, config, caddyfile, seed, dns, dataDir string
	admin                                      *fakeCaddyAdmin
}

const previewSeed = `{"sites": [
 {"hosts": ["monitor.example.test"], "kind": "open", "open_reason": "transition", "target_roles": ["devops", "developer"], "cert": "le:example.test", "target": "k8s", "magicdns": true},
 {"hosts": ["auth.example.test"], "kind": "system", "system_template": "zitadel", "system_config": {}, "cert": "le:example.test", "target": "k8s", "magicdns": true},
 {"hosts": ["hs.example.test"], "kind": "system", "system_template": "headscale", "system_config": {"headplane": false}, "cert": "auto", "target": "k8s", "magicdns": false}
]}`

func newPreviewFixture(t *testing.T, secretMarker string) *previewFixture {
	t.Helper()
	f := &previewFixture{dir: t.TempDir(), admin: &fakeCaddyAdmin{}}
	srv := httptest.NewServer(f.admin)
	t.Cleanup(srv.Close)
	f.dataDir = filepath.Join(f.dir, "data")
	f.caddyfile = filepath.Join(f.dir, "Caddyfile")
	f.seed = filepath.Join(f.dir, "seed.json")
	f.dns = filepath.Join(f.dir, "extra-records.json")
	f.config = filepath.Join(f.dir, "config.yaml")
	secrets := filepath.Join(f.dir, "secrets")
	for _, d := range []string{f.dataDir, secrets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"webhook-signing-key", "groups-signing-key", "zitadel-key.json"} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(secretMarker), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(f.seed, previewSeed)
	write(f.dns, `[{"name":"monitor.example.test","type":"A","value":"100.64.0.4"},{"name":"legacy.example.test","type":"A","value":"100.64.0.9"}]`+"\n")
	write(f.config, fmt.Sprintf(`data_dir: %s
ui:
  socket: %s/ui.sock
  socket_group: tagcess
hook:
  listen: 100.64.0.4:9443
  signing_key_file: %s/webhook-signing-key
  groups_signing_key_file: %s/groups-signing-key
headscale:
  socket: %s/headscale.sock
zitadel:
  issuer: https://auth.example.test
  project_id: "000000000000000000"
  key_file: %s/zitadel-key.json
  oauth2_proxy_app: oauth2-proxy
caddy:
  admin_url: %s
  caddyfile_path: %s
dns:
  records_path: %s
sites:
  allowed_domains: [example.test]
  allowed_targets: [100.64.0.5]
  acme_email: admin@example.test
  certificates: [example.test]
  vpn_address: 100.64.0.4
  tagcess_host: tagcess.example.test
  seed_file: %s
`, f.dataDir, f.dir, secrets, secrets, f.dir, secrets, srv.URL, f.caddyfile, f.dns, f.seed))
	// Today's file means exactly what the seed renders (the tagcess block is never part of today's file).
	write(f.caddyfile, f.render(t))
	return f
}

// render returns the Caddyfile the seed renders the way the parity check renders it.
func (f *previewFixture) render(t *testing.T) string {
	t.Helper()
	return renderPreviewSeed(t, "")
}

// renderPreviewSeed renders the preview seed with the given (k8s) upstream ("" is the default).
func renderPreviewSeed(t *testing.T, upstream string) string {
	t.Helper()
	sites, err := site.PrepareSeed([]byte(previewSeed), site.SeedOptions{TagcessHost: "tagcess.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var kept []site.Site
	for _, s := range sites {
		if s.SystemTemplate != site.TemplateTagcess {
			kept = append(kept, s)
		}
	}
	out, err := render.RenderCaddyfile(kept, render.CaddyConfig{ACMEEmail: "admin@example.test", S06Open: true, Certs: []string{"example.test"},
		ZitadelIssuer: "https://auth.example.test", K8sUpstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *previewFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"-config", f.config}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func decodePreview(t *testing.T, out string) importPreview {
	t.Helper()
	var p importPreview
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("preview output is not JSON: %v\n%s", err, out)
	}
	return p
}

// AC1 (F6-004): an equivalent seed and Caddyfile give parity equal and exit 0.
func TestCLIImportPreview_Equal(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	code, out, errb := f.run(t, "-import-preview")
	p := decodePreview(t, out)
	if code != 0 || p.Parity != "equal" || p.DiffCount != 0 || p.Imported || p.SeedSites != 3 {
		t.Fatalf("code %d preview %+v stderr %s", code, p, errb)
	}
	// The DNS record that no site owns is reported as a manual record the import keeps.
	if len(p.ManualDNS) != 1 || p.ManualDNS[0].Name != "legacy.example.test" {
		t.Fatalf("manual dns %+v", p.ManualDNS)
	}
}

// F6 parity (M6): the preview renders with the configured (k8s) upstream (an existing installation: :8443), so a setting is not
// reported as a difference, while a file whose upstream differs from the setting still is.
func TestCLIImportPreview_K8sUpstreamSetting(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	adopt := renderPreviewSeed(t, "https://100.64.0.5:8443")
	if err := os.WriteFile(f.caddyfile, []byte(adopt), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := f.run(t, "-import-preview")
	if p := decodePreview(t, out); code != previewDiff || !strings.Contains(strings.Join(p.FirstDiffs, "\n"), "100.64.0.5:8443") {
		t.Fatalf("default setting against an :8443 file: code %d preview %+v", code, p)
	}
	cfg, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	withUp := strings.Replace(string(cfg), "  vpn_address: 100.64.0.4\n", "  vpn_address: 100.64.0.4\n  k8s_upstream: https://100.64.0.5:8443\n", 1)
	if err := os.WriteFile(f.config, []byte(withUp), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := f.run(t, "-import-preview")
	if p := decodePreview(t, out); code != previewEqual || p.Parity != "equal" {
		t.Fatalf("k8s_upstream :8443 against an :8443 file: code %d preview %+v stderr %s", code, p, errb)
	}
}

// F6 parity (M6): today's relative `import sites/*.caddy` reaches /adapt as the absolute path under the
// Caddyfile's directory (Caddy would otherwise resolve it against its own working directory and drop the sites);
// the generated text is adapted unchanged.
func TestCLIImportPreview_ResolvesRelativeImports(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	if err := os.WriteFile(f.caddyfile, []byte(f.render(t)+"import sites/*.caddy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.run(t, "-import-preview")
	want := "import " + filepath.Join(filepath.Dir(f.caddyfile), "sites/*.caddy") + "\n"
	if len(f.admin.bodies) != 2 || !strings.HasSuffix(f.admin.bodies[0], want) || strings.Contains(f.admin.bodies[1], "import sites") {
		t.Fatalf("/adapt bodies do not carry the absolute import %q:\n%q", want, f.admin.bodies)
	}
}

// AC2 (F6-004): after the first import the preview reports imported and compares nothing.
func TestCLIImportPreview_AlreadyImported(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	st, err := store.Open(context.Background(), filepath.Join(f.dataDir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{Key: "site.first_import", Value: "passed"}); err != nil {
		t.Fatal(err)
	}
	if pending, done, err := site.ReadFirstImportState(context.Background(), st.Queries()); err != nil || pending || !done {
		t.Fatalf("the key the CLI reads is not the gate's key: pending %v done %v err %v", pending, done, err)
	}
	_ = st.Close()
	// Even a Caddyfile that would differ is not compared.
	if err := os.WriteFile(f.caddyfile, []byte("# tagcess owns this file now\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := f.run(t, "-import-preview")
	p := decodePreview(t, out)
	if code != 0 || !p.Imported || p.Parity != "not_compared" || len(f.admin.calls) != 0 {
		t.Fatalf("code %d preview %+v caddy calls %v", code, p, f.admin.calls)
	}
}

// AC4 (F6-004): a different Caddyfile gives the difference count, the first differences and exit 3.
func TestCLIImportPreview_Diff(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	changed := strings.Replace(f.render(t), "monitor.example.test", "mon2.example.test", 1)
	if err := os.WriteFile(f.caddyfile, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := f.run(t, "-import-preview")
	p := decodePreview(t, out)
	if code != 3 || p.Parity != "diff" || p.DiffCount < 1 || len(p.FirstDiffs) == 0 {
		t.Fatalf("code %d preview %+v", code, p)
	}
	if !strings.Contains(strings.Join(p.FirstDiffs, "\n"), "monitor") {
		t.Fatalf("first differences do not name the change: %v", p.FirstDiffs)
	}
}

func treeSums(t *testing.T, root string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		v := info.Mode().String()
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p) // #nosec G304 -- test temp dir
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			v += " " + hex.EncodeToString(h[:])
		}
		sums[p] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return sums
}

// AC5 (F6-004): the preview changes no file, no database row and asks Caddy only to adapt.
func TestCLIImportPreview_ReadOnly(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	st, err := store.Open(context.Background(), filepath.Join(f.dataDir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{Key: "site.first_import", Value: "pending"}); err != nil {
		t.Fatal(err)
	}
	rowsBefore, err := st.Queries().ListSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	before := treeSums(t, f.dir)
	for _, args := range [][]string{{"-import-preview"}, {"-k8s-manifest", "-k8s-namespaces", "web"}} {
		if code, out, errb := f.run(t, args...); code != 0 {
			t.Fatalf("%v: code %d\n%s\n%s", args, code, out, errb)
		}
	}
	after := treeSums(t, f.dir)
	for p, v := range before {
		if after[p] != v {
			t.Errorf("%s changed: %s -> %s", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s was created", p)
		}
	}
	if f.admin.writes != 0 || len(f.admin.calls) == 0 {
		t.Fatalf("Caddy calls %v (writes %d): only POST /adapt is allowed", f.admin.calls, f.admin.writes)
	}
	st, err = store.Open(context.Background(), filepath.Join(f.dataDir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	rowsAfter, err := st.Queries().ListSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(rowsBefore) != fmt.Sprint(rowsAfter) {
		t.Fatalf("settings rows changed: %v -> %v", rowsBefore, rowsAfter)
	}
}

// AC7 (F6-004): readable secret files never reach the output of either command.
func TestCLIPreview_NoSecretInOutput(t *testing.T) {
	marker := "CLI-SECRET-MARKER-5e1b"
	f := newPreviewFixture(t, marker)
	for _, args := range [][]string{{"-import-preview"}, {"-k8s-manifest", "-k8s-namespaces", "web,monitoring"}, {"-k8s-manifest"}} {
		_, out, errb := f.run(t, args...)
		if strings.Contains(out+errb, marker) {
			t.Fatalf("%v printed a secret file's content", args)
		}
	}
	// A failing preview (no seed) must not print it either.
	if err := os.Remove(f.seed); err != nil {
		t.Fatal(err)
	}
	if code, out, errb := f.run(t, "-import-preview"); code != 1 || strings.Contains(out+errb, marker) {
		t.Fatalf("code %d, output leaks or wrong code", code)
	}
}

// AC6 (F6-004): -k8s-manifest prints the same bytes as the UI's /k8s/setup/manifest download, without a network
// call.
func TestCLIK8sManifest_MatchesUI(t *testing.T) {
	l := newF4Lab(t, f4Fakes{})
	ui := devopsGet(l.h, "/k8s/setup/manifest")
	if ui.Code != http.StatusOK {
		t.Fatalf("UI manifest: %d %s", ui.Code, ui.Body.String())
	}
	f := newPreviewFixture(t, "unused")
	// The CLI reads the same database the UI used (a consistent copy at the configured data_dir).
	if _, err := l.st.DB().ExecContext(context.Background(), "VACUUM INTO ?", filepath.Join(f.dataDir, dbName)); err != nil {
		t.Fatal(err)
	}
	listsBefore := l.lists.Load()
	code, out, errb := f.run(t, "-k8s-manifest")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errb)
	}
	if out != ui.Body.String() {
		t.Fatalf("CLI manifest differs from the UI's:\n--- cli\n%s\n--- ui\n%s", out, ui.Body.String())
	}
	if l.lists.Load() != listsBefore || len(f.admin.calls) != 0 {
		t.Fatalf("-k8s-manifest made network calls (k8s %d -> %d, caddy %v)", listsBefore, l.lists.Load(), f.admin.calls)
	}
	// The ServiceAccount flags match the UI's query parameters.
	ui2 := devopsGet(l.h, "/k8s/setup/manifest?sa_namespace=ops&sa_name=reader")
	if _, out2, _ := f.run(t, "-k8s-manifest", "-sa-namespace", "ops", "-sa-name", "reader"); out2 != ui2.Body.String() {
		t.Fatalf("named ServiceAccount: CLI and UI differ")
	}
}

// s06SiteRoute is monitor.example.test as Caddy adapts it: gated is today's existing block (tailnet and the free
// sources to the target, every other source 403); open is the block tagcess renders with S-06 open.
func s06SiteRoute(gated bool, dial string) any {
	proxy := map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": dial}}}}}
	sub := func(routes ...any) []any { return []any{map[string]any{"handler": "subroute", "routes": routes}} }
	branch := func(ranges ...any) any {
		return map[string]any{"group": "group1", "match": []any{map[string]any{"remote_ip": map[string]any{"ranges": ranges}}}, "handle": sub(proxy)}
	}
	inner := []any{proxy}
	if gated {
		deny := map[string]any{"group": "group1", "handle": sub(map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}}})}
		inner = []any{branch("100.64.0.0/10"), branch("10.8.0.0/24", "127.0.0.1"), deny}
	}
	return map[string]any{"match": []any{map[string]any{"host": []any{"monitor.example.test"}}}, "handle": sub(inner...), "terminal": true}
}

func s06Doc(route any) any {
	return map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{"routes": []any{route}}}}}}
}

// Developer decision 2026-10-07 ([K] F6): the S-06 open start is the one accepted difference. The preview reports
// it by name (parity accepted, the class, its sites and today's sources), exits 0 and warns on stderr; it is never
// reported as plain "equal".
func TestCLIImportPreview_AcceptedS06OpenStart(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	if err := os.WriteFile(f.caddyfile, []byte("# TODAY\n"+f.render(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	f.admin.docFor = func(body string) any {
		return s06Doc(s06SiteRoute(strings.HasPrefix(body, "# TODAY"), "100.64.0.5:443"))
	}
	code, out, errb := f.run(t, "-import-preview")
	p := decodePreview(t, out)
	if code != previewEqual || p.Parity != "accepted" || p.DiffCount != 0 || len(p.FirstDiffs) != 0 {
		t.Fatalf("code %d preview %+v stderr %s", code, p, errb)
	}
	if len(p.Accepted) != 1 || p.Accepted[0].Class != "s06_open_start" || p.Accepted[0].Hosts[0] != "monitor.example.test" ||
		!slices.Contains(p.Accepted[0].TodaySources, "10.8.0.0/24") {
		t.Fatalf("accepted %+v", p.Accepted)
	}
	if !strings.Contains(out, `"accepted": [`) || !strings.Contains(out, `"class": "s06_open_start"`) {
		t.Errorf("the report must carry accepted: s06_open_start:\n%s", out)
	}
	if !strings.Contains(errb, "s06_open_start") || !strings.Contains(errb, "monitor.example.test") {
		t.Errorf("stderr must warn about the accepted class: %q", errb)
	}
}

// A narrowing is a difference (exit 3) and is listed separately from the diff lines.
func TestCLIImportPreview_NarrowerReported(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	if err := os.WriteFile(f.caddyfile, []byte("# TODAY\n"+f.render(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	f.admin.docFor = func(body string) any {
		return s06Doc(s06SiteRoute(!strings.HasPrefix(body, "# TODAY"), "100.64.0.5:443"))
	}
	code, out, _ := f.run(t, "-import-preview")
	p := decodePreview(t, out)
	if code != previewDiff || p.Parity != "diff" || len(p.Accepted) != 0 || p.DiffCount == 0 {
		t.Fatalf("code %d preview %+v", code, p)
	}
	if len(p.Narrower) != 1 || p.Narrower[0].Hosts[0] != "monitor.example.test" || p.Narrower[0].TodaySources[0] != "*" {
		t.Fatalf("narrower %+v", p.Narrower)
	}
}

// The installer's caddy_ui phase adds the tagcess block to today's file before the first import. The preview
// compares the tagcess record too when today's file serves its host (it must not report the installed block as
// "only in today's file"); without the block it is still left out.
func TestCLIImportPreview_InstalledTagcessBlock(t *testing.T) {
	f := newPreviewFixture(t, "unused")
	sites, err := site.PrepareSeed([]byte(previewSeed), site.SeedOptions{TagcessHost: "tagcess.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	full, err := render.RenderCaddyfile(site.WithTagcess(sites, "tagcess.example.test"),
		render.CaddyConfig{ACMEEmail: "admin@example.test", S06Open: true, Certs: []string{"example.test"}, ZitadelIssuer: "https://auth.example.test"})
	if err != nil || !strings.Contains(full, "\ntagcess.example.test {\n") {
		t.Fatalf("render with the tagcess record: %v\n%s", err, full)
	}
	if err := os.WriteFile(f.caddyfile, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	// The fake Caddy adapts a text to one host route per top-level site block, which is all this rule looks at.
	blockHost := regexp.MustCompile(`(?m)^([a-z0-9.-]+) \{$`)
	f.admin.docFor = func(body string) any {
		var routes []any
		for _, m := range blockHost.FindAllStringSubmatch(body, -1) {
			routes = append(routes, map[string]any{"match": []any{map[string]any{"host": []any{m[1]}}},
				"handle": []any{map[string]any{"handler": "subroute", "routes": []any{}}}, "terminal": true})
		}
		return s06Doc2(routes)
	}
	code, out, errb := f.run(t, "-import-preview")
	if p := decodePreview(t, out); code != previewEqual || p.Parity != "equal" {
		t.Fatalf("today's file with the installed tagcess block: code %d preview %+v stderr %s", code, p, errb)
	}
	if n := len(f.admin.bodies); n != 2 || !strings.Contains(f.admin.bodies[1], "\ntagcess.example.test {\n") {
		t.Fatalf("the generated text sent to /adapt must carry the tagcess block when today's file serves it (%d bodies)", n)
	}
}

func s06Doc2(routes []any) any {
	return map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{"routes": routes}}}}}
}
