// Package caddy_test is the external test package for the Caddy apply layer (F2-008, ADR 0005,
// S-04): the admin API client, the apply order adapt → load → atomic file write, and the
// fail-safe paths. The admin API is a fake httptest server; the real pinned Caddy (v2.8.4 of the
// compose stack) is covered by the integration tests in test/compose.
package caddy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/site"
)

// fakeAdmin is a fake Caddy admin API. It records every adapt/load call with its body and
// answers with the configured status codes; the failure bodies imitate Caddy's plain-text and
// JSON error shapes. It also fails the test when a request misses the Content-Type Caddy
// requires for Caddyfile uploads (stack-notes: text/caddyfile).
type fakeAdmin struct {
	mu          sync.Mutex
	adaptStatus int
	loadStatus  int
	// failLoadAt (1-based) makes that /load call fail with 500; 0 disables it.
	failLoadAt int
	adapts     []string
	loads      []string
}

func newFakeAdmin(adaptStatus, loadStatus int) *fakeAdmin {
	return &fakeAdmin{adaptStatus: adaptStatus, loadStatus: loadStatus}
}

func (f *fakeAdmin) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "text/caddyfile" {
			http.Error(w, "content type "+got, http.StatusUnsupportedMediaType)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/adapt":
			f.adapts = append(f.adapts, string(body))
			if f.adaptStatus != http.StatusOK {
				http.Error(w, "adapt: invalid syntax near line 3", f.adaptStatus)
				return
			}
			_, _ = fmt.Fprint(w, `{"apps":{}}`)
		case "/load":
			f.loads = append(f.loads, string(body))
			if f.failLoadAt > 0 && len(f.loads) == f.failLoadAt {
				http.Error(w, "restore refused", http.StatusInternalServerError)
				return
			}
			if f.loadStatus != http.StatusOK {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(f.loadStatus)
				_, _ = fmt.Fprint(w, `{"error":"loading modules: provisioning failed"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeAdmin) calls() (adapts, loads []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.adapts...), append([]string(nil), f.loads...)
}

// systemSites returns the four canonical system sites in a non-render order.
func systemSites() []site.Site {
	base := func(tmpl, host, cert, config string) site.Site {
		return site.Site{
			Hosts:          []string{host},
			Kind:           site.KindSystem,
			SystemTemplate: tmpl,
			SystemConfig:   config,
			Cert:           cert,
			TargetKind:     site.TargetK8s,
			Roles:          []string{}, TargetRoles: []string{},
			APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		}
	}
	return []site.Site{
		base(site.TemplateTagcess, "tagcess.example.com", "auto", `{}`),
		base(site.TemplateWireGuardUI, "vpn.example.com", "auto", `{"enabled":true}`),
		base(site.TemplateHeadscale, "hs.example.com", "auto", `{"headplane":true}`),
		base(site.TemplateZitadel, "auth.example.com", "le:example", `{}`),
	}
}

func withoutTemplate(sites []site.Site, tmpl string) []site.Site {
	out := make([]site.Site, 0, len(sites))
	for _, s := range sites {
		if s.SystemTemplate != tmpl {
			out = append(out, s)
		}
	}
	return out
}

// applyFixture is a temp directory with a pre-existing Caddyfile.
func applyFixture(t *testing.T, previous string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(previous), 0o644); err != nil {
		t.Fatalf("write previous file: %v", err)
	}
	return path
}

const targetConfig = ":8081 {\n\trespond \"target\" 200\n}\n"
const previousConfig = ":8081 {\n\trespond \"previous\" 200\n}\n"

// TestCaddyApply_SystemSitesRequired is the F2-005 handover: the apply path refuses a site set
// that misses any of the four locked system site records — before /adapt is called, so a set
// without the tagcess block can never take the UI away. A duplicated template is refused too.
func TestCaddyApply_SystemSitesRequired(t *testing.T) {
	for _, tmpl := range []string{
		site.TemplateZitadel, site.TemplateTagcess, site.TemplateHeadscale, site.TemplateWireGuardUI,
	} {
		t.Run("missing_"+tmpl, func(t *testing.T) {
			fake := newFakeAdmin(http.StatusOK, http.StatusOK)
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()

			path := applyFixture(t, previousConfig)
			err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path,
				withoutTemplate(systemSites(), tmpl), targetConfig)
			if err == nil {
				t.Fatal("Apply accepted a site set without all four system sites")
			}
			if !strings.Contains(err.Error(), tmpl) {
				t.Errorf("error %v does not name the missing template %q", err, tmpl)
			}
			adapts, loads := fake.calls()
			if len(adapts) != 0 || len(loads) != 0 {
				t.Errorf("Apply called the admin API before the check: %d adapt, %d load calls", len(adapts), len(loads))
			}
			assertFileUnchanged(t, path, previousConfig)
		})
	}

	t.Run("duplicate_template", func(t *testing.T) {
		sites := append(systemSites(), systemSites()[0])
		fake := newFakeAdmin(http.StatusOK, http.StatusOK)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		path := applyFixture(t, previousConfig)
		if err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, sites, targetConfig); err == nil {
			t.Fatal("Apply accepted a duplicated system template")
		}
		adapts, _ := fake.calls()
		if len(adapts) != 0 {
			t.Errorf("Apply called /adapt %d times despite the refusal", len(adapts))
		}
	})

	t.Run("complete_set_passes", func(t *testing.T) {
		fake := newFakeAdmin(http.StatusOK, http.StatusOK)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		path := applyFixture(t, previousConfig)
		if err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig); err != nil {
			t.Fatalf("Apply with all four system sites: %v", err)
		}
	})
}

// TestCaddyApply_LoadFailure is AC1: when /adapt or /load refuses the target, the working
// config and the file stay untouched. A failing /adapt must not reach /load at all.
func TestCaddyApply_LoadFailure(t *testing.T) {
	cases := []struct {
		name        string
		adaptStatus int
		loadStatus  int
		wantLoads   int
	}{
		{"adapt_rejects_syntax", http.StatusBadRequest, http.StatusOK, 0},
		{"adapt_server_error", http.StatusInternalServerError, http.StatusOK, 0},
		{"load_rejects_provisioning", http.StatusOK, http.StatusBadRequest, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeAdmin(tc.adaptStatus, tc.loadStatus)
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()

			path := applyFixture(t, previousConfig)
			err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig)
			if err == nil {
				t.Fatal("Apply succeeded despite the admin API refusing the target")
			}
			var fwe *caddy.FileWriteError
			if errors.As(err, &fwe) {
				t.Errorf("an adapt/load refusal is not a file write failure: %v", err)
			}
			adapts, loads := fake.calls()
			if len(adapts) != 1 {
				t.Errorf("/adapt called %d times, want 1", len(adapts))
			}
			if len(loads) != tc.wantLoads {
				t.Errorf("/load called %d times, want %d", len(loads), tc.wantLoads)
			}
			if len(adapts) == 1 && adapts[0] != targetConfig {
				t.Errorf("/adapt received %q, want the rendered target", adapts[0])
			}
			assertFileUnchanged(t, path, previousConfig)
			assertNoTempFiles(t, path)
		})
	}
}

// TestCaddyApply_AtomicWrite is AC2: after a successful /load the file is replaced atomically —
// a reader holding the old file keeps seeing the old content (rename, not truncate), the new
// file carries the target bytes with 0644, and no temp file is left behind.
func TestCaddyApply_AtomicWrite(t *testing.T) {
	fake := newFakeAdmin(http.StatusOK, http.StatusOK)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	path := applyFixture(t, previousConfig)
	old, err := os.Open(path)
	if err != nil {
		t.Fatalf("open previous file: %v", err)
	}
	defer func() { _ = old.Close() }()

	if err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Rename semantics: the open handle still reads the previous generation.
	oldBytes, err := io.ReadAll(old)
	if err != nil {
		t.Fatalf("read the held-open old file: %v", err)
	}
	if string(oldBytes) != previousConfig {
		t.Errorf("old file handle reads %q after the apply; the write was not a rename", oldBytes)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read applied file: %v", err)
	}
	if string(got) != targetConfig {
		t.Errorf("file = %q, want the applied target %q", got, targetConfig)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat applied file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("file mode = %v, want 0644 (readable by the caddy user)", info.Mode().Perm())
	}
	adapts, loads := fake.calls()
	if len(adapts) != 1 || len(loads) != 1 || loads[0] != targetConfig {
		t.Errorf("admin calls: %d adapt, %d load (last body %q); want one of each with the target", len(adapts), len(loads), last(loads))
	}
	assertNoTempFiles(t, path)
}

// TestCaddyApply_DiskFailure is AC3: when the file write fails after /load succeeded, the
// previous content is loaded back and the returned *FileWriteError marks the critical alert
// (S-04.2). With no previous file there is nothing to restore; the alert then reports the
// runtime/disk divergence without inventing a state. The restore /load failing is its own
// field of the same error.
func TestCaddyApply_DiskFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the write failure cannot be simulated")
	}

	writeFails := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(path, []byte(previousConfig), 0o644); err != nil {
			t.Fatalf("write previous file: %v", err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("read-only dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		return path
	}

	t.Run("restore_previous", func(t *testing.T) {
		fake := newFakeAdmin(http.StatusOK, http.StatusOK)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		path := writeFails(t)
		err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig)
		var fwe *caddy.FileWriteError
		if !errors.As(err, &fwe) {
			t.Fatalf("error = %v, want *caddy.FileWriteError (the caller must raise a critical alert from it)", err)
		}
		if !fwe.Restored {
			t.Errorf("Restored = false, want the previous config loaded back")
		}
		if fwe.RestoreErr != nil {
			t.Errorf("RestoreErr = %v, want nil", fwe.RestoreErr)
		}
		if fwe.WriteErr == nil {
			t.Error("WriteErr = nil, want the atomic write failure")
		}
		_, loads := fake.calls()
		if len(loads) != 2 {
			t.Fatalf("/load called %d times, want 2 (target, then restore)", len(loads))
		}
		if loads[0] != targetConfig {
			t.Errorf("first /load carried %q, want the target", loads[0])
		}
		if loads[1] != previousConfig {
			t.Errorf("restore /load carried %q, want the previous content", loads[1])
		}
		assertFileUnchanged(t, path, previousConfig)
		assertNoTempFiles(t, path)
	})

	t.Run("restore_fails", func(t *testing.T) {
		fake := newFakeAdmin(http.StatusOK, http.StatusOK)
		fake.failLoadAt = 2 // the first /load (target) succeeds; the restore /load fails
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		path := writeFails(t)
		err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig)
		var fwe *caddy.FileWriteError
		if !errors.As(err, &fwe) {
			t.Fatalf("error = %v, want *caddy.FileWriteError", err)
		}
		if fwe.Restored {
			t.Error("Restored = true, want false")
		}
		if fwe.RestoreErr == nil {
			t.Error("RestoreErr = nil, want the failed restore /load")
		}
		_, loads := fake.calls()
		if len(loads) != 2 {
			t.Errorf("/load called %d times, want 2 (target, restore attempt)", len(loads))
		}
	})

	t.Run("no_previous_file", func(t *testing.T) {
		fake := newFakeAdmin(http.StatusOK, http.StatusOK)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		dir := t.TempDir()
		path := filepath.Join(dir, "Caddyfile")
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("read-only dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		err := caddy.Apply(context.Background(), caddy.NewClient(srv.URL), path, systemSites(), targetConfig)
		var fwe *caddy.FileWriteError
		if !errors.As(err, &fwe) {
			t.Fatalf("error = %v, want *caddy.FileWriteError", err)
		}
		if fwe.Restored || fwe.RestoreErr != nil {
			t.Errorf("Restored = %v, RestoreErr = %v; with no previous file there is nothing to restore", fwe.Restored, fwe.RestoreErr)
		}
		_, loads := fake.calls()
		if len(loads) != 1 {
			t.Errorf("/load called %d times, want 1 (no restore without a previous file)", len(loads))
		}
	})
}

// TestClient_AdminAPI pins the wire behaviour of the admin API client: Caddyfile uploads carry
// text/caddyfile, failures surface the response body in the error (plain text and JSON shapes),
// and Config reads the live config.
func TestClient_AdminAPI(t *testing.T) {
	var mu sync.Mutex
	var sawType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawType = r.Header.Get("Content-Type")
		mu.Unlock()
		switch {
		case r.URL.Path == "/adapt" && r.Method == http.MethodPost:
			http.Error(w, "plain adapt failure", http.StatusBadRequest)
		case r.URL.Path == "/load" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"json load failure"}`)
		case r.URL.Path == "/config/" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"apps":{}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cl := caddy.NewClient(srv.URL)

	if err := cl.Adapt(context.Background(), previousConfig); err == nil || !strings.Contains(err.Error(), "plain adapt failure") {
		t.Errorf("Adapt error = %v, want the response body", err)
	}
	if err := cl.Load(context.Background(), previousConfig); err == nil || !strings.Contains(err.Error(), "json load failure") {
		t.Errorf("Load error = %v, want the JSON error field", err)
	}
	mu.Lock()
	typ := sawType
	mu.Unlock()
	if typ != "text/caddyfile" {
		t.Errorf("uploads went out as Content-Type %q, want text/caddyfile", typ)
	}
	cfg, err := cl.Config(context.Background())
	if err != nil || string(cfg) != `{"apps":{}}` {
		t.Errorf("Config = %q, %v; want the live config", cfg, err)
	}
}

func assertFileUnchanged(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("file changed to %q, want it untouched (%q)", got, want)
	}
}

func assertNoTempFiles(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

func last(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[len(ss)-1]
}

// F2-011: the first-import parity gate needs Caddy's adapted JSON, not just a verdict. Caddy's
// /adapt wraps the config as {"result": ..., "warnings": [...]}; AdaptJSON hands back the config
// alone, so two adapted files compare without the warning positions.
func TestClient_AdaptJSONUnwrapsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" || r.Header.Get("Content-Type") != "text/caddyfile" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"result":{"apps":{"http":{}}},"warnings":[{"line":3,"message":"not formatted"}]}`)
	}))
	defer srv.Close()

	got, err := caddy.NewClient(srv.URL).AdaptJSON(context.Background(), targetConfig)
	if err != nil {
		t.Fatalf("AdaptJSON: %v", err)
	}
	if string(got) != `{"apps":{"http":{}}}` {
		t.Errorf("AdaptJSON = %s, want only the result object", got)
	}
}

func TestClient_AdaptJSONErrors(t *testing.T) {
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "adapt: invalid syntax", http.StatusBadRequest)
	}))
	defer refuse.Close()
	if _, err := caddy.NewClient(refuse.URL).AdaptJSON(context.Background(), "x"); err == nil {
		t.Error("a refused adapt returned no error")
	}

	// A 200 without a result is not an adapted config: the gate must not compare an empty document.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"warnings":[]}`)
	}))
	defer empty.Close()
	if _, err := caddy.NewClient(empty.URL).AdaptJSON(context.Background(), "x"); err == nil {
		t.Error("an adapt response without a result returned no error")
	}
}

// The adapted config of the real site count is far larger than an error message; AdaptJSON must
// not cut it short (a truncated document would make the parity gate fail on valid input).
func TestClient_AdaptJSONLargeResult(t *testing.T) {
	big := `{"apps":{"pad":"` + strings.Repeat("x", 200<<10) + `"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"result":`+big+`,"warnings":[]}`)
	}))
	defer srv.Close()

	got, err := caddy.NewClient(srv.URL).AdaptJSON(context.Background(), targetConfig)
	if err != nil {
		t.Fatalf("AdaptJSON: %v", err)
	}
	if string(got) != big {
		t.Errorf("AdaptJSON returned %d bytes, want %d", len(got), len(big))
	}
}

// The running config of the real site count is far larger than an error message. Config must hand
// it back whole: the change pipeline compares the config before and after a failed load to prove
// nothing changed, and a silently truncated read would hide a change past the cut.
func TestClient_ConfigIsNotTruncated(t *testing.T) {
	big := `{"apps":{"pad":"` + strings.Repeat("x", 200<<10) + `"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, big)
	}))
	defer srv.Close()
	got, err := caddy.NewClient(srv.URL).Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if string(got) != big {
		t.Errorf("Config returned %d bytes, want %d", len(got), len(big))
	}
}

// A response past the read limit is an error, never a silently shortened document.
func TestClient_OversizedResponseIsAnError(t *testing.T) {
	huge := strings.Repeat("x", 9<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, huge)
	}))
	defer srv.Close()
	cl := caddy.NewClient(srv.URL)
	if _, err := cl.Config(context.Background()); err == nil {
		t.Error("an oversized /config/ response was returned truncated")
	}
	if _, err := cl.AdaptJSON(context.Background(), "x"); err == nil {
		t.Error("an oversized /adapt response was returned truncated")
	}
}
