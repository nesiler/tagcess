package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// updateGolden rewrites golden files instead of comparing against them.
var updateGolden = flag.Bool("update", false, "rewrite golden files")

func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var b bytes.Buffer
	if err := c.Render(context.Background(), &b); err != nil {
		t.Fatalf("render component: %v", err)
	}
	return b.String()
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return string(b)
}

// AC1: every asset is embedded and no page points at an external address (ADR 0007).
func TestAssets_NoExternalRefs(t *testing.T) {
	page := render(t, Layout(
		Actor{User: "jdoe", Email: "jdoe@example.com"}, "token", "pano", "Pano",
		templ.Raw(`<p>içerik</p>`),
	))
	lower := strings.ToLower(page)
	for _, ref := range []string{`href="http`, `href="//`, `src="http`, `src="//`, `url(http`, `url(//`, `@import`} {
		if strings.Contains(lower, ref) {
			t.Errorf("page references an external address (%q):\n%s", ref, page)
		}
	}
	// The page must load the embedded assets from the local static path, not a CDN.
	for _, name := range []string{"tokens.css", "components.css", "ui.js", "htmx.min.js"} {
		if !strings.Contains(page, "/static/"+name) {
			t.Errorf("page does not reference embedded asset /static/%s", name)
		}
	}
}

// The embedded files are served with their pinned versions, so an accidental upgrade or a broken
// embed fails the build's tests.
func TestStatic_ServesEmbeddedAssets(t *testing.T) {
	handler := Static()
	tests := []struct{ name, marker string }{
		{"tokens.css", "--primary:"},
		{"components.css", ".btn-primary"},
		{"ui.js", "data-theme-toggle"},
		{"htmx.min.js", `version:"2.0.11"`},
		{"editor.js", "data-code-editor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/"+tc.name, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte(tc.marker)) {
				t.Errorf("%s does not contain pinned marker %q", tc.name, tc.marker)
			}
		})
	}
}

// Directory listings are refused: only the exact embedded files are reachable.
func TestStatic_RefusesDirectory(t *testing.T) {
	rec := httptest.NewRecorder()
	Static().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The vendored assets are pinned by content as well as by version, so a swapped or corrupted file
// fails the build's tests, not just the version marker.
func TestStatic_AssetChecksums(t *testing.T) {
	want := map[string]string{
		"static/htmx.min.js": "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
		// Built by tools/editor/build.sh from the pinned CodeMirror 6 packages (docs/ui-guide.md).
		"static/editor.js": "48d1c4ae0cda2bbe3a445cc7d82432caf96a373c2d2bd249e3c370849ae70758",
	}
	for name, wantSum := range want {
		data, err := fs.ReadFile(staticFS, name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantSum {
			t.Errorf("%s checksum = %s, want %s", name, got, wantSum)
		}
	}
}

// AC2: htmx state-changing requests get the CSRF token automatically. The token is set as hx-headers
// on <body>, which htmx inherits, and the header name is the one the CSRF middleware checks.
func TestLayout_HtmxSendsCSRF(t *testing.T) {
	csrf, err := NewCSRF(bytes.Repeat([]byte("k"), csrfKeySize))
	if err != nil {
		t.Fatalf("new csrf: %v", err)
	}
	token := csrf.Token()

	page := render(t, Layout(Actor{User: "jdoe"}, token, "pano", "Pano", templ.Raw("")))
	m := regexp.MustCompile(`hx-headers="([^"]*)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("layout has no hx-headers attribute:\n%s", page)
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &headers); err != nil {
		t.Fatalf("hx-headers is not JSON (%v): %s", err, m[1])
	}
	if got := headers[CSRFHeader]; got != token {
		t.Fatalf("hx-headers[%s] = %q, want the layout's CSRF token", CSRFHeader, got)
	}
}

// AC3: the layout renders the active user and the navigation menu, with the current entry marked.
func TestLayout_Render(t *testing.T) {
	const active = "sync"
	actor := Actor{User: "jdoe", Email: "jdoe@example.com", Groups: []string{"devops", "developer"}}
	page := render(t, Layout(actor, "token", active, "Sync", templ.Raw(`<p id="content">içerik</p>`)))

	if !strings.Contains(page, `data-theme="dark"`) {
		t.Error("layout does not default to dark mode (data-theme)")
	}
	if !strings.Contains(page, actor.Email) {
		t.Errorf("layout does not show the active user %q", actor.Email)
	}
	if !strings.Contains(page, `id="content"`) {
		t.Error("layout does not render the page body")
	}
	// Without a request path the first entry of the active area is marked, and only that one.
	for _, g := range Nav {
		for _, item := range g.Items {
			marked := fmt.Sprintf(`href="%s" aria-current="page"`, item.Href)
			if !strings.Contains(page, fmt.Sprintf(`href="%s"`, item.Href)) {
				t.Errorf("navigation entry %q (%s) missing", item.Label, item.Href)
			}
			if want := item.Href == "/sync"; strings.Contains(page, marked) != want {
				t.Errorf("navigation entry %q (%s) marked = %v, want %v", item.Label, item.Href, !want, want)
			}
		}
	}
	// I12: who is signed in (with roles) and a sign-out link that ends the shared gate session.
	for _, want := range []string{"(devops, developer)", `id="sign-out" href="/oauth2/sign_out?rd=%2F">Çıkış yap</a>`} {
		if !strings.Contains(page, want) {
			t.Errorf("layout is missing %q", want)
		}
	}
	// Golden: the whole shell is stable and must not drift unnoticed. After an intended change,
	// regenerate it with: go test ./internal/web -run TestLayout_Render -update
	if *updateGolden {
		if err := os.WriteFile(filepath.Join("testdata", "layout.golden.html"), []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readTestdata(t, "layout.golden.html"); page != want {
		t.Errorf("layout does not match golden file\n--- got ---\n%s\n--- want ---\n%s", page, want)
	}
}

// J1: with a gate client id the nav sign-out goes through the Zitadel end_session endpoint; invalid
// input is refused and leaves the plain link.
func TestLayout_SignOutEndSession(t *testing.T) {
	old := SignOutHref
	t.Cleanup(func() { SignOutHref = old })
	if err := SetSignOut("https://auth.example.com", "", ""); err != nil || SignOutHref != "/oauth2/sign_out?rd=%2F" {
		t.Fatalf("empty client id: %q, %v", SignOutHref, err)
	}
	if err := SetSignOut("https://auth.example.com", "123@vpn", "https://t.example.com/"); err != nil {
		t.Fatal(err)
	}
	page := render(t, Layout(Actor{Email: "a@example.com"}, "token", "pano", "Pano", templ.Raw("x")))
	if !strings.Contains(page, `id="sign-out" href="/oauth2/sign_out?rd=https%3A%2F%2Fauth.example.com%2Foidc%2Fv1%2Fend_session%3Fclient_id%3D123%2540vpn%26post_logout_redirect_uri%3Dhttps%253A%252F%252Ft.example.com%252F">`) {
		t.Errorf("nav sign-out is not the end_session link:\n%s", page)
	}
	if err := SetSignOut("http://auth.example.com", "123", "https://t.example.com/"); err == nil {
		t.Error("an http issuer was accepted")
	}
}
