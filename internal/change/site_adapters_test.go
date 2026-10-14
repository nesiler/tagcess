package change

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/dns"
)

func TestDNSFile_ReadApplyRestore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "extra-records.json")
	f := NewDNSFile(path, dns.Verifier{}) // no resolver: no verification

	if _, exists, err := f.Current(ctx); err != nil || exists {
		t.Fatalf("Current of a missing file = exists %v, err %v, want a plain missing", exists, err)
	}
	recs := []dns.Record{{Name: "a.example.com", Type: dns.TypeA, Value: "100.64.0.4"}}
	if _, err := f.Apply(ctx, recs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	content, exists, err := f.Current(ctx)
	if err != nil || !exists || !strings.Contains(content, "a.example.com") {
		t.Fatalf("Current = %q, %v, %v, want the written records", content, exists, err)
	}
	if err := f.Restore(ctx, "[]\n"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if content, _, _ := f.Current(ctx); content != "[]\n" {
		t.Errorf("after Restore = %q, want the previous content", content)
	}
	// A directory where the file should be is a read error, never "missing".
	dir := t.TempDir()
	if _, _, err := NewDNSFile(dir, dns.Verifier{}).Current(ctx); err == nil {
		t.Error("an unreadable dns path was reported as missing")
	}
}

func TestCaddyFile_ReadApplyAdapt(t *testing.T) {
	ctx := context.Background()
	var loaded []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/adapt":
			_, _ = fmt.Fprint(w, `{"result":{"apps":{}},"warnings":[]}`)
		case "/load":
			b := make([]byte, 1<<10)
			n, _ := r.Body.Read(b)
			loaded = append(loaded, string(b[:n]))
		case "/config/":
			_, _ = fmt.Fprint(w, `{"apps":{}}`)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "Caddyfile")
	f := NewCaddyFile(caddy.NewClient(srv.URL), path)

	if _, err := f.Current(ctx); err == nil {
		t.Error("a missing Caddyfile was read as empty")
	}
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Current(ctx); err != nil || got != "old\n" {
		t.Errorf("Current = %q, %v", got, err)
	}
	if live, err := f.Live(ctx); err != nil || string(live) != `{"apps":{}}` {
		t.Errorf("Live = %q, %v", live, err)
	}
	doc, err := f.AdaptJSON(ctx, "x")
	if err != nil || string(doc) != `{"apps":{}}` {
		t.Errorf("AdaptJSON = %q, %v", doc, err)
	}
	// Apply is caddy.Apply: it refuses a set without the system sites before it calls Caddy.
	if err := f.Apply(ctx, nil, "new\n"); err == nil || len(loaded) != 0 {
		t.Errorf("Apply without system sites = %v, loads = %d, want a refusal before /load", err, len(loaded))
	}
}

// TestCaddyFile_AdaptResolvesRelativeImports: /adapt gets the Caddyfile text without its file name, so the
// parity adapter resolves relative file imports against the Caddyfile's own directory first (as Caddy does
// when it loads the file); Current keeps the file byte for byte (it is also the rollback copy).
func TestCaddyFile_AdaptResolvesRelativeImports(t *testing.T) {
	ctx := context.Background()
	var adapted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		adapted = append(adapted, string(b))
		_, _ = fmt.Fprint(w, `{"result":{"apps":{}},"warnings":[]}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	const text = "(k8s) {\n\treverse_proxy https://100.64.0.5\n}\nimport sites/*.caddy\n"
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	f := NewCaddyFile(caddy.NewClient(srv.URL), path)
	if got, err := f.Current(ctx); err != nil || got != text {
		t.Fatalf("Current = %q, %v, want the file unchanged", got, err)
	}
	if _, err := f.AdaptJSON(ctx, text); err != nil {
		t.Fatal(err)
	}
	want := "(k8s) {\n\treverse_proxy https://100.64.0.5\n}\nimport " + filepath.Join(dir, "sites/*.caddy") + "\n"
	if len(adapted) != 1 || adapted[0] != want {
		t.Errorf("/adapt got %q, want %q", adapted, want)
	}
}

func TestLineDiff(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
		want          string
	}{
		{"identical", "a\nb\n", "a\nb\n", ""},
		{"added line", "a\nc\n", "a\nb\nc\n", "+b"},
		{"removed line", "a\nb\nc\n", "a\nc\n", "-b"},
		{"changed line", "a\nb\nc\n", "a\nx\nc\n", "-b\n+x"},
		{"from nothing", "", "a\nb\n", "+a\n+b"},
		{"to nothing", "a\n", "", "-a"},
		{"only the trailing newline", "a", "a\n", "! only the trailing newline differs"},
		{"repeated lines keep their order", "}\n}\n", "}\nx\n}\n", "+x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lineDiff(tt.before, tt.after); got != tt.want {
				t.Errorf("lineDiff = %q, want %q", got, tt.want)
			}
		})
	}
	// Past the table limit the diff is the per-line listing, still correct about what differs.
	var a, b []string
	for i := range 2500 {
		a = append(a, fmt.Sprintf("a%d", i))
		b = append(b, fmt.Sprintf("b%d", i))
	}
	got := lineDiff(strings.Join(a, "\n"), strings.Join(b, "\n"))
	if !strings.Contains(got, "-a0") || !strings.Contains(got, "+b2499") {
		t.Errorf("large diff misses the changed lines")
	}
}
