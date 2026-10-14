package web

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// shellTemplates draw the page frame itself and may write the shell's classes (docs/ui-guide.md).
var shellTemplates = []string{"layout.templ"}

// Pages compose internal/web/ui components and never write CSS classes or inline styles of their
// own, so the look lives in one place (docs/ui-guide.md).
func TestPagesUseUIComponents(t *testing.T) {
	files, err := filepath.Glob("*.templ")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	forbidden := regexp.MustCompile(`\bclass=|\bstyle=|<script`)
	for _, f := range files {
		if slices.Contains(shellTemplates, f) {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := forbidden.FindIndex(src); loc != nil {
			t.Errorf("%s writes its own markup style at byte %d (%q); use a ui component", f, loc[0], src[loc[0]:loc[1]])
		}
	}
}

// Technical terms are written in English (docs/ui-glossary.md): tag, node, route, policy, dry-run,
// preview, apply, revision, draft ... The Turkish words they replaced must not come back in page
// text. Comment lines are skipped; "uygulama" stays only for the application behind a site.
func TestUITextUsesGlossaryTerms(t *testing.T) {
	var files []string
	for _, glob := range []string{"*.templ", "*.go", "ui/*.templ", "ui/*.go"} {
		m, err := filepath.Glob(glob)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	old := regexp.MustCompile(`(?i)(?:^|[^\p{L}])(etiket|düğüm|rota\b|rotalar|yönlendirme|senkron|politika|onaylayıcı|küme\w*|keşif|keşf|parite|` +
		`artefakt|tazeli|ölçüm|kapı\w*|muafiyet|dinleyici|aktör|eşik|anahtar|önizle|uygula|revizyon|tasla[kğ]|yapılandırma|` +
		`kurtarma|denetim|kuru çalıştırma|içe aktar|salt[ -]ok)\w*`)
	keep := regexp.MustCompile(`Arkadaki uygulamanın`)
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_templ.go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") || keep.MatchString(line) {
				continue
			}
			if m := old.FindStringSubmatch(line); m != nil {
				t.Errorf("%s:%d: %q; use the English term from docs/ui-glossary.md", f, i+1, m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("no source files scanned")
	}
}
