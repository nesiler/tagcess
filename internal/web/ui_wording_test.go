package web

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// previewVariants are the query strings the preview samples switch on; every page is rendered with
// each of them, so error, empty and stale states are covered too.
var previewVariants = []string{
	"", "?empty=1", "?err=1", "?dry=1", "?blocked=1", "?preview=1", "?error=1", "?ro=1", "?readonly=1", "?off=1",
	"?maint=1", "?fail=1", "?default=1", "?closed=1", "?resolved=1",
}

var previewStates = []string{
	"error", "empty", "stale", "failed", "dry", "expired", "review", "protected", "invalid", "form-error", "blocked",
	"unverified", "unknown", "ineligible", "zitadel-error", "widen", "warning", "warn", "unreadable", "unchanged",
	"tags-error", "syntax", "setup", "saved", "readonly", "readfail", "preview", "pending", "notice", "nochange", "new",
	"mismatch", "many", "inactive", "dry_run", "done", "corrupt", "confirm",
}

// visiblePageText is the text a person reads in <main>: text nodes plus the tooltip-like attributes
// (title, aria-label, placeholder), which show on hover or to screen readers.
func visiblePageText(t *testing.T, body string) string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var main *html.Node
	var find func(n *html.Node)
	find = func(n *html.Node) {
		if main != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "main" {
			main = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			find(c)
		}
	}
	find(doc)
	if main == nil {
		main = doc
	}
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "svg", "textarea", "pre", "code":
				return
			}
			for _, a := range n.Attr {
				if a.Key == "title" || a.Key == "aria-label" || a.Key == "placeholder" {
					b.WriteString(a.Val + "\n")
				}
			}
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data + "\n")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(main)
	return b.String()
}

// The interface is a generic VPN portal: project-internal requirement ids and jargon (S-06, R1,
// K-02, freshness, scope, snapshot, check noktası ...) never reach page text, tooltips included.
// Code, pre and textarea content (config, policy, diffs) is data and is not checked.
func TestUIWordingIsGeneric(t *testing.T) {
	banned := regexp.MustCompile(`(?i)\b(?:[SYHKPAGUDN]-\d\d?|R\d|F\db?-\d{3})\b|freshness|\bscope|snapshot|check noktası|onay hattı|diff/onay|kaynak zamanı|gözlem|tazelik|read-only görünüm`)
	h := PreviewHandler()
	seen := map[string]bool{}
	for _, p := range previewPages {
		queries := append([]string{}, previewVariants...)
		for _, s := range previewStates {
			queries = append(queries, "?state="+s)
		}
		for _, q := range queries {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", p.path+q, nil))
			text := visiblePageText(t, rec.Body.String())
			for _, line := range strings.Split(text, "\n") {
				if m := banned.FindString(line); m != "" {
					key := p.path + "|" + strings.TrimSpace(line)
					if !seen[key] {
						seen[key] = true
						t.Errorf("%s%s: %q in %q", p.path, q, m, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}
