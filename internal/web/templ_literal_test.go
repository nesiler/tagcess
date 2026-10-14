package web

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/web/ui"
)

// M1 (F5 live findings): templ treats an @component call that follows text on the same line as
// plain text, so the page shows "@tagBadges(v.Current)" instead of the badges.

func TestDeviceTagsPageRendersTagBadges(t *testing.T) {
	cases := []struct {
		name string
		view deviceTagsView
		want string
	}{
		{"edit", deviceTagsView{NodeID: 1, Name: "n", Mode: tagsModeEdit, Current: []string{"tag:web"}}, "tag:web"},
		{"confirm", deviceTagsView{NodeID: 1, Name: "n", Mode: tagsModeConfirm, Selected: []string{"tag:db"}}, "tag:db"},
		{"done", deviceTagsView{NodeID: 1, Name: "n", Mode: tagsModeDone, Current: []string{"tag:k8s"}}, "tag:k8s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			if err := DeviceTagsPage(tc.view, "csrf").Render(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if strings.Contains(out, "@tagBadges") {
				t.Fatalf("component call rendered as text:\n%s", out)
			}
			var badge strings.Builder
			if err := ui.Tag(tc.want).Render(context.Background(), &badge); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, badge.String()) {
				t.Fatalf("tag %s is not rendered as a ui.Tag badge (%s):\n%s", tc.want, badge.String(), out)
			}
		})
	}
}

// TestGeneratedTemplHasNoLiteralComponentCalls guards every page: no generated string literal may
// contain an "@name(" component call.
func TestGeneratedTemplHasNoLiteralComponentCalls(t *testing.T) {
	files, err := filepath.Glob("*_templ.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no generated templ files: %v", err)
	}
	literal := regexp.MustCompile(`"[^"\n]*@[A-Za-z_][A-Za-z0-9_.]*\([^"\n]*"`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllString(string(src), -1) {
			t.Errorf("%s: component call rendered as text: %s", f, m)
		}
	}
}
