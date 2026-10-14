package web

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func TestLayoutKeyboardSkipLink(t *testing.T) {
	out := renderAt(t, "/", Layout(Actor{}, "token", "pano", "Pano", templ.Raw("")))
	for _, want := range []string{`href="#main-content"`, `id="main-content" tabindex="-1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing keyboard shortcut %q", want)
		}
	}
}

func TestUIBehaviour(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is unavailable; browser behaviour verification is required")
	}
	out, err := exec.CommandContext(t.Context(), node, "testdata/ui_behavior.test.cjs", "static/ui.js").CombinedOutput()
	if err != nil {
		t.Fatalf("UI behaviour: %v\n%s", err, out)
	}
	// The form helpers: multi-value chips, info tooltips and the live field check (2026-10-06).
	out, err = exec.CommandContext(t.Context(), node, "testdata/ui_forms.test.cjs", "static/ui.js").CombinedOutput()
	if err != nil {
		t.Fatalf("UI form behaviour: %v\n%s", err, out)
	}
}
