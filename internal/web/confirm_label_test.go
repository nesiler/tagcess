package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F5 L4: every preview screen confirms with the same button text. The old per-screen variants must
// not come back in a template, and the screens that used them render the shared label.
func TestConfirmLabelConsistent(t *testing.T) {
	if confirmApplyLabel != "Onayla ve apply et" {
		t.Fatalf("confirmApplyLabel = %q", confirmApplyLabel)
	}
	files, err := filepath.Glob("*.templ")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	old := []string{"Preview'u onayla ve apply et", "Onayla ve kaydet", "Onayla ve geri dön", "Onayla ve kurtar"}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range old {
			if strings.Contains(string(b), o) {
				t.Errorf("%s still says %q", f, o)
			}
		}
	}
	// The policy preview (editor, rollback and recovery share it) shows the shared label.
	if got := saveLabel(policyPreviewView{}); got != confirmApplyLabel {
		t.Errorf("policy preview label = %q", got)
	}
}
