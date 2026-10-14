// Package hsstack tests that do not need Docker. The Docker-backed tests of the fixture live in
// hsstack_integration_test.go behind the `integration` build tag.
package hsstack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakefile_LabIntegrationCoversInternal is AC5 at unit level: the `lab-integration` target must
// run the integration-tagged tests of ./test/compose/... together with all ./internal/... packages,
// so packages added later (hsadmin, policydoc, policywriter, web, ...) are picked up without
// touching the Makefile again.
func TestMakefile_LabIntegrationCoversInternal(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	recipe, ok := targetRecipe(string(data), "lab-integration")
	if !ok {
		t.Fatal("no lab-integration target in the Makefile")
	}
	for _, want := range []string{"go test", "-tags=integration", "./test/compose/...", "./internal/..."} {
		if !strings.Contains(recipe, want) {
			t.Errorf("lab-integration recipe does not run %q:\n%s", want, recipe)
		}
	}
}

// targetRecipe returns the tab-indented recipe lines of a Makefile target.
func targetRecipe(makefile, target string) (string, bool) {
	lines := strings.Split(makefile, "\n")
	var out []string
	for i, line := range lines {
		if !strings.HasPrefix(line, target+":") {
			continue
		}
		for _, r := range lines[i+1:] {
			if !strings.HasPrefix(r, "\t") {
				break
			}
			out = append(out, r)
		}
		return strings.Join(out, "\n"), len(out) > 0
	}
	return "", false
}
