package installer

import (
	"os"
	"strings"
	"testing"
)

// F-7 AC5: the verify role and docs/install.md name the real /healthz endpoint on the UI socket.
func TestVerify_UsesRealHealthzEndpoint(t *testing.T) {
	t.Parallel()
	read := func(p string) string {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed repo paths
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	defaults := read("roles/verify/defaults/main.yml")
	for _, want := range []string{"--unix-socket /run/tagcess/ui.sock http://tagcess/healthz", `"healthz_code"`} {
		if !strings.Contains(defaults, want) {
			t.Errorf("verify defaults lack %q", want)
		}
	}
	if !strings.Contains(read("roles/verify/tasks/main.yml"), "p.healthz_code == '200'") {
		t.Error("the verify verdict does not check healthz_code == 200")
	}
	doc := read("../../docs/install.md")
	if !strings.Contains(doc, "`GET /healthz` on the UI socket") || !strings.Contains(doc, "503") {
		t.Error("docs/install.md does not describe the real /healthz endpoint")
	}
}
