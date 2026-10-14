//go:build installer

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// hostRoots are the trees the read-only tests compare before and after a run.
var hostRoots = []string{"/etc", "/var/lib", "/run", "/usr/local", "/opt", "/srv"}

// AC10 (F6-001): the guide role writes guide/<phase>.md and .json on the controller and nothing on the host
// (a host-side check included).
func TestGuide_WritesControllerFilesOnly(t *testing.T) {
	tg := adopttarget.Up(t, "bare")
	home := t.TempDir()
	items := []map[string]any{
		{"id": "host-check", "title": "Host kontrolü", "steps": []string{"a"}, "check": map[string]string{"host_cmd": "test -d /etc"}},
		{"id": "manual", "title": "Elle", "steps": []string{"b"}},
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	before := tg.Checksums(t, hostRoots)
	res := adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{
		Playbook: "testdata/guide.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars:      map[string]any{"install_env": "guidetest", "tagcess_domain": "example.test", "install_mode": "fresh"},
		ExtraJSON: map[string]any{"guide_phase": "demo", "guide_items": json.RawMessage(raw)},
	})
	if res.ExitCode != 0 || res.Recap[tg.Name].Changed != 0 {
		t.Fatalf("guide run: exit %d recap %+v\n%s", res.ExitCode, res.Recap[tg.Name], res.Output)
	}
	if d := adopttarget.DiffChecksums(before, tg.Checksums(t, hostRoots)); len(d) > 0 {
		t.Fatalf("the guide role wrote on the host:\n%s", strings.Join(d, "\n"))
	}
	g, md := readGuide(t, home, "demo")
	if len(g.Items) != 2 || g.Items[0].Status != "done" || !strings.Contains(md, "## Host kontrolü") {
		t.Fatalf("guide files: %+v\n%s", g, md)
	}
	for _, f := range []string{"demo.json", "demo.md"} {
		st, err := os.Stat(filepath.Join(home, "tagcess-install", "guidetest", "guide", f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v mode %v", f, err, st.Mode())
		}
	}
}
