package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// fixE_shellTasks walks a parsed task list (blocks included) and returns every shell task with its script.
func fixE_shellTasks(node any, file string, out *[]fixE_shellTask) {
	switch v := node.(type) {
	case []any:
		for _, n := range v {
			fixE_shellTasks(n, file, out)
		}
	case map[string]any:
		for _, key := range []string{"ansible.builtin.shell", "shell"} {
			if body, ok := v[key]; ok {
				t := fixE_shellTask{file: file, name: fixE_name(v)}
				switch b := body.(type) {
				case string:
					t.script = b
				case map[string]any:
					t.script, _ = b["cmd"].(string)
				}
				if args, ok := v["args"].(map[string]any); ok {
					t.executable, _ = args["executable"].(string)
				}
				if b, ok := body.(map[string]any); ok && t.executable == "" {
					t.executable, _ = b["executable"].(string)
				}
				*out = append(*out, t)
			}
		}
		for _, n := range v {
			fixE_shellTasks(n, file, out)
		}
	}
}

type fixE_shellTask struct{ file, name, script, executable string }

func fixE_name(m map[string]any) string {
	n, _ := m["name"].(string)
	return n
}

// M5 (F6 fix round): a shell task that uses a Bash feature (`set -o pipefail`, `[[`, here-strings, process
// substitution) names /bin/bash. Ansible's default shell is /bin/sh, which is dash on a Linux controller and
// fails with "Illegal option -o pipefail" after earlier tasks already wrote (a Mac /bin/sh hides it).
func TestInstaller_BashismShellTasksDeclareBash(t *testing.T) {
	t.Parallel()
	var files []string
	for _, pat := range []string{"roles/*/tasks/*.yml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(adopttarget.AnsibleDir(), pat))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- repo files
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var tasks []fixE_shellTask
		fixE_shellTasks(doc, f, &tasks)
		for _, task := range tasks {
			// "[[ " is the Bash test; "[[:space:]]" is a POSIX character class and fine under dash.
			if !strings.Contains(task.script, "pipefail") && !strings.Contains(task.script, "[[ ") &&
				!strings.Contains(task.script, "<<<") && !strings.Contains(task.script, " <(") {
				continue
			}
			checked++
			if task.executable != "/bin/bash" {
				rel, _ := filepath.Rel(adopttarget.AnsibleDir(), task.file)
				t.Errorf("%s: shell task %q uses a Bash feature but sets no `args: executable: /bin/bash` (executable %q)", rel, task.name, task.executable)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("the check found only %d bash-feature shell tasks; the walk is broken", checked)
	}
}

// fixE_dashLikeShell writes a /bin/sh stand-in for ansible_shell_executable: real dash when the machine has it (a Linux
// controller's /bin/sh; macOS ships /bin/dash too), otherwise a wrapper that refuses the Bash-only `pipefail` option
// with dash's own message.
func fixE_dashLikeShell(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sh")
	script := `#!/bin/sh
if command -v dash >/dev/null 2>&1; then exec dash "$@"; fi
for a in "$@"; do
	case "$a" in
	*pipefail*) echo "sh: 1: set: Illegal option -o pipefail" >&2; exit 2 ;;
	esac
done
exec /bin/sh "$@"
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	return p
}

// M5 (F6 fix round): zitadel_install on a controller whose /bin/sh is dash (Linux) installs, writes the PAT file and
// reports the same as on a Mac; the generated-secret, TLS-copy and PAT tasks run under /bin/bash.
func TestZitadelInstall_RunsWhenShIsDash(t *testing.T) {
	t.Parallel()
	adopttarget.RequireAnsible(t)
	r := runZitadelInstall(t, map[string]any{"ansible_shell_executable": fixE_dashLikeShell(t), "zitadel_tls_copy_from": "kube-system/wildcard-tls"}, 0)
	if r.ExitCode != 0 || strings.Contains(r.Output, "Illegal option") {
		t.Fatalf("zitadel_install under a dash-like /bin/sh:\n%s", r.Output)
	}
	dest := filepath.Join(r.home, "tagcess-install", "lab", "secrets", "zitadel-admin.pat")
	if b, err := os.ReadFile(dest); err != nil || string(b) != "pat-"+strings.Repeat("Ab1", 12) { // #nosec G304 -- test temp dir
		t.Fatalf("PAT file: %q %v", b, err)
	}
	all := strings.Join(r.calls, "\n")
	for _, w := range []string{"create secret generic zitadel-db", "-n kube-system get secret wildcard-tls", "apply -f -"} {
		if !strings.Contains(all, w) {
			t.Errorf("calls lack %q:\n%s", w, all)
		}
	}
}
