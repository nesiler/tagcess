package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/test/adopttarget"
)

// fixB_taskKeywords are the task keys that are not the module.
var fixB_taskKeywords = map[string]bool{
	"name": true, "when": true, "vars": true, "tags": true, "register": true, "loop": true, "loop_control": true, "changed_when": true,
	"failed_when": true, "check_mode": true, "no_log": true, "delegate_to": true, "become": true, "notify": true, "args": true,
	"environment": true, "until": true, "retries": true, "delay": true, "ignore_errors": true, "with_items": true, "diff": true,
	"run_once": true, "block": true, "rescue": true, "always": true, "become_user": true, "ignore_unreachable": true,
}

// fixB_mutatingModules write to the host whatever their changed_when says (a candidate copy with changed_when false is a write).
var fixB_mutatingModules = map[string]bool{
	"ansible.builtin.apt": true, "ansible.builtin.get_url": true, "ansible.builtin.copy": true, "ansible.builtin.template": true,
	"ansible.builtin.file": true, "ansible.builtin.systemd_service": true, "ansible.builtin.systemd": true,
	"ansible.builtin.lineinfile": true, "ansible.builtin.replace": true, "ansible.builtin.user": true, "ansible.builtin.group": true,
	"ansible.builtin.unarchive": true,
}

// fixB_mutatingCmd marks a shell/command text that changes the host (cp, mv, sed -i, headscale ... tag, systemctl restart ...).
var fixB_mutatingCmd = regexp.MustCompile(`(^|[\s;&|(])(cp|mv|install|rm|tee|ln|mkdir|chmod|chown|sed -i|docker (stop|rm|tag|load|compose|build|restart)|` +
	`headscale (users create|nodes tag|nodes approve-routes|preauthkeys create|policy set)|systemctl (restart|stop|start|enable|disable|reload))\b`)

type fixB_step struct{ kind, name string } // kind: backup | mut

// fixB_flatten returns, in order, the backup includes and the mutating tasks of a role task file (following literal
// include_tasks/import_tasks of the same role and nested blocks; rescue/always run after the block and are skipped).
func fixB_flatten(t *testing.T, role, file string) []fixB_step {
	t.Helper()
	path := filepath.Join(adopttarget.AnsibleDir(), "roles", role, "tasks", file)
	data, err := os.ReadFile(path) // #nosec G304 -- repo file
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(data, &tasks); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return fixB_walk(t, role, tasks)
}

func fixB_walk(t *testing.T, role string, tasks []map[string]any) []fixB_step {
	t.Helper()
	var out []fixB_step
	for _, task := range tasks {
		name, _ := task["name"].(string)
		if b, ok := task["block"].([]any); ok {
			var sub []map[string]any
			for _, x := range b {
				if m, ok := x.(map[string]any); ok {
					sub = append(sub, m)
				}
			}
			out = append(out, fixB_walk(t, role, sub)...)
			continue
		}
		if cm, ok := task["check_mode"].(bool); ok && cm {
			continue // a dry check of a write (template --check): writes nothing
		}
		if d, _ := task["delegate_to"].(string); d == "localhost" {
			continue // controller side
		}
		module := ""
		for k := range task {
			if !fixB_taskKeywords[k] {
				module = k
			}
		}
		switch module {
		case "ansible.builtin.include_tasks", "ansible.builtin.import_tasks":
			f, _ := task[module].(string)
			if f == "" || strings.Contains(f, "{{") {
				continue
			}
			out = append(out, fixB_flatten(t, role, f)...)
		case "ansible.builtin.include_role", "ansible.builtin.import_role":
			m, _ := task[module].(map[string]any)
			switch m["name"] {
			case "backup":
				out = append(out, fixB_step{"backup", name})
			case "state":
				out = append(out, fixB_step{"mut", name})
			}
		case "ansible.builtin.shell", "ansible.builtin.command", "ansible.builtin.script":
			text := fmt.Sprint(task[module])
			if mm, ok := task[module].(map[string]any); ok {
				text = fmt.Sprint(mm["cmd"], mm["argv"])
			}
			if module == "ansible.builtin.script" || fixB_mutatingCmd.MatchString(text) {
				if module != "ansible.builtin.script" || !strings.Contains(text, "--probe") {
					out = append(out, fixB_step{"mut", name})
				}
			}
		default:
			if fixB_mutatingModules[module] {
				out = append(out, fixB_step{"mut", name})
			}
		}
	}
	return out
}

// H2 (static): every installer phase that writes on the host takes its backup before its first mutating task. The
// phase entry files are the ones site.yml imports (role + tasks_from), so a new writing phase cannot skip the rule.
func TestFixB_BackupIsTheFirstMutation(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(adopttarget.AnsibleDir(), "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		Tasks []map[string]any `yaml:"tasks"`
	}
	if err := yaml.Unmarshal(data, &plays); err != nil {
		t.Fatal(err)
	}
	entry := map[string][2]string{}
	for _, task := range plays[0].Tasks {
		name, _ := task["name"].(string)
		phase, ok := strings.CutPrefix(name, "Phase ")
		if !ok || strings.Contains(phase, ":") {
			continue
		}
		m, _ := task["ansible.builtin.import_role"].(map[string]any)
		file := "main.yml"
		if f, _ := m["tasks_from"].(string); f != "" {
			file = f + ".yml"
		}
		entry[phase] = [2]string{fmt.Sprint(m["name"]), file}
	}
	checked := 0
	for _, p := range phasesYML(t) {
		name, _ := p["name"].(string)
		if p["writes"] != "host" {
			continue
		}
		e, ok := entry[name]
		if !ok {
			t.Errorf("phase %s: no import in site.yml", name)
			continue
		}
		steps := fixB_flatten(t, e[0], e[1])
		firstMut, firstBackup := -1, -1
		for i, s := range steps {
			if s.kind == "mut" && firstMut < 0 {
				firstMut = i
			}
			if s.kind == "backup" && firstBackup < 0 {
				firstBackup = i
			}
		}
		checked++
		t.Logf("phase %s: backup at step %d, first mutation at step %d (%d steps)", name, firstBackup, firstMut, len(steps))
		switch {
		case firstBackup < 0:
			t.Errorf("phase %s (%s/%s): no backup", name, e[0], e[1])
		case firstMut >= 0 && firstMut < firstBackup:
			t.Errorf("phase %s (%s/%s): %q writes before the backup %q", name, e[0], e[1], steps[firstMut].name, steps[firstBackup].name)
		}
	}
	if checked < 14 {
		t.Fatalf("only %d writing phases were checked", checked)
	}
}

// H2 (static): the backup covers what the late phases write: the Headscale OIDC secret file, certbot's credentials
// and /etc/letsencrypt, the Tailscale apt files; headscale_oidc rolls the secret file back too, and the generic
// rollback takes a backup of today's state before it restores.
func TestFixB_BackupScopeAndRollbackBackup(t *testing.T) {
	t.Parallel()
	read := func(rel ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{adopttarget.AnsibleDir()}, rel...)...)) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	defaults := read("roles", "backup", "defaults", "main.yml")
	for _, want := range []string{"headscale_oidc_secret_path", "/root/.secrets/certbot", "/etc/letsencrypt", "tailscale.list", "tailscale-archive-keyring.gpg"} {
		if !strings.Contains(defaults, want) {
			t.Errorf("backup_paths lacks %s", want)
		}
	}
	if d := read("roles", "rollback", "defaults", "main.yml"); !regexp.MustCompile(`headscale_oidc: \[[^\]]*headscale_oidc_secret_path`).MatchString(d) {
		t.Error("the headscale_oidc rollback does not restore the OIDC secret file")
	}
	for _, f := range []string{"prepare.yml", "generic.yml"} {
		steps := fixB_flatten(t, "rollback", f)
		if f == "prepare.yml" && (len(steps) == 0 || steps[0].kind != "backup") {
			t.Errorf("rollback/prepare.yml: the backup of today's state is not its first mutation: %v", steps)
		}
	}
	if !strings.Contains(read("roles", "rollback", "tasks", "generic.yml"), "prepare.yml") {
		t.Error("the generic rollback does not prepare (back up today's state) before restoring")
	}
}
