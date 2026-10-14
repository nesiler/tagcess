// Package adopttarget drives the F6 installer test targets (adopttarget.sh: an adopt-shaped "adopt" and an
// empty "bare" Linux/systemd container) and runs ansible-playbook against them. Test helpers only: nothing
// here reaches a real host.
package adopttarget

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// RepoRoot is the repository root (two levels above this file).
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// AnsibleDir is deploy/ansible.
func AnsibleDir() string { return filepath.Join(RepoRoot(), "deploy", "ansible") }

// RequireDocker skips the test when the local Docker is not reachable. A skip is never a PASS (F6 test rule):
// make installer-test reports it.
func RequireDocker(tb testing.TB) {
	tb.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		tb.Skip("docker is not installed: the installer target tests need the local Docker (OrbStack)")
	}
	if err := exec.CommandContext(context.Background(), "docker", "info").Run(); err != nil {
		tb.Skip("docker is not reachable: the installer target tests need the local Docker (OrbStack)")
	}
}

// RequireAnsible skips the test when ansible-playbook is not installed.
func RequireAnsible(tb testing.TB) {
	tb.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		tb.Skip("ansible-playbook is not installed")
	}
}

// Target is one running test target.
type Target struct {
	Name      string
	Shape     string
	State     string
	Inventory string
	SSHPort   string
	SSHKey    string
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Up starts a fresh target of the given shape under a unique name and removes it when the test ends
// (ADOPT_TARGET_KEEP=1 keeps it for inspection).
func Up(tb testing.TB, shape string) *Target {
	tb.Helper()
	return UpNamed(tb, shape, "tagcess-at-"+shape+"-"+randHex(4))
}

// UpNamed is Up with a fixed name; a running container of that name is replaced.
func UpNamed(tb testing.TB, shape, name string, env ...string) *Target {
	tb.Helper()
	RequireDocker(tb)
	cmd := exec.CommandContext(context.Background(), filepath.Join(RepoRoot(), "test", "adopttarget", "adopttarget.sh"), "up") // #nosec G204 -- the repo's own test script
	cmd.Env = append(os.Environ(), append([]string{"SHAPE=" + shape, "ADOPT_TARGET_NAME=" + name}, env...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		tb.Fatalf("adopttarget up %s: %v\n%s", shape, err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	envFile := lines[len(lines)-1]
	kv, err := readEnv(envFile)
	if err != nil {
		tb.Fatalf("read %s: %v", envFile, err)
	}
	t := &Target{
		Name: kv["ADOPT_TARGET_NAME"], Shape: kv["ADOPT_TARGET_SHAPE"], State: kv["ADOPT_TARGET_STATE"],
		Inventory: kv["ADOPT_TARGET_INVENTORY"], SSHPort: kv["ADOPT_TARGET_SSH_PORT"], SSHKey: kv["ADOPT_TARGET_SSH_KEY"],
	}
	tb.Cleanup(func() {
		if os.Getenv("ADOPT_TARGET_KEEP") == "1" {
			tb.Logf("ADOPT_TARGET_KEEP=1: %s left running (state %s)", t.Name, t.State)
			return
		}
		t.Down(tb)
	})
	return t
}

// Down removes the target with adopttarget.sh down.
func (t *Target) Down(tb testing.TB) {
	tb.Helper()
	cmd := exec.CommandContext(context.Background(), filepath.Join(RepoRoot(), "test", "adopttarget", "adopttarget.sh"), "down") // #nosec G204 -- the repo's own test script
	cmd.Env = append(os.Environ(), "SHAPE="+t.Shape, "ADOPT_TARGET_NAME="+t.Name)
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Errorf("adopttarget down %s: %v\n%s", t.Name, err, out)
	}
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- test-owned temp file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = v
		}
	}
	return kv, sc.Err()
}

// Exec runs a command in the target (docker exec) and returns its combined output.
func (t *Target) Exec(args ...string) (string, error) {
	out, err := exec.CommandContext(context.Background(), "docker", append([]string{"exec", t.Name}, args...)...).CombinedOutput() // #nosec G204 -- test harness: docker exec into its own target
	return string(out), err
}

// Sh runs a shell script in the target and fails the test on a non-zero exit.
func (t *Target) Sh(tb testing.TB, script string) string {
	tb.Helper()
	out, err := t.Exec("sh", "-c", script)
	if err != nil {
		tb.Fatalf("%s: %q: %v\n%s", t.Name, script, err, out)
	}
	return out
}

// ShErr runs a shell script in the target and returns its output and error.
func (t *Target) ShErr(script string) (string, error) { return t.Exec("sh", "-c", script) }

// WriteFile writes content to path in the target with the given mode and owner (user:group).
func (t *Target) WriteFile(tb testing.TB, path, content, mode, owner string) {
	tb.Helper()
	cmd := exec.CommandContext(context.Background(), "docker", "exec", "-i", t.Name, "sh", "-c", // #nosec G204 -- test harness: its own target
		fmt.Sprintf("mkdir -p %q && cat >%q && chmod %s %q && chown %s %q", filepath.Dir(path), path, mode, path, owner, path))
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("write %s in %s: %v\n%s", path, t.Name, err, out)
	}
}

// ReadFile returns a file's content from the target.
func (t *Target) ReadFile(tb testing.TB, path string) string {
	tb.Helper()
	out, err := exec.CommandContext(context.Background(), "docker", "exec", t.Name, "cat", path).Output() // #nosec G204 -- test harness: its own target
	if err != nil {
		tb.Fatalf("read %s in %s: %v", path, t.Name, err)
	}
	return string(out)
}

// VolatilePaths are excluded from the read-only checksum comparisons: they change on a running system
// without anyone writing a managed file (journal, runtime state of systemd/ssh/docker/tailscale, Caddy's
// ACME storage, the Headscale database that Headscale itself writes, package caches).
var VolatilePaths = []string{
	"/run/systemd", "/run/user", "/run/log", "/run/udev", "/run/dbus", "/run/sshd", "/run/sshd.pid", "/run/utmp",
	"/run/lock", "/run/mount", "/run/credentials", "/run/tailscale", "/run/docker", "/run/docker.pid",
	"/run/docker.sock", "/run/containerd", "/run/headscale", "/var/run", "/run/motd.dynamic", "/run/xtables.lock",
	"/var/lib/systemd", "/var/lib/containerd", "/var/lib/docker", "/var/lib/tailscale", "/var/lib/caddy",
	"/var/lib/headscale/db.sqlite", "/var/lib/headscale/db.sqlite-wal", "/var/lib/headscale/db.sqlite-shm",
	"/var/log", "/var/cache", "/var/lib/apt/lists", "/var/lib/private", "/var/lib/dhcp", "/etc/machine-id",
	"/var/lib/dbus", "/var/lib/sss", "/var/lib/polkit-1", "/var/lib/ucf", "/etc/ld.so.cache", "/var/lib/logrotate",
}

// Checksums returns path -> "type mode uid:gid sha256|target" for every file, directory and symlink under
// roots, minus VolatilePaths and extraExclude (prefixes).
func (t *Target) Checksums(tb testing.TB, roots []string, extraExclude ...string) map[string]string {
	tb.Helper()
	var b strings.Builder
	b.WriteString("find")
	for _, r := range roots {
		b.WriteString(" " + shellQuote(r))
	}
	b.WriteString(` -xdev \( -type f -o -type d -o -type l \) -printf '%y %m %U:%G %p\0' 2>/dev/null`)
	out, err := t.ShErr(b.String())
	if err != nil && out == "" {
		tb.Fatalf("checksums in %s: %v", t.Name, err)
	}
	exclude := append(append([]string{}, VolatilePaths...), extraExclude...)
	sums := map[string]string{}
	var files []string
	for _, rec := range strings.Split(out, "\x00") {
		parts := strings.SplitN(rec, " ", 4)
		if len(parts) != 4 {
			continue
		}
		p := parts[3]
		if excluded(p, exclude) {
			continue
		}
		sums[p] = parts[0] + " " + parts[1] + " " + parts[2]
		if parts[0] == "f" {
			files = append(files, p)
		}
	}
	// Hash the regular files in batches (sockets and devices are not listed above).
	for i := 0; i < len(files); i += 200 {
		end := min(i+200, len(files))
		args := append([]string{"exec", t.Name, "sha256sum", "--"}, files[i:end]...)
		hout, _ := exec.CommandContext(context.Background(), "docker", args...).Output() // #nosec G204 -- test harness: fixed docker subcommand
		for _, line := range strings.Split(string(hout), "\n") {
			if sum, path, ok := strings.Cut(line, "  "); ok {
				sums[path] += " " + sum
			}
		}
	}
	return sums
}

func excluded(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if p == x || strings.HasPrefix(p, x+"/") || (strings.HasSuffix(x, "*") && strings.HasPrefix(p, strings.TrimSuffix(x, "*"))) {
			return true
		}
	}
	return false
}

// DiffChecksums lists what differs between two snapshots ("+" new, "-" gone, "~" changed).
func DiffChecksums(before, after map[string]string) []string {
	var d []string
	for p, v := range before {
		w, ok := after[p]
		switch {
		case !ok:
			d = append(d, "- "+p)
		case w != v:
			d = append(d, "~ "+p+" ("+v+" -> "+w+")")
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			d = append(d, "+ "+p)
		}
	}
	sort.Strings(d)
	return d
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Recap is one host's PLAY RECAP line.
type Recap struct {
	Ok, Changed, Unreachable, Failed, Skipped, Rescued, Ignored int
}

// Result is one ansible-playbook run.
type Result struct {
	Output   string
	ExitCode int
	Recap    map[string]Recap
}

// PlaybookOpts configures RunPlaybook.
type PlaybookOpts struct {
	Playbook    string            // relative to deploy/ansible
	Inventories []string          // inventory files (the target's first)
	Vars        map[string]any    // written to an extra inventory as all.vars (overridable by set_fact)
	ExtraVars   map[string]string // -e key=value (confirmations, test hooks)
	ExtraJSON   map[string]any    // -e '<json>' (structured extra vars)
	Tags        []string
	SkipTags    []string
	Check       bool
	Diff        bool
	ConfigHome  string   // XDG_CONFIG_HOME for the controller-side files; a temp dir when empty
	Env         []string // extra environment
	Limit       string
}

// RunPlaybook runs ansible-playbook from deploy/ansible with its ansible.cfg and returns the output, the exit
// code and the recap. It never fails the test by itself.
func RunPlaybook(tb testing.TB, o PlaybookOpts) Result {
	tb.Helper()
	RequireAnsible(tb)
	args := []string{o.Playbook}
	for _, inv := range o.Inventories {
		args = append(args, "-i", inv)
	}
	if len(o.Vars) > 0 {
		inv := filepath.Join(tb.TempDir(), "vars.yml")
		data, err := json.MarshalIndent(map[string]any{"all": map[string]any{"vars": o.Vars}}, "", "  ")
		if err != nil {
			tb.Fatalf("vars: %v", err)
		}
		if err := os.WriteFile(inv, data, 0o600); err != nil {
			tb.Fatal(err)
		}
		args = append(args, "-i", inv)
	}
	keys := make([]string, 0, len(o.ExtraVars))
	for k := range o.ExtraVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+o.ExtraVars[k])
	}
	if len(o.ExtraJSON) > 0 {
		data, err := json.Marshal(o.ExtraJSON)
		if err != nil {
			tb.Fatalf("extra json: %v", err)
		}
		args = append(args, "-e", string(data))
	}
	if len(o.Tags) > 0 {
		args = append(args, "--tags", strings.Join(o.Tags, ","))
	}
	if len(o.SkipTags) > 0 {
		args = append(args, "--skip-tags", strings.Join(o.SkipTags, ","))
	}
	if o.Check {
		args = append(args, "--check")
	}
	if o.Diff {
		args = append(args, "--diff")
	}
	if o.Limit != "" {
		args = append(args, "--limit", o.Limit)
	}
	home := o.ConfigHome
	if home == "" {
		home = tb.TempDir()
	}
	cmd := exec.CommandContext(context.Background(), "ansible-playbook", args...) // #nosec G204 -- test harness: ansible-playbook with test-built arguments
	cmd.Dir = AnsibleDir()
	cmd.Env = append(os.Environ(),
		"ANSIBLE_CONFIG="+filepath.Join(AnsibleDir(), "ansible.cfg"),
		"ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0", "XDG_CONFIG_HOME="+home,
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(home, ".ansible-tmp"),
	)
	cmd.Env = append(cmd.Env, o.Env...)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	res := Result{Output: string(out), Recap: parseRecap(string(out))}
	if err != nil {
		res.ExitCode = 1
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			res.ExitCode = ee.ExitCode()
		}
	}
	return res
}

var recapLine = regexp.MustCompile(`(?m)^(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)\s+rescued=(\d+)\s+ignored=(\d+)`)

func parseRecap(out string) map[string]Recap {
	m := map[string]Recap{}
	for _, g := range recapLine.FindAllStringSubmatch(out, -1) {
		n := func(i int) int { v, _ := strconv.Atoi(g[i]); return v }
		m[g[1]] = Recap{Ok: n(2), Changed: n(3), Unreachable: n(4), Failed: n(5), Skipped: n(6), Rescued: n(7), Ignored: n(8)}
	}
	return m
}

var taskLine = regexp.MustCompile(`^TASK \[(.*)\] \*+$`)

// ChangedTasks lists the names of the tasks reported "changed" in an ansible output (for idempotence failures).
func ChangedTasks(out string) []string {
	var names []string
	task := ""
	for _, line := range strings.Split(out, "\n") {
		if m := taskLine.FindStringSubmatch(line); m != nil {
			task = m[1]
		}
		if strings.HasPrefix(line, "changed:") {
			names = append(names, task)
		}
	}
	return names
}
