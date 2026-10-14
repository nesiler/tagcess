// Runbook safety checks. These read committed documentation only and never touch production or a
// lab. A shared step parser asserts that every `Step N: ... [label]` heading is labelled, every command
// line that mentions production sits in a `read (production)` step, every production step command
// matches a small read-only allowlist, and no command prints a secret or a whole config file. The
// synthetic mutation tests keep the audit honest; docs/install.md is the real subject.
//
// Every fenced block is scanned regardless of its info string (labelled, unlabelled or `zsh`), so a
// write cannot hide; expected output therefore stays in prose, not in a `text` fence.
package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// runbookStep is one `##–#### Step N: ... [etiket]` step and the commands of its fenced blocks.
type runbookStep struct {
	number   int
	title    string
	label    string // read (production) | read (lab) | write (lab) | read (target) | write (target)
	commands []string
}

var (
	// stepHeadingRE matches a numbered, labelled step heading (`##`–`####`).
	stepHeadingRE = regexp.MustCompile("^#{2,4}[ \t]+Step[ \t]+([0-9]+)[.:][ \t]*(.*?)[ \t]*\\[(read \\(production\\)|read \\(lab\\)|write \\(lab\\)|read \\(target\\)|write \\(target\\))\\][ \t]*$")
	// adimHeadingRE matches any step heading, so an unlabelled one is reported rather than skipped.
	adimHeadingRE = regexp.MustCompile("^#{2,4}[ \t]+Step\\b")
	// fenceRE matches a fence line (``` optionally followed by an info string). Any info string is
	// accepted on purpose: an unlabelled or `zsh` fence is still scanned for commands.
	fenceRE = regexp.MustCompile("^[ \t]*```[ \t]*([A-Za-z0-9_+-]*)[ \t]*$")
	// sshRE matches the only allowed production shape: `ssh [-o K=V ...] <host> <remote>`.
	sshRE = regexp.MustCompile(`^ssh[ \t]+(?:-o[ \t]+\S+[ \t]+)*(\S+)[ \t]+(.+)$`)
	// prodAliasRE matches a `-ts` production host alias (vpn-host, k8s-host).
	prodAliasRE = regexp.MustCompile(`(^|[\s'"/])\S*-ts(\s|$|['"/:])`)
	// sedInPlaceRE matches `sed -i` / `--in-place`, never allowed in the read-only pipes.
	sedInPlaceRE = regexp.MustCompile(`(^|\s)(-i|--in-place)(\s|$)`)
	// secretPathRE matches a path whose whole content must never be printed.
	secretPathRE = regexp.MustCompile(`(?i)/etc/headplane/secrets|/etc/oauth2-proxy/|\.env\b|\bsecret\b`)
	// yamlReadRE matches a whole-file read (cat/less/head/tail) of a YAML file.
	yamlReadRE = regexp.MustCompile(`(?i)(^|[^a-z])(cat|less|head|tail)([^a-z]|$)[^|]*\.yaml\b`)
)

// productionIPs are the (documentation) public addresses the runbooks use for the production hosts.
var productionIPs = []string{"203.0.113.10", "203.0.113.20"}

// readRunbook reads a runbook relative to the deploy test directory.
func readRunbook(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read runbook %s: %v", path, err)
	}
	return string(b)
}

// parseRunbookSteps is the shared entry point: it extracts the labelled steps, reports any
// unlabelled step heading, and is reused by the later runbook tests.
func parseRunbookSteps(t *testing.T, raw string) []runbookStep {
	t.Helper()
	steps, findings := parseRunbook(raw)
	for _, f := range findings {
		t.Error(f)
	}
	return steps
}

// parseRunbook extracts the steps and their commands. Every fenced block is treated as commands, so
// a production write cannot hide in an unlabelled or `zsh` fence. A fenced block outside any step
// is attached to a synthetic step so it is audited too.
func parseRunbook(raw string) ([]runbookStep, []string) {
	var (
		steps    []runbookStep
		findings []string
		cur      = -1
		inFence  bool
		body     []string
	)
	closeFence := func() {
		if len(body) > 0 {
			if cur < 0 {
				steps = append(steps, runbookStep{title: "(outside a step)"})
				cur = len(steps) - 1
			}
			steps[cur].commands = append(steps[cur].commands, commandsInFence(body)...)
		}
		body = nil
		inFence = false
	}

	for _, line := range strings.Split(raw, "\n") {
		if m := fenceRE.FindStringSubmatch(line); m != nil {
			if inFence {
				closeFence()
			} else {
				inFence = true
				body = nil
			}
			continue
		}
		if inFence {
			body = append(body, line)
			continue
		}
		if adimHeadingRE.MatchString(line) {
			m := stepHeadingRE.FindStringSubmatch(line)
			if m == nil {
				findings = append(findings, fmt.Sprintf("step heading has no `[read (production)|read (lab)|write (lab)|read (target)|write (target)]` label: %q", line))
				cur = -1
				continue
			}
			n, _ := strconv.Atoi(m[1])
			steps = append(steps, runbookStep{number: n, title: strings.TrimSpace(m[2]), label: m[3]})
			cur = len(steps) - 1
		}
	}
	if inFence {
		closeFence()
	}
	return steps, findings
}

// commandsInFence turns a fence body into commands: blank/comment lines are dropped, a trailing
// backslash joins the next line, and every other line is one command.
func commandsInFence(body []string) []string {
	var out, buf []string
	flush := func() {
		if len(buf) == 0 {
			return
		}
		cmd := strings.TrimSpace(strings.ReplaceAll(strings.Join(buf, " "), "\\ ", " "))
		if cmd != "" {
			out = append(out, cmd)
		}
		buf = nil
	}
	for _, line := range body {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		continues := strings.HasSuffix(t, "\\")
		if continues {
			t = strings.TrimRight(strings.TrimSuffix(t, "\\"), " \t")
		}
		buf = append(buf, t)
		if !continues {
			flush()
		}
	}
	flush()
	return out
}

// auditRunbook applies the allowlist to a runbook's steps and returns every finding. An empty
// result means the runbook is safe.
func auditRunbook(steps []runbookStep) []string {
	var findings []string
	for _, s := range steps {
		for _, cmd := range s.commands {
			if mentionsProduction(cmd) && s.label != "read (production)" {
				findings = append(findings, fmt.Sprintf("step %d (%s) is labelled %q but mentions production: %q", s.number, s.title, s.label, cmd))
			}
			if s.label == "read (production)" {
				findings = append(findings, auditProductionCommand(cmd)...)
			}
			findings = append(findings, auditSecret(cmd)...)
		}
	}
	return findings
}

// mentionsProduction reports whether a command line touches a production host or address.
func mentionsProduction(cmd string) bool {
	if strings.Contains(cmd, "vpn-host") || strings.Contains(cmd, "k8s-host") {
		return true
	}
	for _, ip := range productionIPs {
		if strings.Contains(cmd, ip) {
			return true
		}
	}
	return prodAliasRE.MatchString(cmd)
}

// auditProductionCommand checks one `read (production)` command against the read-only allowlist: the
// shape `ssh <host> '<remote cmd>'`, an allowed leading command, and at most `| grep/awk/sed`.
func auditProductionCommand(cmd string) []string {
	var findings []string
	_, remote, ok := splitSSH(cmd)
	if !ok {
		return []string{fmt.Sprintf("production command is not `ssh <host> '<remote cmd>'`: %q", cmd)}
	}

	bare := stripQuotes(remote)
	if i := strings.IndexAny(bare, ";&><`"); i >= 0 {
		findings = append(findings, fmt.Sprintf("production command has a shell metacharacter %q: %q", string(bare[i]), cmd))
	}
	if strings.Contains(bare, "$(") || strings.Contains(bare, ")") {
		findings = append(findings, fmt.Sprintf("production command has a grouping/substitution metacharacter: %q", cmd))
	}

	for i, seg := range splitUnquoted(remote, '|') {
		head := firstWord(stripQuotes(seg))
		if i == 0 {
			if why := checkRemoteHead(stripQuotes(seg)); why != "" {
				findings = append(findings, fmt.Sprintf("production command %q: %s", cmd, why))
			}
			continue
		}
		switch head {
		case "grep", "awk": // reading pipes only
		case "sed":
			if sedInPlaceRE.MatchString(seg) {
				findings = append(findings, fmt.Sprintf("production pipe uses `sed -i` (in-place): %q", cmd))
			}
			if !strings.Contains(seg, "<email>") {
				findings = append(findings, fmt.Sprintf("production `sed` pipe is only allowed for the e-mail mask (<email>): %q", cmd))
			}
		default:
			findings = append(findings, fmt.Sprintf("production pipe may only feed grep/awk/sed, got %q: %q", head, cmd))
		}
	}
	return findings
}

// splitSSH parses `ssh [-o K=V ...] <host> <quoted remote>` and returns the remote command without
// its quotes. It fails when the command is not an ssh invocation or the remote is not one quoted
// argument.
func splitSSH(cmd string) (host, remote string, ok bool) {
	m := sshRE.FindStringSubmatch(strings.TrimSpace(cmd))
	if m == nil {
		return "", "", false
	}
	remote = strings.TrimSpace(m[2])
	if len(remote) < 2 {
		return "", "", false
	}
	q := remote[0]
	if (q != '\'' && q != '"') || remote[len(remote)-1] != q {
		return "", "", false
	}
	return m[1], remote[1 : len(remote)-1], true
}

// checkRemoteHead enforces the remote command's first word against the allowlist.
func checkRemoteHead(bare string) string {
	f := strings.Fields(bare)
	if len(f) == 0 {
		return "empty remote command"
	}
	switch f[0] {
	case "grep", "awk", "stat", "journalctl", "ls", "ps":
		return ""
	case "systemctl":
		if len(f) >= 2 {
			switch f[1] {
			case "show", "status", "cat", "list-units":
				return ""
			}
		}
		return "only `systemctl show|status|cat|list-units` is allowed"
	case "headscale":
		if len(f) >= 2 && f[1] == "version" {
			return ""
		}
		if len(f) >= 3 && f[2] == "list" {
			return ""
		}
		return "only `headscale <x> list` or `headscale version` is allowed"
	case "kubectl":
		if len(f) >= 2 {
			switch f[1] {
			case "get", "describe", "logs":
				return ""
			}
		}
		return "only `kubectl get|describe|logs` is allowed"
	default:
		return fmt.Sprintf("`%s` is not on the read-only allowlist", f[0])
	}
}

// auditSecret refuses commands that would print a secret path, a `.env`/`*secret*` file or a whole
// YAML config.
func auditSecret(cmd string) []string {
	var findings []string
	if m := secretPathRE.FindString(cmd); m != "" {
		findings = append(findings, fmt.Sprintf("command mentions a secret path %q: %q", m, cmd))
	}
	if m := yamlReadRE.FindString(cmd); m != "" {
		findings = append(findings, fmt.Sprintf("command reads a whole config yaml %q: %q", m, cmd))
	}
	return findings
}

// stripQuotes blanks every quoted run so the shell structure can be inspected without the quoted
// arguments (an awk program or grep pattern that contains `;`, `|` or `$1`).
func stripQuotes(s string) string {
	var b strings.Builder
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			b.WriteByte(' ')
			if c == '\\' && q == '"' && i+1 < len(s) {
				i++
				b.WriteByte(' ')
				continue
			}
			if c == q {
				q = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			q = c
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// splitUnquoted splits on an unquoted separator, keeping quoted text (and its inner separators) in
// the segment.
func splitUnquoted(s string, sep byte) []string {
	var (
		out []string
		b   strings.Builder
		q   byte
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			b.WriteByte(c)
			if c == '\\' && q == '"' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == q {
				q = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			q = c
			b.WriteByte(c)
		case sep:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, strings.TrimSpace(b.String()))
	return out
}

// firstWord returns the first whitespace-separated field.
func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// TestRunbook_RejectsUnsafeMutations is the negative control: each forbidden command must be
// rejected by the same audit. It guards against a parser that silently ignores a fence label, an
// unlabelled fence or a relabelled step.
func TestRunbook_RejectsUnsafeMutations(t *testing.T) {
	mutations := []struct{ name, runbook string }{
		{"systemctl restart", prodStep(`ssh vpn-host 'systemctl restart headscale'`)},
		{"curl -X POST", prodStep(`ssh vpn-host 'curl -X POST http://127.0.0.1/'`)},
		{"caddy reload", prodStep(`ssh vpn-host 'caddy reload'`)},
		{"scp", prodStep(`scp /tmp/x vpn-host:/tmp/`)},
		{"rsync", prodStep(`rsync /tmp/x vpn-host:/tmp/`)},
		{"kubectl exec", prodStep(`ssh k8s-host 'kubectl exec pod -- ls'`)},
		{"output redirection", prodStep(`ssh vpn-host 'echo x>/etc/f'`)},
		{"bash -c", prodStep(`ssh vpn-host 'bash -c whoami'`)},
		{"relabelled production write", synthRunbook("write (lab)", "bash", `ssh vpn-host 'systemctl restart headscale'`)},
		{"unlabelled fence production write", synthRunbook("write (lab)", "", `ssh vpn-host 'systemctl restart headscale'`)},
		{"zsh fence production write", synthRunbook("write (lab)", "zsh", `ssh vpn-host 'systemctl restart headscale'`)},
		{"headplane secrets read", labStep(`cat /etc/headplane/secrets/cookie`)},
		{"oauth2-proxy env read", labStep(`cat /etc/oauth2-proxy/env`)},
		{"headscale config whole read", labStep(`cat /etc/headscale/config.yaml`)},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			steps, _ := parseRunbook(tc.runbook)
			got := auditRunbook(steps)
			if len(got) == 0 {
				t.Fatalf("unsafe command passed the audit:\n%s", tc.runbook)
			}
			t.Logf("rejected with %d finding(s): %s", len(got), strings.Join(got, "; "))
		})
	}
}

// synthRunbook builds a one-step runbook with one fenced block. An empty fenceLang produces an
// unlabelled fence.
func synthRunbook(label, fenceLang, body string) string {
	return "## Step 1: Test [" + label + "]\n\n```" + fenceLang + "\n" + body + "\n```\n"
}

func prodStep(body string) string { return synthRunbook("read (production)", "bash", body) }
func labStep(body string) string  { return synthRunbook("read (lab)", "bash", body) }

var mdLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// The k8s monitoring runbook exists and every local Markdown link resolves to an
// existing file and, when it has a fragment, an existing heading. Wording is reviewed, not tested.
func TestK8sMonitoringDocLinksResolve(t *testing.T) {
	path := filepath.Join("..", "docs", "k8s-monitoring.md")
	raw := readRunbook(t, path)
	for _, m := range mdLink.FindAllStringSubmatch(raw, -1) {
		target := m[1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		file, frag, _ := strings.Cut(target, "#")
		resolved := path
		if file != "" {
			resolved = filepath.Join(filepath.Dir(path), file)
		}
		body, err := os.ReadFile(resolved) // #nosec G304 -- repo documentation path
		if err != nil {
			t.Errorf("link %q: %v", target, err)
			continue
		}
		if frag != "" && !hasHeading(string(body), frag) {
			t.Errorf("link %q: no heading with anchor %q in %s", target, frag, resolved)
		}
	}
}

func hasHeading(md, anchor string) bool {
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#")))
		var b strings.Builder
		for _, r := range h {
			switch {
			case r == ' ' || r == '-':
				b.WriteRune('-')
			case r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r > 127:
				b.WriteRune(r)
			}
		}
		if b.String() == anchor {
			return true
		}
	}
	return false
}

// The deploy/f5 lab scripts are syntactically valid shell that carries no secret value (only file paths and placeholders).
func TestF5LabScripts(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("f5", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no deploy/f5 files: %v", err)
	}
	// Markers of a pasted secret: key material, a bearer/PAT, a lab user password shape, a token value.
	secretRE := regexp.MustCompile(`-----BEGIN|PRIVATE KEY|Bearer [A-Za-z0-9]|F5-[A-Za-z0-9_-]{8,}!|CF_API_TOKEN=[^'"$\s]|client_secret\s*=\s*"`)
	for _, f := range files {
		body, err := os.ReadFile(f) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		if loc := secretRE.FindIndex(body); loc != nil {
			t.Errorf("%s looks like it holds a secret: %q", f, body[loc[0]:loc[1]])
		}
		if strings.HasSuffix(f, ".sh") {
			if out, err := exec.CommandContext(t.Context(), "bash", "-n", f).CombinedOutput(); err != nil {
				t.Errorf("%s: bash -n: %v\n%s", f, err, out)
			}
		}
	}
	// Positive control: the pattern catches a pasted password and token.
	for _, bad := range []string{`["u", "F5-0kTJR3cySs60LgKF!9a"]`, "CF_API_TOKEN=abc123"} {
		if !secretRE.MatchString(bad) {
			t.Errorf("control: %q not caught", bad)
		}
	}
}

// F5 H2 (Codex review): deploy.sh refuses a REMOTE_SRC that is not a "src" directory below the lab
// root, so rsync --delete cannot empty /root/f5 (seed, secrets) or a parent.
func TestF5DeployRemoteSrcGuard(t *testing.T) {
	run := func(p string) error {
		cmd := exec.CommandContext(t.Context(), "bash", "-c", `DEPLOY_SOURCE_ONLY=1 . f5/deploy.sh && check_remote_src "$1"`, "_", p)
		return cmd.Run()
	}
	for _, bad := range []string{"/", "/root", "/root/f5", "/root/f5/", "/root/f5/seed", "/root/f5/src/..", "/root/f5/../src",
		"/root/f5/x/../src", "src", "relative/src", "/root/f5src", "/tmp/src", "/root/f5/src/sub", "/root/f5//src", "/root/f5/s rc", ""} {
		if run(bad) == nil {
			t.Errorf("guard accepted %q", bad)
		}
	}
	// Positive control: the default lab path passes.
	if err := run("/root/f5/src"); err != nil {
		t.Errorf("guard refused /root/f5/src: %v", err)
	}
	body, err := os.ReadFile("f5/deploy.sh") // #nosec G304 -- repo file
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--exclude /seed", "--exclude /secrets", "--dry-run"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("deploy.sh lacks %q", want)
		}
	}
}

// --- the installer runbook (docs/install.md) ---------------------------------------------

const installGuide = "../docs/install.md"

// installerPhase is one entry of deploy/ansible/group_vars/all/phases.yml.
type installerPhase struct {
	Name   string   `yaml:"name"`
	Modes  []string `yaml:"modes"`
	Writes string   `yaml:"writes"`
}

func installerPhases(t *testing.T) []installerPhase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("ansible", "group_vars", "all", "phases.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Phases []installerPhase `yaml:"tagcess_phases"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Phases) == 0 {
		t.Fatal("phases.yml has no phases")
	}
	return f.Phases
}

// runbookSection returns the body of the `## <n>.` section.
func runbookSection(t *testing.T, raw string, n int) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^## ` + strconv.Itoa(n) + `\. .*?(?:^## [0-9]+\. |\z)`)
	m := re.FindString(raw)
	if m == "" {
		t.Fatalf("runbook has no section %d", n)
	}
	return m
}

// readsSecretRE matches a command that prints a file from a secrets directory or a key/PAT file.
var readsSecretRE = regexp.MustCompile(`(^|[|;&]\s*)(cat|less|more|head|tail|xxd|od|base64|strings|bat)\s+[^|;&]*(secrets/|\.pat\b|key\.json|-key\b|token)`)

// AC13: every step of the installer runbook is labelled; no command prints a secret.
func TestInstallGuide_StepsLabelledNoSecrets(t *testing.T) {
	raw := readRunbook(t, installGuide)
	steps := parseRunbookSteps(t, raw)
	if len(steps) < 5 {
		t.Fatalf("want the install and rollback steps, got %d", len(steps))
	}
	for _, f := range auditRunbook(steps) {
		t.Error(f)
	}
	for _, s := range steps {
		if s.label == "read (production)" {
			t.Errorf("step %d: the installer runbook has no production step ", s.number)
		}
		for _, c := range s.commands {
			if readsSecretRE.MatchString(c) {
				t.Errorf("step %d prints a secret: %q", s.number, c)
			}
		}
	}
	// Positive control.
	for _, bad := range []string{"cat ~/.config/tagcess-install/lab/secrets/webhook-signing-key", "head -c 10 zitadel-key.json | base64"} {
		if !readsSecretRE.MatchString(bad) {
			t.Errorf("control: %q not caught", bad)
		}
	}
}

// AC14: the runbook's phase table (with its mode column) is phases.yml, in order.
func TestInstallGuide_PhasesMatchSiteYml(t *testing.T) {
	sec := runbookSection(t, readRunbook(t, installGuide), 5)
	row := regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\| ([a-z, ]+) \\|")
	var got []string
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		got = append(got, m[1]+":"+strings.TrimSpace(m[2]))
	}
	var want []string
	for _, p := range installerPhases(t) {
		want = append(want, p.Name+":"+strings.Join(p.Modes, ", "))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("runbook §5 table:\n%s\nphases.yml:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// guideIDs collects the guide item ids the installer can write: the roles' guide_items and the Zitadel adopt
// tool's guide items.
func guideIDs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var ids []string
	add := func(re *regexp.Regexp, files []string) {
		for _, f := range files {
			b, err := os.ReadFile(f) // #nosec G304 -- repo files
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range re.FindAllSubmatch(b, -1) {
				if id := string(m[1]); !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	var roleFiles []string
	err := filepath.WalkDir(filepath.Join("ansible", "roles"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yml") {
			roleFiles = append(roleFiles, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	add(regexp.MustCompile(`'id': '([a-z0-9-]+)'`), roleFiles)
	goFiles, _ := filepath.Glob(filepath.Join("..", "internal", "zitadeladopt", "*.go"))
	goFiles = slices.DeleteFunc(goFiles, func(f string) bool { return strings.HasSuffix(f, "_test.go") })
	add(regexp.MustCompile(`GuideItem\{ID: "([a-z0-9-]+)"`), goFiles)
	if len(ids) < 10 {
		t.Fatalf("too few guide ids found: %v", ids)
	}
	return ids
}

// AC15: every guide item id is listed in runbook §6, and §6 lists no id the installer cannot write.
func TestInstallGuide_GuideItemsDocumented(t *testing.T) {
	sec := runbookSection(t, readRunbook(t, installGuide), 6)
	ids := guideIDs(t)
	for _, id := range ids {
		if !strings.Contains(sec, "| `"+id+"` |") {
			t.Errorf("guide item %q is not in runbook §6", id)
		}
	}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z0-9-]+)` \\|").FindAllStringSubmatch(sec, -1) {
		if !slices.Contains(ids, m[1]) {
			t.Errorf("runbook §6 lists %q, which no role or tool writes", m[1])
		}
	}
}

// AC16: every phase that writes has its §5 subsection with a rollback line.
func TestInstallGuide_EveryWriteHasRollback(t *testing.T) {
	sec := runbookSection(t, readRunbook(t, installGuide), 5)
	for _, p := range installerPhases(t) {
		re := regexp.MustCompile("(?ms)^### 5\\.[0-9]+ `" + p.Name + "`\n(.*?)(?:^### |\\z)")
		m := re.FindStringSubmatch(sec)
		if m == nil {
			t.Errorf("phase %s has no §5 subsection", p.Name)
			continue
		}
		if p.Writes != "none" && !strings.Contains(m[1], "**Rollback:**") {
			t.Errorf("writing phase %s (%s) has no **Rollback:** line", p.Name, p.Writes)
		}
	}
}
