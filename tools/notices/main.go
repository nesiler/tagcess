// Command notices generates and checks THIRD_PARTY_NOTICES: the list of third-party
// components that ship in the tagcess binaries and the embedded web assets, together
// with the licence each is provided under.
//
//	go run ./tools/notices generate   # write THIRD_PARTY_NOTICES
//	go run ./tools/notices check      # fail if it is stale or a licence is off the allowlist
//
// The Go modules are the ones reachable from ./cmd/... (what actually ships), so test-only
// dependencies and the `go tool` entries (templ, sqlc) are not listed. The allowlist is the
// developer's decision of 2026-10-15 (docs/product-decisions.md §5).
//
// Standard library first: this command is dependency-free on purpose, so it adds nothing to
// go.mod (the alternative, go-licenses, would pull in a sizeable tool tree).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const noticesFile = "THIRD_PARTY_NOTICES"

// The tagcess binaries ship on Linux (the container image and the release builds), and the
// module set `go list` reports depends on GOOS/GOARCH (e.g. go-isatty and go-strftime are
// darwin-only). Pin the target so the generated notices are the same on every host.
const (
	targetGOOS   = "linux"
	targetGOARCH = "amd64"
)

// allowedLicences is the licence allowlist as SPDX ids. Anything else fails the check.
var allowedLicences = []string{
	"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "0BSD", "Unlicense", "OFL-1.1",
}

// component is one third-party entry: a Go module or an embedded JavaScript library.
type component struct {
	name    string
	version string
	licence string
	source  string
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	mode := "check"
	if len(args) > 0 {
		mode = args[0]
	}
	if mode != "generate" && mode != "check" {
		return fmt.Errorf("unknown command %q (want generate or check)", mode)
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	content, err := generate(ctx, root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, noticesFile)
	if mode == "generate" {
		if err := os.WriteFile(path, content, 0o644); err != nil { // #nosec G306 -- a public notices file is world-readable by design
			return err
		}
		fmt.Printf("wrote %s\n", noticesFile)
		return nil
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- the notices file at the fixed repo root
	if err != nil {
		return fmt.Errorf("read %s: %w (run `make notices`)", noticesFile, err)
	}
	if !bytes.Equal(existing, content) {
		return fmt.Errorf("%s is out of date; run `make notices` and commit the result", noticesFile)
	}
	fmt.Println("notices: ok")
	return nil
}

// repoRoot walks up from the working directory to the module root.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// generate renders the notices and fails when a component is licensed off the allowlist.
func generate(ctx context.Context, root string) ([]byte, error) {
	mods, err := goModules(ctx, root)
	if err != nil {
		return nil, err
	}
	assets, err := embeddedAssets(root)
	if err != nil {
		return nil, err
	}
	for _, cs := range [][]component{mods, assets} {
		if err := validate(cs); err != nil {
			return nil, err
		}
	}
	return render(mods, assets), nil
}

// goModules lists the modules that ship in the binaries built from ./cmd/... .
func goModules(ctx context.Context, root string) ([]component, error) {
	const format = `{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}`
	out, err := goList(ctx, root, "list", "-deps", "-f", format, "./cmd/...")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var mods []component
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return nil, fmt.Errorf("unexpected `go list` output: %q", line)
		}
		path, version, dir := parts[0], parts[1], parts[2]
		if seen[path] {
			continue
		}
		if path == "" || dir == "" {
			return nil, fmt.Errorf("module %q has no source directory; is it downloaded? (try `go mod download`)", path)
		}
		seen[path] = true
		licence, err := moduleLicence(dir, path)
		if err != nil {
			return nil, err
		}
		source := "https://pkg.go.dev/" + path
		if version != "" {
			source += "@" + version
		} else {
			version = "(local)"
		}
		mods = append(mods, component{
			name:    path,
			version: version,
			licence: licence,
			source:  source,
		})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].name < mods[j].name })
	return mods, nil
}

func goList(ctx context.Context, root string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- the fixed `go` binary, arguments are constants in this package
	cmd.Dir = root
	cmd.Env = targetEnv()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// targetEnv is the environment for `go list`: the host environment with GOOS, GOARCH and
// CGO_ENABLED forced to the shipping target, so a developer's macOS and the Linux CI runner
// resolve the same module set.
func targetEnv() []string {
	pinned := map[string]string{"GOOS": targetGOOS, "GOARCH": targetGOARCH, "CGO_ENABLED": "0"}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if _, drop := pinned[k]; drop {
				continue
			}
		}
		env = append(env, kv)
	}
	for k, v := range pinned {
		env = append(env, k+"="+v)
	}
	return env
}

// moduleLicence reads the module's licence file and returns the SPDX id(s).
func moduleLicence(dir, path string) (string, error) {
	file, err := licenceFile(dir)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	text, err := os.ReadFile(file) // #nosec G304 -- a licence file found inside the dependency's own module directory
	if err != nil {
		return "", err
	}
	ids := classify(string(text))
	if len(ids) == 0 {
		return "", fmt.Errorf("cannot identify the licence of %s (file %s)", path, file)
	}
	return strings.Join(ids, ", "), nil
}

var licenceName = regexp.MustCompile(`^(licen[cs]e|copying|unlicen[cs]e)(\.(txt|md|rst))?$`)

// licenceFile picks the module's licence file: the one at the module root, or else the
// shallowest one below it. Suffixed files such as LICENSE-3RD-PARTY are not chosen.
func licenceFile(dir string) (string, error) {
	var found []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return fs.SkipDir
			}
			return nil
		}
		if licenceName.MatchString(strings.ToLower(d.Name())) {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", fmt.Errorf("no licence file in %s", dir)
	}
	sort.Slice(found, func(i, j int) bool {
		ri, _ := filepath.Rel(dir, found[i])
		rj, _ := filepath.Rel(dir, found[j])
		di, dj := strings.Count(ri, string(os.PathSeparator)), strings.Count(rj, string(os.PathSeparator))
		if di != dj {
			return di < dj
		}
		return ri < rj
	})
	return found[0], nil
}

// licenceRule identifies a licence by phrases that must (or must not) appear in it.
type licenceRule struct {
	id     string
	has    []string
	absent []string
}

// The rules are ordered so that a more specific licence wins over a broader one; a file
// may match several (a dual licence) and they are all reported.
var licenceRules = []licenceRule{
	{id: "Apache-2.0", has: []string{"apache license", "version 2.0, january 2004"}},
	// The Apache boilerplate notice, as in a dual-licence file that points at the full text.
	{id: "Apache-2.0", has: []string{"licensed under the apache license, version 2.0"}},
	{id: "Unlicense", has: []string{"this is free and unencumbered software released into the public domain"}},
	{id: "OFL-1.1", has: []string{"sil open font license", "version 1.1"}},
	{id: "MIT", has: []string{"permission is hereby granted, free of charge", `the software is provided "as is"`}},
	{id: "ISC", has: []string{"permission to use, copy, modify, and/or distribute this software for any purpose", "provided that the above copyright notice"}},
	{
		id:     "0BSD",
		has:    []string{"permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted"},
		absent: []string{"provided that the above copyright notice"},
	},
	{id: "BSD-3-Clause", has: []string{"redistributions of source code must retain the above copyright", "neither the name"}},
	{id: "BSD-2-Clause", has: []string{"redistributions of source code must retain the above copyright"}, absent: []string{"neither the name"}},
}

// classify returns the SPDX ids of every rule that matches the licence text, sorted and
// deduplicated (two rules can name the same licence, e.g. the full Apache text and its
// boilerplate notice).
func classify(text string) []string {
	n := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	seen := map[string]bool{}
	var ids []string
	for _, r := range licenceRules {
		if !containsAll(n, r.has) || containsAny(n, r.absent) || seen[r.id] {
			continue
		}
		seen[r.id] = true
		ids = append(ids, r.id)
	}
	sort.Strings(ids)
	return ids
}

func containsAll(text string, subs []string) bool {
	for _, s := range subs {
		if !strings.Contains(text, s) {
			return false
		}
	}
	return true
}

func containsAny(text string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// jsLicences maps the npm packages bundled into internal/web/static/editor.js to their
// licence. A package that is not listed fails the check, so a new editor dependency must
// be classified before it can ship.
var jsLicences = map[string]string{
	"@codemirror/commands": "MIT",
	"@codemirror/language": "MIT",
	"@codemirror/state":    "MIT",
	"@codemirror/view":     "MIT",
	"@lezer/highlight":     "MIT",
}

// htmx is vendored directly as internal/web/static/htmx.min.js. Keep the version in sync
// with internal/web/static/README.md when the file is updated.
var embeddedHTMX = component{
	name:    "htmx",
	version: "2.0.11",
	licence: "0BSD",
	source:  "https://unpkg.com/htmx.org@2.0.11/dist/htmx.min.js",
}

// embeddedAssets lists the JavaScript libraries bundled into the embedded web assets: htmx
// and the CodeMirror/Lezer packages the editor build (tools/editor/build.sh) packs into
// editor.js. esbuild only builds the bundle, so it does not ship.
func embeddedAssets(root string) ([]component, error) {
	assets := []component{embeddedHTMX}
	data, err := os.ReadFile(filepath.Join(root, "tools", "editor", "package.json")) // #nosec G304 -- a fixed repo path
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse tools/editor/package.json: %w", err)
	}
	for name, version := range pkg.Dependencies {
		licence, ok := jsLicences[name]
		if !ok {
			return nil, fmt.Errorf("no licence recorded for editor dependency %s; add it to jsLicences", name)
		}
		assets = append(assets, component{
			name:    name,
			version: version,
			licence: licence,
			source:  "https://www.npmjs.com/package/" + name,
		})
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].name < assets[j].name })
	return assets, nil
}

// validate fails when any component's licence (or one option of a dual licence) is not on
// the allowlist.
func validate(cs []component) error {
	for _, c := range cs {
		for _, id := range strings.Split(c.licence, ", ") {
			if !isAllowed(id) {
				return fmt.Errorf("%s is licensed under %s, which is not on the allowlist (%s)",
					c.name, c.licence, strings.Join(displayAllowlist(), ", "))
			}
		}
	}
	return nil
}

func isAllowed(id string) bool {
	for _, a := range allowedLicences {
		if a == id {
			return true
		}
	}
	return false
}

// displayAllowlist returns the allowlist sorted, for the generated header.
func displayAllowlist() []string {
	out := append([]string(nil), allowedLicences...)
	sort.Strings(out)
	return out
}

func render(mods, assets []component) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", noticesFile, strings.Repeat("=", len(noticesFile)))
	b.WriteString("tagcess - https://github.com/nesiler/tagcess\n\n")
	b.WriteString("tagcess is distributed under the MIT License (see LICENSE). This file lists the\n")
	b.WriteString("third-party components that ship in the tagcess binaries and the embedded web\n")
	b.WriteString("assets, together with the licence each is provided under. The module set is resolved\n")
	b.WriteString("for linux, the platform the binaries ship on, so the file is the same whichever host\n")
	b.WriteString("runs the check.\n\n")
	b.WriteString("It is generated by `go run ./tools/notices generate` (`make notices`). Do not edit\n")
	b.WriteString("it by hand: `make notices-check` and CI fail when it is out of date or when a\n")
	b.WriteString("component is licensed under something outside the allowlist\n")
	b.WriteString("(docs/product-decisions.md §5):\n\n")
	fmt.Fprintf(&b, "  %s\n\n", strings.Join(displayAllowlist(), ", "))
	b.WriteString("A component shows more than one licence when its files are covered by different\n")
	b.WriteString("licences; every licence listed must be on the allowlist.\n\n")
	b.WriteString("Go modules\n----------\n\n")
	writeTable(&b, mods)
	b.WriteString("\nEmbedded JavaScript\n-------------------\n\n")
	writeTable(&b, assets)
	return []byte(b.String())
}

func writeTable(b *strings.Builder, cs []component) {
	b.WriteString("| Component | Version | Licence | Source |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, c := range cs {
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", c.name, c.version, c.licence, c.source)
	}
}
