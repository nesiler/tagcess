// Package hostlab_test checks the static side of F3b-002: the image, the Headscale config template and
// the script that put the Linux/systemd host lab on OrbStack. Nothing here starts a container; the live
// side is `make hostlab-up` (and the F3b-003 fixture tests).
package hostlab_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The v0.29.4 release's checksums.txt entries for the .deb packages (2026-10-02). Pinned here too, so
// bumping the version or a digest in the Dockerfile is a deliberate two-place change.
const (
	sha256AMD64 = "1f65364716ae1fcc3845b1a65a47583469022e9c6f194dfdfeb25403f89f0841"
	sha256ARM64 = "021a4aeb2106d09c0e6fb5f936acffcbcdea213ef8882b19ea91b03783e1f816"
)

var labFiles = []string{"Dockerfile", "headscale.config.yaml.tmpl", "hostlab.sh"}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestHostLab_NoSecretsPinned is AC4: the Headscale version and package digests are pinned, and the
// image, config template and script hold no secret value.
func TestHostLab_NoSecretsPinned(t *testing.T) {
	dockerfile := read(t, "Dockerfile")

	pins := []struct{ name, want string }{
		{"base image", "FROM ubuntu:24.04"},
		{"version", "ARG HEADSCALE_VERSION=0.29.4"},
		{"amd64 digest", "ARG HEADSCALE_SHA256_AMD64=" + sha256AMD64},
		{"arm64 digest", "ARG HEADSCALE_SHA256_ARM64=" + sha256ARM64},
		{"digest check", "sha256sum -c"},
	}
	for _, p := range pins {
		if !strings.Contains(dockerfile, p.want) {
			t.Errorf("Dockerfile: %s is not pinned (missing %q)", p.name, p.want)
		}
	}
	if regexp.MustCompile(`(?i):latest\b|\bcurl\b[^\n]*\|\s*(ba)?sh`).MatchString(dockerfile) {
		t.Error("Dockerfile: unpinned :latest or piped installer")
	}
	for _, line := range strings.Split(dockerfile, "\n") {
		if regexp.MustCompile(`^\s*(COPY|ADD)\b.*(\.env|\.secrets)`).MatchString(line) {
			t.Errorf("Dockerfile copies secret material into the image: %q", line)
		}
	}

	// Values that exist on this machine (the lab seed's test/compose/.env) must not appear anywhere.
	var known []string
	if env, err := os.ReadFile("../compose/.env"); err == nil {
		for _, line := range strings.Split(string(env), "\n") {
			if _, v, ok := strings.Cut(line, "="); ok && len(strings.Trim(v, `"' `)) >= 8 {
				known = append(known, strings.Trim(v, `"' `))
			}
		}
	}

	token := regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)
	literalSecret := regexp.MustCompile(`(?i)\b(client_secret|password|api_key|token)\s*[:=]\s*["']?[A-Za-z0-9+/_-]{8,}`)
	for _, name := range labFiles {
		content := read(t, name)
		if strings.Contains(content, "-----BEGIN") {
			t.Errorf("%s: contains PEM material", name)
		}
		for _, v := range known {
			if strings.Contains(content, v) {
				t.Errorf("%s: contains a value from test/compose/.env", name)
			}
		}
		for _, m := range literalSecret.FindAllString(content, -1) {
			t.Errorf("%s: literal secret assignment %q", name, m)
		}
		for _, m := range token.FindAllString(content, -1) {
			if m == sha256AMD64 || m == sha256ARM64 {
				continue
			}
			// Long identifiers (paths, option names, unit names) are fine; a token needs digits and letters.
			if regexp.MustCompile(`\d`).MatchString(m) && regexp.MustCompile(`[A-Za-z]`).MatchString(m) {
				t.Errorf("%s: high-entropy token %q", name, m)
			}
		}
	}

	// The OIDC secret is only ever referenced by file path; the template has no inline secret key.
	tmpl := read(t, "headscale.config.yaml.tmpl")
	if regexp.MustCompile(`(?m)^\s*client_secret\s*:`).MatchString(tmpl) {
		t.Error("config template sets an inline client_secret; only client_secret_path may be used")
	}
	if !strings.Contains(tmpl, "client_secret_path:") {
		t.Error("config template has no client_secret_path")
	}
}

// AC7 (F3b-027): an unsupported architecture fails with an explicit TARGETARCH message. The arch is
// defaulted into a local variable first, so `set -u` cannot abort on an unset TARGETARCH before the
// case handles it.
func TestHostLab_UnsupportedArchMessage(t *testing.T) {
	dockerfile := read(t, "Dockerfile")
	if !strings.Contains(dockerfile, `arch="${TARGETARCH:-$(dpkg --print-architecture)}"`) {
		t.Error("Dockerfile does not default TARGETARCH before use; set -u would abort before the arch check")
	}
	if !regexp.MustCompile(`unsupported architecture TARGETARCH=\$\{?arch\}?`).MatchString(dockerfile) {
		t.Error("Dockerfile has no explicit unsupported-architecture TARGETARCH message")
	}
	if strings.Contains(dockerfile, `unsupported architecture ${TARGETARCH}`) {
		t.Error("Dockerfile expands TARGETARCH bare in the message; set -u would fail first")
	}
}

// TestHostLab_ScriptAndMakefile checks the shape AC1–AC3 depend on: one script with up/down, called by
// the Makefile, that verifies itself and never touches the lab Zitadel's cluster.
func TestHostLab_ScriptAndMakefile(t *testing.T) {
	script := read(t, "hostlab.sh")
	for _, want := range []string{"set -euo pipefail", "up)", "down)", "--privileged", "--network host", "private"} {
		if !strings.Contains(script, want) {
			t.Errorf("hostlab.sh: missing %q", want)
		}
	}
	if regexp.MustCompile(`\b(kubectl|helm)\b`).MatchString(script) {
		t.Error("hostlab.sh must not touch the lab Zitadel cluster (AC3)")
	}

	makefile := read(t, "../../Makefile")
	for _, want := range []string{"\nhostlab-up:", "\nhostlab-down:", "test/hostlab/hostlab.sh up", "test/hostlab/hostlab.sh down"} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile: missing %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\.PHONY:.*\bhostlab-up\b.*\bhostlab-down\b`).MatchString(makefile) {
		t.Error("Makefile: hostlab-up and hostlab-down are not in .PHONY")
	}
}
