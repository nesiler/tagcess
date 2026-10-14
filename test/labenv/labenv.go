// Package labenv resolves the developer's lab settings for the Go side of the lab tooling, with the same names
// and the same order as test/lab/lib.sh: the environment first, then the untracked file
// ${TAGCESS_LAB_ENV:-$HOME/.config/tagcess/lab.env} (KEY=VALUE lines, optional "export " and quotes), then the
// generic defaults. Nothing about a real lab is committed.
package labenv

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Names of the settings (environment variables and lab.env keys).
const (
	EnvFile        = "TAGCESS_LAB_ENV"
	EnvDomain      = "TAGCESS_LAB_DOMAIN"
	EnvZitadelHost = "TAGCESS_LAB_ZITADEL_HOST"
)

// DefaultDomain is the lab domain when nothing is configured.
const DefaultDomain = "lab.example.com"

// Get returns the setting name from the environment, else from the lab env file, else "".
func Get(name string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fileValue(name)
}

// Domain is the lab DNS domain (default lab.example.com).
func Domain() string {
	if v := Get(EnvDomain); v != "" {
		return v
	}
	return DefaultDomain
}

// ZitadelHost is the lab Zitadel host (default tagcess-zitadel.<Domain()>).
func ZitadelHost() string {
	if v := Get(EnvZitadelHost); v != "" {
		return v
	}
	return "tagcess-zitadel." + Domain()
}

// ZitadelIssuer is https://<ZitadelHost()>.
func ZitadelIssuer() string { return "https://" + ZitadelHost() }

func filePath() string {
	if p := os.Getenv(EnvFile); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "tagcess", "lab.env")
}

// fileValue returns the value of the last name=value line of the lab env file.
func fileValue(name string) string {
	p := filePath()
	if p == "" {
		return ""
	}
	f, err := os.Open(p) // #nosec G304 -- the developer's own lab settings file
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	val := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != name {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		val = v
	}
	return val
}
