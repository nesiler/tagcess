// Package discover is the read-only host scan of the setup flow (setup-flow.md §3). The host helper runs it as
// root; it reports what runs on the host as findings. A finding carries only attributes that the scanner copies
// field by field (secret-free by construction), never a file's or a command's raw output.
package discover

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Version is the version of the discovery.json document.
	Version = 1
	// MaxReportBytes bounds the document (ADR 0021 b: results are size-limited).
	MaxReportBytes = 256 << 10

	maxStringRunes = 200
	maxListItems   = 50
)

// Kind is a finding kind, the rows of setup-flow.md §3.2. The list is closed.
type Kind string

const (
	KindHost         Kind = "host"
	KindListener     Kind = "listener"
	KindReverseProxy Kind = "reverse_proxy"
	KindCaddy        Kind = "caddy"
	KindHeadscale    Kind = "headscale"
	KindTailscale    Kind = "tailscale"
	KindWireGuard    Kind = "wireguard"
	KindIdP          Kind = "idp"
	KindK8s          Kind = "k8s"
	KindDocker       Kind = "docker"
	KindContainer    Kind = "container"
	KindOther        Kind = "other"
)

// Result of a run: partial when a core probe (systemd units, listeners) could not run at all.
const (
	ResultComplete = "complete"
	ResultPartial  = "partial"
)

// Attrs is the attribute set of a finding: strings, booleans, integers and string lists only.
type Attrs map[string]any

// Finding is one observation. Subject is its stable key (for example `headscale/systemd`, `listener/443/tcp`);
// Evidence names the check and its result class, never output.
type Finding struct {
	Kind     Kind   `json:"kind"`
	Subject  string `json:"subject"`
	Attrs    Attrs  `json:"attrs"`
	Evidence string `json:"evidence"`
}

// Report is results/discovery.json. It has no timestamps, so a scan of an unchanged host is byte-identical.
type Report struct {
	Version  int       `json:"version"`
	Result   string    `json:"result"`
	Findings []Finding `json:"findings"`
}

// Host is everything the scanner may touch. Callers other than the scanner's own code never see raw output.
type Host interface {
	// ReadFile reads a regular file; the scanner calls it only for the paths of the allow-list in this package.
	ReadFile(path string) ([]byte, error)
	// ReadDir lists the names in a directory.
	ReadDir(path string) ([]string, error)
	Exists(path string) bool
	// Run runs a command (stdout and stderr combined); an error means missing tool or non-zero exit.
	Run(name string, args ...string) (string, error)
	// RunAs is Run as an unprivileged user.
	RunAs(user, name string, args ...string) (string, error)
	// Get is an HTTP GET to a loopback address.
	Get(url string) (status int, body []byte, err error)
}

type scan struct {
	h        Host
	findings []Finding
	partial  bool
	units    map[string]bool
	cont     []container
}

func (s *scan) add(k Kind, subject, evidence string, a Attrs) {
	s.findings = append(s.findings, Finding{Kind: k, Subject: subject, Attrs: a, Evidence: evidence})
}

// Scan runs every check and returns the report document.
func Scan(h Host) ([]byte, error) {
	s := &scan{h: h}
	s.scanHost()
	s.scanUnits()
	s.scanDocker()
	s.scanListeners()
	s.scanCaddy()
	s.scanHeadscale()
	s.scanTailscale()
	s.scanWireGuard()
	s.scanIdP()
	s.scanK8s()
	s.scanOther()
	return s.report()
}

func (s *scan) report() ([]byte, error) {
	r := Report{Version: Version, Result: ResultComplete, Findings: s.findings}
	if s.partial {
		r.Result = ResultPartial
	}
	for i := range r.Findings {
		r.Findings[i].Attrs = sanitize(r.Findings[i].Attrs)
		r.Findings[i].Subject = cleanString(r.Findings[i].Subject)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Subject < b.Subject
	})
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReportBytes {
		return nil, errors.New("discovery report too large")
	}
	return b, nil
}

// sanitize bounds every value: control characters removed, strings and lists capped. It also makes sure no
// attribute holds anything but the allowed value types.
func sanitize(a Attrs) Attrs {
	out := Attrs{}
	for k, v := range a {
		switch x := v.(type) {
		case string:
			out[k] = cleanString(x)
		case bool, int:
			out[k] = x
		case []string:
			l := make([]string, 0, len(x))
			for _, e := range x {
				if len(l) == maxListItems {
					break
				}
				l = append(l, cleanString(e))
			}
			out[k] = l
		}
	}
	return out
}

func cleanString(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxStringRunes {
		s = string(r[:maxStringRunes])
	}
	return strings.TrimSpace(s)
}
