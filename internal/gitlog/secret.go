package gitlog

import (
	"regexp"
	"strings"
)

// Finding names the file and the rule that matched when content looks like a secret.
type Finding struct {
	File string
	Rule string
}

// Scanner reports secret-looking content in the files handed to it. It is defence in depth: the
// renderer and the audit layer already keep secrets out, but a regression must not reach the git
// history (AC2, NFR-04).
type Scanner interface {
	Find(files []File) []Finding
}

// SecretError is returned when a commit was refused because its content looks secret. Findings
// carry only file names and rule names, never the value.
type SecretError struct {
	Findings []Finding
}

func (e *SecretError) Error() string {
	return "gitlog: refusing to commit content that looks secret: " + findingsText(e.Findings)
}

// Scanner rule names.
const (
	rulePrivateKey = "private_key"
	ruleJWT        = "jwt"
	ruleAssignment = "secret_assignment"
)

var (
	// pemPrivateKey matches PEM/OpenSSH private key headers.
	pemPrivateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
	// jwtToken matches a compact JWT (three dot-separated base64url segments).
	jwtToken = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	// secretAssignment matches a secret-ish key assigned a value, in either `key = value` or
	// `"key": "value"` form; the value is captured so a path or a placeholder can be allowed.
	secretAssignment = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key|signing[_-]?key|access[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*["']?([^\s"']+)`)
)

// DefaultScanner returns the built-in regexp scanner.
func DefaultScanner() Scanner { return defaultScanner{} }

type defaultScanner struct{}

func (defaultScanner) Find(files []File) []Finding {
	var findings []Finding
	for _, f := range files {
		content := f.Content
		if pemPrivateKey.Match(content) {
			findings = append(findings, Finding{File: f.Name, Rule: rulePrivateKey})
		}
		if jwtToken.Match(content) {
			findings = append(findings, Finding{File: f.Name, Rule: ruleJWT})
		}
		for _, m := range secretAssignment.FindAllSubmatch(content, -1) {
			if isSafeSecretValue(string(m[2])) {
				continue
			}
			findings = append(findings, Finding{File: f.Name, Rule: ruleAssignment})
			break
		}
	}
	return findings
}

// isSafeSecretValue reports whether a value matched after a secret-ish key is clearly not a secret:
// a file path, an environment/placeholder reference or a masked value. Everything else is treated
// as a secret (fail closed), including a value that merely contains a slash.
func isSafeSecretValue(v string) bool {
	v = strings.TrimRight(strings.TrimSpace(v), ",;")
	switch v {
	case "", "*", "***":
		return true
	}
	// A placeholder must be the whole value; a substring like "mytodo1" is a real secret that
	// merely contains a placeholder word (LOW 7).
	lower := strings.ToLower(v)
	for _, word := range []string{"change_me", "changeme", "placeholder", "redacted", "example", "todo"} {
		if lower == word {
			return true
		}
	}
	// An environment/template reference is not the secret itself.
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "<") {
		return true
	}
	// A path that names where the secret lives is not the secret itself, but require a path-like
	// shape (a further separator or an extension) so an opaque value like "/S3cret" stays a secret
	// (fail closed).
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") ||
		strings.HasPrefix(v, "../") || strings.HasPrefix(v, "~") {
		rest := strings.TrimPrefix(strings.TrimLeft(v, "/."), "~")
		if strings.ContainsAny(rest, "/.") {
			return true
		}
	}
	return false
}
