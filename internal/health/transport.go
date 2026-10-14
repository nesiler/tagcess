// Package health holds the credentialless probe transport (F4-014): one GET to a target the UI
// has approved, over a connection that the shared endpoint policy (netpolicy, ScopeProbe) has
// checked. It reports what came back and nothing more; reading a status as healthy is F4-015 and
// reading a certificate is F4-016.
package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
)

// DefaultTimeout is the per-probe time limit (R3 B-06: 5 s).
const DefaultTimeout = monitor.MaxTimeout

// ErrRejected marks a request refused before any network call. Policy refusals at resolve or dial
// time carry netpolicy.ErrDenied instead; both mean nothing was sent.
var ErrRejected = errors.New("health: probe request rejected")

// Outcome says what the probe saw. Anything that is not OutcomeResponded is not a healthy answer.
type Outcome string

const (
	OutcomeResponded Outcome = "responded" // a final (non-redirect) HTTP response arrived
	OutcomeRedirect  Outcome = "redirect"  // the target answered 3xx; the redirect was not followed
	OutcomeUnknown   Outcome = "unknown"   // not measurable: nothing was sent
)

// Result is the whole record of a probe: no headers, no body.
type Result struct {
	Outcome    Outcome
	StatusCode int
}

// Request is one probe. Host must be on the approved target allowlist and Host:Port must pass the
// probe endpoint policy. Header and Credential exist only so that a caller asking for them is
// refused: the probe carries no custom header, auth or body.
type Request struct {
	Host       string // allowlisted hostname or IP literal; dialled through the policy guard
	Port       int    // must be in the probe policy's port list
	Path       string // absolute path without query, default "/"
	TLS        bool   // https instead of http (chain checks are F4-016)
	ServerName string // optional Host header and SNI, default Host; must be an approved target too
	Template   string // fixed system template name; no adapter exists, so it is never measured
	// SkipVerify does not verify the certificate chain or name. Only the k8s target check sets it:
	// it reaches the ingress exactly as Caddy's (k8s) snippet does (tls_insecure_skip_verify). The
	// gate and TLS-expiry checks always verify.
	SkipVerify bool
	Header     http.Header // must be empty
	Credential string      // must be empty
}

// Transport sends probes. Build it with New; the constructor wires the real resolver and dialer
// behind the policy guard, so a loopback test server is unreachable through it.
type Transport struct {
	targets site.TargetSource
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	timeout time.Duration
	rootCAs *x509.CertPool   // test-only trust pool; nil (system roots) in production
	now     func() time.Time // test-only clock; nil means time.Now
}

// New returns the production transport: system DNS and dialer, both behind the probe policy.
func New(targets site.TargetSource, policy *netpolicy.Store) *Transport {
	guard := netpolicy.NewGuard(policy, nil, nil)
	return newTransport(targets, guard.DialContext(netpolicy.ScopeProbe), DefaultTimeout)
}

// newTransport is the injection point for tests (fake resolver and dialer inside a guard).
func newTransport(targets site.TargetSource, dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) *Transport {
	return &Transport{targets: targets, dial: dial, timeout: timeout}
}

// Get performs the probe. A refused request returns a zero Result and an error without touching
// the network. A redirect is reported, never followed. The response body is never read or kept.
func (t *Transport) Get(ctx context.Context, req Request) (Result, error) {
	// A fixed system template has no trusted adapter: unknown, whatever address came with it.
	if req.Template != "" {
		return Result{Outcome: OutcomeUnknown}, nil
	}
	hostName, serverName, err := t.check(ctx, req)
	if err != nil {
		return Result{}, err
	}
	return t.get(ctx, req, hostName, serverName)
}

// get sends the probe for a request that check has already approved.
func (t *Transport) get(ctx context.Context, req Request, hostName, serverName string) (Result, error) {
	path := req.Path
	if path == "" {
		path = "/"
	}
	scheme := "http"
	if req.TLS {
		scheme = "https"
	}
	target := url.URL{Scheme: scheme, Host: net.JoinHostPort(hostName, strconv.Itoa(req.Port)), Path: path}

	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("%w: build request", ErrRejected)
	}
	httpReq.Host = serverName
	httpReq.Header.Set("User-Agent", "tagcess-probe")

	tr := &http.Transport{
		Proxy:             nil, // never the environment proxy
		DialContext:       t.dial,
		DisableKeepAlives: true,
	}
	tr.TLSClientConfig = t.tlsConfig(serverName)
	if req.SkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // mirrors Caddy's own upstream trust, see Request.SkipVerify
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{}, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return Result{Outcome: OutcomeRedirect, StatusCode: resp.StatusCode}, nil
	}
	return Result{Outcome: OutcomeResponded, StatusCode: resp.StatusCode}, nil
}

// check refuses a malformed, credential-carrying or unapproved request and returns the canonical
// (allowlist spelling) host and Host/SNI name to use on the wire. The port and address checks
// against the endpoint policy run in the guarded dial, before any lookup or connection.
func (t *Transport) check(ctx context.Context, req Request) (host, serverName string, err error) {
	if len(req.Header) > 0 || req.Credential != "" {
		return "", "", fmt.Errorf("%w: custom header or credential is not allowed", ErrRejected)
	}
	// Plain ASCII only: Unicode case folding (U+017F, U+212A) or IDN input must never match an
	// allowed name and then be rewritten to another name by the HTTP stack.
	if !isPlainASCII(req.Host) || !isPlainASCII(req.ServerName) {
		return "", "", fmt.Errorf("%w: host and server name must be plain ASCII", ErrRejected)
	}
	if req.Host == "" || strings.ContainsAny(req.Host, " /?#@[]\\") || req.Port < 1 || req.Port > 65535 {
		return "", "", fmt.Errorf("%w: host or port is invalid", ErrRejected)
	}
	if req.ServerName != "" && strings.ContainsAny(req.ServerName, " /?#@[]\\") {
		return "", "", fmt.Errorf("%w: server name is invalid", ErrRejected)
	}
	if req.Path != "" && (!strings.HasPrefix(req.Path, "/") || strings.ContainsAny(req.Path, "?# \\") || hasControl(req.Path)) {
		return "", "", fmt.Errorf("%w: path must be a plain absolute path", ErrRejected)
	}
	allowed, err := t.targets.ListTargets(ctx)
	if err != nil {
		return "", "", fmt.Errorf("%w: target allowlist unreadable", ErrRejected)
	}
	host, ok := canonicalTarget(allowed, req.Host)
	if !ok {
		return "", "", fmt.Errorf("%w: host is not an approved target", ErrRejected)
	}
	serverName = host
	// The Host header and SNI choose the virtual host at the approved address, so an override is
	// held to the same allowlist: it can never name a site that is not approved.
	if req.ServerName != "" {
		if serverName, ok = canonicalTarget(allowed, req.ServerName); !ok {
			return "", "", fmt.Errorf("%w: server name is not an approved target", ErrRejected)
		}
	}
	return host, serverName, nil
}

// canonicalTarget returns the allowlist spelling of name, matched with ASCII-only case folding.
// name must already be plain ASCII; an allowlist entry that is not ASCII never matches.
func canonicalTarget(list []string, name string) (string, bool) {
	for _, h := range list {
		if isPlainASCII(h) && asciiEqualFold(h, name) {
			return h, true
		}
	}
	return "", false
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// isPlainASCII is true for strings of printable ASCII only (empty is true; emptiness is checked
// where it matters).
func isPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// tlsConfig verifies the certificate normally against serverName; the chain verdict is F4-016's.
func (t *Transport) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, RootCAs: t.rootCAs}
}
