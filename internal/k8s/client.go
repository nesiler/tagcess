package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
)

// The client is the narrow read-only REST client of F4-004: paginated GETs of Ingresses and
// Services in explicitly named namespaces and of IngressClasses cluster-wide, over net/http with the
// credential's CA. A read is all pages or an error; a partial result is never returned. Redirects are
// never followed, the environment proxy is never used, and every connection goes through the F4-043
// API policy (resolution and dial). Keep-alive is off, so every page dials through the policy again:
// a policy that was narrowed or removed in the meantime refuses the next request before any token
// is sent.

const (
	// DefaultTimeout bounds one page request, from dial to the last byte read.
	DefaultTimeout = 30 * time.Second

	pageLimit    = 500      // [Ö] objects per page asked of the API
	maxPages     = 200      // [Ö] a read of this many pages is not a narrow inventory
	maxPageBytes = 32 << 20 // [Ö] one decoded page
)

// ReadError is a failed list read. Its message names the resource and scope and a short reason; it
// never contains the token, a request URL or a response body. Unwrap exposes a fixed cause only
// (see classify): errors.Is works for the context errors and netpolicy.ErrDenied, and no raw
// transport text is reachable through the chain.
type ReadError struct {
	Resource  string // ingresses, services or ingressclasses
	Namespace string // empty for the cluster-scoped IngressClasses
	Page      int    // 1-based page that failed
	Status    int    // HTTP status when the API answered, else 0
	Reason    string
	Err       error
}

func (e *ReadError) Error() string {
	scope := "cluster scope"
	if e.Resource != "ingressclasses" {
		scope = fmt.Sprintf("namespace %q", e.Namespace)
	}
	return fmt.Sprintf("k8s: read %s in %s (page %d): %s", e.Resource, scope, e.Page, e.Reason)
}

func (e *ReadError) Unwrap() error { return e.Err }

// Client reads the three resources. Build it with NewClient. It holds the bearer token, so it prints
// without it (Format, LogValue).
type Client struct {
	base    *url.URL // endpoint, including any path prefix
	token   string
	timeout time.Duration
	http    *http.Client
}

// NewClient returns the production client: system DNS and dialer behind the API policy. The
// credential must be valid (https endpoint, CA, token); the CA is the only trust root.
func NewClient(cred Credential, policy *netpolicy.Store) (*Client, error) {
	return NewClientWithGuard(cred, netpolicy.NewGuard(policy, nil, nil))
}

// NewClientWithGuard is NewClient over an explicit guard. Production passes a guard with the system
// resolver and dialer; the binary's composition tests pass one over a stand-in API.
func NewClientWithGuard(cred Credential, guard *netpolicy.Guard) (*Client, error) {
	return newClient(cred, guard.DialContext(netpolicy.ScopeAPI), DefaultTimeout)
}

// ErrCredentialMismatch means the credential's endpoint or TLS server name differs from the profile's.
// The profile is the authority: the token only goes where the profile says. The text names no value.
var ErrCredentialMismatch = errors.New("k8s: the credential's endpoint or TLS server name differs from the profile")

// checkCredential refuses a credential that does not point where the profile says.
func checkCredential(p Profile, cred Credential) error {
	if cred.Endpoint != p.Endpoint || cred.TLSServerName != p.TLSServerName {
		return ErrCredentialMismatch
	}
	return nil
}

// ClientForProfile is NewClient behind the profile check: a credential for another endpoint or TLS
// name returns ErrCredentialMismatch before anything is resolved or dialed, so the token never
// leaves for a host the profile does not name. Every caller that sends the stored token (reads, the
// permission review) goes through it.
func ClientForProfile(p Profile, cred Credential, policy *netpolicy.Store) (*Client, error) {
	return ClientForProfileWithGuard(p, cred, netpolicy.NewGuard(policy, nil, nil))
}

// ClientForProfileWithGuard is ClientForProfile over an explicit guard (see NewClientWithGuard).
func ClientForProfileWithGuard(p Profile, cred Credential, guard *netpolicy.Guard) (*Client, error) {
	if err := checkCredential(p, cred); err != nil {
		return nil, err
	}
	return NewClientWithGuard(cred, guard)
}

// newClient is the injection point for tests (a guard over a fake resolver and dialer).
func newClient(cred Credential, dial func(ctx context.Context, network, address string) (net.Conn, error), timeout time.Duration) (*Client, error) {
	c, err := normalizeCredential(cred)
	if err != nil {
		return nil, fmt.Errorf("k8s: client credential: %w", err)
	}
	base, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, errors.New("k8s: client endpoint is not a URL")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.CAData)) {
		return nil, errors.New("k8s: client CA has no usable certificate")
	}
	tr := &http.Transport{
		Proxy:               nil, // never the environment proxy
		DialContext:         dial,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true, // every page redials through the API policy
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: c.TLSServerName, // empty: the endpoint host
		},
	}
	return &Client{
		base:    base,
		token:   c.Token,
		timeout: timeout,
		http: &http.Client{
			Transport: tr,
			// A redirect is an answer, not an instruction: the token never follows it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Format and LogValue keep the token out of every fmt verb and slog, for a Client and a *Client.
func (c Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedClient) }
func (c Client) LogValue() slog.Value       { return slog.StringValue(redactedClient) }

const redactedClient = "k8s.Client{token:<redacted>}"

// Close drops idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// ListIngresses reads all Ingresses of one namespace.
func (c *Client) ListIngresses(ctx context.Context, namespace string) ([]Ingress, error) {
	if err := checkNamespace("ingresses", namespace); err != nil {
		return nil, err
	}
	return listAll[Ingress](ctx, c, "ingresses", "IngressList", namespace,
		"apis", "networking.k8s.io", "v1", "namespaces", namespace, "ingresses")
}

// ListServices reads all Services of one namespace.
func (c *Client) ListServices(ctx context.Context, namespace string) ([]Service, error) {
	if err := checkNamespace("services", namespace); err != nil {
		return nil, err
	}
	return listAll[Service](ctx, c, "services", "ServiceList", namespace,
		"api", "v1", "namespaces", namespace, "services")
}

// ListIngressClasses reads all IngressClasses (cluster-scoped).
func (c *Client) ListIngressClasses(ctx context.Context) ([]IngressClass, error) {
	return listAll[IngressClass](ctx, c, "ingressclasses", "IngressClassList", "",
		"apis", "networking.k8s.io", "v1", "ingressclasses")
}

// checkNamespace refuses anything but a plain namespace name before any request is built, so the
// name can never add path segments or a query to the read.
func checkNamespace(resource, namespace string) error {
	if len(namespace) > 63 || !dnsLabel.MatchString(namespace) {
		return &ReadError{Resource: resource, Namespace: namespace, Reason: "namespace is not a valid name"}
	}
	return nil
}

// listAll follows continue tokens to the last page. It returns every item or an error, never both.
func listAll[T any](ctx context.Context, c *Client, resource, kind, namespace string, segments ...string) ([]T, error) {
	fail := func(page, status int, reason string, err error) ([]T, error) {
		return nil, &ReadError{Resource: resource, Namespace: namespace, Page: page, Status: status,
			Reason: c.redact(reason), Err: err}
	}
	target := c.base.JoinPath(segments...)

	all := []T{}
	sent := map[string]bool{"": true}
	cont := ""
	for page := 1; ; page++ {
		if page > maxPages {
			return fail(page, 0, "too many pages", nil)
		}
		l, status, reason, err := fetchPage[T](ctx, c, target, kind, cont)
		if err != nil || reason != "" {
			return fail(page, status, reason, err)
		}
		all = append(all, l.Items...)
		cont = l.Metadata.Continue
		if cont == "" {
			return all, nil
		}
		if sent[cont] {
			return fail(page, 0, "continue token repeated", nil)
		}
		sent[cont] = true
	}
}

// fetchPage reads and decodes one page. On failure it returns a short reason (and the cause, if
// any); the response body is never put into either.
func fetchPage[T any](ctx context.Context, c *Client, target *url.URL, kind, cont string) (l list[T], status int, reason string, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		reason, cause := classify(err)
		return l, 0, reason, cause
	}
	u := *target
	q := url.Values{"limit": {strconv.Itoa(pageLimit)}}
	if cont != "" {
		q.Set("continue", cont)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return l, 0, "request could not be built", errRequest
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tagcess")

	resp, err := c.http.Do(req)
	if err != nil {
		reason, cause := classify(err)
		return l, 0, reason, cause
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return l, resp.StatusCode, "redirect refused (HTTP " + strconv.Itoa(resp.StatusCode) + ")", nil
		}
		return l, resp.StatusCode, "HTTP " + strconv.Itoa(resp.StatusCode), nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil {
		reason, cause := classify(err)
		return l, resp.StatusCode, reason, cause
	}
	if len(body) > maxPageBytes {
		return l, resp.StatusCode, "page is too large", nil
	}
	l, err = decodeList[T](bytes.NewReader(body), kind)
	if err != nil {
		return list[T]{}, resp.StatusCode, "response is not a valid " + kind, err
	}
	return l, resp.StatusCode, "", nil
}

// causeError is the only error type a failed read exposes: a fixed message plus, for the cases
// callers match on, the sentinel it stands for. The raw transport error is dropped, because it can
// hold the request URL (with the continue token) or text the server chose, such as a bad status line.
type causeError struct {
	msg      string
	sentinel error
}

func (e *causeError) Error() string { return e.msg }
func (e *causeError) Unwrap() error { return e.sentinel }

var errRequest = &causeError{msg: "request could not be built"}

var (
	errTimeout   = &causeError{msg: "timeout", sentinel: context.DeadlineExceeded}
	errCanceled  = &causeError{msg: "canceled", sentinel: context.Canceled}
	errDenied    = &causeError{msg: "connection refused by the API address policy", sentinel: netpolicy.ErrDenied}
	errTLS       = &causeError{msg: "TLS certificate verification failed"}
	errConnect   = &causeError{msg: "connection to the API failed"}
	errProtocol  = &causeError{msg: "the API answered with an invalid HTTP response"}
	errTransport = &causeError{msg: "request to the API failed"}
)

// classify maps a transport error to a short reason and a fixed cause. Nothing of the original text
// survives: not the URL, not the status line, not the certificate details.
func classify(err error) (string, error) {
	c := classifyCause(err)
	return c.msg, c
}

func classifyCause(err error) *causeError {
	var (
		cv *tls.CertificateVerificationError
		ne net.Error
		oe *net.OpError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errTimeout
	case errors.Is(err, context.Canceled):
		return errCanceled
	case errors.Is(err, netpolicy.ErrDenied):
		return errDenied
	case errors.As(err, &cv):
		return errTLS
	case errors.As(err, &ne) && ne.Timeout():
		return errTimeout
	case errors.As(err, &oe):
		return errConnect
	case strings.Contains(err.Error(), "malformed HTTP"):
		return errProtocol
	}
	return errTransport
}

// redact keeps the token out of a message even if a lower layer were to echo it.
func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "<redacted>")
}
