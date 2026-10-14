// Package caddy applies rendered Caddyfile artifacts through the Caddy admin API and owns the
// generated Caddyfile on disk (ADR 0005, S-04). The apply order is the one ADR 0005 prescribes:
// /adapt checks the syntax, /load makes Caddy provision the config in isolation (a failure there
// never touches the running config), and only then is the file atomically replaced — so the disk
// never holds a config Caddy could not load on restart. If the file write fails after a
// successful load, the previous content is loaded back and the caller must raise a critical
// alert (S-04.2, rule 7). The apply path also refuses a site set that misses any of the four
// locked system site records, so a broken set can never take the tagcess UI (or Zitadel) offline
// (F2-005 handover, S-05).
package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultAdminAddr is the Caddy admin API address of the production layout
// (architecture.md §6: localhost:2019, loopback only).
const DefaultAdminAddr = "http://localhost:2019"

// adminTimeout bounds one admin API call. /load provisions the whole config;
// seconds are enough for the site counts of this deployment, and a hung Caddy
// must not hang the change pipeline.
const adminTimeout = 30 * time.Second

// errorBodyLimit caps how much of an error response is carried in Go errors.
const errorBodyLimit = 8 << 10

// responseBodyLimit caps what is read from any admin response: an adapted config of the real site
// count is far larger than an error message (AdaptJSON), but must still be bounded.
const responseBodyLimit = 8 << 20

// Client talks to the Caddy admin API. It is safe for concurrent use. Use New.
type Client struct {
	addr string
	hc   *http.Client
}

// NewClient returns a client for the admin API at addr (for example
// DefaultAdminAddr or an httptest server URL).
func NewClient(addr string) *Client {
	return &Client{
		addr: strings.TrimSuffix(addr, "/"),
		hc:   &http.Client{Timeout: adminTimeout},
	}
}

// Adapt sends the Caddyfile to POST /adapt. Caddy only converts and checks the
// syntax there; a config that passes /adapt can still fail /load (CEL and
// path_regexp compile at provisioning), so /adapt alone proves nothing.
func (c *Client) Adapt(ctx context.Context, caddyfile string) error {
	_, err := c.post(ctx, "/adapt", caddyfile)
	return err
}

// AdaptJSON is Adapt that returns the adapted config: Caddy wraps it as
// {"result": ..., "warnings": [...]}, and only the result object is handed back. The first-import
// parity gate (F2-007) compares two adapted files with it. A response without a result is an
// error, so an empty document is never compared.
func (c *Client) AdaptJSON(ctx context.Context, caddyfile string) ([]byte, error) {
	body, err := c.post(ctx, "/adapt", caddyfile)
	if err != nil {
		return nil, err
	}
	var wrapped struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("caddy admin: /adapt: response is not JSON: %w", err)
	}
	if len(wrapped.Result) == 0 || string(wrapped.Result) == "null" {
		return nil, fmt.Errorf("caddy admin: /adapt: response carries no result")
	}
	return wrapped.Result, nil
}

// Load sends the Caddyfile to POST /load. Caddy adapts and provisions the new
// config in an isolated context first: a failure leaves the running config
// untouched and comes back as an error here (ADR 0005).
func (c *Client) Load(ctx context.Context, caddyfile string) error {
	_, err := c.post(ctx, "/load", caddyfile)
	return err
}

// Config reads the live config (GET /config/). It is the read side for drift
// checks and for verifying that an apply really changed (or left) the running
// config.
func (c *Client) Config(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/config/", nil)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: GET /config/: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: GET /config/: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin: GET /config/: %s", adminError(resp.StatusCode, body))
	}
	return body, nil
}

// post uploads the Caddyfile to one admin endpoint and reports the response
// body (limited) on success, an adminError-shaped error otherwise.
func (c *Client) post(ctx context.Context, path, caddyfile string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+path, strings.NewReader(caddyfile))
	if err != nil {
		return nil, fmt.Errorf("caddy admin: %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: %s: read response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin: %s: %s", path, adminError(resp.StatusCode, body))
	}
	return body, nil
}

// readBody reads a response up to responseBodyLimit. A longer body is an error, not a shortened
// document: the readers compare whole configs, and a silent cut would hide what lies past it.
func readBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, responseBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > responseBodyLimit {
		return nil, fmt.Errorf("response is longer than %d bytes", responseBodyLimit)
	}
	return body, nil
}

// adminError renders a non-2xx admin API response: Caddy reports load/adapt
// failures either as {"error":"..."} JSON or as a plain-text body.
func adminError(status int, body []byte) string {
	var j struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &j); err == nil && j.Error != "" {
		return j.Error
	}
	if len(body) > errorBodyLimit {
		body = body[:errorBodyLimit]
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return http.StatusText(status)
	}
	return msg
}
