package change

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// CaddyFile adapts internal/caddy to SiteCaddy: the Caddyfile path is the file a Caddy restart
// reads, the client talks to the admin API.
type CaddyFile struct {
	client *caddy.Client
	path   string
}

// NewCaddyFile returns the SiteCaddy of the real admin client and Caddyfile path.
func NewCaddyFile(client *caddy.Client, path string) *CaddyFile {
	return &CaddyFile{client: client, path: path}
}

// Current reads the Caddyfile on disk. A missing file is an error, not an empty file: drift cannot
// be judged without it.
func (c *CaddyFile) Current(context.Context) (string, error) {
	b, err := os.ReadFile(c.path) //nolint:gosec // the path comes from the operator's configuration
	if err != nil {
		return "", fmt.Errorf("read Caddyfile: %w", err)
	}
	return string(b), nil
}

// Live reads the running config from the admin API.
func (c *CaddyFile) Live(ctx context.Context) ([]byte, error) { return c.client.Config(ctx) }

// Apply is caddy.Apply on the configured file; the pipeline holds the writer lock.
func (c *CaddyFile) Apply(ctx context.Context, sites []site.Site, target string) error {
	return caddy.Apply(ctx, c.client, c.path, sites, target)
}

// AdaptJSON is the adapter of the first-import parity gate. The text is adapted as the file at the
// configured path: /adapt has no file name, so relative file imports (today's `import sites/*.caddy`)
// are resolved against the Caddyfile's directory first (caddy.AbsImports), never against Caddy's
// working directory, where a glob silently matches nothing.
func (c *CaddyFile) AdaptJSON(ctx context.Context, caddyfile string) ([]byte, error) {
	return c.client.AdaptJSON(ctx, caddy.AbsImports(caddyfile, filepath.Dir(c.path)))
}

// DNSFile adapts internal/dns to SiteDNS: the extra-records file Headscale reads and the resolver
// that verifies the changed names.
type DNSFile struct {
	path     string
	verifier dns.Verifier
}

// NewDNSFile returns the SiteDNS of the records file path and resolver verifier.
func NewDNSFile(path string, verifier dns.Verifier) *DNSFile {
	return &DNSFile{path: path, verifier: verifier}
}

// Current reads the file; a missing file reports exists=false, any other read error is an error.
func (d *DNSFile) Current(context.Context) (string, bool, error) {
	b, err := os.ReadFile(d.path) //nolint:gosec // the path comes from the operator's configuration
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read dns file: %w", err)
	}
	return string(b), true, nil
}

// Apply is dns.Apply: atomic write, then the resolver check of the changed names.
func (d *DNSFile) Apply(_ context.Context, records []dns.Record) ([]dns.Mismatch, error) {
	return dns.Apply(d.path, records, d.verifier)
}

// Restore writes previous content back atomically (the rollback of an add).
func (d *DNSFile) Restore(_ context.Context, content string) error {
	return dns.WriteFileAtomic(d.path, content)
}
