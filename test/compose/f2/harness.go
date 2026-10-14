// Package f2 is the shared fixture for tagcess's F2 integration tests. It opens a throwaway
// workspace for the generated Caddyfile, MagicDNS records file and site data, and gives tests a
// read-only view of the shared lab Zitadel records. It runs against the local compose stack
// (Caddy v2.8.4, Headscale, oauth2-proxy) and the lab Zitadel (ADR 0014); Zitadel is never local.
//
// The fixture deliberately does not write to the lab: F2-009 owns the lab redirect-URI write and
// permission probe, F2-010 owns the production merge-verify writer. Cleanup only removes the
// workspace and leaves the lab untouched, which TestF2Harness_Cleanup (test/e2e) asserts. The F1-021
// e2e harness in test/e2e is a separate, heavier fixture (real tagcess binary + disposable
// Headscale); F2 tests that need a site store build it in this workspace.
package f2

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	applicationv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"

	"github.com/nesiler/tagcess/test/compose/seed"
	"github.com/nesiler/tagcess/test/labenv"
)

// The images the local compose stack pins (F1-020/025, .agents/skills/stack-notes). AC1 fails if a
// running service drifts from them, so a version bump in compose.yaml must be mirrored here.
const (
	CaddyImage       = "caddy:2.8.4"
	HeadscaleImage   = "headscale/headscale:0.29.4"
	OAuth2ProxyImage = "quay.io/oauth2-proxy/oauth2-proxy:v7.15.4"
)

// DefaultLabHost is where Zitadel runs for the tests (ADR 0014, test/lab/lib.sh LAB_HOST, resolved by labenv). AC1 pins
// the resolved host to it; TAGCESS_ZITADEL_ADDR only helps while developing against another lab and
// then AC1's host assertion has to be updated with it.
var DefaultLabHost = labenv.ZitadelHost()

// Fixture is one F2 test's isolated workspace plus a read-only handle on the lab.
type Fixture struct {
	t          *testing.T
	dir        string
	composeDir string
	ep         seed.Endpoint
	conn       *grpc.ClientConn
	apps       applicationv2.ApplicationServiceClient
	adminCtx   context.Context
	projID     string
	cleaned    bool
}

// New resolves the lab, opens the fixture's gRPC client and creates a throwaway workspace. The
// workspace is removed and the client closed when the test ends, even if the test forgot to call
// Cleanup; Cleanup itself is idempotent.
func New(t *testing.T) *Fixture {
	t.Helper()
	composeDir, err := composeDir()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := seed.EndpointFromEnv(composeDir)
	if err != nil {
		t.Fatalf("resolve zitadel endpoint: %v", err)
	}
	pat, err := os.ReadFile(ep.PATFile)
	if err != nil {
		t.Fatalf("read bootstrap PAT (is `make lab-up` done?): %v", err)
	}
	dir, err := os.MkdirTemp("", "tagcess-f2-")
	if err != nil {
		t.Fatalf("create fixture workspace: %v", err)
	}
	conn, err := grpc.NewClient(ep.Addr, ep.DialOption())
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("dial zitadel: %v", err)
	}
	f := &Fixture{
		t:          t,
		dir:        dir,
		composeDir: composeDir,
		ep:         ep,
		conn:       conn,
		apps:       applicationv2.NewApplicationServiceClient(conn),
		adminCtx:   metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+strings.TrimSpace(string(pat))),
	}
	t.Cleanup(func() {
		f.Cleanup()
		_ = f.conn.Close()
	})
	return f
}

// composeDir locates test/compose from this source file, independent of the test's working
// directory, so both test/compose/f2 and test/e2e can use the fixture.
func composeDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate the f2 fixture source")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}

// Dir is the throwaway workspace root.
func (f *Fixture) Dir() string { return f.dir }

// HTTPS reports whether the resolved Zitadel endpoint speaks TLS.
func (f *Fixture) HTTPS() bool { return f.ep.TLS }

// CaddyfilePath is where a test writes its generated Caddyfile.
func (f *Fixture) CaddyfilePath() string { return filepath.Join(f.dir, "Caddyfile") }

// DNSFilePath is where a test writes its generated MagicDNS records file.
func (f *Fixture) DNSFilePath() string { return filepath.Join(f.dir, "extra-records.json") }

// SiteDataPath is the fixture's site store path; F2-002 creates the schema there.
func (f *Fixture) SiteDataPath() string { return filepath.Join(f.dir, "sites.db") }

// WriteArtifacts puts representative Caddy, MagicDNS and site files in the workspace and returns
// their paths. The content is a placeholder: the point is that Cleanup removes whatever a test
// generated, so an F2 test can then write its real output to the same paths.
func (f *Fixture) WriteArtifacts() (caddyfile, dnsFile, siteData string) {
	f.t.Helper()
	caddyfile, dnsFile, siteData = f.CaddyfilePath(), f.DNSFilePath(), f.SiteDataPath()
	f.write(caddyfile, ":8080 {\n\trespond 200\n}\n")
	f.write(dnsFile, "[]\n")
	f.write(siteData, "{\"sites\":[]}\n")
	return caddyfile, dnsFile, siteData
}

func (f *Fixture) write(path, content string) {
	f.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatalf("write %s: %v", path, err)
	}
}

// Cleanup removes the throwaway workspace. It is idempotent, so an explicit call in a test and the
// deferred call from New do not conflict. Nothing in the lab is written, so there is nothing else to
// undo.
func (f *Fixture) Cleanup() {
	if f.cleaned {
		return
	}
	f.cleaned = true
	if err := os.RemoveAll(f.dir); err != nil {
		f.t.Errorf("remove fixture workspace %s: %v", f.dir, err)
	}
}

// SharedAppURIs returns the redirect URIs of a lab OIDC application, read-only. F2-009/F2-010 write
// these lists; the fixture only watches them to prove Cleanup left the shared lab alone. The lab is
// reached over the public internet and intermittently slow, so the lookup retries; every attempt has
// its own timeout so a stalled connection cannot hang the test.
func (f *Fixture) SharedAppURIs(name string) []string {
	f.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(f.adminCtx, 30*time.Second)
		list, err := f.apps.ListApplications(ctx, &applicationv2.ListApplicationsRequest{
			Filters: []*applicationv2.ApplicationSearchFilter{
				{Filter: &applicationv2.ApplicationSearchFilter_ProjectIdFilter{
					ProjectIdFilter: &applicationv2.ProjectIDFilter{ProjectId: f.projectID()},
				}},
				{Filter: &applicationv2.ApplicationSearchFilter_NameFilter{
					NameFilter: &applicationv2.ApplicationNameFilter{Name: name},
				}},
			},
		})
		cancel()
		if err != nil {
			if time.Now().After(deadline) {
				f.t.Fatalf("list applications in the lab: %v", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}
		for _, a := range list.GetApplications() {
			if a.GetName() != name {
				continue
			}
			oidc := a.GetOidcConfiguration()
			if oidc == nil {
				f.t.Fatalf("lab application %q is not OIDC", name)
			}
			uris := make([]string, len(oidc.GetRedirectUris()))
			copy(uris, oidc.GetRedirectUris())
			return uris
		}
		f.t.Fatalf("lab OIDC application %q not found (was `make lab-up` run?)", name)
	}
}

// projectID is the seeded vpn project id, cached in test/compose/.env by the seed tool.
func (f *Fixture) projectID() string {
	f.t.Helper()
	if f.projID != "" {
		return f.projID
	}
	data, err := os.ReadFile(filepath.Join(f.composeDir, ".env"))
	if err != nil {
		f.t.Fatalf("read .env (is `make lab-up` done?): %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == "ZITADEL_PROJECT_ID" && v != "" {
			f.projID = v
			return v
		}
	}
	f.t.Fatal("ZITADEL_PROJECT_ID not found in .env; was `make lab-up` run?")
	return ""
}

// Services are the running compose images and the resolved Zitadel host. AC1 compares them to the
// pinned constants.
type Services struct {
	Caddy       string
	Headscale   string
	OAuth2Proxy string
	ZitadelHost string
}

// Services reports the image each local compose service is running and the resolved Zitadel host.
// It reads the running stack through `docker compose ps` + `docker inspect`, so a stack that is down
// or running a different tag fails AC1 instead of silently matching the yaml file.
func (f *Fixture) Services() Services {
	f.t.Helper()
	return Services{
		Caddy:       f.composeImage("caddy"),
		Headscale:   f.composeImage("headscale"),
		OAuth2Proxy: f.composeImage("oauth2-proxy"),
		ZitadelHost: f.ep.Host,
	}
}

func (f *Fixture) composeImage(service string) string {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	composeFile := filepath.Join(f.composeDir, "compose.yaml")
	//nolint:gosec // fixed docker binary; the args are a compose file path and a known service name, not user input
	out, err := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "-q", service).Output()
	if err != nil {
		f.t.Fatalf("docker compose ps -q %s: %v", service, err)
	}
	container := strings.TrimSpace(string(out))
	if container == "" {
		f.t.Fatalf("compose service %q is not running; run `make lab-up`", service)
	}
	//nolint:gosec // fixed docker binary and format string; the container id came from docker compose
	img, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Config.Image}}", container).Output()
	if err != nil {
		f.t.Fatalf("docker inspect %s: %v", service, err)
	}
	return strings.TrimSpace(string(img))
}
