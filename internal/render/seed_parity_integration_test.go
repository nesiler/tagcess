//go:build integration

// Integration tests for F2-007 against the pinned Caddy (v2.8.4, the image of the local compose
// stack). They only need Docker: `go test -tags=integration ./internal/render/ -run TestSiteSeed`.
package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/site"
)

const parityCaddyImage = "caddy:2.8.4"

// dockerAdapt runs `caddy adapt` in the pinned image. Caddy's warnings go to stderr and are not
// part of the JSON.
func dockerAdapt(ctx context.Context, caddyfile string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", parityCaddyImage,
		"caddy", "adapt", "--adapter", "caddyfile", "--config", "/dev/stdin")
	cmd.Stdin = strings.NewReader(caddyfile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("caddy adapt: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// TestSiteSeed_AdaptJSONParity is AC2: today's 21 blocks and the 21 blocks generated from the
// seed adapt to the same JSON once multi-host lists are sorted; the tagcess block is left out.
func TestSiteSeed_AdaptJSONParity(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 22 {
		t.Fatalf("seeded %d sites, want 21 + tagcess", len(sites))
	}
	current := readFixture(t, seedCurrentCaddyfile)
	if err := CheckSeedParity(ctx, dockerAdapt, current, sites, seedParityCfg()); err != nil {
		t.Fatalf("seed is not equivalent to today's Caddyfile: %v", err)
	}

	// The tagcess block is really excluded: rendering it into the compared file would differ.
	full, err := RenderCaddyfile(sites, seedParityCfg())
	if err != nil {
		t.Fatalf("RenderCaddyfile: %v", err)
	}
	diff, err := ParityDiff(ctx, dockerAdapt, current, full)
	if err != nil || diff == "" || !strings.Contains(diff, seedTagcessHost) {
		t.Errorf("the full file (with tagcess) should differ by the tagcess block: diff %q, err %v", diff, err)
	}
}

// TestSiteSeed_ParityComparesInstalledTagcessBlock (F6 parity, M6): the installer's caddy_ui phase adds the
// tagcess block (deploy/caddy/tagcess.caddy) to today's file before the first import. Once today's file serves
// the tagcess host, the generated tagcess block is compared with it like any other block: the same block is
// equal, a different one is a difference named by the tagcess host.
func TestSiteSeed_ParityComparesInstalledTagcessBlock(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	current := readFixture(t, seedCurrentCaddyfile)
	block := seedTagcessHost + " {\n" + caddyTagcessBody + "}\n"
	if err := CheckSeedParity(ctx, dockerAdapt, current+"\n"+block, sites, seedParityCfg()); err != nil {
		t.Fatalf("today's file with the installed tagcess block: %v", err)
	}
	wider := strings.Replace(block, "allowed_groups=devops", "allowed_groups=devops,developer", 1)
	err = CheckSeedParity(ctx, dockerAdapt, current+"\n"+wider, sites, seedParityCfg())
	var perr *ParityError
	if !errors.As(err, &perr) || !strings.Contains(perr.Diff, "host="+seedTagcessHost) || !strings.Contains(perr.Diff, "developer") {
		t.Fatalf("a different tagcess block in today's file must be a difference named by its host: %v", err)
	}
}

// TestSiteSeed_ParityGateReal is AC3 against real Caddy: a changed record is caught, the diff
// names it, and the closed gate lets the same change through.
func TestSiteSeed_ParityGateReal(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	current := readFixture(t, seedCurrentCaddyfile)
	for i := range sites {
		if sites[i].Hosts[0] == "docs.example.com" {
			sites[i].Roles = []string{"devops"}
		}
	}
	err = GateFirstImport(ctx, s, dockerAdapt, current, sites, seedParityCfg())
	var perr *ParityError
	if !errors.As(err, &perr) {
		t.Fatalf("error = %v, want *ParityError", err)
	}
	if !strings.Contains(perr.Diff, "standart") {
		t.Errorf("the diff does not show the changed role list:\n%s", perr.Diff)
	}
	if err := s.CompleteFirstImport(ctx); err != nil {
		t.Fatalf("CompleteFirstImport: %v", err)
	}
	if err := GateFirstImport(ctx, s, dockerAdapt, current, sites, seedParityCfg()); err != nil {
		t.Errorf("an ordinary edit after the first import was gated: %v", err)
	}
}

// TestSiteSeed_ParityDetectsDrift: the normalization must not hide real differences. Each
// mutation of one seeded record changes the meaning of the generated file and has to be caught.
func TestSiteSeed_ParityDetectsDrift(t *testing.T) {
	ctx := context.Background()
	s := openSeededStore(t)
	base, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	current := readFixture(t, seedCurrentCaddyfile)

	mutations := map[string]func(sites []site.Site) []site.Site{
		"roles reordered": func(ss []site.Site) []site.Site {
			find(ss, "monitor.example.com").Roles = []string{"developer", "devops"}
			return ss
		},
		"role dropped": func(ss []site.Site) []site.Site {
			find(ss, "docs.example.com").Roles = []string{"devops", "developer"}
			return ss
		},
		"api rule removed": func(ss []site.Site) []site.Site {
			find(ss, "errors.example.com").APIRules = find(ss, "errors.example.com").APIRules[:1]
			return ss
		},
		"redirect code changed": func(ss []site.Site) []site.Site {
			find(ss, "projects.example.com").Redirects[0].Code = 301
			return ss
		},
		"certificate swapped": func(ss []site.Site) []site.Site {
			find(ss, "blog.internal.example.org").Cert = "le:example.com"
			return ss
		},
		"site removed": func(ss []site.Site) []site.Site {
			return slices.DeleteFunc(ss, func(st site.Site) bool { return st.Hosts[0] == "sandbox.example.net" })
		},
		"host moved to another block": func(ss []site.Site) []site.Site {
			find(ss, "projects-auth.example.com").Hosts = []string{"projects-auth.example.com"}
			find(ss, "monitor.example.com").Hosts = []string{"monitor.example.com", "storage-api.example.com"}
			return ss
		},
		"role site became open": func(ss []site.Site) []site.Site {
			st := find(ss, "dbmetrics.example.com")
			st.Kind, st.OpenReason, st.Roles = site.KindOpen, site.OpenReasonTransition, []string{}
			return ss
		},
		"headplane switched off": func(ss []site.Site) []site.Site {
			find(ss, "hs.example.com").SystemConfig = `{"headplane":false}`
			return ss
		},
		"wireguard ui switched off": func(ss []site.Site) []site.Site {
			find(ss, "vpn.example.com").SystemConfig = `{"enabled":false}`
			return ss
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			sites := cloneSites(base)
			err := CheckSeedParity(ctx, dockerAdapt, current, mutate(sites), seedParityCfg())
			var perr *ParityError
			if !errors.As(err, &perr) {
				t.Fatalf("error = %v, want *ParityError", err)
			}
			if perr.Diff == "" {
				t.Error("the parity error carries no diff")
			}
		})
	}

	t.Run("zitadel internal sources changed", func(t *testing.T) {
		sites := cloneSites(base)
		find(sites, "auth.example.com").SystemConfig = zitadelConfigWith(seedZitadelSources[:len(seedZitadelSources)-1])
		err := CheckSeedParity(ctx, dockerAdapt, current, sites, seedParityCfg())
		var perr *ParityError
		if !errors.As(err, &perr) {
			t.Fatalf("error = %v, want *ParityError", err)
		}
	})
}

func find(sites []site.Site, host string) *site.Site {
	for i := range sites {
		if sites[i].Hosts[0] == host {
			return &sites[i]
		}
	}
	panic("no site with host " + host)
}

// cloneSites copies the sites deeply enough that a mutation cannot reach the shared base.
func cloneSites(in []site.Site) []site.Site {
	out := make([]site.Site, len(in))
	for i, s := range in {
		s.Hosts = slices.Clone(s.Hosts)
		s.Roles = slices.Clone(s.Roles)
		s.APIRules = slices.Clone(s.APIRules)
		s.Redirects = slices.Clone(s.Redirects)
		out[i] = s
	}
	return out
}

// adoptFixtureDir is the adopt-shaped Caddy fixture of the F6 adopt target (example.test names).
const adoptFixtureDir = "../../test/adopttarget/fixtures/adopt/etc/caddy"

// adoptToday returns the fixture Caddyfile with its `import sites/*.caddy` replaced by the site files, as Caddy
// reads it, so the docker adapt sees every block.
func adoptToday(t *testing.T) string {
	t.Helper()
	main := readFixture(t, adoptFixtureDir+"/Caddyfile")
	files, err := filepath.Glob(filepath.Join(adoptFixtureDir, "sites", "*.caddy"))
	if err != nil || len(files) != 20 {
		t.Fatalf("adopt-target site files: %d, %v (want 20)", len(files), err)
	}
	var b strings.Builder
	for _, f := range files {
		b.WriteString(readFixture(t, f))
		b.WriteString("\n")
	}
	if !strings.Contains(main, "\nimport sites/*.caddy") {
		t.Fatal("the adopt Caddyfile no longer imports sites/*.caddy")
	}
	return strings.Replace(main, "\nimport sites/*.caddy", "\n"+b.String(), 1)
}

// adoptSeedSites loads the adopt seed example the way the CLI and the UI do (adopt preview config).
func adoptSeedSites(t *testing.T) ([]site.Site, CaddyConfig) {
	t.Helper()
	seed, err := os.ReadFile("../../deploy/ansible/examples/seed.example.json")
	if err != nil {
		t.Fatal(err)
	}
	sites, err := site.PrepareSeed(seed, site.SeedOptions{
		TagcessHost: "tagcess.c.example.test",
		ZitadelInternalSources: []string{"10.8.0.0/24", "127.0.0.1/32", "::1/128", "192.0.2.10/32", "2001:db8:10::/64",
			"192.0.2.20/32", "2001:db8:20::/64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sites, CaddyConfig{
		ACMEEmail: "admin@c.example.test", S06Open: true,
		Certs:         []string{"internal.a.example.test", "b.example.test", "c.example.test"},
		ZitadelIssuer: "https://auth.c.example.test", K8sUpstream: "https://100.64.0.5:8443",
	}
}

// TestSeedParity_AdoptShapeS06OpenStart (developer decision 2026-10-07): against the pinned Caddy, the adopt
// fixture and the adopt seed example (20 open sites: 18 transition, 2 intentional vpn_only) differ only by the accepted class, once per site, with
// today's tailnet + free sources; every other block is equal. Changing one record still fails the gate.
func TestSeedParity_AdoptShapeS06OpenStart(t *testing.T) {
	ctx := context.Background()
	today := adoptToday(t)
	sites, cfg := adoptSeedSites(t)
	res, err := SeedParity(ctx, dockerAdapt, today, sites, cfg)
	if err != nil {
		t.Fatalf("adopt shape: %v", err)
	}
	var hosts []string
	for _, a := range res.Accepted {
		if a.Class != AcceptedS06OpenStart || !slices.Contains(a.TodaySources, "100.64.0.0/10") || !slices.Contains(a.TodaySources, "10.8.0.0/24") {
			t.Errorf("accepted %+v", a)
		}
		hosts = append(hosts, a.Hosts...)
	}
	var want []string
	for _, s := range sites {
		if s.Kind == site.KindOpen {
			want = append(want, s.Hosts...)
		}
	}
	slices.Sort(hosts)
	slices.Sort(want)
	if len(want) != 20 || !slices.Equal(hosts, want) {
		t.Fatalf("accepted hosts = %v, want the 20 open sites (18 transition, 2 intentional vpn_only) %v", hosts, want)
	}

	// Negative: one transition site sent elsewhere is a real difference, the others stay accepted.
	moved := cloneSites(sites)
	find(moved, "docs.c.example.test").TargetKind = site.TargetURL
	find(moved, "docs.c.example.test").TargetURL = "https://100.64.0.5:443"
	_, err = SeedParity(ctx, dockerAdapt, today, moved, cfg)
	var perr *ParityError
	if !errors.As(err, &perr) || !strings.Contains(perr.Diff, "docs.c.example.test") || len(perr.Accepted) != 19 {
		t.Fatalf("a changed target must fail and be named (19 others accepted): %v", err)
	}
}

// TestSeedParity_AdoptShapeWithInstalledTagcessBlock: the installer's caddy_ui phase adds deploy/caddy/tagcess.caddy
// (for the adopt host) before the first import; the comparison then includes the generated tagcess block and still
// differs only by the accepted class.
func TestSeedParity_AdoptShapeWithInstalledTagcessBlock(t *testing.T) {
	ctx := context.Background()
	sites, cfg := adoptSeedSites(t)
	block := strings.ReplaceAll(readFixture(t, "../../deploy/caddy/tagcess.caddy"), "tagcess.example.com", "tagcess.c.example.test")
	res, err := SeedParity(ctx, dockerAdapt, adoptToday(t)+"\n"+block, site.WithTagcess(sites, "tagcess.c.example.test"), cfg)
	if err != nil {
		t.Fatalf("adopt shape with the installed tagcess block: %v", err)
	}
	if len(res.Accepted) != 20 {
		t.Fatalf("accepted %d sites, want 20", len(res.Accepted))
	}
}
