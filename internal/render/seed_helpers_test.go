package render

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
)

// The G-01 first-import inputs (F2-007): today's Caddyfile with the secrets and server
// addresses replaced by placeholders, and the seed that is meant to reproduce it.
const (
	seedCurrentCaddyfile = "../../test/fixtures/caddyfile-current.caddy"
	seedSitesFile        = "../../test/fixtures/seed-sites.json"
	seedExtraRecords     = "../../test/fixtures/extra-records-current.json"
	seedTagcessHost      = "tagcess.example.com"
)

// seedZitadelSources is the internal source list the first-import fixture lists after the tailnet
// range; like the tagcess host it is a setting the seed loader fills, not seed content (F2-013).
var seedZitadelSources = []string{
	"198.51.100.0/24", "127.0.0.1/32", "::1/128",
	"192.0.2.10/32", "2001:db8:10::/64", "192.0.2.20/32", "2001:db8:20::/64",
}

type staticRoleSource []string

func (s staticRoleSource) ListRoles(context.Context) ([]string, error) { return s, nil }

// seedParityCfg is the render config of the first import: the placeholder ACME email of the
// fixture. The zitadel internal sources live on the seeded record now (F2-013).
func seedParityCfg() CaddyConfig {
	return CaddyConfig{
		ACMEEmail: "admin@example.invalid",
		S06Open:   true,
	}
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// openSeededStore loads the seed fixture into a fresh store and returns the store.
func openSeededStore(t *testing.T) *site.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: []string{"example.com", "internal.example.org", "example.net"},
		AllowedTargets: []string{"100.64.0.5"},
	}, staticRoleSource{"devops", "developer", "standart"})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	s, err := site.New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}
	if _, err := s.LoadSeed(ctx, []byte(readFixture(t, seedSitesFile)), site.SeedOptions{
		TagcessHost:            seedTagcessHost,
		ZitadelInternalSources: seedZitadelSources,
	}); err != nil {
		t.Fatalf("LoadSeed: %v", err)
	}
	return s
}

// compareGolden compares got with testdata/<name>; -update rewrites the file.
func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGoldens {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the render\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
