package site

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// openAllowlist opens a fresh database with both the allowlist store and the site store over it.
func openAllowlist(t *testing.T) (*AllowedTargets, *Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(st.DB(), st.Queries(), newTestValidator(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewAllowedTargets(st.DB(), st.Queries()), s
}

// urlRoleSite is a role-controlled site with a url target, used to prove the allowlist cannot drop
// a host some stored site still uses.
func urlRoleSite(host string) Site {
	s := validRoleSite()
	s.Hosts = []string{"svc.example.com"}
	s.TargetKind = TargetURL
	s.TargetURL = "http://" + host + ":8080"
	return s
}

// AC5: the config seeds the setting only when it is missing; after that the stored list is the
// source of truth and can be replaced from the interface.
func TestAllowedTargets_SeedAndSet(t *testing.T) {
	ctx := context.Background()
	targets, _ := openAllowlist(t)

	if _, err := targets.ListTargets(ctx); err == nil {
		t.Fatal("ListTargets succeeded before the setting existed")
	}
	if err := targets.SeedIfMissing(ctx, []string{"100.64.0.5"}); err != nil {
		t.Fatalf("SeedIfMissing: %v", err)
	}
	got, err := targets.ListTargets(ctx)
	if err != nil || len(got) != 1 || got[0] != "100.64.0.5" {
		t.Fatalf("ListTargets = %v, %v, want [100.64.0.5]", got, err)
	}

	// A second seed must not overwrite an edited value.
	if err := targets.SeedIfMissing(ctx, []string{"10.9.9.9"}); err != nil {
		t.Fatalf("second SeedIfMissing: %v", err)
	}
	if got, _ := targets.ListTargets(ctx); len(got) != 1 || got[0] != "100.64.0.5" {
		t.Errorf("a re-seed overwrote the stored list: %v", got)
	}

	if err := targets.Set(ctx, []string{"100.64.0.5", "10.0.0.7"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, _ := targets.ListTargets(ctx); len(got) != 2 || got[1] != "10.0.0.7" {
		t.Errorf("ListTargets = %v, want the new list", got)
	}
}

// AC5: dropping a host that a stored url target still uses is refused; the stored list and the
// site are untouched.
func TestAllowedTargets_RejectsUsedHost(t *testing.T) {
	ctx := context.Background()
	targets, sites := openAllowlist(t)

	if err := targets.SeedIfMissing(ctx, []string{"100.64.0.5", "10.0.0.7"}); err != nil {
		t.Fatalf("SeedIfMissing: %v", err)
	}
	if _, err := sites.CreateSite(ctx, urlRoleSite("100.64.0.5")); err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	err := targets.Set(ctx, []string{"10.0.0.7"})
	if !errors.Is(err, ErrTargetInUse) {
		t.Fatalf("Set = %v, want ErrTargetInUse", err)
	}
	got, _ := targets.ListTargets(ctx)
	if len(got) != 2 {
		t.Errorf("a refused Set changed the list: %v", got)
	}

	// Removing an unused host is allowed.
	if err := targets.Set(ctx, []string{"100.64.0.5"}); err != nil {
		t.Errorf("Set removing an unused host: %v", err)
	}
}

// AC5: the list itself is validated before anything is stored.
func TestAllowedTargets_RejectsInvalidList(t *testing.T) {
	ctx := context.Background()
	targets, _ := openAllowlist(t)
	if err := targets.SeedIfMissing(ctx, []string{"100.64.0.5"}); err != nil {
		t.Fatalf("SeedIfMissing: %v", err)
	}
	for name, list := range map[string][]string{
		"empty":       {},
		"scheme":      {"http://100.64.0.5"},
		"port":        {"100.64.0.5:8080"},
		"wildcard":    {"*.example.com"},
		"duplicate":   {"100.64.0.5", "100.64.0.5"},
		"empty entry": {""},
	} {
		if err := targets.Set(ctx, list); err == nil {
			t.Errorf("%s: Set accepted %v", name, list)
		}
	}
	if got, _ := targets.ListTargets(ctx); len(got) != 1 || got[0] != "100.64.0.5" {
		t.Errorf("a refused Set changed the list: %v", got)
	}
}

// AC5 / fail closed: a stored value that is no longer a valid list is an error, never a pass.
func TestAllowedTargets_ListRejectsCorruptSetting(t *testing.T) {
	ctx := context.Background()
	targets, _ := openAllowlist(t)
	if err := targets.SeedIfMissing(ctx, []string{"100.64.0.5"}); err != nil {
		t.Fatalf("SeedIfMissing: %v", err)
	}
	if err := targets.q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: settingAllowedTargets, Value: `["http://evil"]`, UpdatedAt: "2026-10-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("corrupt setting: %v", err)
	}
	if _, err := targets.ListTargets(ctx); err == nil {
		t.Error("ListTargets accepted a corrupt setting")
	}
}
