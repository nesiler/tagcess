package monitor

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

// openSettings opens a fresh database with the monitoring settings store over it.
func openSettings(t *testing.T) (*SettingsStore, *store.Store, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tagcess.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewSettingsStore(st.DB(), st.Queries()), st, path
}

func validSettings() Settings {
	return Settings{
		TargetInterval:      30 * time.Second,
		InventoryInterval:   10 * time.Minute,
		TLSInterval:         12 * time.Hour,
		HealthFailThreshold: 5,
		HealthOKThreshold:   3,
		TLSInfoDays:         60,
		TLSWarnDays:         21,
		TLSCriticalDays:     10,
		Path:                "/healthz",
		ExpectedStatuses:    []int{200, 204},
		Timeout:             3 * time.Second,
		Concurrency:         8,
	}
}

// R3-AC-17 / AC1: with no stored settings the typed defaults apply; explicit overrides replace them.
func TestMonitorSettings_DefaultsAndOverrides(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := openSettings(t)

	got, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get on an empty store: %v", err)
	}
	want := DefaultSettings()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get = %+v, want defaults %+v", got, want)
	}
	if want.TargetInterval != 60*time.Second || want.InventoryInterval != 5*time.Minute ||
		want.TLSInterval != 6*time.Hour || want.HealthFailThreshold != 3 || want.HealthOKThreshold != 2 ||
		want.TLSInfoDays != 30 || want.TLSWarnDays != 14 || want.TLSCriticalDays != 7 ||
		want.Path != "/" || want.Timeout != 5*time.Second || want.Concurrency != 4 ||
		len(want.ExpectedStatuses) != 1 || want.ExpectedStatuses[0] != 200 {
		t.Fatalf("DefaultSettings = %+v, want the documented F4 defaults", want)
	}

	custom := validSettings()
	if err := svc.Set(ctx, custom); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err = svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if !reflect.DeepEqual(got, custom) {
		t.Fatalf("Get = %+v, want overrides %+v", got, custom)
	}
}

// AC2: valid values persist and the next getter read (no restart, same open store, and a
// reopened store) sees them.
func TestMonitoringSettingsPersistAndReload(t *testing.T) {
	ctx := context.Background()
	svc, st, path := openSettings(t)

	custom := validSettings()
	if err := svc.Set(ctx, custom); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := svc.Get(ctx)
	if err != nil || !reflect.DeepEqual(got, custom) {
		t.Fatalf("Get = %+v, %v; want %+v", got, err, custom)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st2.Close() }()
	svc2 := NewSettingsStore(st2.DB(), st2.Queries())
	got, err = svc2.Get(ctx)
	if err != nil || !reflect.DeepEqual(got, custom) {
		t.Fatalf("Get after reopen = %+v, %v; want %+v", got, err, custom)
	}
}

// AC3: invalid values are rejected with a field error and the previous settings survive.
func TestMonitoringSettingsRejectInvalidValuesAtomically(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := openSettings(t)

	// A valid write must stick first so we can prove it survives the failed writes.
	custom := validSettings()
	if err := svc.Set(ctx, custom); err != nil {
		t.Fatalf("Set valid: %v", err)
	}

	cases := []struct {
		name   string
		field  string
		mutate func(*Settings)
	}{
		{"zero target interval", "target_interval", func(s *Settings) { s.TargetInterval = 0 }},
		{"sub-second target interval", "target_interval", func(s *Settings) { s.TargetInterval = 500 * time.Millisecond }},
		{"negative inventory", "inventory_interval", func(s *Settings) { s.InventoryInterval = -time.Minute }},
		{"zero TLS interval", "tls_interval", func(s *Settings) { s.TLSInterval = 0 }},
		{"zero timeout", "timeout", func(s *Settings) { s.Timeout = 0 }},
		{"negative timeout", "timeout", func(s *Settings) { s.Timeout = -5 * time.Second }},
		{"non-whole-second timeout", "timeout", func(s *Settings) { s.Timeout = 1500 * time.Millisecond }},
		{"timeout above the probe limit", "timeout", func(s *Settings) { s.Timeout = 6 * time.Second }},
		{"timeout far above the probe limit", "timeout", func(s *Settings) { s.Timeout = 3600 * time.Second }},
		{"timeout not below the target interval", "timeout", func(s *Settings) { s.TargetInterval, s.Timeout = 3*time.Second, 3*time.Second }},
		{"reversed TLS thresholds", "tls thresholds", func(s *Settings) { s.TLSInfoDays, s.TLSWarnDays = s.TLSWarnDays, s.TLSInfoDays }},
		{"equal TLS thresholds", "tls thresholds", func(s *Settings) { s.TLSWarnDays = s.TLSCriticalDays }},
		{"zero TLS days", "tls thresholds", func(s *Settings) { s.TLSInfoDays = 0 }},
		{"zero health fail", "health_fail_threshold", func(s *Settings) { s.HealthFailThreshold = 0 }},
		{"negative health OK", "health_ok_threshold", func(s *Settings) { s.HealthOKThreshold = -2 }},
		{"unsafe path traversal", "path", func(s *Settings) { s.Path = "/../admin" }},
		{"unsafe path encoded traversal", "path", func(s *Settings) { s.Path = "/%2e%2e/admin" }},
		{"unsafe path absolute URL", "path", func(s *Settings) { s.Path = "https://evil.example/x" }},
		{"unsafe path relative", "path", func(s *Settings) { s.Path = "healthz" }},
		{"unsafe path protocol ref", "path", func(s *Settings) { s.Path = "//evil.example" }},
		{"unsafe path query", "path", func(s *Settings) { s.Path = "/x?y=1" }},
		{"unsafe path fragment", "path", func(s *Settings) { s.Path = "/x#f" }},
		{"unsafe path control char", "path", func(s *Settings) { s.Path = "/a\x7f" }},
		{"unsafe path whitespace", "path", func(s *Settings) { s.Path = "/a b" }},
		{"status out of range low", "expected status", func(s *Settings) { s.ExpectedStatuses = []int{99} }},
		{"status out of range high", "expected status", func(s *Settings) { s.ExpectedStatuses = []int{200, 700} }},
		{"empty statuses", "expected_statuses", func(s *Settings) { s.ExpectedStatuses = nil }},
		{"zero concurrency", "concurrency", func(s *Settings) { s.Concurrency = 0 }},
		{"negative concurrency", "concurrency", func(s *Settings) { s.Concurrency = -4 }},
		{"excessive concurrency", "concurrency", func(s *Settings) { s.Concurrency = 1024 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := custom
			tc.mutate(&bad)
			err := svc.Set(ctx, bad)
			if err == nil {
				t.Fatalf("Set(%+v) succeeded, want a field error", bad)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("Set error %q does not name the field %q", err, tc.field)
			}
			got, err := svc.Get(ctx)
			if err != nil {
				t.Fatalf("Get after rejected Set: %v", err)
			}
			if !reflect.DeepEqual(got, custom) {
				t.Fatalf("stored settings changed to %+v after rejected Set, want %+v", got, custom)
			}
		})
	}
}

// POSITIVE CONTROL for validatePath: benign segments that merely contain dots must be accepted,
// so the traversal fix does not over-reject legitimate paths.
func TestMonitoringSettingsAcceptsBenignPaths(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := openSettings(t)

	for _, p := range []string{"/", "/foo..bar", "/v1.2/health", "/a-b_c", "/x%20y"} {
		s := validSettings()
		s.Path = p
		if err := svc.Set(ctx, s); err != nil {
			t.Fatalf("Set with benign path %q: %v", p, err)
		}
		got, err := svc.Get(ctx)
		if err != nil {
			t.Fatalf("Get after benign path %q: %v", p, err)
		}
		if got.Path != p {
			t.Fatalf("Get path = %q, want %q", got.Path, p)
		}
	}
}

// AC4: read/write failures and corrupted stored values surface as errors; neither a silent
// default, a partial write, nor a fresh-success assumption is produced.
func TestMonitoringSettingsReadAndWriteFailure(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := openSettings(t)

	custom := validSettings()
	if err := svc.Set(ctx, custom); err != nil {
		t.Fatalf("Set valid: %v", err)
	}

	// A corrupted persisted value must fail the read, not fall back to defaults.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = 'not-a-duration' WHERE key = 'monitor.target_interval_seconds'`); err != nil {
		t.Fatalf("corrupt value: %v", err)
	}
	if _, err := svc.Get(ctx); err == nil || !strings.Contains(err.Error(), "monitor.target_interval_seconds") {
		t.Fatalf("Get with a corrupted value = %v, want a visible error naming the key", err)
	}
	// Fix the corruption and prove reads recover to the stored (previous) value.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = '30' WHERE key = 'monitor.target_interval_seconds'`); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if got, err := svc.Get(ctx); err != nil || got.TargetInterval != 30*time.Second {
		t.Fatalf("Get after repair = %v, %v; want 30s", got.TargetInterval, err)
	}

	// Cross-field rules must hold on read, not only at write time: a stored value that is a
	// valid positive integer on its own but breaks info > warn > critical must fail Get.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = '70' WHERE key = 'monitor.tls_warn_days'`); err != nil {
		t.Fatalf("corrupt warn threshold: %v", err)
	}
	if _, err := svc.Get(ctx); err == nil || !strings.Contains(err.Error(), "tls thresholds") {
		t.Fatalf("Get with reversed stored thresholds = %v, want an error naming the TLS thresholds", err)
	}
	// An absurd seconds value must fail the read instead of overflowing time.Duration.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = '9223372036854775807' WHERE key = 'monitor.timeout_seconds'`); err != nil {
		t.Fatalf("corrupt timeout: %v", err)
	}
	if _, err := svc.Get(ctx); err == nil || !strings.Contains(err.Error(), "monitor.timeout_seconds") {
		t.Fatalf("Get with an overflowing stored duration = %v, want an error naming the key", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = '21' WHERE key = 'monitor.tls_warn_days'`); err != nil {
		t.Fatalf("repair warn threshold: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE settings SET value = '3' WHERE key = 'monitor.timeout_seconds'`); err != nil {
		t.Fatalf("repair timeout: %v", err)
	}

	// A failure in the middle of the Set transaction must roll back entirely, leaving no torn
	// mix of new and previous values. A SQLite trigger aborts one key's UPDATE.
	if _, err := st.DB().ExecContext(ctx,
		`CREATE TRIGGER fail_warn BEFORE UPDATE ON settings
		 WHEN NEW.key = 'monitor.tls_warn_days'
		 BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	newer := validSettings()
	newer.TargetInterval = 45 * time.Second
	newer.TLSWarnDays = 20
	if err := svc.Set(ctx, newer); err == nil {
		t.Fatal("Set with an aborted key succeeded, want a visible error")
	}
	got, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get after failed Set: %v", err)
	}
	if !reflect.DeepEqual(got, custom) {
		t.Fatalf("partial write: got %+v, want the previous settings %+v", got, custom)
	}
	// Positive control: the same Set succeeds once the injected failure is gone.
	if _, err := st.DB().ExecContext(ctx, `DROP TRIGGER fail_warn`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if err := svc.Set(ctx, newer); err != nil {
		t.Fatalf("Set after dropping the trigger: %v", err)
	}
	if got, err := svc.Get(ctx); err != nil || !reflect.DeepEqual(got, newer) {
		t.Fatalf("Get after successful Set = %+v, %v; want %+v", got, err, newer)
	}

	// A closed database makes both reads and writes fail visibly.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := svc.Get(ctx); err == nil {
		t.Fatal("Get on a closed database succeeded, want an error")
	}
	if err := svc.Set(ctx, custom); err == nil {
		t.Fatal("Set on a closed database succeeded, want an error")
	}
}
