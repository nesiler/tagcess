// Package monitor holds the typed monitoring settings shared by the F4 measurement loops:
// intervals, health/TLS thresholds, check path, expected HTTP statuses, timeout and concurrency.
package monitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Setting keys in the shared settings table (ADR 0030-0032 [K] defaults, R3-AC-17).
const (
	targetIntervalKey    = "monitor.target_interval_seconds"
	inventoryIntervalKey = "monitor.inventory_interval_seconds"
	tlsIntervalKey       = "monitor.tls_interval_seconds"
	healthFailKey        = "monitor.health_fail_threshold"
	healthOKKey          = "monitor.health_success_threshold"
	tlsInfoDaysKey       = "monitor.tls_info_days"
	tlsWarnDaysKey       = "monitor.tls_warn_days"
	tlsCriticalDaysKey   = "monitor.tls_critical_days"
	pathKey              = "monitor.check_path"
	statusesKey          = "monitor.expected_statuses"
	timeoutKey           = "monitor.timeout_seconds"
	concurrencyKey       = "monitor.concurrency"
)

// maxConcurrency bounds the runner's parallel probes; "excessive concurrency" is rejected.
const maxConcurrency = 16

// maxDuration bounds stored durations so a corrupted or absurd value can neither overflow
// time.Duration when multiplied by a second nor configure an effectively infinite interval.
const maxDuration = 30 * 24 * time.Hour

// MaxTimeout is the longest per-probe timeout that has any effect: the probe transport enforces it
// (health.DefaultTimeout is this value), so a larger setting would be stored, audited and shown but
// never applied. [Ö] KISS: the setting is capped here instead of lifting the transport ceiling.
const MaxTimeout = 5 * time.Second

// maxDurationSeconds is maxDuration expressed in the whole seconds the store persists.
const maxDurationSeconds = int(maxDuration / time.Second)

// Settings is the typed monitoring configuration. A zero field is never valid; defaults come
// from DefaultSettings.
type Settings struct {
	TargetInterval      time.Duration
	InventoryInterval   time.Duration
	TLSInterval         time.Duration
	HealthFailThreshold int
	HealthOKThreshold   int
	TLSInfoDays         int
	TLSWarnDays         int
	TLSCriticalDays     int
	Path                string
	ExpectedStatuses    []int
	Timeout             time.Duration
	Concurrency         int
}

// DefaultSettings returns the documented [K] F4 defaults: target 60 sn, inventory 5 dk, TLS 6
// saat, health 3 hata/2 başarı, TLS 30/14/7 gün, path "/", HTTP 200, timeout 5 sn, concurrency 4.
func DefaultSettings() Settings {
	return Settings{
		TargetInterval:      60 * time.Second,
		InventoryInterval:   5 * time.Minute,
		TLSInterval:         6 * time.Hour,
		HealthFailThreshold: 3,
		HealthOKThreshold:   2,
		TLSInfoDays:         30,
		TLSWarnDays:         14,
		TLSCriticalDays:     7,
		Path:                "/",
		ExpectedStatuses:    []int{200},
		Timeout:             5 * time.Second,
		Concurrency:         4,
	}
}

// SettingsStore reads and writes Settings as typed values in the shared settings table. Reads
// always hit the database, so a UI edit applies to the next measurement cycle without a restart.
type SettingsStore struct {
	db *sql.DB
	q  *db.Queries
}

// NewSettingsStore returns the settings store over an open database.
func NewSettingsStore(sqldb *sql.DB, q *db.Queries) *SettingsStore {
	return &SettingsStore{db: sqldb, q: q}
}

// settingKeys is the deterministic read order for every monitoring setting.
var settingKeys = []string{
	targetIntervalKey, inventoryIntervalKey, tlsIntervalKey,
	healthFailKey, healthOKKey, tlsInfoDaysKey, tlsWarnDaysKey, tlsCriticalDaysKey,
	pathKey, statusesKey, timeoutKey, concurrencyKey,
}

// settingParsers converts one stored string into its typed field, or returns a field error.
var settingParsers = map[string]func(*Settings, string) error{
	targetIntervalKey: func(out *Settings, v string) error {
		d, err := parseDurationSeconds(targetIntervalKey, v)
		if err != nil {
			return err
		}
		out.TargetInterval = d
		return nil
	},
	inventoryIntervalKey: func(out *Settings, v string) error {
		d, err := parseDurationSeconds(inventoryIntervalKey, v)
		if err != nil {
			return err
		}
		out.InventoryInterval = d
		return nil
	},
	tlsIntervalKey: func(out *Settings, v string) error {
		d, err := parseDurationSeconds(tlsIntervalKey, v)
		if err != nil {
			return err
		}
		out.TLSInterval = d
		return nil
	},
	healthFailKey: func(out *Settings, v string) error {
		n, err := parsePositiveInt(healthFailKey, v)
		if err != nil {
			return err
		}
		out.HealthFailThreshold = n
		return nil
	},
	healthOKKey: func(out *Settings, v string) error {
		n, err := parsePositiveInt(healthOKKey, v)
		if err != nil {
			return err
		}
		out.HealthOKThreshold = n
		return nil
	},
	tlsInfoDaysKey: func(out *Settings, v string) error {
		n, err := parsePositiveInt(tlsInfoDaysKey, v)
		if err != nil {
			return err
		}
		out.TLSInfoDays = n
		return nil
	},
	tlsWarnDaysKey: func(out *Settings, v string) error {
		n, err := parsePositiveInt(tlsWarnDaysKey, v)
		if err != nil {
			return err
		}
		out.TLSWarnDays = n
		return nil
	},
	tlsCriticalDaysKey: func(out *Settings, v string) error {
		n, err := parsePositiveInt(tlsCriticalDaysKey, v)
		if err != nil {
			return err
		}
		out.TLSCriticalDays = n
		return nil
	},
	pathKey: func(out *Settings, v string) error {
		if err := validatePath(v); err != nil {
			return fmt.Errorf("monitor: setting %s = %q: %w", pathKey, v, err)
		}
		out.Path = v
		return nil
	},
	statusesKey: func(out *Settings, v string) error {
		list, err := parseStatuses(v)
		if err != nil {
			return fmt.Errorf("monitor: setting %s = %q: %w", statusesKey, v, err)
		}
		out.ExpectedStatuses = list
		return nil
	},
	timeoutKey: func(out *Settings, v string) error {
		d, err := parseDurationSeconds(timeoutKey, v)
		if err != nil {
			return err
		}
		out.Timeout = d
		return nil
	},
	concurrencyKey: func(out *Settings, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > maxConcurrency {
			return fmt.Errorf("monitor: setting %s = %q: want a concurrency between 1 and %d", concurrencyKey, v, maxConcurrency)
		}
		out.Concurrency = n
		return nil
	},
}

// Get reads all settings in one query (a consistent snapshot, never a torn mix of old and new
// values), falls back to the documented defaults for unset keys and validates the merged result
// again so cross-field rules still hold on read. Invalid stored values and database errors are
// returned (fail safe: never silently reset to defaults).
func (s *SettingsStore) Get(ctx context.Context) (Settings, error) {
	rows, err := s.q.ListSettings(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("monitor: list settings: %w", err)
	}
	stored := make(map[string]string, len(rows))
	for _, r := range rows {
		stored[r.Key] = r.Value
	}
	out := DefaultSettings()
	for _, key := range settingKeys {
		v, ok := stored[key]
		if !ok {
			continue // unset: keep the documented default
		}
		if perr := settingParsers[key](&out, v); perr != nil {
			return Settings{}, perr
		}
	}
	if err := Validate(out); err != nil {
		return Settings{}, err
	}
	return out, nil
}

// Set validates the whole struct, then writes every key in one transaction; any failure leaves
// the previous settings untouched.
func (s *SettingsStore) Set(ctx context.Context, in Settings) error {
	if err := Validate(in); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("monitor: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op once Commit has succeeded
	q := s.q.WithTx(tx)
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	values := map[string]string{
		targetIntervalKey:    strconv.Itoa(int(in.TargetInterval / time.Second)),
		inventoryIntervalKey: strconv.Itoa(int(in.InventoryInterval / time.Second)),
		tlsIntervalKey:       strconv.Itoa(int(in.TLSInterval / time.Second)),
		healthFailKey:        strconv.Itoa(in.HealthFailThreshold),
		healthOKKey:          strconv.Itoa(in.HealthOKThreshold),
		tlsInfoDaysKey:       strconv.Itoa(in.TLSInfoDays),
		tlsWarnDaysKey:       strconv.Itoa(in.TLSWarnDays),
		tlsCriticalDaysKey:   strconv.Itoa(in.TLSCriticalDays),
		pathKey:              in.Path,
		statusesKey:          joinStatuses(in.ExpectedStatuses),
		timeoutKey:           strconv.Itoa(int(in.Timeout / time.Second)),
		concurrencyKey:       strconv.Itoa(in.Concurrency),
	}
	for _, key := range sortedKeys(values) {
		if err := q.UpsertSetting(ctx, db.UpsertSettingParams{Key: key, Value: values[key], UpdatedAt: now}); err != nil {
			return fmt.Errorf("monitor: write %s: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("monitor: commit: %w", err)
	}
	return nil
}

// Validate reports all field problems; a Settings value is only stored (and trusted on read) when
// fully valid. Durations are persisted as whole seconds, so sub-second or overflowing values are
// rejected here before they could round down to zero.
func Validate(s Settings) error {
	var errs []error
	check := func(cond bool, format string, args ...any) {
		if !cond {
			errs = append(errs, fmt.Errorf("monitor: "+format, args...))
		}
	}
	checkWholeSeconds := func(name string, d time.Duration) {
		check(d >= time.Second && d <= maxDuration && d%time.Second == 0,
			"%s must be a whole number of seconds between 1 and %d, got %s", name, maxDurationSeconds, d)
	}
	checkWholeSeconds("target_interval", s.TargetInterval)
	checkWholeSeconds("inventory_interval", s.InventoryInterval)
	checkWholeSeconds("tls_interval", s.TLSInterval)
	checkWholeSeconds("timeout", s.Timeout)
	check(s.Timeout <= MaxTimeout, "timeout must be at most %s (the probe time limit), got %s", MaxTimeout, s.Timeout)
	check(s.Timeout < s.TargetInterval, "timeout must be shorter than the check interval, got %s", s.Timeout)
	check(s.HealthFailThreshold > 0, "health_fail_threshold must be positive, got %d", s.HealthFailThreshold)
	check(s.HealthOKThreshold > 0, "health_ok_threshold must be positive, got %d", s.HealthOKThreshold)
	check(s.TLSInfoDays > s.TLSWarnDays && s.TLSWarnDays > s.TLSCriticalDays && s.TLSCriticalDays > 0,
		"tls thresholds must be positive and strictly decreasing info > warn > critical, got %d/%d/%d",
		s.TLSInfoDays, s.TLSWarnDays, s.TLSCriticalDays)
	if err := validatePath(s.Path); err != nil {
		errs = append(errs, err)
	}
	if len(s.ExpectedStatuses) == 0 {
		errs = append(errs, errors.New("monitor: expected_statuses must not be empty"))
	}
	for _, code := range s.ExpectedStatuses {
		check(code >= 100 && code <= 599, "expected status %d is not a valid HTTP code (100-599)", code)
	}
	check(s.Concurrency >= 1 && s.Concurrency <= maxConcurrency,
		"concurrency must be between 1 and %d, got %d", maxConcurrency, s.Concurrency)
	return errors.Join(errs...)
}

// validatePath accepts only absolute paths on the target itself: no scheme, host,
// protocol-relative prefix, traversal (including percent-encoded dot segments), query, fragment,
// backslash, whitespace or control characters.
func validatePath(p string) error {
	switch {
	case p == "":
		return errors.New("monitor: path must not be empty")
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return fmt.Errorf("monitor: path %q must be an absolute path on the target", p)
	case strings.Contains(p, "://") || strings.ContainsAny(p, "\\?#"):
		return fmt.Errorf("monitor: path %q must not contain a scheme, query or fragment", p)
	}
	for _, r := range p {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("monitor: path %q must not contain whitespace or control characters", p)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return fmt.Errorf("monitor: path %q contains invalid percent-encoding", p)
		}
		if decoded == "." || decoded == ".." {
			return fmt.Errorf("monitor: path %q must not contain dot-segments", p)
		}
		for _, r := range decoded {
			if r < ' ' || r == 0x7f {
				return fmt.Errorf("monitor: path %q must not contain control characters", p)
			}
		}
	}
	return nil
}

func parseDurationSeconds(key, v string) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 || n > maxDurationSeconds {
		return 0, fmt.Errorf("monitor: setting %s = %q: want a whole number of seconds between 1 and %d", key, v, maxDurationSeconds)
	}
	return time.Duration(n) * time.Second, nil
}

func parsePositiveInt(key, v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 {
		return 0, fmt.Errorf("monitor: setting %s = %q: want a positive integer", key, v)
	}
	return n, nil
}

func joinStatuses(list []int) string {
	parts := make([]string, len(list))
	for i, code := range list {
		parts[i] = strconv.Itoa(code)
	}
	return strings.Join(parts, ",")
}

func parseStatuses(v string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("want HTTP status codes between 100 and 599, got %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("want at least one HTTP status code")
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic write order
	return keys
}
