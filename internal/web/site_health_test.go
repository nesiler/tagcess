package web

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// Item 6: the site list health is one plain state from the stored checks: healthy only when every
// current check succeeded in time; a failed latest check is a problem; overdue checks are not
// current; no checks or an unreadable store is unknown (never healthy). The time is the latest check.
func TestObservationSiteHealth(t *testing.T) {
	now := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return now.Add(-d).Format(obsTimeFormat) }
	good := func(cat string, age time.Duration) db.Observation {
		return db.Observation{Category: cat, Site: "a.example", Host: "a.example", Source: obsSourceProbe, Success: 1, ObservedAt: ts(age), LastAttemptAt: ts(age)}
	}
	failed := good(obsCategoryGate, time.Minute)
	failed.Success, failed.LastAttemptAt = 0, ts(30*time.Second)
	risk := db.Observation{Category: obsCategoryRisk, Site: "a.example", Host: "a.example", Source: obsSourceConfig, RiskFinding: "unknown"}
	cases := []struct {
		name   string
		rows   []db.Observation
		err    error
		status string
		ok     bool
	}{
		{"healthy", []db.Observation{good(obsCategoryTarget, time.Minute), good(obsCategoryTLS, time.Minute), risk}, nil, siteHealthOK, true},
		{"failed check", []db.Observation{good(obsCategoryTarget, time.Minute), failed}, nil, siteHealthProblem, true},
		{"overdue check", []db.Observation{good(obsCategoryTarget, 48*time.Hour)}, nil, siteHealthStale, true},
		{"risk only", []db.Observation{risk}, nil, "", false},
		{"no checks", nil, nil, "", false},
		{"unreadable", nil, errors.New("db"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ObservationSiteHealth{
				Rows: func(_ context.Context, key string) ([]db.Observation, error) {
					if key != "a.example" {
						t.Errorf("site key = %q", key)
					}
					return tc.rows, tc.err
				},
				Settings: func(context.Context) (monitor.Settings, error) { return monitor.DefaultSettings(), nil },
				Now:      func() time.Time { return now },
			}
			got, ok := r.Health(context.Background(), site.Site{ID: 1, Hosts: []string{"a.example", "b.example"}, Kind: site.KindRole})
			if ok != tc.ok || got.Status != tc.status {
				t.Fatalf("health = %+v, %v; want %q, %v", got, ok, tc.status, tc.ok)
			}
			if ok && got.CheckedAt.IsZero() {
				t.Error("no check time")
			}
		})
	}
	unreadable := ObservationSiteHealth{
		Rows: func(context.Context, string) ([]db.Observation, error) {
			return []db.Observation{good(obsCategoryTarget, time.Minute)}, nil
		},
		Settings: func(context.Context) (monitor.Settings, error) { return monitor.Settings{}, errors.New("settings") },
		Now:      func() time.Time { return now },
	}
	if got, ok := unreadable.Health(context.Background(), site.Site{ID: 1, Hosts: []string{"a.example"}}); ok {
		t.Errorf("unreadable settings gave %+v; want unknown", got)
	}
	off := site.Site{ID: 2, Hosts: []string{"wg.example"}, Kind: site.KindSystem, SystemTemplate: site.TemplateWireGuardUI, SystemConfig: `{"enabled":false}`}
	if got, ok := (ObservationSiteHealth{Rows: func(context.Context, string) ([]db.Observation, error) { return nil, nil }}).Health(context.Background(), off); !ok || got.Status != siteHealthOff {
		t.Errorf("disabled system site = %+v, %v", got, ok)
	}
}
