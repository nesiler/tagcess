package health

import (
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

func TestObservationFreshness(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(-d).Format(TimeFormat) }
	interval := time.Minute
	tests := []struct {
		name string
		row  db.Observation
		want string
	}{
		{"fresh success", db.Observation{Success: 1, LastAttemptAt: at(30 * time.Second)}, RowFresh},
		{"exactly two intervals", db.Observation{Success: 1, LastAttemptAt: at(2 * time.Minute)}, RowFresh},
		{"older than two intervals", db.Observation{Success: 1, LastAttemptAt: at(2*time.Minute + time.Second)}, RowStale},
		{"failed attempt is never fresh", db.Observation{Success: 0, LastAttemptAt: at(time.Second)}, RowStale},
		{"no attempt time", db.Observation{Success: 1}, RowStale},
		{"unreadable attempt time", db.Observation{Success: 1, LastAttemptAt: "yesterday"}, RowStale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ObservationFreshness(tc.row, now, interval); got != tc.want {
				t.Fatalf("ObservationFreshness = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestObservationIntervalPicksTLSIntervalForTLS(t *testing.T) {
	s := monitor.DefaultSettings()
	if got := ObservationInterval("tls", s); got != s.TLSInterval {
		t.Fatalf("tls interval = %v, want %v", got, s.TLSInterval)
	}
	for _, c := range []string{"target", "caddy_gate"} {
		if got := ObservationInterval(c, s); got != s.TargetInterval {
			t.Fatalf("%s interval = %v, want %v", c, got, s.TargetInterval)
		}
	}
}

func TestNewestPerSubjectKeepsTheLatestAttemptOfEachProbeKey(t *testing.T) {
	old := db.Observation{ID: 1, Category: "target", Site: "s", Host: "a.test", Path: "/", LastAttemptAt: "2026-10-05T10:00:00.000Z", Success: 1}
	cur := db.Observation{ID: 2, Category: "target", Site: "s", Host: "a.test", Path: "/healthz", LastAttemptAt: "2026-10-05T11:00:00.000Z"}
	gate := db.Observation{ID: 3, Category: "caddy_gate", Site: "s", Host: "a.test", LastAttemptAt: "2026-10-05T09:00:00.000Z"}
	risk1 := db.Observation{ID: 4, Category: "config_risk", Site: "s", Host: "a.test", Route: "r1"}
	risk2 := db.Observation{ID: 5, Category: "config_risk", Site: "s", Host: "a.test", Route: "r2"}
	got := NewestPerSubject([]db.Observation{old, cur, gate, risk1, risk2})
	ids := []int64{}
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	want := []int64{2, 3, 4, 5}
	if len(ids) != len(want) {
		t.Fatalf("kept ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("kept ids = %v, want %v", ids, want)
		}
	}
}

func TestFailureTextCoversTheRunnerLabels(t *testing.T) {
	for _, l := range []string{"unexpected_status", "timeout", "unreachable", "tls_unverified", "guard_rejected", "source_error"} {
		if text, ok := FailureText(l); !ok || text == "" {
			t.Errorf("FailureText(%q) = %q, %v", l, text, ok)
		}
	}
	if _, ok := FailureText("ok"); ok {
		t.Error("ok is not a failure label")
	}
}
