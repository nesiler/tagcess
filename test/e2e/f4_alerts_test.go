//go:build integration

package e2e_test

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// F4-036 AC4: the alert lifecycle end to end (run with `make f4-e2e`, same opt-in and fixtures as
// F4-040). The clock is never moved: the 3-second measurement cycle and the typed thresholds do the
// work, and the "source outage" is the probe policy no longer allowing the target address.

const healthKind = "monitor_target_health"

// alertRowView is one row of the alerts screen.
type alertRowView struct {
	state, subject, source, freshness string
	muted, open                       bool
}

var (
	alertTRRE        = regexp.MustCompile(`(?s)<tr data-state="([a-z]+)">(.*?)</tr>`)
	alertSubjectRE   = regexp.MustCompile(`data-subject="([^"]*)"`)
	alertSourceRE    = regexp.MustCompile(`data-source="([^"]*)"`)
	alertFreshnessRE = regexp.MustCompile(`data-freshness="([a-z]+)"`)
)

// alertRowsOf parses the rows of one alert kind. A row with an acknowledge form is open.
func alertRowsOf(body, kind string) []alertRowView {
	var out []alertRowView
	for _, m := range alertTRRE.FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[2], `data-kind="`+kind+`"`) {
			continue
		}
		r := alertRowView{state: m[1], muted: strings.Contains(m[2], `data-muted="1"`), open: strings.Contains(m[2], "/alerts/ack")}
		if s := alertSubjectRE.FindStringSubmatch(m[2]); s != nil {
			r.subject = html.UnescapeString(s[1])
		}
		if s := alertSourceRE.FindStringSubmatch(m[2]); s != nil {
			r.source = html.UnescapeString(s[1])
		}
		if f := alertFreshnessRE.FindStringSubmatch(m[2]); f != nil {
			r.freshness = f[1]
		}
		out = append(out, r)
	}
	return out
}

// onlyAlert returns the single row of the kind; more than one is a failure (one alert per subject).
func (s *f4Stack) onlyAlert(body string) (alertRowView, bool) {
	s.t.Helper()
	rows := alertRowsOf(body, healthKind)
	if len(rows) > 1 {
		s.t.Fatalf("%d health alert rows, want exactly one: %v", len(rows), rows)
	}
	if len(rows) == 0 {
		return alertRowView{}, false
	}
	return rows[0], true
}

// healthAlertRows counts the stored health alerts, open or all.
func (s *f4Stack) healthAlertRows(openOnly bool) int {
	q := `SELECT count(*) FROM alerts WHERE kind = ?`
	if openOnly {
		q += ` AND resolved_at IS NULL`
	}
	return s.proc.queryInt(s.t, q, healthKind)
}

// TestF4_E2E_AlertLifecycleRestartAndDashboardOnly is F4-036 AC4: three failed health checks raise
// one alert; an acknowledgement, a maintenance window, a measurement outage and a restart change how
// it is shown but never resolve it; two successes resolve it; nothing leaves the dashboard.
func TestF4_E2E_AlertLifecycleRestartAndDashboardOnly(t *testing.T) {
	p := newProbeStack(t, map[string]int{"/": http.StatusInternalServerError})

	// 3 failures (monitor.health_fail default 3) -> one critical alert.
	body := p.waitPage("/alerts", "an open critical health alert", func(b string) bool {
		rows := alertRowsOf(b, healthKind)
		return len(rows) == 1 && rows[0].open && strings.Contains(b, "<td>critical</td>")
	})
	row, _ := p.onlyAlert(body)
	if row.state != "active" || row.muted {
		t.Fatalf("a new alert must be active and not muted: %+v", row)
	}
	id := p.proc.queryInt(t, `SELECT id FROM alerts WHERE kind = ? AND resolved_at IS NULL`, healthKind)

	// Acknowledge: read, not recovered.
	code, out := p.ui.post("/alerts/ack", url.Values{"kind": {healthKind}, "subject": {row.subject}, "source": {row.source}})
	if code >= 400 {
		t.Fatalf("acknowledge: status %d: %s", code, excerpt(out))
	}
	body = p.waitPage("/alerts", "the acknowledged alert", func(b string) bool {
		r, ok := p.onlyAlert(b)
		return ok && r.open && r.state == "acknowledged"
	})
	if n := p.healthAlertRows(true); n != 1 {
		t.Errorf("open health alerts after the acknowledgement = %d, want 1 (ack is not a resolution)", n)
	}

	// Maintenance: the alert is shown muted and stays open.
	code, out = p.ui.post("/alerts/maintenance", url.Values{"subject": {row.subject}, "muted": {"1"}})
	if code >= 400 {
		t.Fatalf("maintenance on: status %d: %s", code, excerpt(out))
	}
	p.waitPage("/alerts", "the muted alert", func(b string) bool {
		r, ok := p.onlyAlert(b)
		return ok && r.open && r.muted
	})

	// Source outage: the target address leaves the probe policy, so no new measurement arrives. The
	// alert stays open and its evidence is labelled stale; it is not a recovery.
	p.setProbePolicy("10.254.254.254")
	p.waitPage("/alerts", "the stale label after the measurement outage", func(b string) bool {
		r, ok := p.onlyAlert(b)
		return ok && r.open && r.freshness == "stale"
	})
	if n := p.healthAlertRows(true); n != 1 {
		t.Errorf("open health alerts during the outage = %d, want 1 (an outage does not resolve)", n)
	}

	// Restart: the same row, still acknowledged and muted, still stale; nothing was re-counted.
	p.restart()
	body = p.waitPage("/alerts", "the persisted alert after the restart", func(b string) bool {
		_, ok := p.onlyAlert(b)
		return ok
	})
	row, _ = p.onlyAlert(body)
	if !row.open || !row.muted || row.state != "acknowledged" {
		t.Errorf("after the restart the alert is %+v, want open, acknowledged and muted", row)
	}
	if got := p.proc.queryInt(t, `SELECT id FROM alerts WHERE kind = ? AND resolved_at IS NULL`, healthKind); got != id {
		t.Errorf("the alert id changed across the restart: %d -> %d", id, got)
	}

	// Recovery: the target answers and may be measured again; 2 successes (monitor.health_ok) resolve.
	p.target.setStatus("/", http.StatusOK)
	p.setProbePolicy(p.ip)
	p.waitPage("/alerts", "the resolved alert", func(b string) bool {
		rows := alertRowsOf(b, healthKind)
		return len(rows) == 1 && !rows[0].open
	})
	if n := p.healthAlertRows(false); n != 1 {
		t.Errorf("health alert rows after the recovery = %d, want the one persistent row", n)
	}
	if n := p.healthAlertRows(true); n != 0 {
		t.Errorf("open health alerts after two successes = %d, want 0", n)
	}

	// Dashboard only: no notification channel exists in the audit trail, the logs or the settings.
	if n := p.proc.queryInt(t, `SELECT count(*) FROM audit_events WHERE lower(event) LIKE '%notif%' OR lower(event) LIKE '%mail%' OR lower(event) LIKE '%webhook.out%'`); n != 0 {
		t.Errorf("%d audit events look like an outbound notification", n)
	}
	logs := strings.ToLower(p.proc.stderr.String())
	for _, bad := range []string{"notification", "smtp", "slack", "sendmail"} {
		if strings.Contains(logs, bad) {
			t.Errorf("tagcess logs mention %q: the alerts must stay on the dashboard", bad)
		}
	}
	if code, page := p.ui.get("/monitor/settings"); code != http.StatusOK || strings.Contains(strings.ToLower(page), "smtp") {
		t.Errorf("monitor settings: status %d; a notification setting must not exist", code)
	}
}
