package health

import (
	"sort"
	"time"

	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/store/db"
)

// This file is the one place that defines how an observation row is judged by its readers (the
// alert bridge and the dashboard): its freshness by age, the subject its alert key uses, the one
// row per subject that counts, and the shared label/time-format vocabulary.

// TimeFormat is the observation store's fixed-width UTC time format; text order is time order.
const TimeFormat = timeFormat

// Observation freshness labels returned by ObservationFreshness.
const (
	RowFresh = "fresh"
	RowStale = "stale"
)

// staleAfterIntervals is how many measurement intervals an attempt may be old before the row stops
// being current (the measurement loop skipped cycles or stopped).
const staleAfterIntervals = 2

// ObservationInterval is the measurement interval that produces the row's category: the TLS
// interval for tls rows, the target interval for every other probe category.
func ObservationInterval(category string, s monitor.Settings) time.Duration {
	if category == "tls" {
		return s.TLSInterval
	}
	return s.TargetInterval
}

// ObservationFreshness is fresh only when the last attempt met its expectation and is not older
// than twice the measurement interval; anything else (a failed attempt, an old attempt, an unreadable
// time) is stale, so a silent measurement loop never keeps a success looking current.
func ObservationFreshness(row db.Observation, now time.Time, interval time.Duration) string {
	if row.Success != 1 || ObservationOverdue(row, now, interval) {
		return RowStale
	}
	return RowFresh
}

// ObservationOverdue reports that the row's last attempt is older than twice the interval, or has no
// readable attempt time.
func ObservationOverdue(row db.Observation, now time.Time, interval time.Duration) bool {
	at, err := time.Parse(TimeFormat, row.LastAttemptAt)
	if err != nil {
		return true
	}
	return now.Sub(at) > staleAfterIntervals*interval
}

// ObservationSubject is the alert subject of a row: its host, or its site when no host is recorded.
func ObservationSubject(row db.Observation) string {
	if row.Host != "" {
		return row.Host
	}
	return row.Site
}

// NewestPerSubject keeps, for the probe categories (target, caddy_gate, tls), only the row with the
// newest last attempt per (category, subject): a row left by a changed path, endpoint, vantage or
// site never counts beside the current one. Other categories pass through unchanged. The order of
// the input is kept.
func NewestPerSubject(rows []db.Observation) []db.Observation {
	type key struct{ category, subject string }
	best := map[key]int{}
	for i, r := range rows {
		if !isProbeCategory(r.Category) {
			continue
		}
		k := key{r.Category, ObservationSubject(r)}
		if j, ok := best[k]; !ok || newerAttempt(r, rows[j]) {
			best[k] = i
		}
	}
	out := make([]db.Observation, 0, len(rows))
	for i, r := range rows {
		if isProbeCategory(r.Category) && best[key{r.Category, ObservationSubject(r)}] != i {
			continue
		}
		out = append(out, r)
	}
	return out
}

func newerAttempt(a, b db.Observation) bool {
	if a.LastAttemptAt != b.LastAttemptAt { // fixed-width UTC text: string order is time order
		return a.LastAttemptAt > b.LastAttemptAt
	}
	return a.ID > b.ID
}

func isProbeCategory(c string) bool { return c == "target" || c == "caddy_gate" || c == "tls" }

// failureLabelText is the fixed last_error of each failure label; probe errors, which can echo
// addresses or response text, are never stored.
var failureLabelText = map[string]string{
	string(KindUnexpectedStatus): "unexpected HTTP status",
	string(KindTimeout):          "no answer within the time limit",
	string(KindUnreachable):      "connection or TLS handshake failed",
	"tls_unverified":             "certificate did not verify",
	"guard_rejected":             "request refused before any connection",
	"source_error":               "probe could not run",
	"redirect_not_followed":      "redirect was not followed",
	"not_measurable":             "not measurable",
	"gate_open":                  "gate kimliksiz isteğe yanıt verdi",
}

// FailureText is the fixed, sanitized text of a failure label; ok is false for a label the runner
// does not know.
func FailureText(label string) (text string, ok bool) {
	text, ok = failureLabelText[label]
	return text, ok
}

// FailureLabels lists every known failure label, sorted. A reader that translates the labels keeps
// its own table complete by comparing with this list.
func FailureLabels() []string {
	out := make([]string, 0, len(failureLabelText))
	for l := range failureLabelText {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}
