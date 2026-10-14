package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/nesiler/tagcess/internal/store/db"
)

// openObservationStore opens a migrated store at path; the caller closes it. Reopening the same
// path models a process restart (AC3).
func openObservationStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return s
}

// obsKey is one full measurement key: category and subject (site/host/route) plus source, vantage,
// dialed endpoint, SNI and path. The key is what keeps categories and measurement dimensions apart.
type obsKey struct {
	category, site, host, route, source, vantage, endpoint, sni, path string
}

func (k obsKey) good() db.UpsertObservationGoodParams {
	return db.UpsertObservationGoodParams{
		Category: k.category, Site: k.site, Host: k.host, Route: k.route, Source: k.source,
		Vantage: k.vantage, Endpoint: k.endpoint, Sni: k.sni, Path: k.path,
	}
}

func (k obsKey) failed() db.UpsertObservationFailedParams {
	return db.UpsertObservationFailedParams{
		Category: k.category, Site: k.site, Host: k.host, Route: k.route, Source: k.source,
		Vantage: k.vantage, Endpoint: k.endpoint, Sni: k.sni, Path: k.path,
	}
}

func (k obsKey) get() db.GetObservationByKeyParams {
	return db.GetObservationByKeyParams{
		Category: k.category, Site: k.site, Host: k.host, Route: k.route, Source: k.source,
		Vantage: k.vantage, Endpoint: k.endpoint, Sni: k.sni, Path: k.path,
	}
}

// AC1: target, caddy_gate, tls and config_risk observations for the same site are stored and read
// back as separate rows, each with its own source, vantage and time; a second vantage is its own
// observation and never overwrites the first.
func TestObservationsKeepCategoriesAndEvidenceSeparate(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const site = "site-1"

	// One good observation per category. Each carries source/vantage/endpoint/SNI/path plus the
	// fields that category actually measures; the rest stay zero so cross-contamination is visible.
	target := obsKey{"target", site, "app.example", "/", "probe", "tagcess-host", "10.0.0.1:443", "app.example", "/"}.good()
	target.ObservedAt = "2026-10-04T01:00:00.000Z"
	target.LastAttemptAt = target.ObservedAt
	target.HttpStatus = 200

	gate := obsKey{"caddy_gate", site, "app.example", "/", "caddy", "tagcess-host", "10.0.0.1:8443", "app.example", "/"}.good()
	gate.ObservedAt = "2026-10-04T01:00:01.000Z"
	gate.LastAttemptAt = gate.ObservedAt
	gate.HttpStatus = 302
	gate.GateClass = "login_redirect"

	leaf := obsKey{"tls", site, "app.example", "", "caddy", "tagcess-host", "10.0.0.1:443", "app.example", ""}.good()
	leaf.ObservedAt = "2026-10-04T01:00:02.000Z"
	leaf.LastAttemptAt = leaf.ObservedAt
	leaf.TlsNotAfter = "2027-01-01T00:00:00.000Z"
	leaf.TlsFingerprint = "fp-app"

	risk := obsKey{"config_risk", site, "app.example", "/", "k8s", "cluster", "", "", "/"}.good()
	risk.ObservedAt = "2026-10-04T01:00:03.000Z"
	risk.LastAttemptAt = risk.ObservedAt
	risk.RiskFinding = "alternative_gate"
	risk.RiskContext = "traefik entryPoint web plus direct Service"
	risk.UnscannedScope = "crd,gateway,hostnetwork"

	for _, p := range []db.UpsertObservationGoodParams{target, gate, leaf, risk} {
		if _, err := q.UpsertObservationGood(ctx, p); err != nil {
			t.Fatalf("UpsertObservationGood(%s): %v", p.Category, err)
		}
	}

	rows, err := q.ListObservationsBySite(ctx, site)
	if err != nil {
		t.Fatalf("ListObservationsBySite: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("observations = %d, want the four categories", len(rows))
	}
	byCategory := map[string]db.Observation{}
	for _, r := range rows {
		byCategory[r.Category] = r
		if r.Success != 1 || r.LastResult != "ok" {
			t.Errorf("%s success=%d result=%q, want a good attempt", r.Category, r.Success, r.LastResult)
		}
	}

	if r := byCategory["target"]; r.HttpStatus != 200 || r.GateClass != "" || r.TlsNotAfter != "" || r.RiskFinding != "" {
		t.Errorf("target row leaked another category: %+v", r)
	}
	if r := byCategory["caddy_gate"]; r.GateClass != "login_redirect" || r.HttpStatus != 302 || r.TlsNotAfter != "" {
		t.Errorf("caddy_gate row = %+v", r)
	}
	if r := byCategory["tls"]; r.TlsNotAfter != "2027-01-01T00:00:00.000Z" || r.TlsFingerprint != "fp-app" || r.HttpStatus != 0 || r.GateClass != "" {
		t.Errorf("tls row = %+v", r)
	}
	if r := byCategory["config_risk"]; r.RiskFinding != "alternative_gate" || r.UnscannedScope != "crd,gateway,hostnetwork" || r.HttpStatus != 0 {
		t.Errorf("config_risk row = %+v", r)
	}
	for _, r := range rows {
		if r.ObservedAt == "" {
			t.Errorf("%s has no observed time", r.Category)
		}
	}

	// A second vantage of the same category/site is a separate observation, and it must not touch
	// the first one's evidence.
	targetFirstKey := obsKey{"target", site, "app.example", "/", "probe", "tagcess-host", "10.0.0.1:443", "app.example", "/"}
	targetInternetKey := targetFirstKey
	targetInternetKey.vantage = "internet"
	targetInternet := targetInternetKey.good()
	targetInternet.ObservedAt = "2026-10-04T02:00:00.000Z"
	targetInternet.LastAttemptAt = targetInternet.ObservedAt
	targetInternet.HttpStatus = 503
	if _, err := q.UpsertObservationGood(ctx, targetInternet); err != nil {
		t.Fatalf("UpsertObservationGood(second vantage): %v", err)
	}
	first, err := q.GetObservationByKey(ctx, targetFirstKey.get())
	if err != nil {
		t.Fatalf("GetObservationByKey(first vantage): %v", err)
	}
	if first.HttpStatus != 200 || first.ObservedAt != "2026-10-04T01:00:00.000Z" {
		t.Errorf("second vantage overwrote the first: %+v", first)
	}
	second, err := q.GetObservationByKey(ctx, targetInternetKey.get())
	if err != nil {
		t.Fatalf("GetObservationByKey(second vantage): %v", err)
	}
	if second.HttpStatus != 503 || second.Vantage != "internet" {
		t.Errorf("second vantage = %+v", second)
	}
}

// AC2: a failed measurement or source read keeps the last good observation; the last attempt, its
// error and the derived freshness stay separate from the older success.
func TestObservationsFailedAttemptKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const site = "site-1"
	k := obsKey{"target", site, "app.example", "/", "probe", "tagcess-host", "10.0.0.1:443", "app.example", "/"}

	good := k.good()
	good.ObservedAt = "2026-10-04T01:00:00.000Z"
	good.LastAttemptAt = good.ObservedAt
	good.HttpStatus = 200
	if _, err := q.UpsertObservationGood(ctx, good); err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}

	// A later attempt times out: only the attempt group changes.
	bad := k.failed()
	bad.LastAttemptAt = "2026-10-04T02:00:00.000Z"
	bad.LastResult = "timeout"
	bad.LastError = "dial timeout"
	if _, err := q.UpsertObservationFailed(ctx, bad); err != nil {
		t.Fatalf("UpsertObservationFailed: %v", err)
	}

	got, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	if got.ObservedAt != "2026-10-04T01:00:00.000Z" || got.HttpStatus != 200 {
		t.Errorf("failed attempt changed the last good group: %+v", got)
	}
	if got.LastAttemptAt != "2026-10-04T02:00:00.000Z" || got.Success != 0 || got.LastResult != "timeout" || got.LastError != "dial timeout" {
		t.Errorf("failed attempt not recorded separately: %+v", got)
	}
	// Freshness is derived, not stored: a later failed attempt means the good evidence is stale.
	if got.ObservedAt >= got.LastAttemptAt || got.Success != 0 {
		t.Errorf("freshness not derivable from observed_at=%q last_attempt_at=%q success=%d", got.ObservedAt, got.LastAttemptAt, got.Success)
	}

	// Cold start: the very first attempt fails, so there is a row with no good observation yet.
	cold := obsKey{"tls", site, "new.example", "", "caddy", "tagcess-host", "10.0.0.1:443", "new.example", ""}
	coldFail := cold.failed()
	coldFail.LastAttemptAt = "2026-10-04T02:00:00.000Z"
	coldFail.LastResult = "refused"
	coldFail.LastError = "connection refused"
	coldRow, err := q.UpsertObservationFailed(ctx, coldFail)
	if err != nil {
		t.Fatalf("UpsertObservationFailed(cold): %v", err)
	}
	if coldRow.ObservedAt != "" || coldRow.Success != 0 || coldRow.LastResult != "refused" {
		t.Errorf("cold failed observation = %+v, want no good evidence", coldRow)
	}

	// A later good attempt refreshes both groups and clears the attempt error.
	good2 := k.good()
	good2.ObservedAt = "2026-10-04T03:00:00.000Z"
	good2.LastAttemptAt = good2.ObservedAt
	good2.HttpStatus = 204
	refreshed, err := q.UpsertObservationGood(ctx, good2)
	if err != nil {
		t.Fatalf("UpsertObservationGood(refresh): %v", err)
	}
	if refreshed.ObservedAt != good2.ObservedAt || refreshed.HttpStatus != 204 || refreshed.Success != 1 || refreshed.LastResult != "ok" || refreshed.LastError != "" {
		t.Errorf("refresh = %+v, want both groups updated and the error cleared", refreshed)
	}
}

// AC3: closing and reopening the database preserves observation keys, times and the last-good /
// last-attempt separation.
func TestObservationsPersistAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := testDBPath(t)

	const site = "site-1"
	goodKey := obsKey{"target", site, "app.example", "/", "probe", "tagcess-host", "10.0.0.1:443", "app.example", "/"}
	mixedKey := obsKey{"tls", site, "app.example", "", "caddy", "tagcess-host", "10.0.0.1:443", "app.example", ""}

	s := openObservationStore(t, path)
	good := goodKey.good()
	good.ObservedAt = "2026-10-04T01:00:00.000Z"
	good.LastAttemptAt = good.ObservedAt
	good.HttpStatus = 200
	if _, err := s.Queries().UpsertObservationGood(ctx, good); err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}
	leaf := mixedKey.good()
	leaf.ObservedAt = "2026-10-04T01:00:00.000Z"
	leaf.LastAttemptAt = leaf.ObservedAt
	leaf.TlsNotAfter = "2027-01-01T00:00:00.000Z"
	leaf.TlsFingerprint = "fp-app"
	if _, err := s.Queries().UpsertObservationGood(ctx, leaf); err != nil {
		t.Fatalf("UpsertObservationGood(tls): %v", err)
	}
	fail := mixedKey.failed()
	fail.LastAttemptAt = "2026-10-04T02:00:00.000Z"
	fail.LastResult = "unreachable"
	fail.LastError = "handshake failed"
	if _, err := s.Queries().UpsertObservationFailed(ctx, fail); err != nil {
		t.Fatalf("UpsertObservationFailed(tls): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2 := openObservationStore(t, path)
	t.Cleanup(func() { _ = s2.Close() })
	q := s2.Queries()

	got, err := q.GetObservationByKey(ctx, goodKey.get())
	if err != nil {
		t.Fatalf("GetObservationByKey(good) after restart: %v", err)
	}
	if got.Site != site || got.Host != "app.example" || got.Source != "probe" || got.Vantage != "tagcess-host" ||
		got.Endpoint != "10.0.0.1:443" || got.Sni != "app.example" || got.Path != "/" ||
		got.ObservedAt != "2026-10-04T01:00:00.000Z" || got.HttpStatus != 200 || got.Success != 1 {
		t.Errorf("good observation after restart = %+v", got)
	}

	mixed, err := q.GetObservationByKey(ctx, mixedKey.get())
	if err != nil {
		t.Fatalf("GetObservationByKey(mixed) after restart: %v", err)
	}
	if mixed.ObservedAt != "2026-10-04T01:00:00.000Z" || mixed.TlsFingerprint != "fp-app" {
		t.Errorf("last good TLS evidence lost after restart: %+v", mixed)
	}
	if mixed.LastAttemptAt != "2026-10-04T02:00:00.000Z" || mixed.Success != 0 || mixed.LastResult != "unreachable" || mixed.LastError != "handshake failed" {
		t.Errorf("last attempt lost after restart: %+v", mixed)
	}

	rows, err := q.ListObservationsBySite(ctx, site)
	if err != nil {
		t.Fatalf("ListObservationsBySite after restart: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("observations after restart = %d, want 2", len(rows))
	}
}

// AC4: a verified presented leaf keeps its NotAfter and fingerprint together with the leaf's
// source, SNI and observation time; a later failed/unverifiable read is diagnostic only and never
// makes that evidence fresh.
func TestObservations_LeafEvidenceKeepsSourceAndTime(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const site = "site-1"
	k := obsKey{"tls", site, "app.example", "", "caddy", "tagcess-host", "10.0.0.1:443", "app.example", ""}
	good := k.good()
	good.ObservedAt = "2026-10-04T01:00:00.000Z"
	good.LastAttemptAt = good.ObservedAt
	good.TlsNotAfter = "2027-01-01T00:00:00.000Z"
	good.TlsFingerprint = "fp-verified"
	if _, err := q.UpsertObservationGood(ctx, good); err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}

	// The next read gets an expired/unverifiable diagnostic leaf: the verified evidence must keep
	// its value and time; the expired leaf is readable only from the attempt group.
	diag := k.failed()
	diag.LastAttemptAt = "2026-10-04T02:00:00.000Z"
	diag.LastResult = "tls_unverified"
	diag.LastTlsNotAfter = "2026-09-01T00:00:00.000Z"
	diag.LastTlsFingerprint = "fp-expired"
	diag.LastTlsVerifyError = "expired"
	if _, err := q.UpsertObservationFailed(ctx, diag); err != nil {
		t.Fatalf("UpsertObservationFailed(diagnostic): %v", err)
	}

	got, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	if got.TlsNotAfter != "2027-01-01T00:00:00.000Z" || got.TlsFingerprint != "fp-verified" {
		t.Errorf("failed read refreshed the last verified leaf: %+v", got)
	}
	if got.Source != "caddy" || got.Sni != "app.example" || got.ObservedAt != "2026-10-04T01:00:00.000Z" {
		t.Errorf("leaf evidence lost its source/SNI/time: %+v", got)
	}
	if got.LastTlsNotAfter != "2026-09-01T00:00:00.000Z" || got.LastTlsVerifyError != "expired" || got.Success != 0 {
		t.Errorf("diagnostic leaf not readable from the attempt group: %+v", got)
	}

	// A later failure with no leaf at all still leaves the verified evidence intact.
	noLeaf := k.failed()
	noLeaf.LastAttemptAt = "2026-10-04T03:00:00.000Z"
	noLeaf.LastResult = "unreachable"
	if _, err := q.UpsertObservationFailed(ctx, noLeaf); err != nil {
		t.Fatalf("UpsertObservationFailed(no leaf): %v", err)
	}
	got, err = q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey(no leaf): %v", err)
	}
	if got.TlsNotAfter != "2027-01-01T00:00:00.000Z" || got.TlsFingerprint != "fp-verified" || got.ObservedAt != "2026-10-04T01:00:00.000Z" {
		t.Errorf("leaf evidence changed after a leafless failure: %+v", got)
	}

	// A second SNI is a separate observation with its own source and time.
	other := k
	other.sni = "other.example"
	otherLeaf := other.good()
	otherLeaf.ObservedAt = "2026-10-04T04:00:00.000Z"
	otherLeaf.LastAttemptAt = otherLeaf.ObservedAt
	otherLeaf.TlsNotAfter = "2028-01-01T00:00:00.000Z"
	otherLeaf.TlsFingerprint = "fp-other"
	if _, err := q.UpsertObservationGood(ctx, otherLeaf); err != nil {
		t.Fatalf("UpsertObservationGood(other SNI): %v", err)
	}
	rows, err := q.ListObservationsBySite(ctx, site)
	if err != nil {
		t.Fatalf("ListObservationsBySite: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("tls observations = %d, want one per SNI", len(rows))
	}
}

// fullGood sets EVERY writable good-attempt column to a value that is distinct per generation n and
// per column, so a dropped or constant-replaced column in an UPSERT cannot go unnoticed.
func fullGood(k obsKey, n int) db.UpsertObservationGoodParams {
	p := k.good()
	p.Backend = fmt.Sprintf("backend-%d", n)
	p.ObservedAt = fmt.Sprintf("2026-10-04T0%d:00:00.000Z", n)
	p.HttpStatus = int64(200 + n)
	p.GateClass = fmt.Sprintf("gate-%d", n)
	p.TlsNotAfter = fmt.Sprintf("202%d-01-01T00:00:00.000Z", 6+n)
	p.TlsFingerprint = fmt.Sprintf("fp-%d", n)
	p.RiskFinding = fmt.Sprintf("finding-%d", n)
	p.RiskContext = fmt.Sprintf("context-%d", n)
	p.UnscannedScope = fmt.Sprintf("scope-%d", n)
	p.LastAttemptAt = fmt.Sprintf("2026-10-04T0%d:30:00.000Z", n)
	return p
}

// wantGoodRow is the whole row a good attempt must leave behind: both column groups written, the
// attempt marked ok and mirroring the good http/TLS values, earlier attempt errors cleared.
func wantGoodRow(id int64, p db.UpsertObservationGoodParams) db.Observation {
	return db.Observation{
		ID: id, Category: p.Category, Site: p.Site, Host: p.Host, Route: p.Route, Source: p.Source,
		Vantage: p.Vantage, Endpoint: p.Endpoint, Sni: p.Sni, Path: p.Path, Backend: p.Backend,
		ObservedAt: p.ObservedAt, HttpStatus: p.HttpStatus, GateClass: p.GateClass,
		TlsNotAfter: p.TlsNotAfter, TlsFingerprint: p.TlsFingerprint,
		RiskFinding: p.RiskFinding, RiskContext: p.RiskContext, UnscannedScope: p.UnscannedScope,
		LastAttemptAt: p.LastAttemptAt, Success: 1, LastResult: "ok", LastHttpStatus: p.HttpStatus,
		LastError: "", LastTlsNotAfter: p.TlsNotAfter, LastTlsFingerprint: p.TlsFingerprint,
		LastTlsVerifyError: "",
	}
}

// fullFailed sets EVERY writable failed-attempt column to a distinct value.
func fullFailed(k obsKey, n int) db.UpsertObservationFailedParams {
	p := k.failed()
	p.LastAttemptAt = fmt.Sprintf("2026-10-04T0%d:45:00.000Z", n)
	p.LastResult = fmt.Sprintf("result-%d", n)
	p.LastHttpStatus = int64(500 + n)
	p.LastError = fmt.Sprintf("error-%d", n)
	p.LastTlsNotAfter = fmt.Sprintf("2025-0%d-01T00:00:00.000Z", n)
	p.LastTlsFingerprint = fmt.Sprintf("fp-diag-%d", n)
	p.LastTlsVerifyError = fmt.Sprintf("verify-%d", n)
	return p
}

// A good attempt writes every column of both groups, on the insert path and on the refresh path,
// and a refresh replaces every earlier value (good, attempt and diagnostic) instead of leaving some.
func TestObservationsGoodWritesEveryColumn(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	k := obsKey{"config_risk", "site-1", "app.example", "/api", "k8s", "cluster", "10.0.0.1:443", "app.example", "/api"}

	first := fullGood(k, 1)
	got, err := q.UpsertObservationGood(ctx, first)
	if err != nil {
		t.Fatalf("UpsertObservationGood(insert): %v", err)
	}
	if want := wantGoodRow(got.ID, first); got != want {
		t.Errorf("insert row = %+v\nwant       %+v", got, want)
	}

	// A failed attempt with its own values in every attempt column sits between the two good ones.
	if _, err := q.UpsertObservationFailed(ctx, fullFailed(k, 2)); err != nil {
		t.Fatalf("UpsertObservationFailed: %v", err)
	}

	second := fullGood(k, 3)
	got2, err := q.UpsertObservationGood(ctx, second)
	if err != nil {
		t.Fatalf("UpsertObservationGood(refresh): %v", err)
	}
	if want := wantGoodRow(got.ID, second); got2 != want {
		t.Errorf("refresh row = %+v\nwant        %+v", got2, want)
	}
	read, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	if read != got2 {
		t.Errorf("stored row = %+v, want the refreshed row %+v", read, got2)
	}
}

// A failed attempt changes exactly the attempt group: every good column keeps its distinct value,
// every attempt column takes the failure's value, and the row identity is unchanged.
func TestObservationsFailedKeepsEveryGoodColumn(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	k := obsKey{"config_risk", "site-1", "app.example", "/api", "k8s", "cluster", "10.0.0.1:443", "app.example", "/api"}
	seed := fullGood(k, 1)
	good, err := q.UpsertObservationGood(ctx, seed)
	if err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}

	fail := fullFailed(k, 2)
	got, err := q.UpsertObservationFailed(ctx, fail)
	if err != nil {
		t.Fatalf("UpsertObservationFailed: %v", err)
	}
	want := wantGoodRow(good.ID, seed) // good group, identity and key stay
	want.LastAttemptAt = fail.LastAttemptAt
	want.Success = 0
	want.LastResult = fail.LastResult
	want.LastHttpStatus = fail.LastHttpStatus
	want.LastError = fail.LastError
	want.LastTlsNotAfter = fail.LastTlsNotAfter
	want.LastTlsFingerprint = fail.LastTlsFingerprint
	want.LastTlsVerifyError = fail.LastTlsVerifyError
	if got != want {
		t.Errorf("failed row = %+v\nwant       %+v", got, want)
	}
	read, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	if read != want {
		t.Errorf("stored row = %+v\nwant        %+v", read, want)
	}

	// A first-ever failure inserts every attempt column and leaves the good group at its defaults.
	cold := obsKey{"tls", "site-1", "cold.example", "", "caddy", "host", "10.0.0.2:443", "cold.example", ""}
	coldFail := fullFailed(cold, 3)
	coldRow, err := q.UpsertObservationFailed(ctx, coldFail)
	if err != nil {
		t.Fatalf("UpsertObservationFailed(cold): %v", err)
	}
	coldWant := db.Observation{
		ID: coldRow.ID, Category: cold.category, Site: cold.site, Host: cold.host, Route: cold.route,
		Source: cold.source, Vantage: cold.vantage, Endpoint: cold.endpoint, Sni: cold.sni, Path: cold.path,
		LastAttemptAt: coldFail.LastAttemptAt, LastResult: coldFail.LastResult, LastHttpStatus: coldFail.LastHttpStatus,
		LastError: coldFail.LastError, LastTlsNotAfter: coldFail.LastTlsNotAfter,
		LastTlsFingerprint: coldFail.LastTlsFingerprint, LastTlsVerifyError: coldFail.LastTlsVerifyError,
	}
	if coldRow != coldWant {
		t.Errorf("cold failed row = %+v\nwant            %+v", coldRow, coldWant)
	}
}

// A failed attempt may not claim success: last_result 'ok' or ” with success=0 would contradict the
// schema rule (success=1 iff last_result='ok'). The write is rejected and nothing changes, on a new
// key and on an existing one; a real failure class on the same keys is the positive control.
func TestObservationsFailedRejectsOkOrEmptyResult(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	existing := obsKey{"target", "site-1", "app.example", "/", "probe", "host", "10.0.0.1:443", "app.example", "/"}
	good, err := q.UpsertObservationGood(ctx, fullGood(existing, 1))
	if err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}
	fresh := obsKey{"target", "site-1", "new.example", "/", "probe", "host", "10.0.0.1:443", "new.example", "/"}

	for _, result := range []string{"ok", ""} {
		for _, k := range []obsKey{existing, fresh} {
			p := fullFailed(k, 2)
			p.LastResult = result
			if _, err := q.UpsertObservationFailed(ctx, p); !errors.Is(err, sql.ErrNoRows) {
				t.Errorf("UpsertObservationFailed(%q result=%q) err = %v, want rejection (sql.ErrNoRows)", k.host, result, err)
			}
		}
	}
	read, err := q.GetObservationByKey(ctx, existing.get())
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	if read != good {
		t.Errorf("rejected failure changed the existing row: %+v want %+v", read, good)
	}
	if _, err := q.GetObservationByKey(ctx, fresh.get()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("rejected failure created a row: err = %v", err)
	}

	// Positive control: a real failure class is accepted on both keys.
	for _, k := range []obsKey{existing, fresh} {
		p := fullFailed(k, 2)
		p.LastResult = "timeout"
		row, err := q.UpsertObservationFailed(ctx, p)
		if err != nil {
			t.Fatalf("UpsertObservationFailed(%q timeout): %v", k.host, err)
		}
		if row.Success != 0 || row.LastResult != "timeout" {
			t.Errorf("failure row = %+v", row)
		}
	}
}

// Every key dimension scopes the queries: rows that differ ONLY in site, category, host, route,
// source, vantage, endpoint, SNI or path are separate observations, GetObservationByKey returns
// exactly its own row, ListObservationsBySite exactly its site's rows in the documented order, and
// a key altered in one dimension finds nothing.
func TestObservationsScopedByEveryKeyDimension(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	base := obsKey{"target", "site-1", "app.example", "/", "probe", "host", "10.0.0.1:443", "app.example", "/"}
	variants := map[string]obsKey{"base": base}
	for name, mutate := range map[string]func(*obsKey){
		"site":     func(k *obsKey) { k.site = "site-2" },
		"category": func(k *obsKey) { k.category = "caddy_gate" },
		"host":     func(k *obsKey) { k.host = "other.example" },
		"route":    func(k *obsKey) { k.route = "/other" },
		"source":   func(k *obsKey) { k.source = "caddy" },
		"vantage":  func(k *obsKey) { k.vantage = "internet" },
		"endpoint": func(k *obsKey) { k.endpoint = "10.0.0.2:443" },
		"sni":      func(k *obsKey) { k.sni = "other.example" },
		"path":     func(k *obsKey) { k.path = "/other" },
	} {
		k := base
		mutate(&k)
		variants[name] = k
	}

	// Each variant gets a distinct status so a wrong row is visible.
	ids := map[string]int64{}
	status := map[string]int64{}
	n := int64(200)
	for name, k := range variants {
		p := k.good()
		p.ObservedAt = "2026-10-04T01:00:00.000Z"
		p.LastAttemptAt = p.ObservedAt
		p.HttpStatus = n
		row, err := q.UpsertObservationGood(ctx, p)
		if err != nil {
			t.Fatalf("UpsertObservationGood(%s): %v", name, err)
		}
		ids[name], status[name] = row.ID, n
		n++
	}
	if len(ids) != len(variants) {
		t.Fatalf("variants collapsed into %d distinct ids, want %d", len(ids), len(variants))
	}

	for name, k := range variants {
		row, err := q.GetObservationByKey(ctx, k.get())
		if err != nil {
			t.Fatalf("GetObservationByKey(%s): %v", name, err)
		}
		if row.ID != ids[name] || row.HttpStatus != status[name] {
			t.Errorf("GetObservationByKey(%s) = id %d status %d, want id %d status %d", name, row.ID, row.HttpStatus, ids[name], status[name])
		}
		if row.Category != k.category || row.Site != k.site || row.Host != k.host || row.Route != k.route ||
			row.Source != k.source || row.Vantage != k.vantage || row.Endpoint != k.endpoint ||
			row.Sni != k.sni || row.Path != k.path {
			t.Errorf("GetObservationByKey(%s) returned another key: %+v", name, row)
		}
	}

	// A key that differs from a stored one in a single dimension only is absent.
	absent := obsKey{"target", "site-9", "app.example", "/", "probe", "host", "10.0.0.1:443", "app.example", "/"}
	for name, mutate := range map[string]func(*obsKey){
		"site":     func(k *obsKey) { k.site = "site-9" },
		"category": func(k *obsKey) { k.category = "tls" },
		"host":     func(k *obsKey) { k.host = "absent.example" },
		"route":    func(k *obsKey) { k.route = "/absent" },
		"source":   func(k *obsKey) { k.source = "absent" },
		"vantage":  func(k *obsKey) { k.vantage = "absent" },
		"endpoint": func(k *obsKey) { k.endpoint = "10.9.9.9:443" },
		"sni":      func(k *obsKey) { k.sni = "absent.example" },
		"path":     func(k *obsKey) { k.path = "/absent" },
	} {
		k := base
		mutate(&k)
		if _, err := q.GetObservationByKey(ctx, k.get()); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("GetObservationByKey(absent %s) err = %v, want sql.ErrNoRows", name, err)
		}
	}
	if _, err := q.GetObservationByKey(ctx, absent.get()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetObservationByKey(absent site) err = %v, want sql.ErrNoRows", err)
	}

	// Listing a site returns exactly its rows (all variants except the site-2 one) in the documented
	// order; the other site returns only its own row; an unknown site returns nothing.
	var want []db.Observation
	for name, k := range variants {
		if k.site != "site-1" {
			continue
		}
		row, err := q.GetObservationByKey(ctx, k.get())
		if err != nil {
			t.Fatalf("GetObservationByKey(%s): %v", name, err)
		}
		want = append(want, row)
	}
	sort.Slice(want, func(i, j int) bool {
		a, b := want[i], want[j]
		for _, c := range [][2]string{
			{a.Category, b.Category}, {a.Host, b.Host}, {a.Route, b.Route}, {a.Source, b.Source},
			{a.Vantage, b.Vantage}, {a.Endpoint, b.Endpoint}, {a.Sni, b.Sni}, {a.Path, b.Path},
		} {
			if c[0] != c[1] {
				return c[0] < c[1]
			}
		}
		return a.ID < b.ID
	})
	got, err := q.ListObservationsBySite(ctx, "site-1")
	if err != nil {
		t.Fatalf("ListObservationsBySite(site-1): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListObservationsBySite(site-1) =\n%+v\nwant\n%+v", got, want)
	}
	other, err := q.ListObservationsBySite(ctx, "site-2")
	if err != nil {
		t.Fatalf("ListObservationsBySite(site-2): %v", err)
	}
	if len(other) != 1 || other[0].ID != ids["site"] {
		t.Errorf("ListObservationsBySite(site-2) = %+v, want only the site-2 row", other)
	}
	none, err := q.ListObservationsBySite(ctx, "site-none")
	if err != nil {
		t.Fatalf("ListObservationsBySite(site-none): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("ListObservationsBySite(site-none) = %d rows, want 0", len(none))
	}
}

// AC5: an observation change that fails part-way keeps the existing data (the change is atomic),
// and neither the stored record nor the write parameters expose a secret/body/header field.
func TestObservationsAtomicityAndSafeFields(t *testing.T) {
	ctx := context.Background()
	s := openObservationStore(t, testDBPath(t))
	t.Cleanup(func() { _ = s.Close() })
	q := s.Queries()

	const site = "site-1"
	k := obsKey{"target", site, "app.example", "/", "probe", "tagcess-host", "10.0.0.1:443", "app.example", "/"}
	extra := obsKey{"tls", site, "app.example", "", "caddy", "tagcess-host", "10.0.0.1:443", "app.example", ""}
	before, err := q.UpsertObservationGood(ctx, fullGood(k, 1))
	if err != nil {
		t.Fatalf("UpsertObservationGood: %v", err)
	}

	// Positive control: the same multi-write change with no failure commits, so the rollback below
	// cannot come from the writes being no-ops.
	change := func(tx *sql.Tx, last func(*db.Queries) error) error {
		qt := q.WithTx(tx)
		if _, err := qt.UpsertObservationGood(ctx, fullGood(k, 2)); err != nil {
			return err
		}
		if _, err := qt.UpsertObservationGood(ctx, fullGood(extra, 2)); err != nil {
			return err
		}
		return last(qt)
	}
	run := func(last func(*db.Queries) error) error {
		tx, err := s.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := change(tx, last); err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				t.Fatalf("rollback: %v", rerr)
			}
			return err
		}
		return tx.Commit()
	}

	// The third write goes through the real query and fails on the category CHECK, after the first
	// two succeeded: the whole change rolls back.
	bogus := fullGood(extra, 3)
	bogus.Category = "bogus"
	err = run(func(qt *db.Queries) error {
		_, err := qt.UpsertObservationGood(ctx, bogus)
		return err
	})
	if err == nil {
		t.Fatal("category CHECK accepted 'bogus'")
	}
	got, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey after rollback: %v", err)
	}
	if got != before {
		t.Errorf("failed change was not atomic: %+v want %+v", got, before)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	if n != 1 {
		t.Errorf("observations = %d, want the single pre-change row", n)
	}

	if err := run(func(qt *db.Queries) error {
		_, err := qt.UpsertObservationFailed(ctx, fullFailed(k, 3))
		return err
	}); err != nil {
		t.Fatalf("committed change: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	if n != 2 {
		t.Errorf("observations after commit = %d, want 2", n)
	}
	committed, err := q.GetObservationByKey(ctx, k.get())
	if err != nil {
		t.Fatalf("GetObservationByKey after commit: %v", err)
	}
	if committed.ObservedAt != fullGood(k, 2).ObservedAt || committed.LastResult != "result-3" {
		t.Errorf("committed change not visible: %+v", committed)
	}

	// The stored record and the write parameters carry no secret/raw-request field.
	forbidden := []string{"token", "credential", "password", "secret", "private", "kubeconfig",
		"cookie", "authorization", "body", "header"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(db.Observation{}),
		reflect.TypeOf(db.UpsertObservationGoodParams{}),
		reflect.TypeOf(db.UpsertObservationFailedParams{}),
	} {
		if f := forbiddenSnapshotField(typ, forbidden); f != "" {
			t.Errorf("%s carries a forbidden field %s", typ.Name(), f)
		}
	}
	// Positive control: a planted struct with a Header field must be flagged, so a clean result
	// cannot come from scanning nothing.
	type planted struct {
		ID     int64
		Header string
	}
	if f := forbiddenSnapshotField(reflect.TypeOf(planted{}), forbidden); f == "" {
		t.Error("forbidden-field scan did not detect a planted Header field")
	}
}
