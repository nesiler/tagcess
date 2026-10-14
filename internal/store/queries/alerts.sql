-- Alerts shown on the dashboard (P-02). F1-010 raises a critical alert when an applied policy could
-- not be verified or recorded safely; F1-011 owns the dedupe and resolve lifecycle: it dedupes and
-- resolves its own read-failure alerts per system, and resolves the pipeline's critical alerts once
-- a reconcile applies cleanly (the only proof the problem is gone).

-- name: InsertAlert :one
INSERT INTO alerts (kind, source, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?)
RETURNING id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary;

-- A repeated alert keeps one row: the open (kind, source) alert's last_seen_at is bumped. The
-- orchestrator calls this first and only inserts when no row was touched, so a recurring read
-- failure does not pile up duplicates (F1-011 AC2/AC3).
-- name: TouchAlert :execrows
UPDATE alerts
SET last_seen_at = ?
WHERE kind = ? AND source = ? AND resolved_at IS NULL;

-- The problem is gone: every open alert of this (kind, source) is marked resolved once.
-- name: ResolveAlerts :execrows
UPDATE alerts
SET resolved_at = ?
WHERE kind = ? AND source = ? AND resolved_at IS NULL;

-- A successful reconcile resolves a critical alert whatever change raised it: the pipeline stamps
-- the source with the change id, so the kind is the only stable key (F1-011).
-- name: ResolveAlertKind :execrows
UPDATE alerts
SET resolved_at = ?
WHERE kind = ? AND resolved_at IS NULL;

-- The sync screen shows every open (unresolved) alert at the top (P-02.1), newest sighting first so
-- a still-happening problem is easy to spot.
-- name: ListOpenAlerts :many
SELECT id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary
FROM alerts
WHERE resolved_at IS NULL
ORDER BY last_seen_at DESC, id DESC;

-- Monitor alerts (P-02.4, ADR 0032 proposal) key on (kind, subject, source) with a non-empty subject;
-- the legacy F1/F3 pipeline alerts keep an empty subject and their own (kind, source) key. This
-- separation holds only while monitor kinds stay disjoint from pipeline kinds: the legacy TouchAlert,
-- ResolveAlerts and ResolveAlertKind match on kind (and source) without filtering subject, so a shared
-- kind would let them touch or resolve monitor rows too. A repeated open monitor key follows the same
-- F1-011 shape as the legacy path: TouchMonitorAlert first, and only when it touched no row does the
-- caller InsertMonitorAlert (SQLite is single-process, low write rate).
-- name: GetOpenMonitorAlert :one
SELECT id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary
FROM alerts
WHERE kind = ? AND subject = ? AND source = ? AND resolved_at IS NULL
ORDER BY id DESC
LIMIT 1;

-- A new monitor alert carries its severity, freshness and sanitized evidence summary (no
-- token/header/body/raw response). last_success and the counters start NULL/0.
-- name: InsertMonitorAlert :one
INSERT INTO alerts (kind, subject, source, severity, freshness, evidence_summary, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, kind, source, first_seen_at, last_seen_at, resolved_at,
          subject, severity, acknowledged_at, last_success, last_consumed_sample,
          freshness, muted, consecutive_failures, consecutive_successes, evidence_summary;

-- A repeated observation of the same open monitor key bumps last_seen_at instead of inserting a
-- duplicate; only the (kind, subject, source) triple is matched, so other subjects/sources and the
-- legacy rows are untouched.
-- name: TouchMonitorAlert :execrows
UPDATE alerts
SET last_seen_at = ?
WHERE kind = ? AND subject = ? AND source = ? AND resolved_at IS NULL;

-- The monitor state transition of one alert: severity/freshness/evidence, last healthy sample, the
-- consumed observation sample (so a restarted consumer does not re-count it) and the consecutive
-- counters. It deliberately never touches resolved_at or the alert identity columns.
-- name: UpdateMonitorAlert :execrows
UPDATE alerts
SET severity = ?, freshness = ?, evidence_summary = ?, last_success = ?,
    last_consumed_sample = ?, consecutive_failures = ?, consecutive_successes = ?,
    last_seen_at = ?
WHERE id = ? AND resolved_at IS NULL;

-- Acknowledging records who/when read the alert; it is not a recovery and does not resolve (P-02.4).
-- name: SetAlertAcknowledged :execrows
UPDATE alerts
SET acknowledged_at = ?
WHERE id = ? AND resolved_at IS NULL;

-- Maintenance mutes the monitor label only; the alert stays open and measurement continues (P-02.5).
-- name: SetAlertMuted :execrows
UPDATE alerts
SET muted = ?
WHERE id = ? AND resolved_at IS NULL;

-- Subject-specific recovery resolves only the exact (kind, subject, source) alert. The broad
-- ResolveAlertKind/ResolveAlerts path stays the pipeline's own contract and is not used here.
-- name: ResolveMonitorAlert :execrows
UPDATE alerts
SET resolved_at = ?
WHERE kind = ? AND subject = ? AND source = ? AND resolved_at IS NULL;

-- The alerts screen (F4-026) shows the monitor-alert lifecycle, resolved rows included, so the
-- resolution state stays visible after recovery. Rows below the opening threshold (severity '') are
-- bookkeeping and the legacy F1/F3 pipeline kinds are not monitor alerts; both are excluded.
-- name: ListMonitorAlerts :many
SELECT id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary
FROM alerts
WHERE substr(kind, 1, 8) = 'monitor_' AND severity <> ''
ORDER BY last_seen_at DESC, id DESC
LIMIT ?;

-- The alerts screen reads the open rows without a limit (an old open alert must never fall out of a
-- window of newer rows) and bounds only the resolved history. Same filters as ListMonitorAlerts.
-- name: ListOpenMonitorAlertRows :many
SELECT id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary
FROM alerts
WHERE substr(kind, 1, 8) = 'monitor_' AND severity <> '' AND resolved_at IS NULL
ORDER BY last_seen_at DESC, id DESC;

-- name: ListResolvedMonitorAlertRows :many
SELECT id, kind, source, first_seen_at, last_seen_at, resolved_at,
       subject, severity, acknowledged_at, last_success, last_consumed_sample,
       freshness, muted, consecutive_failures, consecutive_successes, evidence_summary
FROM alerts
WHERE substr(kind, 1, 8) = 'monitor_' AND severity <> '' AND resolved_at IS NOT NULL
ORDER BY last_seen_at DESC, id DESC
LIMIT ?;
