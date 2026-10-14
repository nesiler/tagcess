-- F4 persistence schema (F4-006, R3 B-02/B-04/B-05/B-07, ADR 0030-0032 Önerildi). One version bump
-- for the whole F4 schema: k8s snapshots (successful reads) with a separate read-attempt log,
-- the incomplete draft kept separate from the applicable site record, and category/source/vantage/
-- endpoint/SNI/path measurement observations. The legacy alerts table gains the lifecycle columns;
-- old rows keep their kind/source/resolved_at meaning and get safe defaults. No credential, raw body,
-- header, cookie, kubeconfig or private key column lives here (R3 B-07: evidence stays metadata).

-- k8s_snapshots holds ONLY successful, complete reads (a history is kept: drafts reference the exact
-- snapshot_id they came from). A failed read never touches this table, so a failure can never read back
-- as an empty or partial current snapshot: the current snapshot of a (scope, profile_version) is
-- the latest row of that pair (ORDER BY observed_at DESC, id DESC) and nothing else. profile_version
-- keeps an old profile/scope version's snapshot from being served as the new version's snapshot:
-- readers always filter by the exact pair, and the older version's rows stay available as explicit
-- "old scope" data (F4-007 AC4). payload may not be empty. Retention (pruning old rows per pair) is a
-- query concern of F4-042; the foreign keys that point here are ON DELETE SET NULL so pruning never
-- needs a new migration.
CREATE TABLE k8s_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scope            TEXT NOT NULL,
    profile_version  TEXT NOT NULL DEFAULT '',
    observed_at      TEXT NOT NULL,
    payload          TEXT NOT NULL CHECK (payload <> '')
);

CREATE INDEX idx_k8s_snapshots_scope ON k8s_snapshots (scope, profile_version, observed_at DESC, id DESC);

-- Every read attempt is recorded here, including the first failed read and the first read of a new
-- profile version (when no snapshot row exists yet). A successful attempt is written in the same
-- transaction as its snapshot row and links it (snapshot_id); a failed attempt links nothing (CHECK)
-- and carries an error_class label (e.g. credential_expired, forbidden, timeout, decode) and a
-- sanitized, truncated error text (callers must not write raw response body/headers/tokens). The last
-- attempt of a (scope, profile_version) is the latest row of the pair; "stale" is derived by readers
-- from that attempt being failed or newer than the snapshot's observed_at. Failed rows pile up, so
-- retention is again a query concern of F4-042.
CREATE TABLE k8s_snapshot_attempts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scope            TEXT NOT NULL,
    profile_version  TEXT NOT NULL DEFAULT '',
    attempted_at     TEXT NOT NULL,
    outcome          TEXT NOT NULL CHECK (outcome IN ('ok', 'failed')),
    error_class      TEXT NOT NULL DEFAULT '',
    error            TEXT NOT NULL DEFAULT '',
    snapshot_id      INTEGER REFERENCES k8s_snapshots (id) ON DELETE SET NULL,
    CHECK (outcome = 'ok' OR snapshot_id IS NULL)
);

CREATE INDEX idx_k8s_snapshot_attempts_scope
    ON k8s_snapshot_attempts (scope, profile_version, attempted_at DESC, id DESC);

-- A draft is the incomplete, not-yet-applied site proposal for one HOST (R3 B-04: one host, one site;
-- several Ingress routes of the same host merge into its evidence list, and the user's choices are
-- stored once). It is separate from the applicable site record: nothing here is a SiteStore row.
-- profile_version/snapshot_id/observed_at say which discovery the proposal came from, so a later
-- snapshot or profile change shows up as a stale source without overwriting the user's choices.
-- A draft needs a non-empty host: empty/wildcard-host routes are review items computed from the
-- snapshot, not drafts. review_* keeps the route-conflict/ambiguity review request alive until the
-- user answers (R3 B-04): reason label, candidate targets (JSON) and the default assessment with its
-- basis; an unresolved review never widens access.
CREATE TABLE k8s_drafts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster           TEXT NOT NULL DEFAULT '',
    host              TEXT NOT NULL CHECK (host <> ''),
    profile_version   TEXT NOT NULL DEFAULT '',
    snapshot_id       INTEGER REFERENCES k8s_snapshots (id) ON DELETE SET NULL,
    observed_at       TEXT NOT NULL DEFAULT '',
    access_choice     TEXT NOT NULL DEFAULT '',
    roles             TEXT NOT NULL DEFAULT '[]',
    target            TEXT NOT NULL DEFAULT '',
    cert              TEXT NOT NULL DEFAULT '',
    note              TEXT NOT NULL DEFAULT '',
    review_state      TEXT NOT NULL DEFAULT '' CHECK (review_state IN ('', 'needed', 'resolved')),
    review_reason     TEXT NOT NULL DEFAULT '',
    review_candidates TEXT NOT NULL DEFAULT '[]',
    review_default    TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

-- One host holds one draft per cluster: repeated discovery updates that draft instead of piling up
-- duplicates (the F4-009 save/continue key, F4-010 AC7 host identity).
CREATE UNIQUE INDEX idx_k8s_drafts_host ON k8s_drafts (cluster, host);

-- Route provenance of a draft: one row per Ingress route (namespace, Ingress UID/name, resourceVersion,
-- host rule path/pathType, backend service/port, class). resource_version/backend/class are mutable
-- observations and stay out of the key; the route identity is the immutable Ingress UID plus path
-- and pathType. Deleting a draft removes its provenance.
CREATE TABLE k8s_draft_routes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    draft_id         INTEGER NOT NULL REFERENCES k8s_drafts (id) ON DELETE CASCADE,
    namespace        TEXT NOT NULL DEFAULT '',
    ingress_name     TEXT NOT NULL DEFAULT '',
    ingress_uid      TEXT NOT NULL DEFAULT '',
    resource_version TEXT NOT NULL DEFAULT '',
    path             TEXT NOT NULL DEFAULT '',
    path_type        TEXT NOT NULL DEFAULT '',
    backend_service  TEXT NOT NULL DEFAULT '',
    backend_port     TEXT NOT NULL DEFAULT '',
    class            TEXT NOT NULL DEFAULT '',
    observed_at      TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_k8s_draft_routes_key ON k8s_draft_routes (draft_id, namespace, ingress_uid, path, path_type);

-- One row per measurement, identified by its whole evidence key: category and subject (site/host/
-- route) plus source, vantage, dialed endpoint (IPv4/IPv6), SNI and path, so a second vantage,
-- endpoint, SNI or path is a separate observation rather than overwriting the first (R3 B-05/B-06).
-- Categories never overwrite each other (target, caddy_gate, tls, config_risk).
--
-- LAST-GOOD RULE. The row holds two separate groups of columns:
--   last good (evidence): observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
--     risk_finding, risk_context, unscanned_scope
--   last attempt: last_attempt_at, success, last_result, last_http_status, last_error,
--     last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
-- An attempt that meets its category's expectation (target answered with an expected status; the gate
-- answered with a recognized class; a leaf was obtained AND verified; the risk evaluation completed
-- from a complete read) writes BOTH groups in one UPSERT. Any other attempt (unexpected status,
-- timeout, refused, guard/policy reject, source read error, unverifiable or expired leaf) writes ONLY
-- the attempt group and never touches the good group, so a failure can never refresh stale evidence;
-- the first-ever failed attempt inserts a row with observed_at = '' (no good observation yet). An
-- unverifiable/expired leaf is still readable from last_tls_* (diagnostic, "TLS not verified") for
-- the immediate-critical alert, while tls_not_after stays the last VERIFIED leaf. success is 1 iff the
-- last attempt met the expectation (last_result = 'ok'); last_result is a class label (ok,
-- unexpected_status, timeout, refused, guard_rejected, tls_unverified, source_error, ...).
-- Freshness is derived by readers from observed_at vs last_attempt_at and last_result; it is not
-- stored. The sample identity an alert consumer records in alerts.last_consumed_sample is
-- "<observations.id>@<last_attempt_at>". last_error is caller-written free text: callers must
-- truncate and sanitize it (no raw response body/headers/tokens). backend is the route backend
-- (service:port) a config_risk candidate was bound to; unscanned_scope lists labels of paths that
-- were NOT scanned (e.g. crd, gateway, hostnetwork, internet); the internet vantage is "not tested"
-- unless a row with that vantage exists.
CREATE TABLE observations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    category              TEXT NOT NULL CHECK (category IN ('target', 'caddy_gate', 'tls', 'config_risk')),
    site                  TEXT NOT NULL DEFAULT '',
    host                  TEXT NOT NULL DEFAULT '',
    route                 TEXT NOT NULL DEFAULT '',
    source                TEXT NOT NULL DEFAULT '',
    vantage               TEXT NOT NULL DEFAULT '',
    endpoint              TEXT NOT NULL DEFAULT '',
    sni                   TEXT NOT NULL DEFAULT '',
    path                  TEXT NOT NULL DEFAULT '',
    backend               TEXT NOT NULL DEFAULT '',
    observed_at           TEXT NOT NULL DEFAULT '',
    http_status           INTEGER NOT NULL DEFAULT 0,
    gate_class            TEXT NOT NULL DEFAULT '',
    tls_not_after         TEXT NOT NULL DEFAULT '',
    tls_fingerprint       TEXT NOT NULL DEFAULT '',
    risk_finding          TEXT NOT NULL DEFAULT '',
    risk_context          TEXT NOT NULL DEFAULT '',
    unscanned_scope       TEXT NOT NULL DEFAULT '',
    last_attempt_at       TEXT NOT NULL DEFAULT '',
    success               INTEGER NOT NULL DEFAULT 0 CHECK (success IN (0, 1)),
    last_result           TEXT NOT NULL DEFAULT '',
    last_http_status      INTEGER NOT NULL DEFAULT 0,
    last_error            TEXT NOT NULL DEFAULT '',
    last_tls_not_after    TEXT NOT NULL DEFAULT '',
    last_tls_fingerprint  TEXT NOT NULL DEFAULT '',
    last_tls_verify_error TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_observations_key
    ON observations (category, site, host, route, source, vantage, endpoint, sni, path);

-- Alert lifecycle columns (P-02.4; F1/F3 legacy rows keep subject '' and shared dedupe semantics).
-- last_success marks the last healthy sample; last_consumed_sample lets a restarted consumer avoid
-- re-counting the same observation; freshness/muted and the consecutive counters are monitor state.
ALTER TABLE alerts ADD COLUMN subject TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT;
ALTER TABLE alerts ADD COLUMN last_success TEXT;
ALTER TABLE alerts ADD COLUMN last_consumed_sample TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN freshness TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN muted INTEGER NOT NULL DEFAULT 0 CHECK (muted IN (0, 1));
ALTER TABLE alerts ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0;
-- Short sanitized metadata summary shown on the alerts page (no body/header/token/personal data).
ALTER TABLE alerts ADD COLUMN evidence_summary TEXT NOT NULL DEFAULT '';

-- F4-022 looks alerts up by (kind, subject, source). Non-unique on purpose: legacy F1/F3 rows keep
-- subject '' and may repeat the same (kind, source) after resolution, so dedupe stays in the queries.
CREATE INDEX idx_alerts_kind_subject_source ON alerts (kind, subject, source);
