-- Initial tagcess schema (architecture.md §3, F1 tables only).
-- Site tables (F2) and health tables (F4) arrive in their own migrations.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE changes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,
    actor          TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('pending_approval', 'applied', 'failed', 'rolled_back')),
    before_summary TEXT NOT NULL DEFAULT '',
    after_summary  TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- Append-only: no update or delete query is generated for this table.
CREATE TABLE audit_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    event  TEXT NOT NULL,
    target TEXT NOT NULL,
    diff   TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL
);

CREATE INDEX idx_audit_events_at ON audit_events (at);

CREATE TABLE applied_artifacts (
    kind       TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    hash       TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE sync_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    trigger      TEXT NOT NULL CHECK (trigger IN ('webhook', 'periodic', 'manual')),
    result       TEXT NOT NULL,
    diff_summary TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_sync_runs_started_at ON sync_runs (started_at);

CREATE TABLE webhook_events (
    event_id    TEXT PRIMARY KEY,
    received_at TEXT NOT NULL
);

CREATE INDEX idx_webhook_events_received_at ON webhook_events (received_at);

CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    source        TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    resolved_at   TEXT
);

CREATE INDEX idx_alerts_kind_source ON alerts (kind, source);

-- Y-06.2: the first installation starts in dry-run mode.
INSERT INTO settings (key, value, updated_at)
VALUES ('dry_run', 'true', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
