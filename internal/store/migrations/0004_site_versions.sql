-- Durable site source versions (A-03.4, ADR 0017, F2-020). Every applied site change stores the
-- site's source model as one row, bound to the Git revision of the change's verified artifacts
-- (ADR 0016). site_id has no foreign key on purpose: a deleted site keeps its history, and the
-- tombstone row (deleted = 1) holds the model it had when it was deleted. The row is never updated
-- except to bind a revision that was committed late (revision '' -> the real id, once).
CREATE TABLE site_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL,
    change_id   INTEGER NOT NULL,
    op          TEXT NOT NULL CHECK (op IN ('add', 'update', 'delete', 'resync')),
    deleted     INTEGER NOT NULL DEFAULT 0,
    rollback_of INTEGER NOT NULL DEFAULT 0,
    hosts       TEXT NOT NULL,
    snapshot    TEXT NOT NULL,
    revision    TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_site_versions_site ON site_versions (site_id, id);
CREATE INDEX idx_site_versions_change ON site_versions (change_id);
