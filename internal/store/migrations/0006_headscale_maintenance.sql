-- Headscale maintenance flag (H-07, ADR 0021 c/d, F3b-013). One row, always present: the durable
-- barrier that stops widening Headscale writes while a host config change is open or unresolved.
-- state moves off -> active -> reconcile_pending -> off; only the maintenance package changes it.
-- last_host_result is the helper's last result as secret-free JSON ('' while no result is in yet);
-- pending_reconcile is a held automatic reconcile; close_note describes how the last maintenance ended.
CREATE TABLE headscale_maintenance (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    state             TEXT NOT NULL DEFAULT 'off' CHECK (state IN ('off', 'active', 'reconcile_pending')),
    request_id        TEXT NOT NULL DEFAULT '',
    actor             TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT '',
    last_host_result  TEXT NOT NULL DEFAULT '',
    pending_reconcile INTEGER NOT NULL DEFAULT 0 CHECK (pending_reconcile IN (0, 1)),
    close_note        TEXT NOT NULL DEFAULT ''
);

INSERT INTO headscale_maintenance (id, updated_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
