-- name: InsertChange :one
INSERT INTO changes (kind, actor, status, before_summary, after_summary, error, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, kind, actor, status, before_summary, after_summary, error, created_at, updated_at;

-- name: GetChange :one
SELECT id, kind, actor, status, before_summary, after_summary, error, created_at, updated_at
FROM changes
WHERE id = ?;

-- name: UpdateChange :exec
UPDATE changes
SET status = ?, before_summary = ?, after_summary = ?, error = ?, updated_at = ?
WHERE id = ?;

-- The sync screen lists what is waiting for an operator (Y-03.4). A pending change is superseded by
-- a newer proposal only when the pipeline replans it; the page shows the newest first.
-- name: ListPendingChanges :many
SELECT id, kind, actor, status, before_summary, after_summary, error, created_at, updated_at
FROM changes
WHERE status = 'pending_approval'
ORDER BY created_at DESC, id DESC;

-- Rejecting a pending change closes it without touching Headscale. The status CHECK allows only
-- pending/applied/failed/rolled_back, so a rejection is recorded as failed with the reason in error;
-- the WHERE guard makes it a no-op if the change is no longer pending (F1-017 AC3).
-- name: RejectChange :execrows
UPDATE changes
SET status = 'failed', error = ?, updated_at = ?
WHERE id = ? AND status = 'pending_approval';
