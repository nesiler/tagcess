-- name: InsertPolicyRevision :one
INSERT INTO policy_revisions (parent_id, base_hash, raw, raw_hash, canonical_hash, source, actor, created_at, reason, validation, change_id, rollback_of)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, parent_id, base_hash, raw, raw_hash, canonical_hash, source, actor, created_at, reason, validation, apply_status, apply_detail, change_id, rollback_of;

-- name: GetPolicyRevision :one
SELECT id, parent_id, base_hash, raw, raw_hash, canonical_hash, source, actor, created_at, reason, validation, apply_status, apply_detail, change_id, rollback_of
FROM policy_revisions
WHERE id = ?;

-- name: ListPolicyRevisions :many
SELECT id, parent_id, base_hash, raw, raw_hash, canonical_hash, source, actor, created_at, reason, validation, apply_status, apply_detail, change_id, rollback_of
FROM policy_revisions
ORDER BY id DESC
LIMIT ?;

-- name: LatestPolicyRevisionID :one
SELECT CAST(COALESCE(MAX(id), 0) AS INTEGER) AS id
FROM policy_revisions;

-- The live policy is what the newest applied revision holds; failed, unknown and dry-run attempts
-- never became live, a pending one is still in flight.
-- name: LatestAppliedPolicyRevision :one
SELECT id, parent_id, base_hash, raw, raw_hash, canonical_hash, source, actor, created_at, reason, validation, apply_status, apply_detail, change_id, rollback_of
FROM policy_revisions
WHERE apply_status = 'applied'
ORDER BY id DESC
LIMIT 1;

-- The only change a stored revision ever gets: the one-time pending -> final transition.
-- name: FinishPolicyRevision :execrows
UPDATE policy_revisions
SET apply_status = ?, apply_detail = ?
WHERE id = ? AND apply_status = 'pending';
