-- Append-only audit log (A-01, security.md 9). Only INSERT and SELECT are defined here.
-- There is deliberately no UPDATE or DELETE against audit_events, enforced by
-- TestAudit_NoMutationQueries.

-- name: InsertAuditEvent :one
INSERT INTO audit_events (at, actor, event, target, diff, result)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, at, actor, event, target, diff, result;

-- name: GetAuditEvent :one
SELECT id, at, actor, event, target, diff, result FROM audit_events WHERE id = ?;

-- name: ListAuditEvents :many
-- Newest first, with id as a tiebreaker so pages never overlap. An empty filter matches every row;
-- this is the only listing the UI uses (A-01). Read-only: no UPDATE or DELETE is defined.
SELECT id, at, actor, event, target, diff, result FROM audit_events
WHERE actor = COALESCE(sqlc.narg('actor'), actor)
  AND event = COALESCE(sqlc.narg('event'), event)
ORDER BY at DESC, id DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');
