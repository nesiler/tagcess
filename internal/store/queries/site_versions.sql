-- name: InsertSiteVersion :one
INSERT INTO site_versions (site_id, change_id, op, deleted, rollback_of, hosts, snapshot, revision, actor, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, site_id, change_id, op, deleted, rollback_of, hosts, snapshot, revision, actor, created_at;

-- name: GetSiteVersion :one
SELECT id, site_id, change_id, op, deleted, rollback_of, hosts, snapshot, revision, actor, created_at
FROM site_versions
WHERE id = ?;

-- name: LatestSiteVersion :one
SELECT id, site_id, change_id, op, deleted, rollback_of, hosts, snapshot, revision, actor, created_at
FROM site_versions
WHERE site_id = ?
ORDER BY id DESC
LIMIT 1;

-- name: ListSiteVersions :many
SELECT id, site_id, change_id, op, deleted, rollback_of, hosts, snapshot, revision, actor, created_at
FROM site_versions
WHERE site_id = ?
ORDER BY id DESC;

-- A revision is bound once: an intent that was committed late fills the empty revision of its
-- change's versions, and a bound revision is never replaced.
-- name: BindSiteVersionRevision :execrows
UPDATE site_versions
SET revision = ?
WHERE change_id = ? AND revision = '';
