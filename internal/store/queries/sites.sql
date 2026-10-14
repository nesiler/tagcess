-- name: InsertSite :one
INSERT INTO sites (
    kind, open_reason, system_template, system_config, roles, target_roles,
    cert, target_kind, target_url, target_tls_insecure, magicdns, maintenance,
    note, owner, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, kind, open_reason, system_template, system_config, roles, target_roles,
    cert, target_kind, target_url, target_tls_insecure, magicdns, maintenance,
    note, owner, created_at, updated_at;

-- name: UpdateSite :one
UPDATE sites SET
    kind = ?, open_reason = ?, system_template = ?, system_config = ?, roles = ?, target_roles = ?,
    cert = ?, target_kind = ?, target_url = ?, target_tls_insecure = ?, magicdns = ?, maintenance = ?,
    note = ?, owner = ?, updated_at = ?
WHERE id = ?
RETURNING id, kind, open_reason, system_template, system_config, roles, target_roles,
    cert, target_kind, target_url, target_tls_insecure, magicdns, maintenance,
    note, owner, created_at, updated_at;

-- name: GetSite :one
SELECT id, kind, open_reason, system_template, system_config, roles, target_roles,
    cert, target_kind, target_url, target_tls_insecure, magicdns, maintenance,
    note, owner, created_at, updated_at
FROM sites
WHERE id = ?;

-- name: ListSites :many
SELECT id, kind, open_reason, system_template, system_config, roles, target_roles,
    cert, target_kind, target_url, target_tls_insecure, magicdns, maintenance,
    note, owner, created_at, updated_at
FROM sites
ORDER BY id;

-- name: DeleteSite :execrows
DELETE FROM sites WHERE id = ?;
