-- name: GetOwnedURIs :one
SELECT uris FROM zitadel_owned_uris WHERE id = 1;

-- name: UpsertOwnedURIs :exec
INSERT INTO zitadel_owned_uris (id, uris, updated_at)
VALUES (1, ?, ?)
ON CONFLICT (id) DO UPDATE SET uris = excluded.uris, updated_at = excluded.updated_at;
