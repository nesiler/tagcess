-- name: GetItem :one
SELECT id, name FROM items WHERE id = ?;
