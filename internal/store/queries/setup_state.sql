-- Setup token and session (I-5). Every mutation is a conditional UPDATE so single use and session
-- replacement are atomic.

-- name: GetSetupState :one
SELECT id, token_hash, token_expires_at, session_hash, session_created_at, session_last_seen_at,
       sealed_at, sealed_identity, reopen_count
FROM setup_state WHERE id = 1;

-- name: ReplaceSetupToken :exec
-- A new token invalidates the old one and ends every setup session.
UPDATE setup_state
SET token_hash = ?, token_expires_at = ?, session_hash = '', session_created_at = '', session_last_seen_at = ''
WHERE id = 1;

-- name: ConsumeSetupToken :execrows
-- Succeeds only for the stored, unexpired hash of an unsealed setup; the token is gone afterwards.
UPDATE setup_state
SET token_hash = '', token_expires_at = '', session_hash = ?, session_created_at = ?, session_last_seen_at = ?
WHERE id = 1 AND sealed_at = '' AND token_hash = ? AND token_hash <> '' AND token_expires_at > ?;

-- name: TouchSetupSession :execrows
UPDATE setup_state SET session_last_seen_at = ?
WHERE id = 1 AND session_hash = ? AND session_hash <> '';

-- name: EndSetupSession :exec
UPDATE setup_state SET session_hash = '', session_created_at = '', session_last_seen_at = ''
WHERE id = 1 AND session_hash = ?;
