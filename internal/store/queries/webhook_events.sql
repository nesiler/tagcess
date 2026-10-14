-- Replay protection for webhook events (Y-01.3, security.md 6.3). The Zitadel Actions v2 payload
-- has no event id, so the caller builds event_id from aggregateID and sequence; an event seen in
-- the last 24 hours is a replay and must not trigger a reconcile. Rows older than the window are
-- overwritten by a fresh claim and cleaned up below.

-- name: ClaimWebhookEvent :execrows
INSERT INTO webhook_events (event_id, received_at)
SELECT sqlc.arg(event_id), sqlc.arg(received_at)
WHERE NOT EXISTS (
    SELECT 1 FROM webhook_events w
    WHERE w.event_id = sqlc.arg(event_id) AND w.received_at >= sqlc.arg(fresh_since)
)
ON CONFLICT (event_id) DO UPDATE SET received_at = excluded.received_at;

-- Retention: the table keeps only the last 24 hours (architecture.md 3).
-- name: DeleteWebhookEventsBefore :execrows
DELETE FROM webhook_events WHERE received_at < ?;
