-- The single Headscale maintenance row (H-07, ADR 0021). Every transition is one conditional
-- UPDATE, so two concurrent callers cannot both win; zero rows affected means the precondition
-- (state, request ID, host result) did not hold.

-- name: GetHeadscaleMaintenance :one
SELECT state, request_id, actor, started_at, updated_at, last_host_result, pending_reconcile, close_note
FROM headscale_maintenance
WHERE id = 1;

-- off -> active. A new maintenance starts clean: no host result, no reconcile intent, no old note.
-- name: StartHeadscaleMaintenance :execrows
UPDATE headscale_maintenance
SET state = 'active', request_id = ?1, actor = ?2, started_at = ?3, updated_at = ?3,
    last_host_result = '', pending_reconcile = 0, close_note = ''
WHERE id = 1 AND state = 'off';

-- active -> active with a new request ID, only when the helper's last result is terminal. The
-- maintenance keeps its start time.
-- name: RenewHeadscaleMaintenance :execrows
UPDATE headscale_maintenance
SET request_id = ?1, actor = ?2, updated_at = ?3, last_host_result = ''
WHERE id = 1 AND state = 'active'
  AND json_valid(last_host_result)
  AND json_extract(last_host_result, '$.status') IN ('succeeded', 'failed', 'interrupted');

-- name: SetHeadscaleMaintenanceHostResult :execrows
UPDATE headscale_maintenance
SET last_host_result = ?1, updated_at = ?2
WHERE id = 1 AND state = 'active' AND request_id = ?3;

-- name: HoldHeadscaleMaintenanceReconcile :exec
UPDATE headscale_maintenance
SET pending_reconcile = 1, updated_at = ?1
WHERE id = 1 AND state <> 'off';

-- active -> reconcile_pending for the request the caller saw.
-- name: ReconcilePendingHeadscaleMaintenance :execrows
UPDATE headscale_maintenance
SET state = 'reconcile_pending', updated_at = ?1
WHERE id = 1 AND state = 'active' AND request_id = ?2;

-- reconcile_pending -> off. The request is cleared; the note stays for the UI.
-- name: CloseHeadscaleMaintenance :execrows
UPDATE headscale_maintenance
SET state = 'off', request_id = '', actor = '', started_at = '', updated_at = ?1,
    last_host_result = '', pending_reconcile = 0, close_note = ?2
WHERE id = 1 AND state = 'reconcile_pending';
