-- One row per reconcile run (Y-05.2). The change pipeline writes the row for the run it drove; the
-- orchestrator writes one for a run that failed before reaching the pipeline.

-- name: InsertSyncRun :one
INSERT INTO sync_runs (started_at, trigger, result, diff_summary)
VALUES (?, ?, ?, ?)
RETURNING id, started_at, trigger, result, diff_summary;

-- The sync screen shows the most recent run's time, trigger and result (Y-05.2). Fixed-width
-- timestamps make the text ordering chronological; id breaks a tie between same-millisecond runs.
-- name: GetLatestSyncRun :one
SELECT id, started_at, trigger, result, diff_summary
FROM sync_runs
ORDER BY started_at DESC, id DESC
LIMIT 1;
