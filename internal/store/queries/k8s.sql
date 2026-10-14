-- Persistent snapshot query contract (F4-042, R3 B-02/B-08, ADR 0030 proposed). k8s_snapshots holds
-- only successful, complete reads; every read attempt lives in k8s_snapshot_attempts. A reader
-- publishes a snapshot and its "ok" attempt in ONE transaction (InsertK8sSnapshot +
-- InsertK8sSnapshotAttempt with snapshot_id, then commit), so a rolled-back read leaves no partial
-- snapshot and a failure can never read back as an empty current snapshot. The current snapshot of a
-- (scope, profile_version) is the latest row of that exact pair: readers must filter by the pair so an
-- old profile/scope version is never served as the new version's current snapshot. Payload is the
-- secretless discovery JSON (no credential/token/body/header column exists in the schema).
--
-- observed_at/attempted_at are TEXT compared lexicographically. Callers MUST write fixed-format UTC
-- ("2006-01-02T15:04:05.000Z", the repo's canonical clock format, fixed-width milliseconds ending in
-- Z) so the text order is the chronological order; a mixed format (e.g. fractional seconds or a
-- non-UTC offset) would misorder because '.' < 'Z'.

-- name: InsertK8sSnapshot :one
INSERT INTO k8s_snapshots (scope, profile_version, observed_at, payload)
VALUES (?, ?, ?, ?)
RETURNING id, scope, profile_version, observed_at, payload;

-- name: GetK8sSnapshot :one
SELECT id, scope, profile_version, observed_at, payload
FROM k8s_snapshots
WHERE id = ?;

-- The exact-pair filter is the contract: a v1 snapshot never answers a v2 query (F4-007 AC4).
-- name: LatestK8sSnapshot :one
SELECT id, scope, profile_version, observed_at, payload
FROM k8s_snapshots
WHERE scope = ? AND profile_version = ?
ORDER BY observed_at DESC, id DESC
LIMIT 1;

-- An "ok" attempt links the snapshot row written in the same transaction; a "failed" attempt passes
-- a NULL snapshot_id (schema CHECK) and keeps a sanitized error_class plus a truncated, sanitized
-- error text. Callers must not write raw response bodies/headers/tokens.
-- name: InsertK8sSnapshotAttempt :one
INSERT INTO k8s_snapshot_attempts (scope, profile_version, attempted_at, outcome, error_class, error, snapshot_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, scope, profile_version, attempted_at, outcome, error_class, error, snapshot_id;

-- The last read attempt of the exact (scope, profile_version); readers derive staleness from this
-- being failed or newer than the current snapshot's observed_at. Failure never rewrites the snapshot.
-- name: LatestK8sSnapshotAttempt :one
SELECT id, scope, profile_version, attempted_at, outcome, error_class, error, snapshot_id
FROM k8s_snapshot_attempts
WHERE scope = ? AND profile_version = ?
ORDER BY attempted_at DESC, id DESC
LIMIT 1;

-- On a scope/profile change the new pair has no snapshot yet (LatestK8sSnapshot returns ErrNoRows).
-- F4-007 AC4 must then show the previous scope's data as explicit OLD data without serving it as the
-- new pair's current snapshot. This returns the latest snapshot of any OTHER (scope,
-- profile_version) pair, and ErrNoRows when no other pair exists yet. Same fixed-format UTC ordering
-- rule as above.
-- name: LatestK8sSnapshotOtherPair :one
SELECT id, scope, profile_version, observed_at, payload
FROM k8s_snapshots
WHERE NOT (scope = ? AND profile_version = ?)
ORDER BY observed_at DESC, id DESC
LIMIT 1;
