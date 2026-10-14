-- Persistent incomplete-draft query contract (F4-009, R3 B-04/B-08, R3-AC-13, ADR 0030 proposed).
-- A draft is the incomplete, not-yet-applied site proposal for one HOST: one row per (cluster, host),
-- never a SiteStore row. Saving, updating or deleting a draft touches only k8s_drafts and
-- k8s_draft_routes, so a stored proposal can never widen the running access settings (fail safe).
--
-- Column groups:
--   provenance (discovery-owned): profile_version, snapshot_id, observed_at
--   choices (user-owned):         access_choice, roles, target, cert, note
--   review request:               review_state, review_reason, review_candidates, review_default
-- UpsertK8sDraft writes every column of a draft; UpdateK8sDraftProvenance refreshes only the
-- discovery-owned group so a later snapshot/profile never overwrites the user's choices. created_at
-- is set once and never rewritten.

-- name: UpsertK8sDraft :one
INSERT INTO k8s_drafts (
    cluster, host, profile_version, snapshot_id, observed_at,
    access_choice, roles, target, cert, note,
    review_state, review_reason, review_candidates, review_default,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (cluster, host) DO UPDATE SET
    profile_version   = excluded.profile_version,
    snapshot_id       = excluded.snapshot_id,
    observed_at       = excluded.observed_at,
    access_choice     = excluded.access_choice,
    roles             = excluded.roles,
    target            = excluded.target,
    cert              = excluded.cert,
    note              = excluded.note,
    review_state      = excluded.review_state,
    review_reason     = excluded.review_reason,
    review_candidates = excluded.review_candidates,
    review_default    = excluded.review_default,
    updated_at        = excluded.updated_at
RETURNING id, cluster, host, profile_version, snapshot_id, observed_at,
          access_choice, roles, target, cert, note,
          review_state, review_reason, review_candidates, review_default,
          created_at, updated_at;

-- The draft is addressed by its host identity (cluster, host), never by host alone: the same host in
-- another cluster is a different draft (F4-010 AC7).
-- name: GetK8sDraft :one
SELECT id, cluster, host, profile_version, snapshot_id, observed_at,
       access_choice, roles, target, cert, note,
       review_state, review_reason, review_candidates, review_default,
       created_at, updated_at
FROM k8s_drafts
WHERE cluster = ? AND host = ?;

-- Discovery refresh: only the provenance of an existing draft changes, so the user's choices and the
-- review request stay exactly as the user left them (no read-merge-write in callers).
-- name: UpdateK8sDraftProvenance :one
UPDATE k8s_drafts
SET profile_version = ?, snapshot_id = ?, observed_at = ?, updated_at = ?
WHERE cluster = ? AND host = ?
RETURNING id, cluster, host, profile_version, snapshot_id, observed_at,
          access_choice, roles, target, cert, note,
          review_state, review_reason, review_candidates, review_default,
          created_at, updated_at;

-- Deleting a draft removes only that exact (cluster, host) row; its routes follow through the
-- k8s_draft_routes ON DELETE CASCADE. Other clusters' same-host draft is untouched.
-- name: DeleteK8sDraft :execrows
DELETE FROM k8s_drafts
WHERE cluster = ? AND host = ?;

-- Route provenance: one row per Ingress route of the draft. The identity (draft_id, namespace,
-- ingress_uid, path, path_type) is immutable; resource_version/backend/class/name/observed_at are
-- mutable observations, so a re-read updates them in place instead of failing on the unique key.
-- name: UpsertK8sDraftRoute :one
INSERT INTO k8s_draft_routes (
    draft_id, namespace, ingress_name, ingress_uid, resource_version,
    path, path_type, backend_service, backend_port, class, observed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (draft_id, namespace, ingress_uid, path, path_type) DO UPDATE SET
    ingress_name     = excluded.ingress_name,
    resource_version = excluded.resource_version,
    backend_service  = excluded.backend_service,
    backend_port     = excluded.backend_port,
    class            = excluded.class,
    observed_at      = excluded.observed_at
RETURNING id, draft_id, namespace, ingress_name, ingress_uid, resource_version,
          path, path_type, backend_service, backend_port, class, observed_at;

-- The draft's provenance, deterministically ordered so a golden/list test is stable.
-- name: ListK8sDraftRoutes :many
SELECT id, draft_id, namespace, ingress_name, ingress_uid, resource_version,
       path, path_type, backend_service, backend_port, class, observed_at
FROM k8s_draft_routes
WHERE draft_id = ?
ORDER BY namespace, ingress_uid, path, path_type;

-- Full provenance refresh: clear one draft's routes so the current observation set can be reinserted.
-- name: DeleteK8sDraftRoutes :execrows
DELETE FROM k8s_draft_routes
WHERE draft_id = ?;
