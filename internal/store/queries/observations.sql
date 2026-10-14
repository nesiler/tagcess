-- Measurement observation store (F4-017, K-02/K-03/P-02, R3 B-05/B-06, ADR 0031/0032 proposed).
-- One row per measurement key (category, site, host, route, source, vantage, endpoint, sni, path);
-- the schema's unique index keeps categories apart and makes a second vantage/endpoint/SNI/path its
-- own observation. No token/credential/body/header column exists; the model carries metadata only.
--
-- LAST-GOOD RULE (0007_f4.sql): a row has two column groups. An attempt that met its category's
-- expectation writes BOTH groups in one UPSERT (UpsertObservationGood); any other attempt writes
-- ONLY the attempt group and never refreshes the good evidence (UpsertObservationFailed). The
-- first-ever failed attempt inserts a row with observed_at = '' (no good observation yet). An
-- unverifiable/expired leaf stays readable from last_tls_* as a diagnostic while tls_not_after
-- keeps the last VERIFIED leaf.
--
-- Timestamps are TEXT compared lexicographically. Callers MUST write the repo's canonical
-- fixed-format UTC ("2006-01-02T15:04:05.000Z", fixed-width milliseconds ending in Z) so text order
-- is chronological order. last_error is caller-written free text: callers must truncate and
-- sanitize it (no raw response body/headers/tokens).

-- A good attempt: the category expectation was met. Both the last-good evidence group and the
-- attempt group are written in one statement, the attempt is marked ok and any earlier attempt error
-- is cleared. The reused named args keep the two groups consistent: last_http_status mirrors
-- http_status and the verified TLS attempt values mirror tls_not_after/tls_fingerprint.
-- name: UpsertObservationGood :one
INSERT INTO observations (
    category, site, host, route, source, vantage, endpoint, sni, path, backend,
    observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
    risk_finding, risk_context, unscanned_scope,
    last_attempt_at, success, last_result, last_http_status, last_error,
    last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
) VALUES (
    sqlc.arg(category), sqlc.arg(site), sqlc.arg(host), sqlc.arg(route), sqlc.arg(source),
    sqlc.arg(vantage), sqlc.arg(endpoint), sqlc.arg(sni), sqlc.arg(path), sqlc.arg(backend),
    sqlc.arg(observed_at), sqlc.arg(http_status), sqlc.arg(gate_class), sqlc.arg(tls_not_after), sqlc.arg(tls_fingerprint),
    sqlc.arg(risk_finding), sqlc.arg(risk_context), sqlc.arg(unscanned_scope),
    sqlc.arg(last_attempt_at), 1, 'ok', sqlc.arg(http_status), '',
    sqlc.arg(tls_not_after), sqlc.arg(tls_fingerprint), ''
)
ON CONFLICT (category, site, host, route, source, vantage, endpoint, sni, path) DO UPDATE SET
    backend = excluded.backend,
    observed_at = excluded.observed_at,
    http_status = excluded.http_status,
    gate_class = excluded.gate_class,
    tls_not_after = excluded.tls_not_after,
    tls_fingerprint = excluded.tls_fingerprint,
    risk_finding = excluded.risk_finding,
    risk_context = excluded.risk_context,
    unscanned_scope = excluded.unscanned_scope,
    last_attempt_at = excluded.last_attempt_at,
    success = 1,
    last_result = 'ok',
    last_http_status = excluded.http_status,
    last_error = '',
    last_tls_not_after = excluded.tls_not_after,
    last_tls_fingerprint = excluded.tls_fingerprint,
    last_tls_verify_error = ''
RETURNING id, category, site, host, route, source, vantage, endpoint, sni, path, backend,
          observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
          risk_finding, risk_context, unscanned_scope,
          last_attempt_at, success, last_result, last_http_status, last_error,
          last_tls_not_after, last_tls_fingerprint, last_tls_verify_error;

-- A failed attempt (unexpected status, timeout, refused, guard/policy reject, source read error,
-- unverifiable or expired leaf): ONLY the attempt group changes. On a first-ever failure the good
-- group keeps its column defaults (observed_at = ''), so there is a row but no good observation.
-- The diagnostic leaf values (if any) are the attempt's own and never refresh tls_not_after.
-- A last_result of 'ok' or '' would contradict success = 0 (schema rule: success is 1 iff
-- last_result = 'ok'), so such a call writes nothing and returns sql.ErrNoRows. The WHERE is the
-- guard (SQLite needs a WHERE on INSERT ... SELECT before ON CONFLICT); sqlc does not expand
-- sqlc.arg() in that WHERE, so it names last_result by position: ?11 is the 11th argument above.
-- name: UpsertObservationFailed :one
INSERT INTO observations (
    category, site, host, route, source, vantage, endpoint, sni, path,
    last_attempt_at, last_result, last_http_status, last_error,
    last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
) SELECT
    sqlc.arg(category), sqlc.arg(site), sqlc.arg(host), sqlc.arg(route), sqlc.arg(source),
    sqlc.arg(vantage), sqlc.arg(endpoint), sqlc.arg(sni), sqlc.arg(path),
    sqlc.arg(last_attempt_at), sqlc.arg(last_result), sqlc.arg(last_http_status), sqlc.arg(last_error),
    sqlc.arg(last_tls_not_after), sqlc.arg(last_tls_fingerprint), sqlc.arg(last_tls_verify_error)
WHERE ?11 NOT IN ('', 'ok')
ON CONFLICT (category, site, host, route, source, vantage, endpoint, sni, path) DO UPDATE SET
    last_attempt_at = excluded.last_attempt_at,
    success = 0,
    last_result = excluded.last_result,
    last_http_status = excluded.last_http_status,
    last_error = excluded.last_error,
    last_tls_not_after = excluded.last_tls_not_after,
    last_tls_fingerprint = excluded.last_tls_fingerprint,
    last_tls_verify_error = excluded.last_tls_verify_error
RETURNING id, category, site, host, route, source, vantage, endpoint, sni, path, backend,
          observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
          risk_finding, risk_context, unscanned_scope,
          last_attempt_at, success, last_result, last_http_status, last_error,
          last_tls_not_after, last_tls_fingerprint, last_tls_verify_error;

-- The observation of one exact measurement key. Freshness is derived by the caller from observed_at
-- (last good) versus last_attempt_at/last_result; it is not stored.
-- name: GetObservationByKey :one
SELECT id, category, site, host, route, source, vantage, endpoint, sni, path, backend,
       observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
       risk_finding, risk_context, unscanned_scope,
       last_attempt_at, success, last_result, last_http_status, last_error,
       last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
FROM observations
WHERE category = ? AND site = ? AND host = ? AND route = ? AND source = ?
  AND vantage = ? AND endpoint = ? AND sni = ? AND path = ?;

-- Every observation of a site for the dashboard, in a stable order. Each row keeps its own
-- source/vantage/endpoint/SNI/path and both time groups.
-- name: ListObservationsBySite :many
SELECT id, category, site, host, route, source, vantage, endpoint, sni, path, backend,
       observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
       risk_finding, risk_context, unscanned_scope,
       last_attempt_at, success, last_result, last_http_status, last_error,
       last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
FROM observations
WHERE site = ?
ORDER BY category, host, route, source, vantage, endpoint, sni, path, id;

-- The probe rows one runner vantage owns (target, Caddy gate and TLS of the net_probe source), for
-- the runner's own cleanup of keys it no longer measures (changed path/endpoint, removed site).
-- name: ListProbeObservationsByVantage :many
SELECT id, category, site, host, route, source, vantage, endpoint, sni, path, backend,
       observed_at, http_status, gate_class, tls_not_after, tls_fingerprint,
       risk_finding, risk_context, unscanned_scope,
       last_attempt_at, success, last_result, last_http_status, last_error,
       last_tls_not_after, last_tls_fingerprint, last_tls_verify_error
FROM observations
WHERE source = 'net_probe' AND vantage = ? AND category IN ('target', 'caddy_gate', 'tls')
ORDER BY id;

-- Removes one stale observation row by id.
-- name: DeleteObservation :execrows
DELETE FROM observations WHERE id = ?;
