-- Sub-records of a site are rewritten as a whole inside the site write's transaction, so every
-- table only needs insert, list and clear. All lists are stored and returned in position order.

-- name: InsertSiteHost :exec
INSERT INTO site_hosts (site_id, position, hostname) VALUES (?, ?, ?);

-- name: ListSiteHosts :many
SELECT site_id, position, hostname FROM site_hosts WHERE site_id = ? ORDER BY position;

-- name: DeleteSiteHosts :exec
DELETE FROM site_hosts WHERE site_id = ?;

-- GetHostOwner backs the hostname ownership check (F2-002 AC2): the site_hosts.hostname unique
-- index is the constraint, this query turns a violation into a typed refusal before any write.
-- name: GetHostOwner :one
SELECT site_id FROM site_hosts WHERE hostname = ?;

-- name: InsertSiteAPIRule :exec
INSERT INTO site_api_rules (site_id, position, type, value) VALUES (?, ?, ?, ?);

-- name: ListSiteAPIRules :many
SELECT site_id, position, type, value FROM site_api_rules WHERE site_id = ? ORDER BY position;

-- name: DeleteSiteAPIRules :exec
DELETE FROM site_api_rules WHERE site_id = ?;

-- name: InsertSiteRedirect :exec
INSERT INTO site_redirects (site_id, position, source_path, target, code) VALUES (?, ?, ?, ?, ?);

-- name: ListSiteRedirects :many
SELECT site_id, position, source_path, target, code FROM site_redirects WHERE site_id = ? ORDER BY position;

-- name: DeleteSiteRedirects :exec
DELETE FROM site_redirects WHERE site_id = ?;

-- name: InsertSiteHeader :exec
INSERT INTO site_headers (site_id, position, name, value) VALUES (?, ?, ?, ?);

-- name: ListSiteHeaders :many
SELECT site_id, position, name, value FROM site_headers WHERE site_id = ? ORDER BY position;

-- name: DeleteSiteHeaders :exec
DELETE FROM site_headers WHERE site_id = ?;
