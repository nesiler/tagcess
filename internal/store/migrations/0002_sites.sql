-- Site schema (architecture.md §3 site tables, ADR 0010). dns_records (F2-006) and
-- zitadel_owned_uris (F2-010) arrive with the migrations of the tasks that own them.

-- Ordered name lists (roles, target_roles) are JSON text columns: architecture.md §3 keeps
-- them on the site record itself, and only hosts need a table of their own, for the global
-- unique constraint (F2-002 AC2). Field-level validation is the validation layer's job (F2-003);
-- the CHECKs here only pin the enumerations and the kind pairing ADR 0010 defines.
CREATE TABLE sites (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                TEXT NOT NULL CHECK (kind IN ('role', 'open', 'system')),
    open_reason         TEXT CHECK (open_reason IS NULL OR open_reason IN ('intentional', 'transition')),
    system_template     TEXT CHECK (system_template IS NULL OR system_template IN ('zitadel', 'headscale', 'wireguard_ui', 'tagcess')),
    system_config       TEXT NOT NULL DEFAULT '',
    roles               TEXT NOT NULL DEFAULT '[]',
    target_roles        TEXT NOT NULL DEFAULT '[]',
    cert                TEXT NOT NULL,
    target_kind         TEXT NOT NULL CHECK (target_kind IN ('k8s', 'url')),
    target_url          TEXT NOT NULL DEFAULT '',
    target_tls_insecure INTEGER NOT NULL DEFAULT 0,
    magicdns            INTEGER NOT NULL DEFAULT 1,
    maintenance         INTEGER NOT NULL DEFAULT 0,
    note                TEXT NOT NULL DEFAULT '',
    owner               TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    CHECK ((kind = 'open') = (open_reason IS NOT NULL)),
    CHECK ((kind = 'system') = (system_template IS NOT NULL))
);

-- Hosts are ordered per site and unique across all sites: the same host cannot belong to a
-- second site (F2-002 AC2). ON DELETE CASCADE frees the hostnames when a site is deleted.
CREATE TABLE site_hosts (
    site_id  INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (site_id, position)
);

CREATE UNIQUE INDEX idx_site_hosts_hostname ON site_hosts (hostname);

-- API exemption rules (ADR 0011): only the two structural rule types, OR-combined, in order.
CREATE TABLE site_api_rules (
    site_id  INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    type     TEXT NOT NULL CHECK (type IN ('header_present', 'path_regex')),
    value    TEXT NOT NULL,
    PRIMARY KEY (site_id, position)
);

CREATE TABLE site_redirects (
    site_id     INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    source_path TEXT NOT NULL,
    target      TEXT NOT NULL,
    code        INTEGER NOT NULL CHECK (code IN (301, 302, 307, 308)),
    PRIMARY KEY (site_id, position)
);

CREATE TABLE site_headers (
    site_id  INTEGER NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    name     TEXT NOT NULL,
    value    TEXT NOT NULL,
    PRIMARY KEY (site_id, position)
);
