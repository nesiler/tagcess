-- The redirect URI set O that tagcess last wrote to the oauth2-proxy app in Zitadel (ADR 0012,
-- F2-010). One row at most: no row means the first import has not happened yet, an empty list
-- means tagcess owns no URI. The list is JSON text (ordered, like the site name lists).
CREATE TABLE zitadel_owned_uris (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    uris       TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
