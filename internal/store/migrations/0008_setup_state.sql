-- Setup token and setup session (setup-flow.md §2, I-5). One row, always present. Only hashes are
-- stored: the plain token lives only in the runtime file for the install script, the plain session
-- value only in the cookie. Empty strings mean "none". Times are the audit time format.
CREATE TABLE setup_state (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash            TEXT NOT NULL DEFAULT '',
    token_expires_at      TEXT NOT NULL DEFAULT '',
    session_hash          TEXT NOT NULL DEFAULT '',
    session_created_at    TEXT NOT NULL DEFAULT '',
    session_last_seen_at  TEXT NOT NULL DEFAULT '',
    sealed_at             TEXT NOT NULL DEFAULT '',
    sealed_identity       TEXT NOT NULL DEFAULT '',
    reopen_count          INTEGER NOT NULL DEFAULT 0
);

INSERT INTO setup_state (id) VALUES (1);
