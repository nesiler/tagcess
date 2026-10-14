-- Durable Headscale policy revisions (H-04, A-03, ADR 0020, F3-005). Every applied or attempted
-- policy is stored as the exact raw HuJSON text with its hashes and outcome. parent_id, change_id
-- and rollback_of have no foreign key on purpose (0 = none): history outlives the rows it points at.
-- A revision is never edited or deleted. The one allowed change is the apply_status/apply_detail
-- transition from 'pending' to a final state, once; the triggers enforce this for every writer.
CREATE TABLE policy_revisions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id      INTEGER NOT NULL DEFAULT 0,
    base_hash      TEXT NOT NULL DEFAULT '',
    raw            TEXT NOT NULL,
    raw_hash       TEXT NOT NULL,
    canonical_hash TEXT NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('ui', 'sync', 'rollback', 'recovery', 'external')),
    actor          TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    validation     TEXT NOT NULL DEFAULT '{}',
    apply_status   TEXT NOT NULL DEFAULT 'pending'
                   CHECK (apply_status IN ('pending', 'applied', 'failed', 'unknown', 'dry_run')),
    apply_detail   TEXT NOT NULL DEFAULT '',
    change_id      INTEGER NOT NULL DEFAULT 0,
    rollback_of    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_policy_revisions_applied ON policy_revisions (apply_status, id);

CREATE TRIGGER policy_revisions_no_delete BEFORE DELETE ON policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'policy_revisions is append-only');
END;

CREATE TRIGGER policy_revisions_finish_once BEFORE UPDATE ON policy_revisions
WHEN OLD.apply_status <> 'pending'
  OR NEW.apply_status = 'pending'
  OR NEW.id IS NOT OLD.id
  OR NEW.parent_id IS NOT OLD.parent_id
  OR NEW.base_hash IS NOT OLD.base_hash
  OR NEW.raw IS NOT OLD.raw
  OR NEW.raw_hash IS NOT OLD.raw_hash
  OR NEW.canonical_hash IS NOT OLD.canonical_hash
  OR NEW.source IS NOT OLD.source
  OR NEW.actor IS NOT OLD.actor
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.reason IS NOT OLD.reason
  OR NEW.validation IS NOT OLD.validation
  OR NEW.change_id IS NOT OLD.change_id
  OR NEW.rollback_of IS NOT OLD.rollback_of
BEGIN
    SELECT RAISE(ABORT, 'policy_revisions content is immutable; a pending revision finishes once');
END;
