-- Free-text note for system records such as retention summaries.
ALTER TABLE audit_log ADD COLUMN note TEXT NOT NULL DEFAULT '';

-- Deletes from audit_log are allowed only while a row exists here. Retention
-- inserts it, deletes archived records, and removes it in one transaction, so
-- accidental deletes still fail.
CREATE TABLE audit_prune_guard (active INTEGER NOT NULL);

DROP TRIGGER audit_log_no_delete;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
WHEN NOT EXISTS (SELECT 1 FROM audit_prune_guard)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
