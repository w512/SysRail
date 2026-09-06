CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    event           TEXT    NOT NULL,
    agent           TEXT    NOT NULL DEFAULT '',
    session         TEXT    NOT NULL DEFAULT '',
    capability      TEXT    NOT NULL DEFAULT '',
    resource        TEXT    NOT NULL DEFAULT '',
    arguments_hash  TEXT    NOT NULL DEFAULT '',
    arguments       TEXT    NOT NULL DEFAULT '',
    policy_decision TEXT    NOT NULL DEFAULT '',
    policy_rule     TEXT    NOT NULL DEFAULT '',
    request_id      TEXT    NOT NULL DEFAULT '',
    result          TEXT    NOT NULL,
    error_code      TEXT    NOT NULL DEFAULT '',
    error_message   TEXT    NOT NULL DEFAULT '',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    actor           TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_agent ON audit_log (agent, id);
CREATE INDEX audit_log_request ON audit_log (request_id);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TABLE requests (
    id              TEXT PRIMARY KEY,
    agent           TEXT NOT NULL,
    session         TEXT NOT NULL DEFAULT '',
    capability      TEXT NOT NULL,
    resource        TEXT NOT NULL DEFAULT '',
    args            TEXT NOT NULL,
    args_hash       TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    risk            TEXT NOT NULL,
    status          TEXT NOT NULL,
    policy_rule     TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    created_at      TEXT NOT NULL,
    expires_at      TEXT,
    decided_at      TEXT,
    decided_by      TEXT NOT NULL DEFAULT '',
    decision_note   TEXT NOT NULL DEFAULT '',
    completed_at    TEXT,
    result          TEXT,
    error           TEXT
);

CREATE UNIQUE INDEX requests_idempotency ON requests (agent, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX requests_status ON requests (status, created_at);
