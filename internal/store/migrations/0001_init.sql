CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    totp_secret     BLOB,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    id_hash     BLOB    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    ip          TEXT    NOT NULL,
    user_agent  TEXT    NOT NULL
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE messages (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder       TEXT    NOT NULL,
    message_id   TEXT    NOT NULL DEFAULT '',
    subject      TEXT    NOT NULL DEFAULT '',
    from_addr    TEXT    NOT NULL DEFAULT '',
    to_addrs     TEXT    NOT NULL DEFAULT '',
    date         INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    seen         INTEGER NOT NULL DEFAULT 0,
    flagged      INTEGER NOT NULL DEFAULT 0,
    has_attach   INTEGER NOT NULL DEFAULT 0,
    auth_summary TEXT    NOT NULL DEFAULT '',
    raw          BLOB    NOT NULL,
    created_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX messages_user_folder ON messages(user_id, folder, id DESC);

CREATE TABLE queue_messages (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    mail_from  TEXT    NOT NULL,
    raw        BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE queue_rcpts (
    id           INTEGER PRIMARY KEY,
    msg_id       INTEGER NOT NULL REFERENCES queue_messages(id) ON DELETE CASCADE,
    rcpt         TEXT    NOT NULL,
    domain       TEXT    NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL,
    last_error   TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX queue_rcpts_due ON queue_rcpts(next_attempt);

CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    user_id INTEGER,
    event   TEXT    NOT NULL,
    ip      TEXT    NOT NULL DEFAULT '',
    detail  TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX audit_user_ts ON audit_log(user_id, ts DESC);
