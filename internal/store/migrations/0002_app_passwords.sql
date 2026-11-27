CREATE TABLE app_passwords (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    hash       BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used  INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX app_passwords_user ON app_passwords(user_id);
