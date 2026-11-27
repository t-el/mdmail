-- Per-recipient task-list state. A row exists only after the mailbox owner
-- toggled an item; otherwise the state written in the message applies.
-- (message_id identifies one stored copy, which belongs to exactly one user.)
CREATE TABLE checklist_state (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item       INTEGER NOT NULL CHECK (item >= 0 AND item < 500),
    checked    INTEGER NOT NULL CHECK (checked IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (message_id, item)
) STRICT;
CREATE INDEX checklist_state_user ON checklist_state(user_id);

-- Links a sender's Sent copy to the copies delivered to local recipients
-- on this server, recorded at submission time (never inferred from
-- Message-ID headers, which anyone can forge). Used only to show a local
-- sender their local recipients' checklist progress.
CREATE TABLE local_deliveries (
    sent_msg_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    rcpt_msg_id INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY (sent_msg_id, rcpt_msg_id)
) STRICT;
