package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// MaxChecklistItem is the exclusive upper bound of a task-list item index
// (mirrors mdrender.MaxTasks and the CHECK constraint in the schema).
const MaxChecklistItem = 500

// ChecklistState returns the stored task-list overrides of one message,
// keyed by item index. Only the owner's own copy is ever read: a message
// that does not belong to userID yields ErrNotFound.
func (s *Store) ChecklistState(ctx context.Context, userID, msgID int64) (map[int]bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE id = ? AND user_id = ?`, msgID, userID).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT item, checked FROM checklist_state WHERE message_id = ? AND user_id = ?`, msgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var item, checked int
		if err := rows.Scan(&item, &checked); err != nil {
			return nil, err
		}
		out[item] = checked == 1
	}
	return out, rows.Err()
}

// SetChecklistItem records the state of one task-list item. The write is
// conditional on userID owning msgID in the same statement, so a request
// for someone else's message changes nothing and returns ErrNotFound.
func (s *Store) SetChecklistItem(ctx context.Context, userID, msgID int64, item int, checked bool) error {
	if item < 0 || item >= MaxChecklistItem {
		return errors.New("store: checklist item out of range")
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO checklist_state(message_id, user_id, item, checked, updated_at)
		SELECT id, user_id, ?, ?, ? FROM messages WHERE id = ? AND user_id = ?
		ON CONFLICT(message_id, item) DO UPDATE SET checked = excluded.checked, updated_at = excluded.updated_at
		WHERE checklist_state.user_id = excluded.user_id`,
		item, b2i(checked), time.Now().Unix(), msgID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// LinkLocalDelivery records that rcptMsgID is the copy of sentMsgID that was
// delivered to a local recipient. Both rows must already exist.
func (s *Store) LinkLocalDelivery(ctx context.Context, sentMsgID, rcptMsgID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO local_deliveries(sent_msg_id, rcpt_msg_id) VALUES (?, ?)`, sentMsgID, rcptMsgID)
	return err
}

// IsLocallyDelivered reports whether the owner's message msgID was delivered
// locally from a Sent copy on this server (i.e. its sender can see its
// checklist progress when sharing is enabled).
func (s *Store) IsLocallyDelivered(ctx context.Context, userID, msgID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_deliveries l JOIN messages r ON r.id = l.rcpt_msg_id
		WHERE l.rcpt_msg_id = ? AND r.user_id = ?`, msgID, userID).Scan(&n)
	return n > 0, err
}

// RecipientChecklist is a local recipient's progress on a sent message.
type RecipientChecklist struct {
	Email   string
	Checked map[int]bool // stored overrides only
}

// RecipientChecklists returns, for a message in the sender's own mailbox,
// the checklist overrides of each local recipient copy linked to it at
// submission time. Copies the recipient deleted are gone (ON DELETE
// CASCADE). A message not owned by senderID yields no rows.
func (s *Store) RecipientChecklists(ctx context.Context, senderID, sentMsgID int64) ([]RecipientChecklist, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, u.email, c.item, c.checked
		FROM local_deliveries l
		JOIN messages s ON s.id = l.sent_msg_id AND s.user_id = ?
		JOIN messages r ON r.id = l.rcpt_msg_id
		JOIN users u ON u.id = r.user_id
		LEFT JOIN checklist_state c ON c.message_id = r.id AND c.user_id = r.user_id
		WHERE l.sent_msg_id = ?
		ORDER BY u.email, r.id, c.item`, senderID, sentMsgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecipientChecklist{}
	idx := map[int64]int{}
	for rows.Next() {
		var rid int64
		var email string
		var item, checked sql.Null[int]
		if err := rows.Scan(&rid, &email, &item, &checked); err != nil {
			return nil, err
		}
		i, ok := idx[rid]
		if !ok {
			i = len(out)
			idx[rid] = i
			out = append(out, RecipientChecklist{Email: email, Checked: map[int]bool{}})
		}
		if item.Valid && checked.Valid {
			out[i].Checked[item.V] = checked.V == 1
		}
	}
	return out, rows.Err()
}
