package store

import (
	"context"
	"strings"
	"time"
)

// QueueItem is one recipient awaiting remote delivery.
type QueueItem struct {
	RcptID    int64
	MsgID     int64
	UserID    *int64
	MailFrom  string
	Rcpt      string
	Domain    string
	Attempts  int
	CreatedAt time.Time
	Raw       []byte
}

// Enqueue stores a message for remote delivery to rcpts.
func (s *Store) Enqueue(ctx context.Context, userID *int64, mailFrom string, rcpts []string, raw []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO queue_messages(user_id, mail_from, raw, created_at) VALUES (?,?,?,?)`, userID, mailFrom, raw, now)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for _, r := range rcpts {
		dom := strings.ToLower(r[strings.LastIndexByte(r, '@')+1:])
		if _, err := tx.ExecContext(ctx, `INSERT INTO queue_rcpts(msg_id, rcpt, domain, next_attempt) VALUES (?,?,?,?)`, id, r, dom, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ClaimDue returns up to limit due recipients and leases them for lease so
// that they are not picked up again while being delivered.
func (s *Store) ClaimDue(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]*QueueItem, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT r.id, r.msg_id, m.user_id, m.mail_from, r.rcpt, r.domain, r.attempts, m.created_at, m.raw
		FROM queue_rcpts r JOIN queue_messages m ON m.id = r.msg_id
		WHERE r.next_attempt <= ? ORDER BY r.next_attempt LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	var items []*QueueItem
	for rows.Next() {
		var it QueueItem
		var created int64
		if err := rows.Scan(&it.RcptID, &it.MsgID, &it.UserID, &it.MailFrom, &it.Rcpt, &it.Domain, &it.Attempts, &created, &it.Raw); err != nil {
			_ = rows.Close()
			return nil, err
		}
		it.CreatedAt = time.Unix(created, 0)
		items = append(items, &it)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE queue_rcpts SET next_attempt = ? WHERE id = ?`, now.Add(lease).Unix(), it.RcptID); err != nil {
			return nil, err
		}
	}
	return items, tx.Commit()
}

// Delivered removes a recipient (and the message once no recipients remain).
func (s *Store) Delivered(ctx context.Context, rcptID, msgID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM queue_rcpts WHERE id = ?`, rcptID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM queue_messages WHERE id = ? AND NOT EXISTS (SELECT 1 FROM queue_rcpts WHERE msg_id = ?)`, msgID, msgID); err != nil {
		return err
	}
	return tx.Commit()
}

// Retry schedules another attempt.
func (s *Store) Retry(ctx context.Context, rcptID int64, next time.Time, lastErr string) error {
	if len(lastErr) > 1000 {
		lastErr = lastErr[:1000]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE queue_rcpts SET attempts = attempts + 1, next_attempt = ?, last_error = ? WHERE id = ?`, next.Unix(), lastErr, rcptID)
	return err
}

// QueueStatus summarises the outbound queue.
type QueueStatus struct {
	Rcpt      string
	Attempts  int
	Next      time.Time
	LastError string
}

// ListQueue returns every queued recipient.
func (s *Store) ListQueue(ctx context.Context) ([]QueueStatus, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rcpt, attempts, next_attempt, last_error FROM queue_rcpts ORDER BY next_attempt`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueueStatus
	for rows.Next() {
		var q QueueStatus
		var n int64
		if err := rows.Scan(&q.Rcpt, &q.Attempts, &n, &q.LastError); err != nil {
			return nil, err
		}
		q.Next = time.Unix(n, 0)
		out = append(out, q)
	}
	return out, rows.Err()
}
