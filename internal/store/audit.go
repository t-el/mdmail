package store

import (
	"context"
	"time"
)

// AuditEntry is a security-relevant event.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	UserID *int64    `json:"-"`
	Event  string    `json:"event"`
	IP     string    `json:"ip"`
	Detail string    `json:"detail"`
}

// AddAudit appends an audit entry.
func (s *Store) AddAudit(ctx context.Context, e *AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts, user_id, event, ip, detail) VALUES (?,?,?,?,?)`, e.Time.Unix(), e.UserID, e.Event, e.IP, e.Detail)
	return err
}

// ListAudit returns the newest entries for a user.
func (s *Store) ListAudit(ctx context.Context, userID int64, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, event, ip, detail FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Event, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit deletes entries older than t.
func (s *Store) PruneAudit(ctx context.Context, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts < ?`, t.Unix())
	return err
}
