package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AppPassword is a per-device credential for SMTP submission. Only the
// SHA-256 of the 128-bit random secret is stored.
type AppPassword struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// CreateAppPassword stores a new app password hash.
func (s *Store) CreateAppPassword(ctx context.Context, userID int64, name string, hash []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO app_passwords(user_id, name, hash, created_at) VALUES (?,?,?,?)`, userID, name, hash, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MatchAppPassword checks whether hash belongs to userID and records its use.
func (s *Store) MatchAppPassword(ctx context.Context, userID int64, hash []byte) (bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM app_passwords WHERE user_id = ? AND hash = ?`, userID, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE app_passwords SET last_used = ? WHERE id = ?`, time.Now().Unix(), id)
	return true, err
}

// ListAppPasswords lists a user's app passwords.
func (s *Store) ListAppPasswords(ctx context.Context, userID int64) ([]AppPassword, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, last_used FROM app_passwords WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppPassword{}
	for rows.Next() {
		var a AppPassword
		var c, l int64
		if err := rows.Scan(&a.ID, &a.Name, &c, &l); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(c, 0).UTC()
		if l > 0 {
			a.LastUsed = time.Unix(l, 0).UTC()
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAppPassword revokes an app password.
func (s *Store) DeleteAppPassword(ctx context.Context, userID, id int64) error {
	return s.execOne(ctx, `DELETE FROM app_passwords WHERE id = ? AND user_id = ?`, id, userID)
}
