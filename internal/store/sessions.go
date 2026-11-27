package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a web login session. Only the SHA-256 of the session token is stored.
type Session struct {
	IDHash    []byte
	UserID    int64
	CSRF      string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
	IP        string
	UserAgent string
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, x *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, expires_at, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)`,
		x.IDHash, x.UserID, x.CSRF, x.CreatedAt.Unix(), x.ExpiresAt.Unix(), x.LastSeen.Unix(), x.IP, x.UserAgent)
	return err
}

// SessionByHash loads a session by token hash.
func (s *Store) SessionByHash(ctx context.Context, h []byte) (*Session, error) {
	var x Session
	var c, e, l int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash, user_id, csrf_token, created_at, expires_at, last_seen, ip, user_agent FROM sessions WHERE id_hash = ?`, h).
		Scan(&x.IDHash, &x.UserID, &x.CSRF, &c, &e, &l, &x.IP, &x.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	x.CreatedAt, x.ExpiresAt, x.LastSeen = time.Unix(c, 0), time.Unix(e, 0), time.Unix(l, 0)
	return &x, nil
}

// TouchSession updates the last-seen time.
func (s *Store) TouchSession(ctx context.Context, h []byte, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, t.Unix(), h)
	return err
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, h []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, h)
	return err
}

// DeleteUserSessions removes all sessions of a user except the one given (may be nil).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, except []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id_hash IS NOT ?`, userID, except)
	return err
}

// PurgeSessions deletes expired and idle sessions.
func (s *Store) PurgeSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`, now.Unix(), now.Add(-idle).Unix())
	return err
}
