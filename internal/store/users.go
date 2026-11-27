package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// User is an account.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	TOTPSecret   []byte // encrypted at rest
	TOTPEnabled  bool
	IsAdmin      bool
	Disabled     bool
	FailedLogins int
	LockedUntil  time.Time
	CreatedAt    time.Time
}

const userCols = `id, email, password_hash, totp_secret, totp_enabled, is_admin, disabled, failed_logins, locked_until, created_at`

func scanUser(r interface{ Scan(...any) error }) (*User, error) {
	var u User
	var totp, admin, dis int
	var locked, created int64
	if err := r.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.TOTPSecret, &totp, &admin, &dis, &u.FailedLogins, &locked, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.TOTPEnabled, u.IsAdmin, u.Disabled = totp == 1, admin == 1, dis == 1
	u.LockedUntil, u.CreatedAt = time.Unix(locked, 0), time.Unix(created, 0)
	return &u, nil
}

// CreateUser inserts a new account.
func (s *Store) CreateUser(ctx context.Context, email, hash string, admin bool) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)`,
		strings.ToLower(email), hash, b2i(admin), time.Now().Unix())
	if isUnique(err) {
		return 0, ErrExists
	}
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UserByEmail looks up an account by address (case-insensitive).
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, strings.ToLower(email)))
}

// UserByID looks up an account by id.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// ListUsers returns all accounts ordered by email.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword replaces the password hash and clears any lockout.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	return s.execOne(ctx, `UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = 0 WHERE id = ?`, hash, id)
}

// SetDisabled enables or disables an account.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	return s.execOne(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, b2i(disabled), id)
}

// SetTOTP stores the (encrypted) TOTP secret and its enabled state. A nil
// secret removes TOTP.
func (s *Store) SetTOTP(ctx context.Context, id int64, secret []byte, enabled bool) error {
	return s.execOne(ctx, `UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, secret, b2i(enabled && secret != nil), id)
}

// RecordLoginFailure increments the failure counter and locks the account for
// an exponentially growing period once threshold is reached. It returns the
// lock expiry (zero when not locked).
func (s *Store) RecordLoginFailure(ctx context.Context, id int64, threshold int, base, maxLock time.Duration) (time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ? RETURNING failed_logins`, id).Scan(&n); err != nil {
		return time.Time{}, err
	}
	var until time.Time
	if n >= threshold {
		d := base
		for i := threshold; i < n && d < maxLock; i++ {
			d *= 2
		}
		if d > maxLock {
			d = maxLock
		}
		until = time.Now().Add(d)
		if _, err := tx.ExecContext(ctx, `UPDATE users SET locked_until = ? WHERE id = ?`, until.Unix(), id); err != nil {
			return time.Time{}, err
		}
	}
	return until, tx.Commit()
}

// ResetLoginFailures clears the failure counter after a successful login.
func (s *Store) ResetLoginFailures(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?`, id)
	return err
}

// DeleteUser removes an account and all of its mail.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	return s.execOne(ctx, `DELETE FROM users WHERE id = ?`, id)
}
