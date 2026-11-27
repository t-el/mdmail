package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Standard folders. Custom folders are not supported; Archive covers filing.
const (
	FolderInbox   = "INBOX"
	FolderSent    = "Sent"
	FolderArchive = "Archive"
	FolderJunk    = "Junk"
	FolderTrash   = "Trash"
)

// Folders lists the folders in display order.
var Folders = []string{FolderInbox, FolderSent, FolderArchive, FolderJunk, FolderTrash}

// ValidFolder reports whether f is a known folder.
func ValidFolder(f string) bool {
	for _, x := range Folders {
		if x == f {
			return true
		}
	}
	return false
}

// Message is a stored message with its indexed metadata.
type Message struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"-"`
	Folder      string    `json:"folder"`
	MessageID   string    `json:"message_id"`
	Subject     string    `json:"subject"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Date        time.Time `json:"date"`
	Size        int64     `json:"size"`
	Seen        bool      `json:"seen"`
	Flagged     bool      `json:"flagged"`
	HasAttach   bool      `json:"has_attachments"`
	AuthSummary string    `json:"auth_summary"`
	Raw         []byte    `json:"-"`
}

// InsertMessage stores a message and returns its id.
func (s *Store) InsertMessage(ctx context.Context, m *Message) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO messages(user_id, folder, message_id, subject, from_addr, to_addrs, date, size, seen, flagged, has_attach, auth_summary, raw, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.UserID, m.Folder, m.MessageID, m.Subject, m.From, m.To, m.Date.Unix(), int64(len(m.Raw)), b2i(m.Seen), b2i(m.Flagged), b2i(m.HasAttach), m.AuthSummary, m.Raw, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const msgCols = `id, user_id, folder, message_id, subject, from_addr, to_addrs, date, size, seen, flagged, has_attach, auth_summary`

func scanMsg(r interface{ Scan(...any) error }, withRaw bool) (*Message, error) {
	var m Message
	var date int64
	var seen, flagged, att int
	dst := []any{&m.ID, &m.UserID, &m.Folder, &m.MessageID, &m.Subject, &m.From, &m.To, &date, &m.Size, &seen, &flagged, &att, &m.AuthSummary}
	if withRaw {
		dst = append(dst, &m.Raw)
	}
	if err := r.Scan(dst...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.Date, m.Seen, m.Flagged, m.HasAttach = time.Unix(date, 0).UTC(), seen == 1, flagged == 1, att == 1
	return &m, nil
}

// ListMessages lists a folder newest first. beforeID > 0 paginates. query,
// when non-empty, filters on subject/from/to (case-insensitive substring).
func (s *Store) ListMessages(ctx context.Context, userID int64, folder string, beforeID int64, limit int, query string) ([]*Message, error) {
	q := `SELECT ` + msgCols + ` FROM messages WHERE user_id = ? AND folder = ?`
	args := []any{userID, folder}
	if beforeID > 0 {
		q += ` AND id < ?`
		args = append(args, beforeID)
	}
	if query != "" {
		like := "%" + escapeLike(query) + "%"
		q += ` AND (subject LIKE ? ESCAPE '\' OR from_addr LIKE ? ESCAPE '\' OR to_addrs LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Message{}
	for rows.Next() {
		m, err := scanMsg(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// GetMessage loads a message including its raw MIME, scoped to the owner.
func (s *Store) GetMessage(ctx context.Context, userID, id int64) (*Message, error) {
	return scanMsg(s.db.QueryRowContext(ctx, `SELECT `+msgCols+`, raw FROM messages WHERE id = ? AND user_id = ?`, id, userID), true)
}

// UpdateMessage changes flags and/or folder. Nil fields are left unchanged.
func (s *Store) UpdateMessage(ctx context.Context, userID, id int64, seen, flagged *bool, folder *string) error {
	sets := []string{}
	args := []any{}
	if seen != nil {
		sets, args = append(sets, "seen = ?"), append(args, b2i(*seen))
	}
	if flagged != nil {
		sets, args = append(sets, "flagged = ?"), append(args, b2i(*flagged))
	}
	if folder != nil {
		if !ValidFolder(*folder) {
			return errors.New("store: invalid folder")
		}
		sets, args = append(sets, "folder = ?"), append(args, *folder)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id, userID)
	return s.execOne(ctx, `UPDATE messages SET `+strings.Join(sets, ", ")+` WHERE id = ? AND user_id = ?`, args...)
}

// DeleteMessage permanently deletes a message owned by userID.
func (s *Store) DeleteMessage(ctx context.Context, userID, id int64) error {
	return s.execOne(ctx, `DELETE FROM messages WHERE id = ? AND user_id = ?`, id, userID)
}

// EmptyFolder permanently deletes all messages in a folder.
func (s *Store) EmptyFolder(ctx context.Context, userID int64, folder string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM messages WHERE user_id = ? AND folder = ?`, userID, folder)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FolderCount holds per-folder totals.
type FolderCount struct {
	Name   string `json:"name"`
	Total  int    `json:"total"`
	Unread int    `json:"unread"`
}

// FolderCounts returns totals for every standard folder.
func (s *Store) FolderCounts(ctx context.Context, userID int64) ([]FolderCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT folder, COUNT(*), SUM(CASE WHEN seen = 0 THEN 1 ELSE 0 END) FROM messages WHERE user_id = ? GROUP BY folder`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]FolderCount{}
	for rows.Next() {
		var fc FolderCount
		if err := rows.Scan(&fc.Name, &fc.Total, &fc.Unread); err != nil {
			return nil, err
		}
		m[fc.Name] = fc
	}
	out := make([]FolderCount, 0, len(Folders))
	for _, f := range Folders {
		fc := m[f]
		fc.Name = f
		out = append(out, fc)
	}
	return out, rows.Err()
}

// FindByMessageID returns the newest message of a user with the given Message-ID header.
func (s *Store) FindByMessageID(ctx context.Context, userID int64, mid string) (*Message, error) {
	return scanMsg(s.db.QueryRowContext(ctx, `SELECT `+msgCols+`, raw FROM messages WHERE user_id = ? AND message_id = ? ORDER BY id DESC LIMIT 1`, userID, mid), true)
}
