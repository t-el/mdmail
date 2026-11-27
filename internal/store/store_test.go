package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.db")
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
}

func TestUsersAndLockout(t *testing.T) {
	s, ctx := open(t), context.Background()
	id, err := s.CreateUser(ctx, "Alice@Example.com", "h", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice@example.com", "h", false); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	u, err := s.UserByEmail(ctx, "ALICE@example.com")
	if err != nil || u.ID != id || u.Email != "alice@example.com" {
		t.Fatalf("lookup: %v %+v", err, u)
	}
	for i := 0; i < 4; i++ {
		until, _ := s.RecordLoginFailure(ctx, id, 5, time.Minute, time.Hour)
		if !until.IsZero() {
			t.Fatal("locked too early")
		}
	}
	until, _ := s.RecordLoginFailure(ctx, id, 5, time.Minute, time.Hour)
	if until.Before(time.Now().Add(50 * time.Second)) {
		t.Fatal("not locked at threshold")
	}
	until, _ = s.RecordLoginFailure(ctx, id, 5, time.Minute, time.Hour)
	if until.Before(time.Now().Add(110 * time.Second)) {
		t.Fatal("lock did not grow exponentially")
	}
}

func TestMessageIsolation(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, _ := s.CreateUser(ctx, "a@example.com", "h", false)
	b, _ := s.CreateUser(ctx, "b@example.com", "h", false)
	id, err := s.InsertMessage(ctx, &Message{UserID: a, Folder: FolderInbox, Subject: "100%_secret", Date: time.Now(), Raw: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMessage(ctx, b, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("user b can read user a's message")
	}
	if err := s.DeleteMessage(ctx, b, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("user b can delete user a's message")
	}
	f := FolderTrash
	if err := s.UpdateMessage(ctx, b, id, nil, nil, &f); !errors.Is(err, ErrNotFound) {
		t.Fatal("user b can move user a's message")
	}
	l, _ := s.ListMessages(ctx, a, FolderInbox, 0, 10, "100%")
	if len(l) != 1 {
		t.Fatal("search failed")
	}
	l, _ = s.ListMessages(ctx, a, FolderInbox, 0, 10, "100%x")
	if len(l) != 0 {
		t.Fatal("LIKE wildcard not escaped")
	}
	fc, _ := s.FolderCounts(ctx, a)
	if fc[0].Name != FolderInbox || fc[0].Unread != 1 {
		t.Fatalf("counts %+v", fc)
	}
}

func TestQueue(t *testing.T) {
	s, ctx := open(t), context.Background()
	if err := s.Enqueue(ctx, nil, "a@example.com", []string{"x@one.test", "y@two.test"}, []byte("raw")); err != nil {
		t.Fatal(err)
	}
	items, err := s.ClaimDue(ctx, time.Now(), 10, time.Hour)
	if err != nil || len(items) != 2 {
		t.Fatalf("claim: %v %d", err, len(items))
	}
	if again, _ := s.ClaimDue(ctx, time.Now(), 10, time.Hour); len(again) != 0 {
		t.Fatal("leased items claimed twice")
	}
	if err := s.Delivered(ctx, items[0].RcptID, items[0].MsgID); err != nil {
		t.Fatal(err)
	}
	if err := s.Retry(ctx, items[1].RcptID, time.Now().Add(-time.Second), "450 try later"); err != nil {
		t.Fatal(err)
	}
	items, _ = s.ClaimDue(ctx, time.Now(), 10, time.Hour)
	if len(items) != 1 || items[0].Attempts != 1 || string(items[0].Raw) != "raw" {
		t.Fatalf("retry: %+v", items)
	}
	_ = s.Delivered(ctx, items[0].RcptID, items[0].MsgID)
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM queue_messages`).Scan(&n)
	if n != 0 {
		t.Fatal("queue message not removed after last recipient")
	}
}

func TestBackup(t *testing.T) {
	s, ctx := open(t), context.Background()
	if _, err := s.CreateUser(ctx, "a@example.com", "h", false); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, dest); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	b, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.UserByEmail(ctx, "a@example.com"); err != nil {
		t.Fatal("backup is missing data")
	}
}

// Regression: admin tools must not silently create a second, empty database
// when MDMAIL_DATA_DIR points somewhere the server does not use.
func TestOpenExisting(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "mdmail.db")
	if _, err := OpenExisting(ctx, p); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("missing db: err = %v, want ErrNoDatabase", err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("OpenExisting created the data directory")
	}
	st, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "a@example.com", "h", false); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := OpenExisting(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, err := st2.UserByEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("existing db not opened: %v", err)
	}
}
