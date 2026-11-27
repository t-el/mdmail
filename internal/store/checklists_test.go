package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestChecklistStateOwnership(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, _ := s.CreateUser(ctx, "a@example.com", "h", false)
	b, _ := s.CreateUser(ctx, "b@example.com", "h", false)
	id, err := s.InsertMessage(ctx, &Message{UserID: a, Folder: FolderInbox, Date: time.Now(), Raw: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetChecklistItem(ctx, a, id, 2, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChecklistItem(ctx, a, id, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChecklistItem(ctx, a, id, 0, false); err != nil { // update in place
		t.Fatal(err)
	}
	st, err := s.ChecklistState(ctx, a, id)
	if err != nil || len(st) != 2 || !st[2] || st[0] {
		t.Fatalf("state %v %v", st, err)
	}
	// Another user can neither read nor write the owner's state.
	if err := s.SetChecklistItem(ctx, b, id, 2, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign write: %v", err)
	}
	if _, err := s.ChecklistState(ctx, b, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign read: %v", err)
	}
	if st, _ := s.ChecklistState(ctx, a, id); !st[2] {
		t.Fatal("foreign write changed state")
	}
	for _, item := range []int{-1, MaxChecklistItem} {
		if err := s.SetChecklistItem(ctx, a, id, item, true); err == nil {
			t.Fatalf("item %d accepted", item)
		}
	}
	if err := s.SetChecklistItem(ctx, a, id+999, 0, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing message: %v", err)
	}
	// State is removed with the message.
	if err := s.DeleteMessage(ctx, a, id); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM checklist_state`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d orphaned rows", n)
	}
}

func TestLocalDeliveryLinks(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, _ := s.CreateUser(ctx, "a@example.com", "h", false)
	b, _ := s.CreateUser(ctx, "b@example.com", "h", false)
	c, _ := s.CreateUser(ctx, "c@example.com", "h", false)
	ins := func(u int64, f string) int64 {
		id, err := s.InsertMessage(ctx, &Message{UserID: u, Folder: f, Date: time.Now(), Raw: []byte("x")})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sent, rb, rc := ins(a, FolderSent), ins(b, FolderInbox), ins(c, FolderInbox)
	for _, r := range []int64{rb, rc} {
		if err := s.LinkLocalDelivery(ctx, sent, r); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.SetChecklistItem(ctx, b, rb, 1, true)
	_ = s.SetChecklistItem(ctx, b, rb, 0, false)

	got, err := s.RecipientChecklists(ctx, a, sent)
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Email != "b@example.com" || !got[0].Checked[1] || got[0].Checked[0] || len(got[0].Checked) != 2 {
		t.Fatalf("b: %+v", got[0])
	}
	if got[1].Email != "c@example.com" || len(got[1].Checked) != 0 {
		t.Fatalf("c: %+v", got[1])
	}
	// Only the owner of the Sent copy may see recipient progress.
	for _, u := range []int64{b, c} {
		if l, _ := s.RecipientChecklists(ctx, u, sent); len(l) != 0 {
			t.Fatalf("user %d sees progress of a's message", u)
		}
	}
	if ok, _ := s.IsLocallyDelivered(ctx, b, rb); !ok {
		t.Fatal("link not reported to recipient")
	}
	if ok, _ := s.IsLocallyDelivered(ctx, a, rb); ok {
		t.Fatal("link reported to non-owner")
	}
	// A recipient deleting their copy removes it from the sender's view.
	if err := s.DeleteMessage(ctx, c, rc); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.RecipientChecklists(ctx, a, sent); len(l) != 1 {
		t.Fatalf("deleted copy still visible: %+v", l)
	}
	if err := s.LinkLocalDelivery(ctx, sent, rb); err == nil {
		t.Fatal("duplicate link accepted")
	}
}
