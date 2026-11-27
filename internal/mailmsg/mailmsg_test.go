package mailmsg

import (
	"bytes"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
)

func TestBuildParseRoundtrip(t *testing.T) {
	d := &Draft{
		From:     &mail.Address{Name: "Alice", Address: "alice@example.com"},
		To:       []*mail.Address{{Address: "bob@example.org"}},
		Bcc:      []*mail.Address{{Address: "secret@example.net"}},
		Subject:  "Héllo **world**",
		Markdown: "# Hi Bob\n\nThis is *Markdown*.\n",
		Hostname: "mail.example.com",
		Attachments: []Attachment{
			{Filename: "../../etc/passwd", ContentType: "text/plain", Data: []byte("file content")},
		},
		InReplyTo: "orig@example.org",
	}
	raw, mid, err := Build(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(mid, "@mail.example.com") {
		t.Errorf("message id %q", mid)
	}
	if bytes.Contains(raw, []byte("secret@example.net")) || bytes.Contains(bytes.ToLower(raw), []byte("\nbcc:")) {
		t.Fatal("Bcc leaked into message")
	}
	if got := d.Recipients(); len(got) != 2 {
		t.Fatalf("recipients %v", got)
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "Héllo **world**" || p.FromAddr != "alice@example.com" || p.InReplyTo != "orig@example.org" {
		t.Errorf("headers: %+v", p)
	}
	if !strings.Contains(p.Text, "This is *Markdown*.") {
		t.Errorf("text part should be the markdown source: %q", p.Text)
	}
	if !p.HasHTML || !strings.Contains(p.HTML, "<em>Markdown</em>") {
		t.Errorf("html part: %q", p.HTML)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Filename != "passwd" {
		t.Fatalf("attachments: %+v", p.Attachments)
	}
	a, err := GetAttachment(raw, p.Attachments[0].Index, 1<<20)
	if err != nil || string(a.Data) != "file content" {
		t.Fatalf("attachment: %v %q", err, a)
	}
}

func TestHeaderInjection(t *testing.T) {
	d := &Draft{From: &mail.Address{Address: "a@example.com"}, To: []*mail.Address{{Address: "b@example.com"}},
		Subject: "hi\r\nBcc: victim@example.com", Hostname: "h.example.com"}
	if _, _, err := Build(d); err != ErrHeaderInjection {
		t.Fatalf("want ErrHeaderInjection, got %v", err)
	}
	if _, err := ParseAddressList("a@example.com\r\nX: y"); err == nil {
		t.Fatal("CRLF in address list accepted")
	}
}

func TestValidAddressAndFilename(t *testing.T) {
	for _, a := range []string{"a@example.com", "first.last+tag@sub.example.co.uk"} {
		if !ValidAddress(a) {
			t.Errorf("%s rejected", a)
		}
	}
	for _, a := range []string{"", "a", "@example.com", "a@", "a@localhost", "a b@example.com", "a@example..com", "<a@example.com>"} {
		if ValidAddress(a) {
			t.Errorf("%q accepted", a)
		}
	}
	if SafeFilename("..") != "attachment" || SafeFilename(`C:\x\evil".exe`) != "evil.exe" {
		t.Error("SafeFilename")
	}
}
