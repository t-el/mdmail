// Package mailmsg builds outgoing MIME messages from Markdown and parses
// stored messages for display.
package mailmsg

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-message/mail"

	"github.com/t-el/mdmail/internal/mdrender"
)

// Attachment is a file attached to an outgoing message.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Draft is an outgoing message authored in Markdown.
type Draft struct {
	From        *mail.Address
	To, Cc, Bcc []*mail.Address
	Subject     string
	Markdown    string
	InReplyTo   string
	References  []string
	Attachments []Attachment
	Hostname    string // used for the Message-ID
	Date        time.Time
}

// Recipients returns all envelope recipients (To, Cc and Bcc), de-duplicated.
func (d *Draft) Recipients() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]*mail.Address{d.To, d.Cc, d.Bcc} {
		for _, a := range l {
			k := strings.ToLower(a.Address)
			if !seen[k] {
				seen[k] = true
				out = append(out, a.Address)
			}
		}
	}
	return out
}

// ErrHeaderInjection is returned when a header value contains control characters.
var ErrHeaderInjection = errors.New("mailmsg: control characters in header value")

func cleanHeader(s string) (string, error) {
	for _, r := range s {
		if r == '\r' || r == '\n' || (unicode.IsControl(r) && r != '\t') {
			return "", ErrHeaderInjection
		}
	}
	return strings.TrimSpace(s), nil
}

// Build renders the draft as a MIME message:
//
//	multipart/mixed (only when there are attachments)
//	├── multipart/alternative
//	│   ├── text/plain; charset=utf-8   (the Markdown source, RFC 7763-compatible)
//	│   └── text/html;  charset=utf-8   (goldmark GFM, sanitized by bluemonday)
//	└── attachments…
//
// Bcc is never written to the header. It returns the raw message and its Message-ID.
func Build(d *Draft) ([]byte, string, error) {
	if d.From == nil {
		return nil, "", errors.New("mailmsg: missing From")
	}
	if len(d.To)+len(d.Cc)+len(d.Bcc) == 0 {
		return nil, "", errors.New("mailmsg: no recipients")
	}
	subject, err := cleanHeader(d.Subject)
	if err != nil {
		return nil, "", err
	}
	if len(subject) > 998 {
		return nil, "", errors.New("mailmsg: subject too long")
	}
	for _, l := range [][]*mail.Address{{d.From}, d.To, d.Cc, d.Bcc} {
		for _, a := range l {
			if _, err := cleanHeader(a.Name); err != nil {
				return nil, "", err
			}
			if _, err := cleanHeader(a.Address); err != nil {
				return nil, "", err
			}
		}
	}

	var h mail.Header
	date := d.Date
	if date.IsZero() {
		date = time.Now()
	}
	h.SetDate(date)
	h.SetAddressList("From", []*mail.Address{d.From})
	if len(d.To) > 0 {
		h.SetAddressList("To", d.To)
	}
	if len(d.Cc) > 0 {
		h.SetAddressList("Cc", d.Cc)
	}
	h.SetSubject(subject)
	if err := h.GenerateMessageIDWithHostname(d.Hostname); err != nil {
		return nil, "", err
	}
	mid, _ := h.MessageID()
	if d.InReplyTo != "" {
		h.SetMsgIDList("In-Reply-To", []string{d.InReplyTo})
		refs := append(append([]string{}, d.References...), d.InReplyTo)
		if len(refs) > 50 {
			refs = refs[len(refs)-50:]
		}
		h.SetMsgIDList("References", refs)
	}
	h.Set("MIME-Version", "1.0")
	h.Set("User-Agent", "mdmail")

	htmlBody, err := mdrender.RenderEmailHTML(d.Markdown, subject)
	if err != nil {
		return nil, "", err
	}
	text := normalizeNewlines(d.Markdown)

	var buf bytes.Buffer
	writeAlt := func(iw *mail.InlineWriter) error {
		var th mail.InlineHeader
		th.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
		th.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err := iw.CreatePart(th)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(text)); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		var hh mail.InlineHeader
		hh.SetContentType("text/html", map[string]string{"charset": "utf-8"})
		hh.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err = iw.CreatePart(hh)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(htmlBody)); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return iw.Close()
	}

	if len(d.Attachments) == 0 {
		iw, err := mail.CreateInlineWriter(&buf, h)
		if err != nil {
			return nil, "", err
		}
		if err := writeAlt(iw); err != nil {
			return nil, "", err
		}
	} else {
		mw, err := mail.CreateWriter(&buf, h)
		if err != nil {
			return nil, "", err
		}
		iw, err := mw.CreateInline()
		if err != nil {
			return nil, "", err
		}
		if err := writeAlt(iw); err != nil {
			return nil, "", err
		}
		for _, a := range d.Attachments {
			var ah mail.AttachmentHeader
			ct := a.ContentType
			if mt, _, err := mime.ParseMediaType(ct); err != nil || !strings.Contains(mt, "/") {
				ct = "application/octet-stream"
			} else {
				ct = mt
			}
			ah.SetContentType(ct, nil)
			ah.SetFilename(SafeFilename(a.Filename))
			ah.Set("Content-Transfer-Encoding", "base64")
			w, err := mw.CreateAttachment(ah)
			if err != nil {
				return nil, "", err
			}
			if _, err := w.Write(a.Data); err != nil {
				return nil, "", err
			}
			if err := w.Close(); err != nil {
				return nil, "", err
			}
		}
		if err := mw.Close(); err != nil {
			return nil, "", err
		}
	}
	return buf.Bytes(), mid, nil
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// SafeFilename strips path components and control characters from a filename.
func SafeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	var b strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) || r == '"' || r == '/' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" || out == "." || out == ".." {
		out = "attachment"
	}
	if len(out) > 200 {
		ext := filepath.Ext(out)
		if len(ext) > 20 {
			ext = ""
		}
		out = out[:200-len(ext)] + ext
	}
	return out
}

// ParseAddressList parses a user-entered comma separated address list.
func ParseAddressList(s string) ([]*mail.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if _, err := cleanHeader(s); err != nil {
		return nil, err
	}
	l, err := mail.ParseAddressList(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address list: %w", err)
	}
	for _, a := range l {
		if !ValidAddress(a.Address) {
			return nil, fmt.Errorf("invalid address %q", a.Address)
		}
	}
	return l, nil
}

// ValidAddress performs a conservative syntax check of an addr-spec.
func ValidAddress(a string) bool {
	if len(a) > 254 {
		return false
	}
	at := strings.LastIndexByte(a, '@')
	if at < 1 || at == len(a)-1 || len(a[:at]) > 64 {
		return false
	}
	dom := a[at+1:]
	if !strings.Contains(dom, ".") || strings.HasPrefix(dom, ".") || strings.HasSuffix(dom, ".") || strings.Contains(dom, "..") {
		return false
	}
	for _, r := range a {
		if r <= ' ' || r == '<' || r == '>' || r == ',' || r == ';' || r == 0x7f {
			return false
		}
	}
	return true
}
