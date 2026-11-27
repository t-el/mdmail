package mailmsg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // decode legacy charsets
	"github.com/emersion/go-message/mail"
)

// Limits applied when parsing untrusted messages.
const (
	maxParts     = 500
	maxTextBytes = 4 << 20
)

// AttachmentInfo describes an attachment without its content.
type AttachmentInfo struct {
	Index       int    `json:"index"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}

// Parsed is a message decoded for display.
type Parsed struct {
	Subject     string           `json:"subject"`
	From        string           `json:"from"`
	FromAddr    string           `json:"from_addr"`
	ReplyTo     string           `json:"reply_to"`
	To          string           `json:"to"`
	Cc          string           `json:"cc"`
	Date        time.Time        `json:"date"`
	MessageID   string           `json:"message_id"`
	InReplyTo   string           `json:"in_reply_to"`
	References  []string         `json:"references"`
	Text        string           `json:"text"`
	HTML        string           `json:"-"` // untrusted; must be sanitized before display
	HasHTML     bool             `json:"has_html"`
	Attachments []AttachmentInfo `json:"attachments"`
	AuthResults string           `json:"auth_results"`
}

// Meta is the subset used for indexing.
type Meta struct {
	Subject, From, To, MessageID string
	Date                         time.Time
	HasAttach                    bool
}

func formatList(l []*mail.Address) string {
	s := make([]string, 0, len(l))
	for _, a := range l {
		if a.Name != "" {
			s = append(s, fmt.Sprintf("%s <%s>", a.Name, a.Address))
		} else {
			s = append(s, a.Address)
		}
	}
	return strings.Join(s, ", ")
}

func headerList(h *mail.Header, key string) string {
	l, err := h.AddressList(key)
	if err != nil || len(l) == 0 {
		v, _ := h.Text(key)
		return toValidUTF8(v)
	}
	return formatList(l)
}

func toValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

// Parse decodes a raw message.
func Parse(raw []byte) (*Parsed, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return nil, err
	}
	h := mr.Header
	p := &Parsed{}
	p.Subject, _ = h.Subject()
	p.Subject = toValidUTF8(p.Subject)
	p.From = headerList(&h, "From")
	if l, err := h.AddressList("From"); err == nil && len(l) > 0 {
		p.FromAddr = l[0].Address
	}
	p.ReplyTo = headerList(&h, "Reply-To")
	p.To = headerList(&h, "To")
	p.Cc = headerList(&h, "Cc")
	p.Date, _ = h.Date()
	p.MessageID, _ = h.MessageID()
	if l, err := h.MsgIDList("In-Reply-To"); err == nil && len(l) > 0 {
		p.InReplyTo = l[0]
	}
	p.References, _ = h.MsgIDList("References")
	p.AuthResults = toValidUTF8(h.Get("Authentication-Results"))

	idx := 0
	for n := 0; n < maxParts; n++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil && !message.IsUnknownCharset(err) {
			// Malformed trailing structure: show what we have.
			break
		}
		switch ph := part.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			body, _ := io.ReadAll(io.LimitReader(part.Body, maxTextBytes))
			switch ct {
			case "text/plain", "":
				if p.Text == "" {
					p.Text = toValidUTF8(string(body))
				}
			case "text/html":
				if p.HTML == "" {
					p.HTML = toValidUTF8(string(body))
					p.HasHTML = true
				}
			default:
				n, _ := io.Copy(io.Discard, part.Body)
				p.Attachments = append(p.Attachments, AttachmentInfo{Index: idx, Filename: "part-" + fmt.Sprint(idx), ContentType: ct, Size: len(body) + int(n)})
			}
		case *mail.AttachmentHeader:
			ct, _, _ := ph.ContentType()
			name, _ := ph.Filename()
			if name == "" {
				_, params, _ := ph.ContentType()
				name = params["name"]
			}
			n, _ := io.Copy(io.Discard, part.Body)
			p.Attachments = append(p.Attachments, AttachmentInfo{Index: idx, Filename: SafeFilename(toValidUTF8(name)), ContentType: ct, Size: int(n)})
		}
		idx++
	}
	return p, nil
}

// ErrNoAttachment is returned when an attachment index does not exist.
var ErrNoAttachment = errors.New("mailmsg: no such attachment")

// GetAttachment returns the decoded content of the attachment at index.
func GetAttachment(raw []byte, index int, maxBytes int64) (*Attachment, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return nil, err
	}
	for idx := 0; idx < maxParts; idx++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil && !message.IsUnknownCharset(err) {
			return nil, err
		}
		if idx != index {
			continue
		}
		var name, ct string
		switch ph := part.Header.(type) {
		case *mail.AttachmentHeader:
			ct, _, _ = ph.ContentType()
			name, _ = ph.Filename()
		case *mail.InlineHeader:
			ct, _, _ = ph.ContentType()
			if ct == "text/plain" || ct == "text/html" || ct == "" {
				return nil, ErrNoAttachment
			}
			name = "part-" + fmt.Sprint(idx)
		}
		data, err := io.ReadAll(io.LimitReader(part.Body, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, errors.New("mailmsg: attachment too large")
		}
		return &Attachment{Filename: SafeFilename(toValidUTF8(name)), ContentType: ct, Data: data}, nil
	}
	return nil, ErrNoAttachment
}

// AllAttachments returns all attachments (used when forwarding).
func AllAttachments(raw []byte, maxTotal int64) ([]Attachment, error) {
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	var out []Attachment
	var total int64
	for _, ai := range p.Attachments {
		a, err := GetAttachment(raw, ai.Index, maxTotal)
		if err != nil {
			return nil, err
		}
		total += int64(len(a.Data))
		if total > maxTotal {
			return nil, errors.New("mailmsg: attachments too large")
		}
		out = append(out, *a)
	}
	return out, nil
}

// ParseMeta extracts indexing metadata cheaply.
func ParseMeta(raw []byte) Meta {
	var m Meta
	p, err := Parse(raw)
	if err != nil {
		m.Date = time.Now()
		return m
	}
	m.Subject, m.From, m.To, m.MessageID, m.Date = p.Subject, p.From, p.To, p.MessageID, p.Date
	if m.Date.IsZero() || m.Date.After(time.Now().Add(48*time.Hour)) {
		m.Date = time.Now()
	}
	m.HasAttach = len(p.Attachments) > 0
	if len(m.Subject) > 1000 {
		m.Subject = m.Subject[:1000]
	}
	return m
}

// ContentDisposition builds a safe attachment Content-Disposition header.
func ContentDisposition(filename string) string {
	return mime.FormatMediaType("attachment", map[string]string{"filename": SafeFilename(filename)})
}
