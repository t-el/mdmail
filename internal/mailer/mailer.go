// Package mailer contains the shared message pipeline: submission by
// authenticated users (web UI and SMTP), local delivery and bounces.
package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailmsg"
	"github.com/t-el/mdmail/internal/ratelimit"
	"github.com/t-el/mdmail/internal/store"
)

// Errors reported to submitters.
var (
	ErrRateLimited    = errors.New("sending rate limit exceeded, try again later")
	ErrFromMismatch   = errors.New("the From address must be your own address")
	ErrTooManyRcpts   = errors.New("too many recipients")
	ErrUnknownLocal   = errors.New("unknown local recipient")
	ErrNoRecipients   = errors.New("no recipients")
	ErrInvalidAddress = errors.New("invalid recipient address")
	ErrTooLarge       = errors.New("message too large")
)

// Mailer routes messages.
type Mailer struct {
	Cfg    *config.Config
	St     *store.Store
	Signer *mailauth.Signer
	Audit  *audit.Logger
	Log    *slog.Logger
	Wake   func() // nudges the delivery worker

	submitLimit *ratelimit.Keyed
}

// New returns a Mailer.
func New(cfg *config.Config, st *store.Store, signer *mailauth.Signer, al *audit.Logger, log *slog.Logger) *Mailer {
	per := time.Hour / time.Duration(cfg.SubmitPerHour)
	return &Mailer{Cfg: cfg, St: st, Signer: signer, Audit: al, Log: log, Wake: func() {},
		submitLimit: ratelimit.New(per, cfg.SubmitPerHour)}
}

// RateLimiter exposes the submission limiter for GC.
func (m *Mailer) RateLimiter() *ratelimit.Keyed { return m.submitLimit }

func domainOf(a string) string { return strings.ToLower(a[strings.LastIndexByte(a, '@')+1:]) }

// CheckLocalRecipient reports whether rcpt is deliverable locally. For
// non-local domains it returns (false, nil).
func (m *Mailer) CheckLocalRecipient(ctx context.Context, rcpt string) (local bool, err error) {
	if !m.Cfg.IsLocalDomain(domainOf(rcpt)) {
		return false, nil
	}
	u, err := m.St.UserByEmail(ctx, rcpt)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
		return true, ErrUnknownLocal
	}
	return true, err
}

// Submit accepts a complete message from an authenticated user, enforces
// sender identity and limits, DKIM-signs it, files a copy in Sent, delivers
// to local recipients and queues remote ones.
func (m *Mailer) Submit(ctx context.Context, u *store.User, rcpts []string, raw []byte, ip, via string) error {
	if len(rcpts) == 0 {
		return ErrNoRecipients
	}
	if len(rcpts) > m.Cfg.MaxRecipients {
		return ErrTooManyRcpts
	}
	if int64(len(raw)) > m.Cfg.MaxMessageBytes {
		return ErrTooLarge
	}
	seen := map[string]bool{}
	var uniq []string
	for _, r := range rcpts {
		if !mailmsg.ValidAddress(r) {
			return fmt.Errorf("%w: %s", ErrInvalidAddress, r)
		}
		if k := strings.ToLower(r); !seen[k] {
			seen[k] = true
			uniq = append(uniq, r)
		}
	}
	if !m.submitLimit.AllowN(fmt.Sprint(u.ID), len(uniq)) {
		m.Audit.Event(ctx, u.ID, "submit_rate_limited", ip, via)
		return ErrRateLimited
	}

	raw, fromDomain, err := m.normalizeSubmission(raw, u.Email)
	if err != nil {
		return err
	}

	var local, remote []string
	for _, r := range uniq {
		isLocal, err := m.CheckLocalRecipient(ctx, r)
		if err != nil {
			return fmt.Errorf("%w: %s", err, r)
		}
		if isLocal {
			local = append(local, r)
		} else {
			remote = append(remote, r)
		}
	}

	signed, err := m.Signer.Sign(raw, fromDomain)
	if err != nil {
		return fmt.Errorf("dkim sign: %w", err)
	}

	if _, err := m.store(ctx, u.ID, store.FolderSent, signed, "", true); err != nil {
		return err
	}
	for _, r := range local {
		ru, err := m.St.UserByEmail(ctx, r)
		if err != nil {
			return err
		}
		ar := m.Cfg.Hostname + "; auth=pass smtp.auth=" + u.Email
		withTrace, err := mailauth.PrependTrace(signed, m.Cfg.Hostname, ar, m.receivedLocal(via))
		if err != nil {
			return err
		}
		if _, err := m.store(ctx, ru.ID, store.FolderInbox, withTrace, "local", false); err != nil {
			return err
		}
	}
	if len(remote) > 0 {
		uid := u.ID
		if err := m.St.Enqueue(ctx, &uid, u.Email, remote, signed); err != nil {
			return err
		}
		m.Wake()
	}
	m.Audit.Event(ctx, u.ID, "message_submitted", ip, fmt.Sprintf("via=%s local=%d remote=%d bytes=%d", via, len(local), len(remote), len(signed)))
	return nil
}

func (m *Mailer) receivedLocal(via string) string {
	return fmt.Sprintf("from authenticated user by %s (mdmail) with %s id %s; %s", m.Cfg.Hostname, via, newID(), time.Now().UTC().Format(time.RFC1123Z))
}

// normalizeSubmission enforces From == authenticated address, strips Bcc,
// and adds Date / Message-ID when missing.
func (m *Mailer) normalizeSubmission(raw []byte, userEmail string) ([]byte, string, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, "", fmt.Errorf("malformed header: %w", err)
	}
	mh := mail.Header{Header: message.Header{Header: h}}
	if len(mh.Values("From")) != 1 {
		return nil, "", ErrFromMismatch
	}
	from, err := mh.AddressList("From")
	if err != nil || len(from) != 1 || !strings.EqualFold(from[0].Address, userEmail) {
		return nil, "", ErrFromMismatch
	}
	if mh.Has("Sender") {
		s, err := mh.AddressList("Sender")
		if err != nil || len(s) != 1 || !strings.EqualFold(s[0].Address, userEmail) {
			return nil, "", ErrFromMismatch
		}
	}
	mh.Del("Bcc")
	mh.Del("Resent-Bcc")
	mh.Del("Return-Path")
	if !mh.Has("Date") {
		mh.SetDate(time.Now())
	}
	if !mh.Has("Message-Id") {
		if err := mh.GenerateMessageIDWithHostname(m.Cfg.Hostname); err != nil {
			return nil, "", err
		}
	}
	var out bytes.Buffer
	if err := textproto.WriteHeader(&out, mh.Header.Header); err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(&out, br); err != nil {
		return nil, "", err
	}
	return out.Bytes(), domainOf(from[0].Address), nil
}

// DeliverLocal files an inbound message into a user's folder.
func (m *Mailer) DeliverLocal(ctx context.Context, userID int64, folder string, raw []byte, authSummary string) (int64, error) {
	return m.store(ctx, userID, folder, raw, authSummary, false)
}

func (m *Mailer) store(ctx context.Context, userID int64, folder string, raw []byte, authSummary string, seen bool) (int64, error) {
	meta := mailmsg.ParseMeta(raw)
	return m.St.InsertMessage(ctx, &store.Message{
		UserID: userID, Folder: folder, MessageID: meta.MessageID, Subject: meta.Subject,
		From: meta.From, To: meta.To, Date: meta.Date, Seen: seen, HasAttach: meta.HasAttach,
		AuthSummary: authSummary, Raw: raw,
	})
}

// Bounce files a delivery status notification in the sender's inbox
// (only local senders can have queued mail, so no remote bounces are sent;
// this avoids backscatter).
func (m *Mailer) Bounce(ctx context.Context, userID int64, rcpt, reason string, original []byte) error {
	u, err := m.St.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	var h mail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", []*mail.Address{{Name: "Mail Delivery System", Address: "mailer-daemon@" + m.Cfg.Hostname}})
	h.SetAddressList("To", []*mail.Address{{Address: u.Email}})
	h.SetSubject("Undelivered Mail Returned to Sender")
	if err := h.GenerateMessageIDWithHostname(m.Cfg.Hostname); err != nil {
		return err
	}
	h.Set("Auto-Submitted", "auto-replied")
	var buf bytes.Buffer
	mw, err := mail.CreateWriter(&buf, h)
	if err != nil {
		return err
	}
	var th mail.InlineHeader
	th.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	w, err := mw.CreateSingleInline(th)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Your message could not be delivered to:\n\n    %s\n\nReason:\n\n    %s\n\nThe original message headers are attached.\n", rcpt, reason)
	if err := w.Close(); err != nil {
		return err
	}
	var ah mail.AttachmentHeader
	ah.SetContentType("text/rfc822-headers", nil)
	ah.SetFilename("original-headers.txt")
	aw, err := mw.CreateAttachment(ah)
	if err != nil {
		return err
	}
	if i := bytes.Index(original, []byte("\r\n\r\n")); i > 0 {
		_, _ = aw.Write(original[:i+2])
	} else if i := bytes.Index(original, []byte("\n\n")); i > 0 {
		_, _ = aw.Write(original[:i+1])
	}
	if err := aw.Close(); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	_, err = m.store(ctx, u.ID, store.FolderInbox, buf.Bytes(), "local", false)
	return err
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewID returns a random trace identifier.
func NewID() string { return newID() }
