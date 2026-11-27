// Package smtpserver implements the inbound MX listener (port 25) and the
// authenticated submission listeners (587 STARTTLS, 465 implicit TLS).
package smtpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/mailmsg"
	"github.com/t-el/mdmail/internal/ratelimit"
	"github.com/t-el/mdmail/internal/store"
)

// Deps are the collaborators of the SMTP servers.
type Deps struct {
	Cfg      *config.Config
	St       *store.Store
	Mailer   *mailer.Mailer
	Auth     *auth.Authenticator
	Verifier *mailauth.Verifier
	Audit    *audit.Logger
	Log      *slog.Logger
	TLS      *tls.Config

	connLimit *ratelimit.Keyed
	authLimit *ratelimit.Keyed
}

// Limiters returns the rate limiters for periodic GC.
func (d *Deps) Limiters() []*ratelimit.Keyed { return []*ratelimit.Keyed{d.connLimit, d.authLimit} }

// Init prepares shared limiters. Call once before creating servers.
func (d *Deps) Init() {
	d.connLimit = ratelimit.New(2*time.Second, 30)  // per IP: 30 burst, then 30/min
	d.authLimit = ratelimit.New(30*time.Second, 10) // per IP: 10 burst, then 2/min
}

var (
	errTooMany = &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many connections, slow down"}
	errTemp    = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary local error, try again later"}
	errRelay   = &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Relay access denied"}
	errNoUser  = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such user here"}
	errNeedTLS = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Must issue a STARTTLS command first"}
	errBadAddr = &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Invalid address"}
	errRcpts   = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	errAuth    = &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication credentials invalid"}
	errAuthRL  = &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many authentication attempts, try later"}
	errSender  = &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender address must match the authenticated user"}
)

func remoteIP(c *smtp.Conn) net.IP {
	if a, ok := c.Conn().RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	host, _, _ := net.SplitHostPort(c.Conn().RemoteAddr().String())
	return net.ParseIP(host)
}

func baseServer(d *Deps, be smtp.Backend) *smtp.Server {
	s := smtp.NewServer(be)
	s.Domain = d.Cfg.Hostname
	s.MaxMessageBytes = d.Cfg.MaxMessageBytes
	s.MaxRecipients = d.Cfg.MaxRecipients
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	s.MaxLineLength = 2000
	s.AllowInsecureAuth = false
	s.EnableSMTPUTF8 = true
	s.TLSConfig = d.TLS
	s.ErrorLog = slogAdapter{d.Log.With("component", "smtp")}
	return s
}

type slogAdapter struct{ l *slog.Logger }

func (a slogAdapter) Printf(format string, v ...interface{}) { a.l.Warn(fmt.Sprintf(format, v...)) }
func (a slogAdapter) Println(v ...interface{})               { a.l.Warn(fmt.Sprint(v...)) }

func sanitizeTrace(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' || r == '(' || r == ')' || r == ';' {
			return '_'
		}
		return r
	}, s)
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// ---------------------------------------------------------------- inbound

// NewInbound returns the MX server. It never offers AUTH and only accepts
// recipients in local domains (no open relay).
func NewInbound(d *Deps) *smtp.Server {
	return baseServer(d, smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		ip := remoteIP(c)
		if !d.connLimit.Allow("in:" + ip.String()) {
			d.Log.Warn("inbound connection rate limited", "ip", ip.String())
			return nil, errTooMany
		}
		return &inSession{d: d, c: c, ip: ip}, nil
	}))
}

type inSession struct {
	d       *Deps
	c       *smtp.Conn
	ip      net.IP
	from    string
	rcpts   []*store.User
	badRcpt int
}

func (s *inSession) Reset()        { s.from, s.rcpts = "", nil }
func (s *inSession) Logout() error { return nil }

func (s *inSession) Mail(from string, _ *smtp.MailOptions) error {
	if _, isTLS := s.c.TLSConnectionState(); s.d.Cfg.InboundRequireTLS && !isTLS {
		return errNeedTLS
	}
	if from != "" && !mailmsg.ValidAddress(from) {
		return errBadAddr
	}
	s.from = from
	return nil
}

func (s *inSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.badRcpt >= 10 {
		return errTooMany
	}
	if !mailmsg.ValidAddress(to) {
		s.badRcpt++
		return errBadAddr
	}
	if len(s.rcpts) >= s.d.Cfg.MaxRecipients {
		return errRcpts
	}
	dom := strings.ToLower(to[strings.LastIndexByte(to, '@')+1:])
	if !s.d.Cfg.IsLocalDomain(dom) {
		s.badRcpt++
		s.d.Log.Warn("relay attempt denied", "ip", s.ip.String(), "rcpt_domain", dom)
		return errRelay
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	u, err := s.d.St.UserByEmail(ctx, to)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
		s.badRcpt++
		return errNoUser
	}
	if err != nil {
		s.d.Log.Error("rcpt lookup", "err", err)
		return errTemp
	}
	for _, x := range s.rcpts {
		if x.ID == u.ID {
			return nil
		}
	}
	s.rcpts = append(s.rcpts, u)
	return nil
}

func (s *inSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, s.d.Cfg.MaxMessageBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > s.d.Cfg.MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too big"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	helo := s.c.Hostname()
	res := s.d.Verifier.Verify(ctx, s.ip, helo, s.from, raw)
	if res.Action == mailauth.Reject {
		s.d.Log.Warn("inbound rejected by DMARC", "ip", s.ip.String(), "from_domain", res.FromDomain, "auth", res.Summary())
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Rejected by DMARC policy of " + res.FromDomain}
	}
	proto := "ESMTP"
	if cs, ok := s.c.TLSConnectionState(); ok {
		proto = "ESMTPS (" + tls.VersionName(cs.Version) + ")"
	}
	folder := store.FolderInbox
	if res.Action == mailauth.Junk {
		folder = store.FolderJunk
	}
	id := mailer.NewID()
	for _, u := range s.rcpts {
		received := fmt.Sprintf("from %s ([%s]) by %s (mdmail) with %s id %s for <%s>; %s",
			sanitizeTrace(helo), s.ip.String(), s.d.Cfg.Hostname, proto, id, u.Email, time.Now().UTC().Format(time.RFC1123Z))
		msg, err := mailauth.PrependTrace(raw, s.d.Cfg.Hostname, res.Header, received)
		if err != nil {
			return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Malformed message header"}
		}
		if bytes.Count(msg, []byte("\nReceived:")) > 100 {
			return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 4, 6}, Message: "Routing loop detected"}
		}
		if _, err := s.d.Mailer.DeliverLocal(ctx, u.ID, folder, msg, res.Summary()); err != nil {
			s.d.Log.Error("local delivery failed", "err", err)
			return errTemp
		}
	}
	s.d.Log.Info("inbound accepted", "id", id, "ip", s.ip.String(), "rcpts", len(s.rcpts), "folder", folder, "auth", res.Summary(), "reason", res.Reason)
	return nil
}

// ------------------------------------------------------------- submission

// NewSubmission returns a submission server. AUTH is required and is only
// offered over TLS (STARTTLS on 587, or implicit TLS on 465).
func NewSubmission(d *Deps) *smtp.Server {
	return baseServer(d, smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		ip := remoteIP(c)
		if !d.connLimit.Allow("sub:" + ip.String()) {
			return nil, errTooMany
		}
		return &subSession{d: d, c: c, ip: ip}, nil
	}))
}

type subSession struct {
	d     *Deps
	c     *smtp.Conn
	ip    net.IP
	user  *store.User
	rcpts []string
}

func (s *subSession) Reset()        { s.rcpts = nil }
func (s *subSession) Logout() error { return nil }

func (s *subSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *subSession) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnsupported
	}
	if _, isTLS := s.c.TLSConnectionState(); !isTLS {
		return nil, errNeedTLS
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		ipStr := s.ip.String()
		if !s.d.authLimit.Allow(ipStr) {
			s.d.Audit.Event(context.Background(), 0, "smtp_auth_rate_limited", ipStr, "")
			return errAuthRL
		}
		if identity != "" && !strings.EqualFold(identity, username) {
			return errAuth
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		u, err := s.d.Auth.LoginSMTP(ctx, username, password)
		if err != nil {
			var uid int64
			if u != nil {
				uid = u.ID
			}
			s.d.Audit.Event(ctx, uid, "smtp_auth_failure", ipStr, err.Error())
			if errors.Is(err, auth.ErrLocked) || errors.Is(err, auth.ErrInvalid) {
				return errAuth
			}
			return errTemp
		}
		s.user = u
		s.d.Audit.Event(ctx, u.ID, "smtp_auth_success", ipStr, "")
		return nil
	}), nil
}

func (s *subSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}
	if !strings.EqualFold(from, s.user.Email) {
		return errSender
	}
	return nil
}

func (s *subSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}
	if !mailmsg.ValidAddress(to) {
		return errBadAddr
	}
	if len(s.rcpts) >= s.d.Cfg.MaxRecipients {
		return errRcpts
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.d.Mailer.CheckLocalRecipient(ctx, to); errors.Is(err, mailer.ErrUnknownLocal) {
		return errNoUser
	} else if err != nil {
		return errTemp
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *subSession) Data(r io.Reader) error {
	if s.user == nil {
		return smtp.ErrAuthRequired
	}
	raw, err := io.ReadAll(io.LimitReader(r, s.d.Cfg.MaxMessageBytes+1))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err = s.d.Mailer.Submit(ctx, s.user, s.rcpts, raw, s.ip.String(), "ESMTPSA")
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mailer.ErrRateLimited):
		return &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: err.Error()}
	case errors.Is(err, mailer.ErrFromMismatch):
		return errSender
	case errors.Is(err, mailer.ErrTooLarge):
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too big"}
	case errors.Is(err, mailer.ErrTooManyRcpts), errors.Is(err, mailer.ErrInvalidAddress), errors.Is(err, mailer.ErrUnknownLocal), errors.Is(err, mailer.ErrNoRecipients):
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 5, 0}, Message: err.Error()}
	default:
		s.d.Log.Error("submission failed", "err", err)
		return errTemp
	}
}
