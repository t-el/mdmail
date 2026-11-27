// Package delivery implements the outbound queue: MX resolution, SMTP
// delivery with STARTTLS, retries with backoff and bounces.
package delivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/store"
)

// Resolver is the DNS subset needed for delivery.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Worker drains the outbound queue.
type Worker struct {
	Cfg      *config.Config
	St       *store.Store
	Mailer   *mailer.Mailer
	Log      *slog.Logger
	Resolver Resolver
	Port     string // remote SMTP port, "25"
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)

	// MaxAge is how long a message is retried before bouncing.
	MaxAge      time.Duration
	Concurrency int

	wake chan struct{}
}

// NewWorker builds a worker with production defaults.
func NewWorker(cfg *config.Config, st *store.Store, m *mailer.Mailer, log *slog.Logger) *Worker {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	w := &Worker{Cfg: cfg, St: st, Mailer: m, Log: log.With("component", "delivery"), Resolver: net.DefaultResolver,
		Port: "25", Dial: d.DialContext, MaxAge: 5 * 24 * time.Hour, Concurrency: 8, wake: make(chan struct{}, 1)}
	m.Wake = w.Wake
	return w
}

// Wake triggers a queue run.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run processes the queue until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		w.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.wake:
		}
	}
}

type groupKey struct {
	msg    int64
	domain string
}

func (w *Worker) runOnce(ctx context.Context) {
	items, err := w.St.ClaimDue(ctx, time.Now(), 200, 30*time.Minute)
	if err != nil {
		w.Log.Error("queue claim failed", "err", err)
		return
	}
	if len(items) == 0 {
		return
	}
	groups := map[groupKey][]*store.QueueItem{}
	for _, it := range items {
		k := groupKey{it.MsgID, it.Domain}
		groups[k] = append(groups[k], it)
	}
	sem := make(chan struct{}, w.Concurrency)
	var wg sync.WaitGroup
	for k, g := range groups {
		wg.Add(1)
		sem <- struct{}{}
		go func(k groupKey, g []*store.QueueItem) {
			defer wg.Done()
			defer func() { <-sem }()
			w.deliverGroup(ctx, k.domain, g)
		}(k, g)
	}
	wg.Wait()
}

// deliveryError carries per-recipient permanence.
type deliveryError struct {
	perm bool
	msg  string
}

func (e *deliveryError) Error() string { return e.msg }

func temp(format string, a ...any) *deliveryError {
	return &deliveryError{msg: fmt.Sprintf(format, a...)}
}
func perm(format string, a ...any) *deliveryError {
	return &deliveryError{perm: true, msg: fmt.Sprintf(format, a...)}
}

func (w *Worker) deliverGroup(ctx context.Context, domain string, items []*store.QueueItem) {
	results := w.deliver(ctx, domain, items)
	for i, it := range items {
		derr := results[i]
		if derr == nil {
			if err := w.St.Delivered(ctx, it.RcptID, it.MsgID); err != nil {
				w.Log.Error("queue update failed", "err", err)
			}
			w.Log.Info("delivered", "rcpt_domain", domain, "msg", it.MsgID)
			continue
		}
		expired := time.Since(it.CreatedAt) > w.MaxAge
		if derr.perm || expired {
			reason := derr.msg
			if expired && !derr.perm {
				reason = "delivery timed out after repeated temporary failures: " + derr.msg
			}
			w.Log.Warn("delivery failed permanently", "rcpt_domain", domain, "msg", it.MsgID, "err", reason)
			if it.UserID != nil {
				if err := w.Mailer.Bounce(ctx, *it.UserID, it.Rcpt, reason, it.Raw); err != nil {
					w.Log.Error("bounce failed", "err", err)
				}
			}
			if err := w.St.Delivered(ctx, it.RcptID, it.MsgID); err != nil {
				w.Log.Error("queue update failed", "err", err)
			}
			continue
		}
		next := time.Now().Add(Backoff(it.Attempts))
		w.Log.Info("delivery deferred", "rcpt_domain", domain, "msg", it.MsgID, "attempt", it.Attempts+1, "next", next, "err", derr.msg)
		if err := w.St.Retry(ctx, it.RcptID, next, derr.msg); err != nil {
			w.Log.Error("queue update failed", "err", err)
		}
	}
}

// Backoff returns the delay before retry number attempts+1.
func Backoff(attempts int) time.Duration {
	steps := []time.Duration{5 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour}
	if attempts < len(steps) {
		return steps[attempts]
	}
	return 12 * time.Hour
}

type mxTarget struct {
	host string
	pref uint16
}

func (w *Worker) lookupMX(ctx context.Context, domain string) ([]mxTarget, *deliveryError) {
	mxs, err := w.Resolver.LookupMX(ctx, domain)
	var dnsErr *net.DNSError
	if err != nil {
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// RFC 5321 5.1: implicit MX is the domain itself (if it has addresses).
			if _, aerr := w.Resolver.LookupIPAddr(ctx, domain); aerr != nil {
				return nil, perm("domain %s has no MX or address records", domain)
			}
			return []mxTarget{{host: domain}}, nil
		}
		return nil, temp("MX lookup for %s failed: %v", domain, err)
	}
	var out []mxTarget
	for _, mx := range mxs {
		h := strings.TrimSuffix(mx.Host, ".")
		if h == "" { // RFC 7505 null MX
			return nil, perm("domain %s does not accept mail (null MX)", domain)
		}
		out = append(out, mxTarget{host: strings.ToLower(h), pref: mx.Pref})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].pref < out[j].pref })
	if len(out) > 10 {
		out = out[:10]
	}
	return out, nil
}

// allowedIP refuses loopback, private and other special addresses so that a
// hostile MX record cannot make the server connect to internal services.
func (w *Worker) allowedIP(ip net.IP) bool {
	if w.Cfg.AllowPrivateMX {
		return !ip.IsUnspecified()
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func (w *Worker) deliver(ctx context.Context, domain string, items []*store.QueueItem) []*deliveryError {
	results := make([]*deliveryError, len(items))
	setAll := func(e *deliveryError) {
		for i := range results {
			results[i] = e
		}
	}
	mxs, derr := w.lookupMX(ctx, domain)
	if derr != nil {
		setAll(derr)
		return results
	}
	var last *deliveryError = temp("no usable mail exchanger for %s", domain)
	for _, mx := range mxs {
		addrs, err := w.Resolver.LookupIPAddr(ctx, mx.host)
		if err != nil {
			last = temp("resolve %s: %v", mx.host, err)
			continue
		}
		tried := 0
		for _, a := range addrs {
			if !w.allowedIP(a.IP) {
				last = perm("MX %s resolves to non-public address %s", mx.host, a.IP)
				continue
			}
			if tried >= 2 {
				break
			}
			tried++
			res, sessErr := w.session(ctx, mx.host, a.IP, items)
			if sessErr == nil {
				return res
			}
			last = sessErr
			if sessErr.perm {
				setAll(sessErr)
				return results
			}
		}
	}
	setAll(last)
	return results
}

// session runs one SMTP transaction. A nil error means the per-recipient
// results in the returned slice are authoritative.
func (w *Worker) session(ctx context.Context, mxHost string, ip net.IP, items []*store.QueueItem) ([]*deliveryError, *deliveryError) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	conn, err := w.Dial(ctx, "tcp", net.JoinHostPort(ip.String(), w.Port))
	if err != nil {
		return nil, temp("connect %s [%s]: %v", mxHost, ip, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return nil, smtpErr(mxHost, "greeting", err)
	}
	defer c.Close()
	if err := c.Hello(w.Cfg.Hostname); err != nil {
		return nil, smtpErr(mxHost, "EHLO", err)
	}

	verified := false
	if ok, _ := c.Extension("STARTTLS"); ok {
		tc := w.clientTLSConfig(mxHost, &verified)
		if err := c.StartTLS(tc); err != nil {
			return nil, temp("STARTTLS with %s failed: %v", mxHost, err)
		}
	} else if w.Cfg.OutboundTLS != config.OutboundTLSOpportunistic {
		return nil, temp("%s does not offer STARTTLS (MDMAIL_OUTBOUND_TLS=%s)", mxHost, w.Cfg.OutboundTLS)
	}
	w.Log.Debug("smtp session", "mx", mxHost, "tls_verified", verified)

	if err := c.Mail(items[0].MailFrom); err != nil {
		return nil, smtpErr(mxHost, "MAIL FROM", err)
	}
	results := make([]*deliveryError, len(items))
	accepted := 0
	for i, it := range items {
		if err := c.Rcpt(it.Rcpt); err != nil {
			results[i] = smtpErr(mxHost, "RCPT TO", err)
			continue
		}
		accepted++
	}
	if accepted == 0 {
		_ = c.Reset()
		_ = c.Quit()
		return results, nil
	}
	wc, err := c.Data()
	if err != nil {
		return nil, smtpErr(mxHost, "DATA", err)
	}
	if _, err := wc.Write(toCRLF(items[0].Raw)); err != nil {
		return nil, temp("writing message to %s: %v", mxHost, err)
	}
	if err := wc.Close(); err != nil {
		de := smtpErr(mxHost, "end of DATA", err)
		for i := range results {
			if results[i] == nil {
				results[i] = de
			}
		}
		return results, nil
	}
	_ = c.Quit()
	return results, nil
}

func (w *Worker) clientTLSConfig(host string, verified *bool) *tls.Config {
	policy := w.Cfg.OutboundTLS
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Verification is done in VerifyConnection so that policy "encrypt"
		// can accept unverifiable certificates (as most MTAs do, RFC 7435)
		// while policy "verify" rejects them.
		InsecureSkipVerify: true, // #nosec G402 -- verification performed in VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			*verified = err == nil
			if err != nil && policy == config.OutboundTLSVerify {
				return fmt.Errorf("certificate verification failed: %w", err)
			}
			return nil
		},
	}
}

func smtpErr(host, stage string, err error) *deliveryError {
	var te *textproto.Error
	if errors.As(err, &te) {
		msg := fmt.Sprintf("%s rejected %s: %d %s", host, stage, te.Code, te.Msg)
		if te.Code >= 500 {
			return perm("%s", msg)
		}
		return temp("%s", msg)
	}
	return temp("%s %s: %v", host, stage, err)
}

func toCRLF(b []byte) []byte {
	if !bytes.Contains(b, []byte("\n")) || bytes.Count(b, []byte("\r\n")) == bytes.Count(b, []byte("\n")) {
		return b
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}
