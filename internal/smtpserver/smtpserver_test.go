package smtpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/smtp"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/store"
)

type fakeDNS struct{}

func (fakeDNS) LookupTXT(_ context.Context, n string) ([]string, error) {
	return nil, &net.DNSError{Err: "nx", Name: n, IsNotFound: true}
}
func (fakeDNS) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "nx", Name: n, IsNotFound: true}
}
func (fakeDNS) LookupIPAddr(_ context.Context, n string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "nx", Name: n, IsNotFound: true}
}
func (fakeDNS) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

const host = "mx.example.com"

type env struct {
	st       *store.Store
	deps     *Deps
	roots    *x509.CertPool
	alice    int64
	bob      int64
	enqueued int
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{Hostname: host, Domains: []string{"example.com"}, MaxMessageBytes: 1 << 20, MaxRecipients: 5, SubmitPerHour: 100}
	box, _, _ := auth.LoadOrCreateKey(filepath.Join(dir, "key"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := mailauth.GenerateKey(filepath.Join(dir, "dkim"), "example.com"); err != nil {
		t.Fatal(err)
	}
	signer, _, err := mailauth.LoadSigner(filepath.Join(dir, "dkim"), "mdmail", cfg.Domains)
	if err != nil {
		t.Fatal(err)
	}
	al := audit.New(st, log)
	m := mailer.New(cfg, st, signer, al, log)
	cert, roots := selfSigned(t)
	deps := &Deps{Cfg: cfg, St: st, Mailer: m, Auth: auth.NewAuthenticator(st, box), Audit: al, Log: log,
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Verifier: &mailauth.Verifier{Hostname: host, Resolver: fakeDNS{}, Enforce: true}}
	deps.Init()
	h, _ := auth.HashPassword("alice-password-123")
	a, _ := st.CreateUser(ctx, "alice@example.com", h, false)
	b, _ := st.CreateUser(ctx, "bob@example.com", h, false)
	e := &env{st: st, deps: deps, roots: roots, alice: a, bob: b}
	m.Wake = func() { e.enqueued++ }
	return e
}

func serve(t *testing.T, srv interface{ Serve(net.Listener) error }) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) *smtp.Client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	return c
}

func code(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()[:3]
}

func TestInboundNoRelayAndDelivery(t *testing.T) {
	e := setup(t)
	addr := serve(t, NewInbound(e.deps))
	c := dial(t, addr)
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("MX must not offer AUTH")
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("MX must offer STARTTLS")
	}
	if err := c.Mail("someone@remote.test"); err != nil {
		t.Fatal(err)
	}
	if got := code(c.Rcpt("victim@gmail.com")); got != "554" {
		t.Fatalf("open relay! RCPT to foreign domain: %s", got)
	}
	if got := code(c.Rcpt("nobody@example.com")); got != "550" {
		t.Fatalf("unknown local user: %s", got)
	}
	if err := c.Rcpt("Bob@Example.com"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "Authentication-Results: mx.example.com; dkim=pass\r\nFrom: Someone <someone@remote.test>\r\nTo: bob@example.com\r\nSubject: hello\r\n\r\nhi bob\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	msgs, _ := e.st.ListMessages(context.Background(), e.bob, store.FolderInbox, 0, 10, "")
	if len(msgs) != 1 || msgs[0].Subject != "hello" {
		t.Fatalf("not delivered: %+v", msgs)
	}
	full, _ := e.st.GetMessage(context.Background(), e.bob, msgs[0].ID)
	raw := string(full.Raw)
	if !strings.HasPrefix(raw, "Received: from client.test ([127.0.0.1]) by mx.example.com") {
		t.Errorf("missing Received: %s", raw[:120])
	}
	if strings.Contains(raw, "; dkim=pass\r\n") {
		t.Error("forged Authentication-Results not removed")
	}
	if !strings.Contains(raw, "Authentication-Results: mx.example.com;") {
		t.Error("no Authentication-Results added")
	}
}

func TestSubmissionRequiresTLSAndAuth(t *testing.T) {
	e := setup(t)
	addr := serve(t, NewSubmission(e.deps))
	c := dial(t, addr)
	if ok, _ := c.Extension("AUTH"); ok {
		t.Fatal("AUTH offered before TLS")
	}
	if got := code(c.Mail("alice@example.com")); got != "530" && got != "502" {
		t.Fatalf("MAIL without auth: %s", got)
	}
	if err := c.StartTLS(&tls.Config{ServerName: host, RootCAs: e.roots, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	if ok, mechs := c.Extension("AUTH"); !ok || !strings.Contains(mechs, "PLAIN") {
		t.Fatal("AUTH PLAIN not offered after TLS")
	}
	if err := c.Auth(smtp.PlainAuth("", "alice@example.com", "wrong-password-1", host)); err == nil {
		t.Fatal("wrong password accepted")
	}
	// net/smtp closes the connection after a failed AUTH; reconnect.
	c = dial(t, addr)
	if err := c.StartTLS(&tls.Config{ServerName: host, RootCAs: e.roots, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	if err := c.Auth(smtp.PlainAuth("", "alice@example.com", "alice-password-123", host)); err != nil {
		t.Fatal(err)
	}
	if got := code(c.Mail("bob@example.com")); got != "553" {
		t.Fatalf("envelope sender spoofing allowed: %s", got)
	}
	if err := c.Mail("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"bob@example.com", "carol@remote.test"} {
		if err := c.Rcpt(r); err != nil {
			t.Fatal(err)
		}
	}
	w, _ := c.Data()
	_, _ = io.WriteString(w, "From: Alice <alice@example.com>\r\nTo: bob@example.com, carol@remote.test\r\nBcc: hidden@remote.test\r\nSubject: via smtp\r\n\r\nhello\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sent, _ := e.st.ListMessages(ctx, e.alice, store.FolderSent, 0, 10, "")
	if len(sent) != 1 {
		t.Fatal("no Sent copy")
	}
	full, _ := e.st.GetMessage(ctx, e.alice, sent[0].ID)
	if !strings.HasPrefix(string(full.Raw), "DKIM-Signature:") || strings.Contains(string(full.Raw), "hidden@remote.test") {
		t.Fatalf("sent copy not signed or Bcc leaked:\n%s", full.Raw)
	}
	inbox, _ := e.st.ListMessages(ctx, e.bob, store.FolderInbox, 0, 10, "")
	if len(inbox) != 1 {
		t.Fatal("local recipient did not receive")
	}
	q, _ := e.st.ListQueue(ctx)
	if len(q) != 1 || q[0].Rcpt != "carol@remote.test" || e.enqueued != 1 {
		t.Fatalf("remote recipient not queued: %+v", q)
	}

	// Header From spoofing is refused even with a valid envelope.
	if err := c.Mail("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	_ = c.Rcpt("bob@example.com")
	w, _ = c.Data()
	_, _ = io.WriteString(w, "From: ceo@example.com\r\nSubject: spoof\r\n\r\nx\r\n")
	if got := code(w.Close()); got != "553" {
		t.Fatalf("header From spoofing: %s", got)
	}
}
