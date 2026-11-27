package delivery

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/store"
)

type remote struct {
	mu   sync.Mutex
	got  map[string][]byte
	from string
}

type remoteSession struct {
	r     *remote
	rcpts []string
}

func (s *remoteSession) Reset()        {}
func (s *remoteSession) Logout() error { return nil }
func (s *remoteSession) Mail(from string, _ *smtp.MailOptions) error {
	s.r.mu.Lock()
	s.r.from = from
	s.r.mu.Unlock()
	return nil
}
func (s *remoteSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if strings.HasPrefix(to, "reject@") {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	if strings.HasPrefix(to, "later@") {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 2, 0}, Message: "greylisted"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}
func (s *remoteSession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	for _, rc := range s.rcpts {
		s.r.got[rc] = b
	}
	return nil
}

type fakeResolver struct{}

func (fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	switch name {
	case "remote.test":
		return []*net.MX{{Host: "mx.remote.test.", Pref: 10}}, nil
	case "nullmx.test":
		return []*net.MX{{Host: ".", Pref: 0}}, nil
	}
	return nil, &net.DNSError{Err: "nx", Name: name, IsNotFound: true}
}
func (fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	if name == "mx.remote.test" {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	return nil, &net.DNSError{Err: "nx", Name: name, IsNotFound: true}
}

func setup(t *testing.T, allowPrivate bool) (*Worker, *store.Store, int64, *remote) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rem := &remote{got: map[string][]byte{}}
	srv := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) { return &remoteSession{r: rem}, nil }))
	srv.Domain = "mx.remote.test"
	srv.AllowInsecureAuth = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	cfg := &config.Config{Hostname: "mx.example.com", Domains: []string{"example.com"}, MaxMessageBytes: 1 << 20,
		MaxRecipients: 10, SubmitPerHour: 100, OutboundTLS: config.OutboundTLSOpportunistic, AllowPrivateMX: allowPrivate}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, _, _ := mailauth.LoadSigner(t.TempDir(), "s", nil)
	m := mailer.New(cfg, st, signer, audit.New(st, log), log)
	w := NewWorker(cfg, st, m, log)
	w.Resolver = fakeResolver{}
	w.Port = port
	uid, _ := st.CreateUser(ctx, "alice@example.com", "h", false)
	return w, st, uid, rem
}

const raw = "From: alice@example.com\r\nTo: x@remote.test\r\nSubject: out\r\n\r\nbody\r\n"

func TestDeliverySuccessBounceAndRetry(t *testing.T) {
	w, st, uid, rem := setup(t, true)
	ctx := context.Background()
	if err := st.Enqueue(ctx, &uid, "alice@example.com", []string{"ok@remote.test", "reject@remote.test", "later@remote.test", "x@nullmx.test"}, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	w.runOnce(ctx)
	if b := rem.got["ok@remote.test"]; !strings.Contains(string(b), "Subject: out") {
		t.Fatalf("not delivered: %q", b)
	}
	if rem.from != "alice@example.com" {
		t.Errorf("MAIL FROM = %q", rem.from)
	}
	inbox, _ := st.ListMessages(ctx, uid, store.FolderInbox, 0, 10, "")
	if len(inbox) != 2 {
		t.Fatalf("expected 2 bounces (550 + null MX), got %d", len(inbox))
	}
	for _, m := range inbox {
		if m.Subject != "Undelivered Mail Returned to Sender" {
			t.Errorf("unexpected message %q", m.Subject)
		}
	}
	q, _ := st.ListQueue(ctx)
	if len(q) != 1 || q[0].Rcpt != "later@remote.test" || q[0].Attempts != 1 || !strings.Contains(q[0].LastError, "451") {
		t.Fatalf("temporary failure not rescheduled: %+v", q)
	}
	if q[0].Next.Before(time.Now().Add(4 * time.Minute)) {
		t.Error("retry scheduled too early")
	}
}

func TestPrivateMXRefused(t *testing.T) {
	w, st, uid, rem := setup(t, false)
	ctx := context.Background()
	_ = st.Enqueue(ctx, &uid, "alice@example.com", []string{"ok@remote.test"}, []byte(raw))
	w.runOnce(ctx)
	if len(rem.got) != 0 {
		t.Fatal("delivered to a loopback MX")
	}
	inbox, _ := st.ListMessages(ctx, uid, store.FolderInbox, 0, 10, "")
	if len(inbox) != 1 {
		t.Fatal("expected a bounce for non-public MX")
	}
}

func TestRequireTLSPolicy(t *testing.T) {
	w, st, uid, rem := setup(t, true)
	w.Cfg.OutboundTLS = config.OutboundTLSEncrypt
	ctx := context.Background()
	_ = st.Enqueue(ctx, &uid, "alice@example.com", []string{"ok@remote.test"}, []byte(raw))
	w.runOnce(ctx)
	if len(rem.got) != 0 {
		t.Fatal("delivered in plaintext although TLS is required")
	}
	q, _ := st.ListQueue(ctx)
	if len(q) != 1 || !strings.Contains(q[0].LastError, "STARTTLS") {
		t.Fatalf("expected deferred delivery, got %+v", q)
	}
}

func TestBackoff(t *testing.T) {
	if Backoff(0) != 5*time.Minute || Backoff(100) != 12*time.Hour {
		t.Fatal("backoff schedule")
	}
	var de *deliveryError
	if !errors.As(error(perm("x")), &de) || !de.perm {
		t.Fatal("perm")
	}
}
