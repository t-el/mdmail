package mailauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/authres"
)

type fakeDNS struct {
	txt map[string][]string
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (f *fakeDNS) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (f *fakeDNS) LookupAddr(_ context.Context, _ string) ([]string, error) { return nil, nil }

const msg = "From: Alice <alice@sender.test>\r\nTo: bob@example.com\r\nSubject: hi\r\nDate: Mon, 02 Jan 2006 15:04:05 +0000\r\nMessage-ID: <1@sender.test>\r\n\r\nHello\r\n"

func signerFor(t *testing.T, domain string) (*Signer, string) {
	t.Helper()
	dir := t.TempDir()
	rec, err := GenerateKey(dir, domain)
	if err != nil {
		t.Fatal(err)
	}
	s, missing, err := LoadSigner(dir, "sel", []string{domain, "other.test"})
	if err != nil || len(missing) != 1 || missing[0] != "other.test" {
		t.Fatal(err, missing)
	}
	if _, err := GenerateKey(dir, domain); err == nil {
		t.Fatal("GenerateKey overwrote an existing key")
	}
	if st, _ := os.Stat(KeyPath(dir, domain)); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	return s, rec
}

func TestDKIMSignVerifyAndDMARCPass(t *testing.T) {
	s, rec := signerFor(t, "sender.test")
	signed, err := s.Sign([]byte(msg), "sender.test")
	if err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS{txt: map[string][]string{
		"sel._domainkey.sender.test": {rec},
		"_dmarc.sender.test":         {"v=DMARC1; p=reject"},
		"sender.test":                {"v=spf1 -all"},
	}}
	v := &Verifier{Hostname: "mx.example.com", Resolver: dns, Enforce: true}
	res := v.Verify(context.Background(), net.ParseIP("203.0.113.9"), "mta.sender.test", "alice@sender.test", signed)
	if res.SPF != spf.Fail {
		t.Errorf("spf = %s", res.SPF)
	}
	if len(res.DKIM) != 1 || res.DKIM[0].Value != authres.ResultPass {
		t.Fatalf("dkim = %+v", res.DKIM)
	}
	if res.DMARC != authres.ResultPass || res.Action != Deliver {
		t.Fatalf("dmarc = %s action = %s (%s)", res.DMARC, res.Action, res.Reason)
	}
	if !strings.HasPrefix(res.Header, "mx.example.com;") || !strings.Contains(res.Header, "dkim=pass") {
		t.Errorf("header = %s", res.Header)
	}

	// Tampering with the body breaks DKIM -> DMARC fails -> reject.
	tampered := []byte(strings.Replace(string(signed), "Hello", "Pay me", 1))
	res = v.Verify(context.Background(), net.ParseIP("203.0.113.9"), "mta.sender.test", "alice@sender.test", tampered)
	if res.DMARC != authres.ResultFail || res.Action != Reject {
		t.Fatalf("tampered: dmarc=%s action=%s", res.DMARC, res.Action)
	}
	v.Enforce = false
	res = v.Verify(context.Background(), net.ParseIP("203.0.113.9"), "mta.sender.test", "alice@sender.test", tampered)
	if res.Action != Junk {
		t.Fatalf("non-enforcing reject should junk, got %s", res.Action)
	}
}

func TestDMARCOrgDomainAndQuarantine(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{
		"_dmarc.sender.test": {"v=DMARC1; p=reject; sp=quarantine"},
		"sender.test":        {"v=spf1 ip4:198.51.100.1 -all"},
	}}
	v := &Verifier{Hostname: "mx.example.com", Resolver: dns, Enforce: true}
	m := strings.Replace(msg, "alice@sender.test", "alice@news.sender.test", 1)
	res := v.Verify(context.Background(), net.ParseIP("203.0.113.9"), "x", "bounce@other.test", []byte(m))
	if res.DMARC != authres.ResultFail || res.Action != Junk {
		t.Fatalf("subdomain policy: dmarc=%s action=%s", res.DMARC, res.Action)
	}
	// SPF pass with relaxed alignment through the organizational domain.
	res = v.Verify(context.Background(), net.ParseIP("198.51.100.1"), "x", "bounce@sender.test", []byte(m))
	if res.DMARC != authres.ResultPass {
		t.Fatalf("relaxed spf alignment: %s", res.DMARC)
	}
}

func TestMultipleFromRejected(t *testing.T) {
	v := &Verifier{Hostname: "mx.example.com", Resolver: &fakeDNS{}}
	m := "From: a@x.test\r\nFrom: b@y.test\r\n\r\nbody\r\n"
	res := v.Verify(context.Background(), net.ParseIP("203.0.113.9"), "x", "", []byte(m))
	if res.DMARC != authres.ResultPermError || res.Action != Junk {
		t.Fatalf("got %s %s", res.DMARC, res.Action)
	}
}

func TestPrependTraceRemovesForgedResults(t *testing.T) {
	in := "Authentication-Results: mx.example.com; dkim=pass header.d=bank.test\r\nAuthentication-Results: other.test; spf=pass\r\n" + msg
	out, err := PrependTrace([]byte(in), "mx.example.com", "mx.example.com; spf=fail", "from x by y")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "header.d=bank.test") {
		t.Fatal("forged Authentication-Results kept")
	}
	if !strings.Contains(s, "other.test; spf=pass") || !strings.HasPrefix(s, "Received: from x by y\r\n") {
		t.Fatalf("unexpected output:\n%s", s)
	}
	if !strings.HasSuffix(s, "\r\n\r\nHello\r\n") {
		t.Fatal("body altered")
	}
}

func TestParsePKCS1Key(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(filepath.Join(dir, "d.test.pem"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _, err := LoadSigner(dir, "s", []string{"d.test"})
	if err != nil || !s.HasKey("D.TEST") {
		t.Fatal("PKCS#1 key not loaded", err)
	}
}
