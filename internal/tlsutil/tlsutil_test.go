package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/t-el/mdmail/internal/config"
)

func writeCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalECPrivateKey(k)
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cf, kf
}

func TestFilesModeAndRedirect(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writeCert(t, dir, "mail.example.com")
	cfg := &config.Config{Hostname: "mail.example.com", TLSMode: config.TLSModeFiles, TLSCertFile: cf, TLSKeyFile: kf, HTTPAddr: ":80", MTASTSMode: "none"}
	b, err := Setup(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if b.Mail.MinVersion != tls.VersionTLS12 || b.Web.MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS 1.2 minimum not enforced")
	}
	c, err := b.Mail.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c == nil {
		t.Fatal("no certificate for SNI-less client", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://evil.test/x", nil)
	b.HTTP.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://mail.example.com/" {
		t.Fatalf("redirect: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHosts(t *testing.T) {
	cfg := &config.Config{Hostname: "mail.example.com", Domains: []string{"a.test", "b.test"}, MTASTSMode: "enforce"}
	if h := Hosts(cfg); len(h) != 3 || h[1] != "mta-sts.a.test" {
		t.Fatalf("hosts %v", h)
	}
}
