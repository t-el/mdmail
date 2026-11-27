// Package tlsutil builds hardened TLS configurations backed either by ACME
// (Let's Encrypt via autocert) or by certificate files that are reloaded
// automatically when renewed.
package tlsutil

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/t-el/mdmail/internal/config"
)

// Bundle holds the TLS configurations for each protocol.
type Bundle struct {
	Web  *tls.Config  // HTTPS (h2 + http/1.1)
	Mail *tls.Config  // SMTP STARTTLS / implicit TLS
	HTTP http.Handler // port-80 handler (ACME http-01 + redirect); may be nil
}

// Hosts returns the names the certificate must cover.
func Hosts(cfg *config.Config) []string {
	hosts := []string{cfg.Hostname}
	if cfg.MTASTSMode != "none" {
		for _, d := range cfg.Domains {
			hosts = append(hosts, "mta-sts."+d)
		}
	}
	return hosts
}

func base() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// TLS 1.3 suites are not configurable (all are AEAD). For TLS 1.2,
		// only forward-secret AEAD suites are allowed.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}
}

// Setup builds the TLS bundle.
func Setup(cfg *config.Config, log *slog.Logger) (*Bundle, error) {
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	b := &Bundle{}
	switch cfg.TLSMode {
	case config.TLSModeACME:
		if err := os.MkdirAll(cfg.ACMECacheDir(), 0o700); err != nil {
			return nil, err
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.ACMECacheDir()),
			HostPolicy: autocert.HostWhitelist(Hosts(cfg)...),
			Email:      cfg.ACMEEmail,
		}
		if cfg.ACMEDirectory != "" {
			m.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectory}
		}
		getCert = m.GetCertificate
		b.HTTP = m.HTTPHandler(redirectHandler(cfg.Hostname))
	case config.TLSModeFiles:
		r, err := newReloader(cfg.TLSCertFile, cfg.TLSKeyFile, log)
		if err != nil {
			return nil, err
		}
		getCert = r.get
		if cfg.HTTPAddr != "" {
			b.HTTP = redirectHandler(cfg.Hostname)
		}
	default:
		return nil, errors.New("tlsutil: unknown TLS mode")
	}
	host := cfg.Hostname
	withSNIDefault := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "" {
			// Many SMTP clients omit SNI; serve the MX hostname certificate.
			h.ServerName = host
		}
		return getCert(h)
	}
	b.Web = base()
	b.Web.GetCertificate = withSNIDefault
	b.Web.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	b.Mail = base()
	b.Mail.GetCertificate = withSNIDefault
	return b, nil
}

func redirectHandler(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "use HTTPS", http.StatusBadRequest)
			return
		}
		// Always redirect to the configured host (never reflect Host header).
		http.Redirect(w, r, "https://"+host+"/", http.StatusMovedPermanently)
	})
}

type reloader struct {
	certFile, keyFile string
	log               *slog.Logger
	mu                sync.RWMutex
	cert              *tls.Certificate
	modTime           time.Time
	checked           time.Time
}

func newReloader(certFile, keyFile string, log *slog.Logger) (*reloader, error) {
	r := &reloader{certFile: filepath.Clean(certFile), keyFile: filepath.Clean(keyFile), log: log}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *reloader) load() error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("tlsutil: load certificate: %w", err)
	}
	r.mu.Lock()
	r.cert, r.modTime = &c, st.ModTime()
	r.mu.Unlock()
	return nil
}

func (r *reloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	c, checked, mod := r.cert, r.checked, r.modTime
	r.mu.RUnlock()
	if time.Since(checked) > time.Minute {
		r.mu.Lock()
		r.checked = time.Now()
		r.mu.Unlock()
		if st, err := os.Stat(r.certFile); err == nil && st.ModTime().After(mod) {
			if err := r.load(); err != nil {
				r.log.Error("certificate reload failed; keeping previous certificate", "err", err)
			} else {
				r.log.Info("certificate reloaded")
				r.mu.RLock()
				c = r.cert
				r.mu.RUnlock()
			}
		}
	}
	return c, nil
}
