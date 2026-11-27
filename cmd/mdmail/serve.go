package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/delivery"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/ratelimit"
	"github.com/t-el/mdmail/internal/smtpserver"
	"github.com/t-el/mdmail/internal/store"
	"github.com/t-el/mdmail/internal/tlsutil"
	"github.com/t-el/mdmail/internal/web"
)

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting mdmail", "version", version, "hostname", cfg.Hostname, "domains", cfg.Domains, "database", cfg.DBPath())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	box, created, err := auth.LoadOrCreateKey(cfg.SecretKeyFile)
	if err != nil {
		return err
	}
	if created {
		logger.Warn("generated new secret key; back it up together with the database", "path", cfg.SecretKeyFile)
	}
	authn := auth.NewAuthenticator(st, box)
	al := audit.New(st, logger)

	signer, missing, err := mailauth.LoadSigner(cfg.DKIMKeyDir, cfg.DKIMSelector, cfg.Domains)
	if err != nil {
		return err
	}
	for _, d := range missing {
		logger.Warn("no DKIM key for domain; outgoing mail will be unsigned. Run: mdmail dkim generate "+d, "domain", d)
	}

	m := mailer.New(cfg, st, signer, al, logger)
	worker := delivery.NewWorker(cfg, st, m, logger)

	bundle, err := tlsutil.Setup(cfg, logger)
	if err != nil {
		return err
	}

	deps := &smtpserver.Deps{Cfg: cfg, St: st, Mailer: m, Auth: authn, Audit: al, Log: logger, TLS: bundle.Mail,
		Verifier: &mailauth.Verifier{Hostname: cfg.Hostname, Resolver: net.DefaultResolver, Enforce: cfg.DMARCEnforce}}
	deps.Init()

	ws := web.New(cfg, st, authn, m, al, logger)

	limiters := append(append([]*ratelimit.Keyed{m.RateLimiter()}, deps.Limiters()...), ws.Limiters()...)
	for _, l := range limiters {
		go l.RunGC(ctx.Done(), 10*time.Minute)
	}

	errc := make(chan error, 8)
	var wg sync.WaitGroup
	var shutdowns []func(context.Context) error

	startSMTP := func(name, addr string, srv *smtp.Server, implicitTLS bool) {
		if addr == "" {
			return
		}
		var ln net.Listener
		var err error
		if implicitTLS {
			ln, err = tls.Listen("tcp", addr, bundle.Mail)
		} else {
			ln, err = net.Listen("tcp", addr)
		}
		if err != nil {
			errc <- fmt.Errorf("%s listen %s: %w", name, addr, err)
			return
		}
		logger.Info("listening", "service", name, "addr", addr)
		shutdowns = append(shutdowns, srv.Shutdown)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	startHTTP := func(name string, srv *http.Server, tlsOn bool) {
		if srv.Addr == "" {
			return
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			errc <- fmt.Errorf("%s listen %s: %w", name, srv.Addr, err)
			return
		}
		logger.Info("listening", "service", name, "addr", srv.Addr)
		shutdowns = append(shutdowns, srv.Shutdown)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if tlsOn {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	httpErrLog := log.New(slogWriter{logger.With("component", "http")}, "", 0)
	newHTTP := func(addr string, h http.Handler, tc *tls.Config) *http.Server {
		return &http.Server{Addr: addr, Handler: h, TLSConfig: tc, ErrorLog: httpErrLog,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
			IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10}
	}

	startSMTP("smtp", cfg.SMTPAddr, smtpserver.NewInbound(deps), false)
	startSMTP("submission", cfg.SubmissionAddr, smtpserver.NewSubmission(deps), false)
	startSMTP("submissions", cfg.SubmissionsAddr, smtpserver.NewSubmission(deps), true)
	startHTTP("https", newHTTP(cfg.HTTPSAddr, ws.Handler(), bundle.Web), true)
	if bundle.HTTP != nil {
		startHTTP("http", newHTTP(cfg.HTTPAddr, bundle.HTTP, nil), false)
	}
	startHTTP("health", newHTTP(cfg.HealthAddr, web.HealthHandler(st), nil), false)

	go worker.Run(ctx)
	go ws.PurgeLoop(ctx)

	var fatal error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case fatal = <-errc:
		logger.Error("fatal", "err", fatal)
		stop()
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, fn := range shutdowns {
		_ = fn(sctx)
	}
	wg.Wait()
	logger.Info("stopped")
	return fatal
}

type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.l.Warn(string(p))
	return len(p), nil
}

func healthcheck() error {
	addr := os.Getenv("MDMAIL_HEALTH_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !net.ParseIP(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")).IsLoopback() && host != "localhost" {
		return fmt.Errorf("MDMAIL_HEALTH_ADDR must be a loopback address")
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz") // #nosec G704 -- address validated to be loopback above
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
