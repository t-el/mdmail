// Package web serves the HTTPS JSON API and the embedded web client.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/ratelimit"
	"github.com/t-el/mdmail/internal/store"
)

//go:embed static
var staticFS embed.FS

// Server is the web application.
type Server struct {
	Cfg    *config.Config
	St     *store.Store
	Auth   *auth.Authenticator
	Mailer *mailer.Mailer
	Audit  *audit.Logger
	Log    *slog.Logger

	// SecureCookies must be true in production (always, since we only
	// serve HTTPS). Tests may disable it.
	SecureCookies bool

	ipLimit      *ratelimit.Keyed
	loginLimit   *ratelimit.Keyed
	previewLimit *ratelimit.Keyed // per user
	taskLimit    *ratelimit.Keyed // per user
}

// New creates the web server.
func New(cfg *config.Config, st *store.Store, a *auth.Authenticator, m *mailer.Mailer, al *audit.Logger, log *slog.Logger) *Server {
	return &Server{Cfg: cfg, St: st, Auth: a, Mailer: m, Audit: al, Log: log.With("component", "web"), SecureCookies: true,
		ipLimit:      ratelimit.New(50*time.Millisecond, 100), // 20 req/s sustained, burst 100
		loginLimit:   ratelimit.New(12*time.Second, 10),       // 5/min sustained, burst 10
		previewLimit: ratelimit.New(200*time.Millisecond, 20), // 5/s sustained, burst 20
		taskLimit:    ratelimit.New(250*time.Millisecond, 20), // 4/s sustained, burst 20
	}
}

// Limiters returns the rate limiters for periodic GC.
func (s *Server) Limiters() []*ratelimit.Keyed {
	return []*ratelimit.Keyed{s.ipLimit, s.loginLimit, s.previewLimit, s.taskLimit}
}

// Handler builds the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServerFS(static)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, static, "index.html")
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", noDirListing(fileServer)))

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.authed(s.handleLogout))
	mux.HandleFunc("GET /api/session", s.authed(s.handleSession))

	mux.HandleFunc("GET /api/folders", s.authed(s.handleFolders))
	mux.HandleFunc("POST /api/folders/{folder}/empty", s.authed(s.handleEmptyFolder))
	mux.HandleFunc("GET /api/messages", s.authed(s.handleList))
	mux.HandleFunc("GET /api/messages/{id}", s.authed(s.handleGet))
	mux.HandleFunc("GET /api/messages/{id}/body", s.authed(s.handleBody))
	mux.HandleFunc("GET /api/messages/{id}/raw", s.authed(s.handleRaw))
	mux.HandleFunc("GET /api/messages/{id}/attachments/{idx}", s.authed(s.handleAttachment))
	mux.HandleFunc("GET /api/messages/{id}/checklist", s.authed(s.handleChecklist))
	mux.HandleFunc("POST /api/messages/{id}/checklist/{item}", s.authed(s.handleChecklistToggle))
	mux.HandleFunc("PATCH /api/messages/{id}", s.authed(s.handleUpdate))
	mux.HandleFunc("DELETE /api/messages/{id}", s.authed(s.handleDelete))
	mux.HandleFunc("POST /api/preview", s.authed(s.handlePreview))
	mux.HandleFunc("POST /api/send", s.authed(s.handleSend))

	mux.HandleFunc("GET /api/account", s.authed(s.handleAccount))
	mux.HandleFunc("POST /api/account/password", s.authed(s.handleChangePassword))
	mux.HandleFunc("POST /api/account/totp/setup", s.authed(s.handleTOTPSetup))
	mux.HandleFunc("POST /api/account/totp/enable", s.authed(s.handleTOTPEnable))
	mux.HandleFunc("POST /api/account/totp/disable", s.authed(s.handleTOTPDisable))
	mux.HandleFunc("POST /api/account/app-passwords", s.authed(s.handleAppPasswordCreate))
	mux.HandleFunc("DELETE /api/account/app-passwords/{id}", s.authed(s.handleAppPasswordDelete))
	mux.HandleFunc("POST /api/account/sessions/revoke", s.authed(s.handleRevokeSessions))

	return s.securityHeaders(s.hostCheck(s.rateLimit(mux)))
}

func noDirListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		ct, ok := staticTypes[path.Ext(r.URL.Path)]
		if !ok {
			http.NotFound(w, r) // only known asset types are served
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// staticTypes pins the Content-Type of every embedded asset type instead of
// relying on the host's MIME database (absent in distroless images).
// Together with X-Content-Type-Options: nosniff, a script or style sheet is
// only ever executed or applied with its correct type.
var staticTypes = map[string]string{
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".ico":  "image/x-icon",
}

// mainCSP applies to the application shell. No inline script or style is
// permitted; message bodies are rendered in a separate sandboxed document.
const mainCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; manifest-src 'self'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", mainCSP)
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == s.Cfg.Hostname {
			next.ServeHTTP(w, r)
			return
		}
		if s.Cfg.MTASTSMode != "none" && strings.HasPrefix(host, "mta-sts.") && s.Cfg.IsLocalDomain(strings.TrimPrefix(host, "mta-sts.")) {
			s.serveMTASTS(w, r)
			return
		}
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
	})
}

func (s *Server) serveMTASTS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/mta-sts.txt" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	_, _ = io.WriteString(w, "version: STSv1\nmode: "+s.Cfg.MTASTSMode+"\nmx: "+s.Cfg.Hostname+"\nmax_age: "+
		strconv.FormatInt(int64(s.Cfg.MTASTSMaxAge/time.Second), 10)+"\n")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ipLimit.Allow(clientIP(r)) {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- helpers

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

const maxJSONBody = 256 << 10

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSONLimit(w, r, v, maxJSONBody)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.ErrorContext(r.Context(), "internal error", "path", r.URL.Path, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// HealthHandler returns the loopback-only health endpoint.
func HealthHandler(st *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}
