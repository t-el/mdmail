package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/store"
)

// cookieName uses the __Host- prefix: the browser enforces Secure, Path=/
// and no Domain attribute, preventing subdomain cookie injection.
const cookieName = "__Host-mdmail"

const cookieNameInsecure = "mdmail" // tests only (SecureCookies=false)

type reqCtx struct {
	user *store.User
	sess *store.Session
	ip   string
}

func (s *Server) cookieName() string {
	if s.SecureCookies {
		return cookieName
	}
	return cookieNameInsecure
}

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, maxAge time.Duration) {
	// #nosec G124 -- Secure is always true in production (SecureCookies is only disabled by tests).
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: token, Path: "/", MaxAge: int(maxAge / time.Second),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	// #nosec G124 -- see setSessionCookie.
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
}

// sameOrigin verifies that a state-changing request was issued by our own
// origin (defence in depth on top of SameSite=Strict and the CSRF token).
// It returns a short server-side reason when the check fails; the reason is
// for logs only and is never sent to the client.
func (s *Server) sameOrigin(r *http.Request) (ok bool, reason string) {
	sfs := r.Header.Get("Sec-Fetch-Site")
	if sfs != "" && sfs != "same-origin" {
		return false, "sec-fetch-site=" + sfs
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		// Browsers send Origin on every non-GET fetch, but a same-origin
		// POST from a page with Referrer-Policy: no-referrer is sent as
		// "Origin: null" by spec-following browsers (Fetch §3.1). The
		// browser-controlled Sec-Fetch-Site header then decides.
		if sfs == "same-origin" {
			return true, ""
		}
		return false, "missing origin (origin=" + strconv.Quote(origin) + ", no sec-fetch-site)"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false, "unparseable origin " + strconv.Quote(origin)
	}
	if !strings.EqualFold(u.Hostname(), s.Cfg.Hostname) {
		return false, "origin host " + strconv.Quote(u.Hostname()) + " != MDMAIL_HOSTNAME " + strconv.Quote(s.Cfg.Hostname)
	}
	// Any port is accepted: the listener port (e.g. :8443 behind NAT or in
	// local testing) is not part of the trust decision, the host name is.
	if u.Scheme != "https" && s.SecureCookies {
		return false, "origin scheme " + strconv.Quote(u.Scheme) + " is not https"
	}
	return true, ""
}

func isSafeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// authed wraps a handler with session authentication and CSRF protection.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *reqCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName())
		if err != nil || len(c.Value) < 20 || len(c.Value) > 100 {
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		ctx := r.Context()
		sess, err := s.St.SessionByHash(ctx, hashToken(c.Value))
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		now := time.Now()
		if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > s.Cfg.SessionIdle {
			_ = s.St.DeleteSession(ctx, sess.IDHash)
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		if !isSafeMethod(r.Method) {
			tok := r.Header.Get("X-CSRF-Token")
			reason := ""
			if ok, why := s.sameOrigin(r); !ok {
				reason = why
			} else if tok == "" {
				reason = "missing X-CSRF-Token"
			} else if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) != 1 {
				reason = "X-CSRF-Token does not match session"
			}
			if reason != "" {
				s.Log.DebugContext(ctx, "request refused by CSRF protection", "path", r.URL.Path, "reason", reason, "ip", clientIP(r))
				writeJSON(w, http.StatusForbidden, apiError{Error: msgSecurityCheck, Code: codeCSRF})
				return
			}
		}
		u, err := s.St.UserByID(ctx, sess.UserID)
		if err != nil || u.Disabled {
			_ = s.St.DeleteSession(ctx, sess.IDHash)
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if now.Sub(sess.LastSeen) > time.Minute {
			_ = s.St.TouchSession(ctx, sess.IDHash, now)
		}
		h(w, r, &reqCtx{user: u, sess: sess, ip: clientIP(r)})
	}
}

type userView struct {
	Email       string `json:"email"`
	TOTPEnabled bool   `json:"totp_enabled"`
	IsAdmin     bool   `json:"is_admin"`
}

type sessionResp struct {
	User userView `json:"user"`
	CSRF string   `json:"csrf"`
}

func viewOf(u *store.User) userView {
	return userView{Email: u.Email, TOTPEnabled: u.TOTPEnabled, IsAdmin: u.IsAdmin}
}

// Client-facing login error messages and codes. Credential failures share
// one message (no account enumeration, and a lockout is not disclosed);
// request-integrity failures get a distinct one so that a misconfigured
// origin or a stale page is not mistaken for a wrong password.
const (
	msgLoginFailed   = "invalid email, password or code"
	msgSecurityCheck = "request blocked by a security check (cross-site or stale page); reload the page from the server's own address and try again"
	codeLoginFailed  = "invalid_credentials"
	codeCSRF         = "csrf_failed"
	codeOrigin       = "origin_rejected"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	ctx := r.Context()
	if ok, why := s.sameOrigin(r); !ok {
		s.Log.DebugContext(ctx, "login refused by origin check", "reason", why, "ip", ip,
			"origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"), "host", r.Host)
		writeJSON(w, http.StatusForbidden, apiError{Error: msgSecurityCheck, Code: codeOrigin})
		return
	}
	if !s.loginLimit.Allow(ip) {
		s.Audit.Event(ctx, 0, "login_rate_limited", ip, "")
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.Auth.Login(ctx, req.Email, req.Password, req.TOTP, true)
	if err != nil {
		var uid int64
		if u != nil {
			uid = u.ID
		}
		switch {
		case errors.Is(err, auth.ErrTOTPRequired):
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "enter your authenticator code", Code: "totp_required"})
		case errors.Is(err, auth.ErrInvalid), errors.Is(err, auth.ErrLocked):
			reason := auth.FailureReason(err)
			s.Audit.Event(ctx, uid, "login_failure", ip, err.Error())
			s.Log.DebugContext(ctx, "login failed", "reason", reason, "email", auth.NormalizeEmail(req.Email),
				"user_id", uid, "ip", ip, "detail", err.Error())
			writeJSON(w, http.StatusUnauthorized, apiError{Error: msgLoginFailed, Code: codeLoginFailed})
		default:
			s.internalError(w, r, err)
		}
		return
	}
	token, err := randToken(32)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	csrf, err := randToken(32)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now()
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	sess := &store.Session{IDHash: hashToken(token), UserID: u.ID, CSRF: csrf, CreatedAt: now,
		ExpiresAt: now.Add(s.Cfg.SessionTTL), LastSeen: now, IP: ip, UserAgent: ua}
	if err := s.St.CreateSession(ctx, sess); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setSessionCookie(w, token, s.Cfg.SessionTTL)
	s.Audit.Event(ctx, u.ID, "login_success", ip, ua)
	writeJSON(w, http.StatusOK, sessionResp{User: viewOf(u), CSRF: csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if err := s.St.DeleteSession(r.Context(), rc.sess.IDHash); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.clearSessionCookie(w)
	s.Audit.Event(r.Context(), rc.user.ID, "logout", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, _ *http.Request, rc *reqCtx) {
	writeJSON(w, http.StatusOK, sessionResp{User: viewOf(rc.user), CSRF: rc.sess.CSRF})
}

// PurgeLoop removes expired sessions periodically.
func (s *Server) PurgeLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.St.PurgeSessions(ctx, time.Now(), s.Cfg.SessionIdle); err != nil {
				s.Log.Error("session purge failed", "err", err)
			}
			if err := s.St.PruneAudit(ctx, time.Now().AddDate(0, 0, -180)); err != nil {
				s.Log.Error("audit prune failed", "err", err)
			}
		}
	}
}
