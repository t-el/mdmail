package web

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/store"
)

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	aps, err := s.St.ListAppPasswords(ctx, rc.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	events, err := s.St.ListAudit(ctx, rc.user.ID, 50)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": viewOf(rc.user), "app_passwords": aps, "events": events,
		"smtp": map[string]any{"host": s.Cfg.Hostname, "submission_port": 587, "submissions_port": 465},
	})
}

// reauth re-verifies the current password for sensitive operations.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, rc *reqCtx, password, event string) bool {
	if err := auth.VerifyPassword(rc.user.PasswordHash, password); err != nil {
		_, _ = s.St.RecordLoginFailure(r.Context(), rc.user.ID, auth.LockThreshold, auth.LockBase, auth.LockMax)
		s.Audit.Event(r.Context(), rc.user.ID, event+"_reauth_failure", rc.ip, "")
		writeErr(w, http.StatusForbidden, "current password is incorrect")
		return false
	}
	return true
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.reauth(w, r, rc, req.Current, "password_change") {
		return
	}
	if err := auth.ValidatePassword(req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.EqualFold(req.New, rc.user.Email) {
		writeErr(w, http.StatusBadRequest, "password must not equal your address")
		return
	}
	h, err := auth.HashPassword(req.New)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := s.St.SetPassword(ctx, rc.user.ID, h); err != nil {
		s.internalError(w, r, err)
		return
	}
	// Invalidate all other sessions.
	if err := s.St.DeleteUserSessions(ctx, rc.user.ID, rc.sess.IDHash); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Audit.Event(ctx, rc.user.ID, "password_changed", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if rc.user.TOTPEnabled {
		writeErr(w, http.StatusConflict, "two-factor authentication is already enabled")
		return
	}
	if !s.reauth(w, r, rc, req.Password, "totp_setup") {
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	ct, err := s.Auth.SealTOTPSecret(rc.user.ID, secret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.St.SetTOTP(r.Context(), rc.user.ID, ct, false); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": auth.TOTPURI("mdmail "+s.Cfg.Hostname, rc.user.Email, secret)})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if rc.user.TOTPEnabled || len(rc.user.TOTPSecret) == 0 {
		writeErr(w, http.StatusConflict, "start setup first")
		return
	}
	secret, err := s.Auth.OpenTOTPSecret(rc.user.ID, rc.user.TOTPSecret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if _, ok := auth.VerifyTOTP(secret, req.Code, time.Now()); !ok {
		writeErr(w, http.StatusBadRequest, "invalid code; check your device clock")
		return
	}
	if err := s.St.SetTOTP(r.Context(), rc.user.ID, rc.user.TOTPSecret, true); err != nil {
		s.internalError(w, r, err)
		return
	}
	_ = s.St.DeleteUserSessions(r.Context(), rc.user.ID, rc.sess.IDHash)
	s.Audit.Event(r.Context(), rc.user.ID, "totp_enabled", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !rc.user.TOTPEnabled {
		writeErr(w, http.StatusConflict, "two-factor authentication is not enabled")
		return
	}
	if !s.reauth(w, r, rc, req.Password, "totp_disable") {
		return
	}
	if !s.Auth.CheckTOTP(rc.user, req.Code) {
		writeErr(w, http.StatusForbidden, "invalid code")
		return
	}
	if err := s.St.SetTOTP(r.Context(), rc.user.ID, nil, false); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Audit.Event(r.Context(), rc.user.ID, "totp_disabled", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAppPasswordCreate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 60 || strings.ContainsAny(req.Name, "\r\n\x00") {
		writeErr(w, http.StatusBadRequest, "name must be 1-60 characters")
		return
	}
	if !s.reauth(w, r, rc, req.Password, "app_password_create") {
		return
	}
	aps, err := s.St.ListAppPasswords(r.Context(), rc.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(aps) >= 20 {
		writeErr(w, http.StatusBadRequest, "at most 20 app passwords")
		return
	}
	pw, h, err := auth.NewAppPassword()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	id, err := s.St.CreateAppPassword(r.Context(), rc.user.ID, req.Name, h)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Audit.Event(r.Context(), rc.user.ID, "app_password_created", rc.ip, req.Name)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": req.Name, "password": pw})
}

func (s *Server) handleAppPasswordDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	err := s.St.DeleteAppPassword(r.Context(), rc.user.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Audit.Event(r.Context(), rc.user.ID, "app_password_revoked", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if err := s.St.DeleteUserSessions(r.Context(), rc.user.ID, rc.sess.IDHash); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.Audit.Event(r.Context(), rc.user.ID, "sessions_revoked", rc.ip, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
