// Package audit records security events to both the structured log and the
// database (so users can review recent activity on their account).
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/t-el/mdmail/internal/store"
)

// Logger writes audit events.
type Logger struct {
	st  *store.Store
	log *slog.Logger
}

// New returns an audit logger.
func New(st *store.Store, log *slog.Logger) *Logger {
	return &Logger{st: st, log: log.With("component", "audit")}
}

// Event records an event. userID may be 0 when unknown.
func (l *Logger) Event(ctx context.Context, userID int64, event, ip, detail string) {
	var uid *int64
	if userID > 0 {
		uid = &userID
	}
	l.log.LogAttrs(ctx, slog.LevelInfo, event, slog.Int64("user_id", userID), slog.String("ip", ip), slog.String("detail", detail))
	if len(detail) > 500 {
		detail = detail[:500]
	}
	// Audit persistence must not be cancelled by a client disconnect.
	ctx2, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := l.st.AddAudit(ctx2, &store.AuditEntry{Time: time.Now(), UserID: uid, Event: event, IP: ip, Detail: detail}); err != nil {
		l.log.Error("audit persist failed", "err", err, "event", event)
	}
}
