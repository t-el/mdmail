package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/t-el/mdmail/internal/store"
)

// Login policy.
const (
	LockThreshold = 5
	LockBase      = 5 * time.Minute
	LockMax       = 24 * time.Hour
)

// Errors returned by Authenticator.Login. All map to a single generic
// message for clients to avoid account enumeration.
var (
	ErrInvalid      = errors.New("invalid credentials")
	ErrLocked       = errors.New("account temporarily locked")
	ErrTOTPRequired = errors.New("totp code required")
)

// Failure reasons carried by *LoginError. They are for server-side logs and
// the audit trail only and must never be sent to clients.
const (
	ReasonUnknownUser = "unknown_user"
	ReasonBadEmail    = "malformed_email"
	ReasonDisabled    = "account_disabled"
	ReasonBadPassword = "wrong_password"
	ReasonBadTOTP     = "wrong_totp_code"
	ReasonTOTPOnSMTP  = "account_password_refused_2fa_enabled"
	ReasonLocked      = "account_locked"
)

// LoginError is a failed login. It matches ErrInvalid or ErrLocked with
// errors.Is (so callers keep a single generic client response) and carries
// the precise reason for operators.
type LoginError struct {
	Kind   error     // ErrInvalid or ErrLocked
	Reason string    // one of the Reason* constants
	Until  time.Time // lockout end, when known
}

func (e *LoginError) Error() string {
	if !e.Until.IsZero() {
		return e.Kind.Error() + " (" + e.Reason + " until " + e.Until.UTC().Format(time.RFC3339) + ")"
	}
	return e.Kind.Error() + " (" + e.Reason + ")"
}

// Unwrap lets errors.Is match the generic sentinel.
func (e *LoginError) Unwrap() error { return e.Kind }

// FailureReason returns the server-side reason of a login error, or "" when
// err is not a *LoginError.
func FailureReason(err error) string {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Reason
	}
	return ""
}

func invalid(reason string) error { return &LoginError{Kind: ErrInvalid, Reason: reason} }

func locked(until time.Time) error {
	return &LoginError{Kind: ErrLocked, Reason: ReasonLocked, Until: until}
}

// failure records a failed attempt and returns the resulting error: when this
// attempt triggers a lockout the caller learns it (server-side) immediately.
func (a *Authenticator) failure(ctx context.Context, u *store.User, reason string) error {
	until, err := a.St.RecordLoginFailure(ctx, u.ID, LockThreshold, LockBase, LockMax)
	if err != nil {
		return err
	}
	le := &LoginError{Kind: ErrInvalid, Reason: reason}
	if !until.IsZero() {
		le.Until = until
	}
	return le
}

// Authenticator implements the login policy shared by the web UI and SMTP AUTH.
type Authenticator struct {
	St  *store.Store
	Box *Box

	mu       sync.Mutex
	lastStep map[int64]uint64 // TOTP replay protection
}

// NewAuthenticator returns an Authenticator.
func NewAuthenticator(st *store.Store, box *Box) *Authenticator {
	return &Authenticator{St: st, Box: box, lastStep: map[int64]uint64{}}
}

// Login checks email/password (and the TOTP code when enabled and
// requireTOTP is set). SMTP AUTH cannot carry a second factor, so callers pass
// requireTOTP=false there; see docs/security.md (app passwords are not
// implemented; TOTP users authenticate SMTP with their password).
func (a *Authenticator) Login(ctx context.Context, email, password, totpCode string, requireTOTP bool) (*store.User, error) {
	email = NormalizeEmail(email)
	if len(email) > 254 || email == "" {
		BurnTime(password)
		return nil, invalid(ReasonBadEmail)
	}
	u, err := a.St.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		BurnTime(password)
		return nil, invalid(ReasonUnknownUser)
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Before(u.LockedUntil) {
		BurnTime(password)
		return u, locked(u.LockedUntil)
	}
	if u.Disabled {
		BurnTime(password)
		return u, invalid(ReasonDisabled)
	}
	if err := VerifyPassword(u.PasswordHash, password); err != nil {
		if errors.Is(err, ErrMismatch) {
			return u, a.failure(ctx, u, ReasonBadPassword)
		}
		// A corrupt stored hash is an operator problem, not a guess.
		return nil, fmt.Errorf("auth: verify password for user %d: %w", u.ID, err)
	}
	if requireTOTP && u.TOTPEnabled {
		if totpCode == "" {
			return u, ErrTOTPRequired
		}
		if !a.CheckTOTP(u, totpCode) {
			return u, a.failure(ctx, u, ReasonBadTOTP)
		}
	}
	if u.FailedLogins > 0 {
		if err := a.St.ResetLoginFailures(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// NormalizeEmail is the canonical form of a login/account address. The CLI
// and every login path must use it so that accounts created with
// "mdmail user add" are found by web and SMTP logins.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// CheckTOTP verifies a code for a user with TOTP enabled, rejecting reuse of
// an already-accepted time step.
func (a *Authenticator) CheckTOTP(u *store.User, code string) bool {
	secret, err := a.OpenTOTPSecret(u.ID, u.TOTPSecret)
	if err != nil {
		return false
	}
	step, ok := VerifyTOTP(secret, code, time.Now())
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, seen := a.lastStep[u.ID]; seen && step <= last {
		return false
	}
	a.lastStep[u.ID] = step
	return true
}

// SealTOTPSecret encrypts a TOTP secret bound to the user id.
func (a *Authenticator) SealTOTPSecret(userID int64, secret string) ([]byte, error) {
	return a.Box.Seal([]byte(secret), totpAAD(userID))
}

// OpenTOTPSecret decrypts a stored TOTP secret.
func (a *Authenticator) OpenTOTPSecret(userID int64, ct []byte) (string, error) {
	if len(ct) == 0 {
		return "", errors.New("auth: no totp secret")
	}
	pt, err := a.Box.Open(ct, totpAAD(userID))
	if err != nil {
		return "", fmt.Errorf("auth: decrypt totp secret: %w", err)
	}
	return string(pt), nil
}

func totpAAD(id int64) []byte { return []byte("mdmail-totp:" + strconv.FormatInt(id, 10)) }

// NewAppPassword returns a random app password (shown once) and its hash.
func NewAppPassword() (string, []byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	s := strings.ToLower(b32.EncodeToString(b)) // 32 chars, 160 bits
	pretty := s[0:8] + "-" + s[8:16] + "-" + s[16:24] + "-" + s[24:32]
	return pretty, HashAppPassword(pretty), nil
}

// HashAppPassword normalises and hashes an app password. App passwords carry
// 160 bits of entropy so a fast hash is sufficient (and allows indexed lookup).
func HashAppPassword(p string) []byte {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "-", ""))
	h := sha256.Sum256([]byte("mdmail-app-password:" + p))
	return h[:]
}

// LoginSMTP authenticates SMTP AUTH. App passwords are always accepted; the
// account password is accepted only when TOTP is not enabled, so that
// enabling 2FA cannot be bypassed through SMTP.
func (a *Authenticator) LoginSMTP(ctx context.Context, email, password string) (*store.User, error) {
	email = NormalizeEmail(email)
	if len(email) > 254 || email == "" {
		BurnTime(password)
		return nil, invalid(ReasonBadEmail)
	}
	u, err := a.St.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		BurnTime(password)
		return nil, invalid(ReasonUnknownUser)
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Before(u.LockedUntil) {
		return u, locked(u.LockedUntil)
	}
	if u.Disabled {
		return u, invalid(ReasonDisabled)
	}
	if ok, err := a.St.MatchAppPassword(ctx, u.ID, HashAppPassword(password)); err != nil {
		return nil, err
	} else if ok {
		if u.FailedLogins > 0 {
			_ = a.St.ResetLoginFailures(ctx, u.ID)
		}
		return u, nil
	}
	reason := ReasonBadPassword
	if u.TOTPEnabled {
		BurnTime(password)
		reason = ReasonTOTPOnSMTP
	} else if err := VerifyPassword(u.PasswordHash, password); err == nil {
		if u.FailedLogins > 0 {
			_ = a.St.ResetLoginFailures(ctx, u.ID)
		}
		return u, nil
	} else if !errors.Is(err, ErrMismatch) {
		return nil, fmt.Errorf("auth: verify password for user %d: %w", u.ID, err)
	}
	return u, a.failure(ctx, u, reason)
}
