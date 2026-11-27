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
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) > 254 || email == "" {
		BurnTime(password)
		return nil, ErrInvalid
	}
	u, err := a.St.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		BurnTime(password)
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Before(u.LockedUntil) {
		BurnTime(password)
		return u, ErrLocked
	}
	if u.Disabled {
		BurnTime(password)
		return u, ErrInvalid
	}
	if err := VerifyPassword(u.PasswordHash, password); err != nil {
		if _, ferr := a.St.RecordLoginFailure(ctx, u.ID, LockThreshold, LockBase, LockMax); ferr != nil {
			return nil, ferr
		}
		return u, ErrInvalid
	}
	if requireTOTP && u.TOTPEnabled {
		if totpCode == "" {
			return u, ErrTOTPRequired
		}
		if !a.CheckTOTP(u, totpCode) {
			if _, ferr := a.St.RecordLoginFailure(ctx, u.ID, LockThreshold, LockBase, LockMax); ferr != nil {
				return nil, ferr
			}
			return u, ErrInvalid
		}
	}
	if u.FailedLogins > 0 {
		if err := a.St.ResetLoginFailures(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

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
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := a.St.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		BurnTime(password)
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Before(u.LockedUntil) {
		return u, ErrLocked
	}
	if u.Disabled {
		return u, ErrInvalid
	}
	if ok, err := a.St.MatchAppPassword(ctx, u.ID, HashAppPassword(password)); err != nil {
		return nil, err
	} else if ok {
		if u.FailedLogins > 0 {
			_ = a.St.ResetLoginFailures(ctx, u.ID)
		}
		return u, nil
	}
	if u.TOTPEnabled {
		BurnTime(password)
	} else if VerifyPassword(u.PasswordHash, password) == nil {
		if u.FailedLogins > 0 {
			_ = a.St.ResetLoginFailures(ctx, u.ID)
		}
		return u, nil
	}
	if _, ferr := a.St.RecordLoginFailure(ctx, u.ID, LockThreshold, LockBase, LockMax); ferr != nil {
		return nil, ferr
	}
	return u, ErrInvalid
}
