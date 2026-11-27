package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t-el/mdmail/internal/store"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if err := VerifyPassword(h, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(h, "wrong horse battery staple"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt not random")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := VerifyPassword("$argon2id$v=19$m=99999999,t=1,p=1$AAAA$AAAA", "x"); err == nil {
		t.Fatal("absurd parameters accepted")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 Appendix B, SHA1 seed "12345678901234567890".
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, code := range vectors {
		if _, ok := VerifyTOTP(secret, code, time.Unix(ts, 0)); !ok {
			t.Errorf("t=%d: code %s rejected", ts, code)
		}
	}
	if _, ok := VerifyTOTP(secret, "287082", time.Unix(59+300, 0)); ok {
		t.Error("stale code accepted")
	}
	if _, ok := VerifyTOTP(secret, "28708", time.Unix(59, 0)); ok {
		t.Error("short code accepted")
	}
}

func TestBox(t *testing.T) {
	b, created, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "k"))
	if err != nil || !created {
		t.Fatal(err, created)
	}
	ct, err := b.Seal([]byte("secret"), []byte("aad1"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := b.Open(ct, []byte("aad1")); err != nil || string(pt) != "secret" {
		t.Fatal("roundtrip failed", err)
	}
	if _, err := b.Open(ct, []byte("aad2")); err == nil {
		t.Fatal("ciphertext not bound to AAD")
	}
}

func newAuth(t *testing.T) (*Authenticator, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b, _, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	return NewAuthenticator(st, b), st
}

func TestLoginLockoutAndTOTP(t *testing.T) {
	a, st := newAuth(t)
	ctx := context.Background()
	h, _ := HashPassword("a-very-good-password")
	id, err := st.CreateUser(ctx, "alice@example.com", h, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "ALICE@example.com", "a-very-good-password", "", true); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := a.Login(ctx, "nobody@example.com", "a-very-good-password", "", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown user: %v", err)
	}
	for i := 0; i < LockThreshold; i++ {
		_, _ = a.Login(ctx, "alice@example.com", "wrong-password-123", "", true)
	}
	if _, err := a.Login(ctx, "alice@example.com", "a-very-good-password", "", true); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected lockout, got %v", err)
	}
	if err := st.ResetLoginFailures(ctx, id); err != nil {
		t.Fatal(err)
	}

	secret, _ := NewTOTPSecret()
	ct, _ := a.SealTOTPSecret(id, secret)
	if err := st.SetTOTP(ctx, id, ct, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "alice@example.com", "a-very-good-password", "", true); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("expected totp required, got %v", err)
	}
	key, _ := b32.DecodeString(secret)
	code := totpAt(key, uint64(time.Now().Unix())/totpPeriod)
	if _, err := a.Login(ctx, "alice@example.com", "a-very-good-password", code, true); err != nil {
		t.Fatalf("login with totp: %v", err)
	}
	if _, err := a.Login(ctx, "alice@example.com", "a-very-good-password", code, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TOTP replay accepted: %v", err)
	}
	// With TOTP enabled the account password must not work over SMTP...
	if _, err := a.LoginSMTP(ctx, "alice@example.com", "a-very-good-password"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SMTP password login with 2FA: %v", err)
	}
	// ...but an app password does.
	pw, hash, err := NewAppPassword()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAppPassword(ctx, id, "phone", hash); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LoginSMTP(ctx, "alice@example.com", strings.ToUpper(pw)); err != nil {
		t.Fatalf("app password: %v", err)
	}
}

// Regression: every failed login maps to the generic sentinels (one client
// message) but carries a distinct server-side reason, so an operator can tell
// "unknown user / wrong database" from "wrong password" from "locked".
func TestLoginFailureReasons(t *testing.T) {
	a, st := newAuth(t)
	ctx := context.Background()
	h, _ := HashPassword("a-very-good-password")
	id, err := st.CreateUser(ctx, "alice@example.com", h, false)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, err error, sentinel error, reason string) {
		t.Helper()
		if !errors.Is(err, sentinel) {
			t.Fatalf("%s: err = %v, want %v", name, err, sentinel)
		}
		if got := FailureReason(err); got != reason {
			t.Fatalf("%s: reason = %q, want %q", name, got, reason)
		}
	}
	_, err = a.Login(ctx, "  ", "x", "", true)
	check("empty email", err, ErrInvalid, ReasonBadEmail)
	_, err = a.Login(ctx, "nobody@example.com", "a-very-good-password", "", true)
	check("unknown user", err, ErrInvalid, ReasonUnknownUser)
	_, err = a.Login(ctx, "alice@example.com", "wrong-password-123", "", true)
	check("wrong password", err, ErrInvalid, ReasonBadPassword)
	_, err = a.LoginSMTP(ctx, "alice@example.com", "wrong-password-123")
	check("smtp wrong password", err, ErrInvalid, ReasonBadPassword)
	_, err = a.LoginSMTP(ctx, "nobody@example.com", "x")
	check("smtp unknown user", err, ErrInvalid, ReasonUnknownUser)

	// The attempt that crosses the threshold reports the lock end.
	var last error
	for i := 2; i < LockThreshold; i++ {
		_, last = a.Login(ctx, "alice@example.com", "wrong-password-123", "", true)
	}
	var le *LoginError
	if !errors.As(last, &le) || le.Until.IsZero() {
		t.Fatalf("threshold attempt should carry lock end: %v", last)
	}
	// A correct password during the lock is refused as "locked".
	_, err = a.Login(ctx, "alice@example.com", "a-very-good-password", "", true)
	check("locked", err, ErrLocked, ReasonLocked)
	if errors.Is(err, ErrInvalid) {
		t.Fatal("locked must not match ErrInvalid")
	}
	// SetPassword (mdmail user passwd) clears the lock.
	h2, _ := HashPassword("another-good-password")
	if err := st.SetPassword(ctx, id, h2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "Alice@Example.com ", "another-good-password", "", true); err != nil {
		t.Fatalf("login after passwd: %v", err)
	}
	if err := st.SetDisabled(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	_, err = a.Login(ctx, "alice@example.com", "another-good-password", "", true)
	check("disabled", err, ErrInvalid, ReasonDisabled)

	// A corrupt stored hash is an internal error, not a credential failure.
	if err := st.SetDisabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword(ctx, id, "$argon2id$garbage"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "alice@example.com", "another-good-password", "", true); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupt hash: err = %v, want internal error", err)
	}
}
