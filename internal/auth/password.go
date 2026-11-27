// Package auth implements password hashing (argon2id), TOTP (RFC 6238),
// at-rest encryption of secrets and the shared login policy.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP 2024+ recommendation exceeded: m=64MiB, t=3, p=2).
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

// MinPasswordLen is the minimum accepted password length (NIST SP 800-63B).
const MinPasswordLen = 12

// MaxPasswordLen bounds hashing cost from attacker-supplied input.
const MaxPasswordLen = 1024

// ErrMismatch indicates a wrong password.
var ErrMismatch = errors.New("auth: password mismatch")

// hashSem bounds concurrent argon2 computations (each uses 64 MiB).
var hashSem = make(chan struct{}, 4)

// HashPassword returns an encoded argon2id hash in PHC string format.
func HashPassword(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashSem <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	<-hashSem
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	if !utf8.ValidString(pw) {
		return errors.New("password must be valid UTF-8")
	}
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	}
	return nil
}

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(encoded, pw string) error {
	if len(pw) > MaxPasswordLen {
		return ErrMismatch
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("auth: unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("auth: unsupported argon2 version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return errors.New("auth: bad argon2 parameters")
	}
	if m > 1024*1024 || t > 20 || p == 0 || p > 16 {
		return errors.New("auth: argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("auth: bad salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return errors.New("auth: bad hash")
	}
	hashSem <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) // #nosec G115 -- len(want) <= 128
	<-hashSem
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// dummyHash is verified against when a user does not exist so that response
// timing does not reveal which accounts exist.
var dummyHash = sync.OnceValue(func() string {
	h, err := HashPassword("dummy-password-for-timing-equalisation")
	if err != nil {
		panic(err)
	}
	return h
})

// BurnTime performs a verification with the same cost as a real one.
func BurnTime(pw string) { _ = VerifyPassword(dummyHash(), pw) }
