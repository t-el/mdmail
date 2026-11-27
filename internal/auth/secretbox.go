package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Box encrypts small secrets (TOTP seeds) at rest with AES-256-GCM.
type Box struct{ aead cipher.AEAD }

// LoadOrCreateKey reads a base64 32-byte key from path, creating it with
// 0600 permissions if it does not exist.
func LoadOrCreateKey(path string) (*Box, bool, error) {
	created := false
	b, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		enc := base64.StdEncoding.EncodeToString(key)
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, false, err
		}
		if _, err := f.WriteString(enc + "\n"); err != nil {
			_ = f.Close()
			return nil, false, err
		}
		if err := f.Close(); err != nil {
			return nil, false, err
		}
		b, created = []byte(enc), true
	} else if err != nil {
		return nil, false, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, false, fmt.Errorf("auth: %s must contain a base64-encoded 32-byte key", path)
	}
	box, err := NewBox(key)
	return box, created, err
}

// NewBox builds a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return &Box{aead: g}, nil
}

// Seal encrypts plaintext; aad binds the ciphertext to a context (e.g. user id).
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts a value produced by Seal.
func (b *Box) Open(ct, aad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(ct) < n {
		return nil, errors.New("auth: ciphertext too short")
	}
	return b.aead.Open(nil, ct[:n], ct[n:], aad)
}
