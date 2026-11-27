package mailauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// signedHeaders lists the fields covered by our DKIM signatures. From and
// Subject are listed twice ("oversigning") so that adding another instance
// later invalidates the signature.
var signedHeaders = []string{
	"From", "From", "Reply-To", "Subject", "Subject", "Date", "To", "Cc", "Message-ID",
	"In-Reply-To", "References", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
}

// Signer signs outbound mail with per-domain DKIM keys.
type Signer struct {
	selector string
	keys     map[string]crypto.Signer
}

// KeyPath returns the private-key path for a domain.
func KeyPath(dir, domain string) string { return filepath.Join(dir, domain+".pem") }

// LoadSigner loads keys for the given domains. Domains without a key are
// returned in missing (mail from them is sent unsigned and a warning logged).
func LoadSigner(dir, selector string, domains []string) (*Signer, []string, error) {
	s := &Signer{selector: selector, keys: map[string]crypto.Signer{}}
	var missing []string
	for _, d := range domains {
		b, err := os.ReadFile(filepath.Clean(KeyPath(dir, d)))
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, d)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		k, err := parseKey(b)
		if err != nil {
			return nil, nil, fmt.Errorf("dkim key for %s: %w", d, err)
		}
		s.keys[d] = k
	}
	return s, missing, nil
}

func parseKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("unsupported key type")
	}
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

// HasKey reports whether a key is loaded for domain.
func (s *Signer) HasKey(domain string) bool { _, ok := s.keys[strings.ToLower(domain)]; return ok }

// Sign returns raw with a DKIM-Signature field prepended. If no key exists
// for domain, raw is returned unchanged.
func (s *Signer) Sign(raw []byte, domain string) ([]byte, error) {
	k, ok := s.keys[strings.ToLower(domain)]
	if !ok {
		return raw, nil
	}
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(raw), &dkim.SignOptions{
		Domain:                 strings.ToLower(domain),
		Selector:               s.selector,
		Signer:                 k,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             signedHeaders,
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// GenerateKey creates a 2048-bit RSA key for domain in dir (mode 0600) and
// returns the DNS TXT record value to publish at <selector>._domainkey.<domain>.
func GenerateKey(dir, domain string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := KeyPath(dir, domain)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return PublicRecord(&k.PublicKey)
}

// PublicRecordForDomain reads the key for domain and returns its TXT record.
func PublicRecordForDomain(dir, domain string) (string, error) {
	b, err := os.ReadFile(filepath.Clean(KeyPath(dir, domain)))
	if err != nil {
		return "", err
	}
	k, err := parseKey(b)
	if err != nil {
		return "", err
	}
	return PublicRecord(k.Public())
}

// PublicRecord formats a DKIM TXT record for a public key.
func PublicRecord(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	kt := "rsa"
	if _, ok := pub.(*rsa.PublicKey); !ok {
		kt = "ed25519"
	}
	return "v=DKIM1; k=" + kt + "; p=" + base64.StdEncoding.EncodeToString(der), nil
}
