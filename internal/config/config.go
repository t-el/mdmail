// Package config loads mdmail configuration from environment variables.
//
// Every secret-bearing option also accepts a *_FILE variant that points to a
// file containing the value (Docker/Kubernetes secrets). Secrets are never
// read from command-line flags so they do not leak through /proc/*/cmdline.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TLS modes.
const (
	TLSModeACME  = "acme"
	TLSModeFiles = "files"
)

// Outbound TLS policies.
const (
	OutboundTLSVerify        = "verify"
	OutboundTLSEncrypt       = "encrypt"
	OutboundTLSOpportunistic = "opportunistic"
)

// Config is the complete runtime configuration.
type Config struct {
	Hostname string   // FQDN of this mail server (EHLO name, MX target, web UI host)
	Domains  []string // mail domains hosted here
	DataDir  string

	TLSMode       string
	ACMEEmail     string
	ACMEDirectory string
	TLSCertFile   string
	TLSKeyFile    string

	SMTPAddr        string // inbound MX (port 25)
	SubmissionAddr  string // STARTTLS submission (port 587)
	SubmissionsAddr string // implicit TLS submission (port 465)
	HTTPSAddr       string
	HTTPAddr        string // ACME http-01 + redirect to HTTPS; empty disables
	HealthAddr      string // plain-HTTP health endpoint, loopback only

	MaxMessageBytes   int64
	MaxRecipients     int
	SubmitPerHour     int
	InboundRequireTLS bool
	DMARCEnforce      bool
	OutboundTLS       string
	AllowPrivateMX    bool

	DKIMSelector string
	DKIMKeyDir   string

	SessionTTL  time.Duration
	SessionIdle time.Duration

	MTASTSMode   string // none|testing|enforce
	MTASTSMaxAge time.Duration

	// ChecklistSharing lets a local sender see checklist progress of
	// recipients who are local users of this server. Nothing is ever sent
	// to other servers; see docs/security.md.
	ChecklistSharing bool

	SecretKeyFile string
	LogLevel      string
}

// DBPath returns the SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "mdmail.db") }

// ACMECacheDir returns the autocert cache location.
func (c *Config) ACMECacheDir() string { return filepath.Join(c.DataDir, "acme") }

// IsLocalDomain reports whether d is one of the hosted domains.
func (c *Config) IsLocalDomain(d string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	for _, x := range c.Domains {
		if x == d {
			return true
		}
	}
	return false
}

type getenv func(string) string

// Load reads the configuration from the process environment.
func Load() (*Config, error) { return load(os.Getenv) }

func load(env getenv) (*Config, error) {
	var errs []error
	str := func(key, def string) string {
		if v := strings.TrimSpace(env(key)); v != "" {
			return v
		}
		if f := strings.TrimSpace(env(key + "_FILE")); f != "" {
			b, err := os.ReadFile(filepath.Clean(f))
			if err != nil {
				errs = append(errs, fmt.Errorf("%s_FILE: %w", key, err))
				return def
			}
			return strings.TrimSpace(string(b))
		}
		return def
	}
	integer := func(key string, def, min, max int64) int64 {
		v := str(key, "")
		if v == "" {
			return def
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Errorf("%s: must be an integer in [%d,%d]", key, min, max))
			return def
		}
		return n
	}
	boolean := func(key string, def bool) bool {
		v := str(key, "")
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: must be true or false", key))
			return def
		}
		return b
	}
	duration := func(key string, def, min time.Duration) time.Duration {
		v := str(key, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < min {
			errs = append(errs, fmt.Errorf("%s: must be a duration >= %s", key, min))
			return def
		}
		return d
	}

	c := &Config{
		Hostname:          strings.ToLower(strings.TrimSuffix(str("MDMAIL_HOSTNAME", ""), ".")),
		DataDir:           str("MDMAIL_DATA_DIR", "/data"),
		TLSMode:           strings.ToLower(str("MDMAIL_TLS_MODE", TLSModeACME)),
		ACMEEmail:         str("MDMAIL_ACME_EMAIL", ""),
		ACMEDirectory:     str("MDMAIL_ACME_DIRECTORY", ""),
		TLSCertFile:       str("MDMAIL_TLS_CERT_FILE", ""),
		TLSKeyFile:        str("MDMAIL_TLS_KEY_FILE", ""),
		SMTPAddr:          str("MDMAIL_SMTP_ADDR", ":25"),
		SubmissionAddr:    str("MDMAIL_SUBMISSION_ADDR", ":587"),
		SubmissionsAddr:   str("MDMAIL_SUBMISSIONS_ADDR", ":465"),
		HTTPSAddr:         str("MDMAIL_HTTPS_ADDR", ":443"),
		HTTPAddr:          str("MDMAIL_HTTP_ADDR", ":80"),
		HealthAddr:        str("MDMAIL_HEALTH_ADDR", "127.0.0.1:9090"),
		MaxMessageBytes:   integer("MDMAIL_MAX_MESSAGE_BYTES", 25<<20, 64<<10, 100<<20),
		MaxRecipients:     int(integer("MDMAIL_MAX_RECIPIENTS", 50, 1, 1000)),
		SubmitPerHour:     int(integer("MDMAIL_SUBMIT_PER_HOUR", 200, 1, 100000)),
		InboundRequireTLS: boolean("MDMAIL_INBOUND_REQUIRE_TLS", false),
		DMARCEnforce:      boolean("MDMAIL_DMARC_ENFORCE", true),
		OutboundTLS:       strings.ToLower(str("MDMAIL_OUTBOUND_TLS", OutboundTLSEncrypt)),
		AllowPrivateMX:    boolean("MDMAIL_ALLOW_PRIVATE_MX", false),
		DKIMSelector:      str("MDMAIL_DKIM_SELECTOR", "mdmail"),
		SessionTTL:        duration("MDMAIL_SESSION_TTL", 12*time.Hour, 5*time.Minute),
		SessionIdle:       duration("MDMAIL_SESSION_IDLE", 30*time.Minute, time.Minute),
		MTASTSMode:        strings.ToLower(str("MDMAIL_MTASTS_MODE", "none")),
		MTASTSMaxAge:      duration("MDMAIL_MTASTS_MAX_AGE", 7*24*time.Hour, time.Hour),
		ChecklistSharing:  boolean("MDMAIL_CHECKLIST_SHARING", true),
		SecretKeyFile:     str("MDMAIL_SECRET_KEY_FILE", ""),
		LogLevel:          strings.ToLower(str("MDMAIL_LOG_LEVEL", "info")),
	}
	if dd, err := absDir(c.DataDir); err != nil {
		errs = append(errs, fmt.Errorf("MDMAIL_DATA_DIR: %w", err))
	} else {
		c.DataDir = dd
	}
	c.DKIMKeyDir = str("MDMAIL_DKIM_KEY_DIR", filepath.Join(c.DataDir, "dkim"))
	if c.SecretKeyFile == "" {
		c.SecretKeyFile = filepath.Join(c.DataDir, "secret.key")
	}

	for _, d := range strings.Split(str("MDMAIL_DOMAINS", ""), ",") {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		if !validDomain(d) {
			errs = append(errs, fmt.Errorf("MDMAIL_DOMAINS: invalid domain %q", d))
			continue
		}
		c.Domains = append(c.Domains, d)
	}

	if c.Hostname == "" || !validDomain(c.Hostname) {
		errs = append(errs, errors.New("MDMAIL_HOSTNAME: required, must be a fully qualified domain name"))
	}
	if len(c.Domains) == 0 {
		errs = append(errs, errors.New("MDMAIL_DOMAINS: at least one mail domain is required"))
	}
	switch c.TLSMode {
	case TLSModeACME:
		if c.HTTPAddr == "" {
			errs = append(errs, errors.New("MDMAIL_HTTP_ADDR: required for ACME http-01 challenges"))
		}
	case TLSModeFiles:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			errs = append(errs, errors.New("MDMAIL_TLS_CERT_FILE and MDMAIL_TLS_KEY_FILE are required with MDMAIL_TLS_MODE=files"))
		}
	default:
		errs = append(errs, errors.New("MDMAIL_TLS_MODE: must be acme or files"))
	}
	switch c.OutboundTLS {
	case OutboundTLSVerify, OutboundTLSEncrypt, OutboundTLSOpportunistic:
	default:
		errs = append(errs, errors.New("MDMAIL_OUTBOUND_TLS: must be verify, encrypt or opportunistic"))
	}
	switch c.MTASTSMode {
	case "none", "testing", "enforce":
	default:
		errs = append(errs, errors.New("MDMAIL_MTASTS_MODE: must be none, testing or enforce"))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("MDMAIL_LOG_LEVEL: must be debug, info, warn or error"))
	}
	if !validSelector(c.DKIMSelector) {
		errs = append(errs, errors.New("MDMAIL_DKIM_SELECTOR: must be a DNS label"))
	}
	if h, _, err := net.SplitHostPort(c.HealthAddr); c.HealthAddr != "" && (err != nil || (h != "127.0.0.1" && h != "::1" && h != "localhost")) {
		errs = append(errs, errors.New("MDMAIL_HEALTH_ADDR: must bind to a loopback address"))
	}
	if c.SessionIdle > c.SessionTTL {
		errs = append(errs, errors.New("MDMAIL_SESSION_IDLE must not exceed MDMAIL_SESSION_TTL"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// LoadForCLI loads only what administrative commands need (data dir and
// domains), so that they work without TLS settings.
func LoadForCLI() (*Config, error) {
	c := &Config{DataDir: os.Getenv("MDMAIL_DATA_DIR")}
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	dd, err := absDir(c.DataDir)
	if err != nil {
		return nil, fmt.Errorf("MDMAIL_DATA_DIR: %w", err)
	}
	c.DataDir = dd
	c.DKIMSelector = os.Getenv("MDMAIL_DKIM_SELECTOR")
	if c.DKIMSelector == "" {
		c.DKIMSelector = "mdmail"
	}
	if !validSelector(c.DKIMSelector) {
		return nil, errors.New("MDMAIL_DKIM_SELECTOR: must be a DNS label")
	}
	c.DKIMKeyDir = os.Getenv("MDMAIL_DKIM_KEY_DIR")
	if c.DKIMKeyDir == "" {
		c.DKIMKeyDir = filepath.Join(c.DataDir, "dkim")
	}
	c.SecretKeyFile = os.Getenv("MDMAIL_SECRET_KEY_FILE")
	if c.SecretKeyFile == "" {
		c.SecretKeyFile = filepath.Join(c.DataDir, "secret.key")
	}
	for _, d := range strings.Split(os.Getenv("MDMAIL_DOMAINS"), ",") {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" && validDomain(d) {
			c.Domains = append(c.Domains, d)
		}
	}
	return c, nil
}

// absDir makes the data directory absolute so that the server and the admin
// CLI, which may run from different working directories, always agree on
// which database they use, and so that the path can be logged unambiguously.
func absDir(d string) (string, error) {
	d = strings.TrimSpace(d)
	if d == "" {
		return "", errors.New("must not be empty")
	}
	a, err := filepath.Abs(d)
	if err != nil {
		return "", err
	}
	return filepath.Clean(a), nil
}

func validDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validSelector(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
