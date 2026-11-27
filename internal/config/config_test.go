package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) getenv { return func(k string) string { return m[k] } }

func TestLoadValid(t *testing.T) {
	c, err := load(envMap(map[string]string{
		"MDMAIL_HOSTNAME": "Mail.Example.COM.", "MDMAIL_DOMAINS": "example.com, Example.org",
		"MDMAIL_TLS_MODE": "files", "MDMAIL_TLS_CERT_FILE": "/c", "MDMAIL_TLS_KEY_FILE": "/k",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Hostname != "mail.example.com" {
		t.Errorf("hostname = %q", c.Hostname)
	}
	if !c.IsLocalDomain("EXAMPLE.org.") || c.IsLocalDomain("evil.com") {
		t.Error("IsLocalDomain wrong")
	}
	if c.MaxMessageBytes != 25<<20 || c.OutboundTLS != OutboundTLSEncrypt || !c.DMARCEnforce || !c.ChecklistSharing {
		t.Error("defaults wrong")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"missing hostname": {"MDMAIL_DOMAINS": "example.com"},
		"bad domain":       {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "exa_mple.com"},
		"bad tls mode":     {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_TLS_MODE": "none"},
		"public health":    {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_HEALTH_ADDR": "0.0.0.0:9090"},
		"bad size":         {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_MAX_MESSAGE_BYTES": "1"},
		"files w/o cert":   {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_TLS_MODE": "files"},
		"bad sharing":      {"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_CHECKLIST_SHARING": "maybe"},
	}
	for name, env := range cases {
		if _, err := load(envMap(env)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestFileSecrets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "email")
	if err := os.WriteFile(p, []byte("admin@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := load(envMap(map[string]string{"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_ACME_EMAIL_FILE": p}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ACMEEmail != "admin@example.com" {
		t.Errorf("ACMEEmail = %q", c.ACMEEmail)
	}
	_, err = load(envMap(map[string]string{"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com", "MDMAIL_ACME_EMAIL_FILE": "/nonexistent"}))
	if err == nil || !strings.Contains(err.Error(), "MDMAIL_ACME_EMAIL_FILE") {
		t.Errorf("expected file error, got %v", err)
	}
}

// Regression: a relative MDMAIL_DATA_DIR is resolved to an absolute path, so
// the server and the admin CLI agree on the database and logs show the
// exact location.
func TestDataDirAbsolute(t *testing.T) {
	c, err := load(envMap(map[string]string{
		"MDMAIL_HOSTNAME": "mail.example.com", "MDMAIL_DOMAINS": "example.com",
		"MDMAIL_TLS_MODE": "files", "MDMAIL_TLS_CERT_FILE": "/c", "MDMAIL_TLS_KEY_FILE": "/k",
		"MDMAIL_DATA_DIR": "local/../local/data",
	}))
	if err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	want := filepath.Join(wd, "local", "data")
	if c.DataDir != want || c.DBPath() != filepath.Join(want, "mdmail.db") || c.SecretKeyFile != filepath.Join(want, "secret.key") {
		t.Fatalf("DataDir = %q, DBPath = %q, SecretKeyFile = %q; want under %q", c.DataDir, c.DBPath(), c.SecretKeyFile, want)
	}
	t.Setenv("MDMAIL_DATA_DIR", "local/data")
	cc, err := LoadForCLI()
	if err != nil {
		t.Fatal(err)
	}
	if cc.DBPath() != c.DBPath() {
		t.Fatalf("CLI DBPath %q != server DBPath %q", cc.DBPath(), c.DBPath())
	}
}
