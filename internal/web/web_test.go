package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t-el/mdmail/internal/audit"
	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/store"
)

type testEnv struct {
	ts  *httptest.Server
	st  *store.Store
	srv *Server
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{Hostname: "127.0.0.1", Domains: []string{"example.com"}, MaxMessageBytes: 1 << 20, MaxRecipients: 10,
		SubmitPerHour: 100, SessionTTL: time.Hour, SessionIdle: 30 * time.Minute, MTASTSMode: "enforce", MTASTSMaxAge: 24 * time.Hour}
	box, _, _ := auth.LoadOrCreateKey(filepath.Join(dir, "key"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, _, _ := mailauth.LoadSigner(dir, "s", nil)
	al := audit.New(st, log)
	m := mailer.New(cfg, st, signer, al, log)
	srv := New(cfg, st, auth.NewAuthenticator(st, box), m, al, log)
	srv.SecureCookies = false
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	for _, u := range []string{"alice@example.com", "bob@example.com"} {
		h, _ := auth.HashPassword("password-" + strings.Split(u, "@")[0])
		if _, err := st.CreateUser(ctx, u, h, false); err != nil {
			t.Fatal(err)
		}
	}
	return &testEnv{ts: ts, st: st, srv: srv}
}

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (e *testEnv) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: e.ts.URL, hc: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body io.Reader, ct string, mod func(*http.Request)) *http.Response {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, body)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Origin", c.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if mod != nil {
		mod(req)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func (c *client) json(method, path string, in any, out any) int {
	c.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	resp := c.do(method, path, body, "application/json", nil)
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (c *client) login(email, pw string) {
	c.t.Helper()
	var r sessionResp
	if code := c.json("POST", "/api/login", map[string]string{"email": email, "password": pw}, &r); code != 200 {
		c.t.Fatalf("login %s: %d", email, code)
	}
	c.csrf = r.CSRF
}

func TestSecurityHeadersAndStatic(t *testing.T) {
	e := setup(t)
	resp, err := http.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "/static/app.js") {
		t.Fatalf("index: %d", resp.StatusCode)
	}
	h := resp.Header
	for k, want := range map[string]string{
		"Content-Security-Policy": "script-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
		"Strict-Transport-Security": "max-age=", "Referrer-Policy": "no-referrer", "Cross-Origin-Opener-Policy": "same-origin",
	} {
		if !strings.Contains(h.Get(k), want) {
			t.Errorf("%s = %q", k, h.Get(k))
		}
	}
	if strings.Contains(h.Get("Content-Security-Policy"), "unsafe-inline") {
		t.Error("CSP allows unsafe-inline")
	}
	r2, _ := http.Get(e.ts.URL + "/static/")
	r2.Body.Close()
	if r2.StatusCode != 404 {
		t.Errorf("directory listing: %d", r2.StatusCode)
	}
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.Host = "evil.test"
	r3, _ := http.DefaultClient.Do(req)
	r3.Body.Close()
	if r3.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("foreign Host accepted: %d", r3.StatusCode)
	}
	req, _ = http.NewRequest("GET", e.ts.URL+"/.well-known/mta-sts.txt", nil)
	req.Host = "mta-sts.example.com"
	r4, _ := http.DefaultClient.Do(req)
	pol, _ := io.ReadAll(r4.Body)
	r4.Body.Close()
	if !strings.Contains(string(pol), "mode: enforce\nmx: 127.0.0.1\nmax_age: 86400") {
		t.Errorf("mta-sts policy: %q", pol)
	}
}

func TestLoginSessionAndCSRF(t *testing.T) {
	e := setup(t)
	c := e.client(t)
	if code := c.json("GET", "/api/folders", nil, nil); code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	if code := c.json("POST", "/api/login", map[string]string{"email": "alice@example.com", "password": "nope-nope-nope"}, nil); code != 401 {
		t.Fatalf("bad password: %d", code)
	}
	resp := c.do("POST", "/api/login", strings.NewReader(`{"email":"alice@example.com","password":"password-alice"}`), "application/json", nil)
	resp.Body.Close()
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "mdmail" {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags: %+v", cookie)
	}
	c.login("alice@example.com", "password-alice")
	if code := c.json("GET", "/api/folders", nil, nil); code != 200 {
		t.Fatalf("folders: %d", code)
	}
	tok := c.csrf
	c.csrf = ""
	if code := c.json("POST", "/api/preview", map[string]string{"markdown": "x"}, nil); code != 403 {
		t.Fatalf("missing CSRF token accepted: %d", code)
	}
	c.csrf = tok
	resp = c.do("POST", "/api/preview", strings.NewReader(`{"markdown":"x"}`), "application/json", func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.test")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin request accepted: %d", resp.StatusCode)
	}
	var prev map[string]string
	if code := c.json("POST", "/api/preview", map[string]string{"markdown": "**hi** <script>alert(1)</script>"}, &prev); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	if !strings.Contains(prev["html"], "<strong>hi</strong>") || strings.Contains(prev["html"], "script") {
		t.Fatalf("preview html: %q", prev["html"])
	}
	if code := c.json("POST", "/api/logout", map[string]string{}, nil); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code := c.json("GET", "/api/folders", nil, nil); code != 401 {
		t.Fatalf("session survived logout: %d", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := setup(t)
	c := e.client(t)
	var last int
	for i := 0; i < 12; i++ {
		last = c.json("POST", "/api/login", map[string]string{"email": "x@example.com", "password": "whatever-123"}, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("login not rate limited: %d", last)
	}
}

func TestSendReadIsolation(t *testing.T) {
	e := setup(t)
	alice := e.client(t)
	alice.login("alice@example.com", "password-alice")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("to", "Bob <bob@example.com>")
	_ = mw.WriteField("subject", "Markdown test")
	_ = mw.WriteField("markdown", "# Hello\n\n<img src=x onerror=alert(1)> **bold**")
	fw, _ := mw.CreateFormFile("attachment", "evil.html")
	_, _ = fw.Write([]byte("<script>alert(1)</script>"))
	mw.Close()
	resp := alice.do("POST", "/api/send", &buf, mw.FormDataContentType(), nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("send: %d %s", resp.StatusCode, body)
	}

	bob := e.client(t)
	bob.login("bob@example.com", "password-bob")
	var list []store.Message
	bob.json("GET", "/api/messages?folder=INBOX", nil, &list)
	if len(list) != 1 || list[0].Subject != "Markdown test" || !list[0].HasAttach {
		t.Fatalf("bob inbox: %+v", list)
	}
	id := list[0].ID
	path := "/api/messages/" + jsonInt(id)

	var mv struct {
		Parsed struct {
			Text        string `json:"text"`
			Attachments []struct {
				Index int `json:"index"`
			} `json:"attachments"`
		} `json:"parsed"`
	}
	if code := bob.json("GET", path, nil, &mv); code != 200 || !strings.Contains(mv.Parsed.Text, "# Hello") {
		t.Fatalf("get: %d %+v", code, mv)
	}

	r := bob.do("GET", path+"/body", nil, "", nil)
	html, _ := io.ReadAll(r.Body)
	r.Body.Close()
	csp := r.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("body CSP: %q", csp)
	}
	if !strings.Contains(string(html), "<h1") || strings.Contains(string(html), "onerror") {
		t.Errorf("body html: %s", html)
	}

	r = bob.do("GET", path+"/attachments/"+jsonInt(int64(mv.Parsed.Attachments[0].Index)), nil, "", nil)
	att, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.Header.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") || string(att) != "<script>alert(1)</script>" {
		t.Errorf("attachment served unsafely: %v", r.Header)
	}

	// Alice must not be able to read, modify or delete Bob's message.
	if code := alice.json("GET", path, nil, nil); code != 404 {
		t.Fatalf("IDOR read: %d", code)
	}
	if code := alice.json("PATCH", path, map[string]any{"folder": "Trash"}, nil); code != 404 {
		t.Fatalf("IDOR update: %d", code)
	}
	if code := alice.json("DELETE", path, nil, nil); code != 404 {
		t.Fatalf("IDOR delete: %d", code)
	}

	// Delete moves to Trash; deleting again removes it.
	bob.json("DELETE", path, nil, nil)
	bob.json("GET", "/api/messages?folder=Trash", nil, &list)
	if len(list) != 1 {
		t.Fatal("not moved to Trash")
	}
	bob.json("DELETE", path, nil, nil)
	if code := bob.json("GET", path, nil, nil); code != 404 {
		t.Fatal("not permanently deleted")
	}

	var sent []store.Message
	alice.json("GET", "/api/messages?folder=Sent", nil, &sent)
	if len(sent) != 1 {
		t.Fatal("no Sent copy for alice")
	}
}

func TestSendValidation(t *testing.T) {
	e := setup(t)
	c := e.client(t)
	c.login("alice@example.com", "password-alice")
	send := func(fields map[string]string) int {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		mw.Close()
		r := c.do("POST", "/api/send", &buf, mw.FormDataContentType(), nil)
		r.Body.Close()
		return r.StatusCode
	}
	if code := send(map[string]string{"to": "nobody@example.com", "subject": "x", "markdown": "x"}); code != 400 {
		t.Errorf("unknown local recipient: %d", code)
	}
	if code := send(map[string]string{"to": "bob@example.com", "subject": "x\r\nBcc: a@b.c", "markdown": "x"}); code != 400 {
		t.Errorf("header injection: %d", code)
	}
	if code := send(map[string]string{"to": "", "subject": "x", "markdown": "x"}); code != 400 {
		t.Errorf("no recipients: %d", code)
	}
	if code := send(map[string]string{"to": "bob@example.com", "from": "ceo@example.com"}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
}

func TestAccountTOTPAndAppPasswords(t *testing.T) {
	e := setup(t)
	c := e.client(t)
	c.login("alice@example.com", "password-alice")
	var setupResp map[string]string
	if code := c.json("POST", "/api/account/totp/setup", map[string]string{"password": "wrong"}, nil); code != 403 {
		t.Fatalf("totp setup without reauth: %d", code)
	}
	if code := c.json("POST", "/api/account/totp/setup", map[string]string{"password": "password-alice"}, &setupResp); code != 200 {
		t.Fatalf("totp setup: %d", code)
	}
	if !strings.HasPrefix(setupResp["uri"], "otpauth://totp/") {
		t.Fatalf("uri %q", setupResp["uri"])
	}
	var ap map[string]any
	if code := c.json("POST", "/api/account/app-passwords", map[string]string{"name": "phone", "password": "password-alice"}, &ap); code != 200 {
		t.Fatalf("app password: %d", code)
	}
	var acct struct {
		AppPasswords []store.AppPassword `json:"app_passwords"`
		Events       []store.AuditEntry  `json:"events"`
	}
	c.json("GET", "/api/account", nil, &acct)
	if len(acct.AppPasswords) != 1 || len(acct.Events) == 0 {
		t.Fatalf("account: %+v", acct)
	}
	if code := c.json("POST", "/api/account/password", map[string]string{"current": "password-alice", "new": "short"}, nil); code != 400 {
		t.Fatalf("weak password accepted: %d", code)
	}
	if code := c.json("POST", "/api/account/password", map[string]string{"current": "password-alice", "new": "a-much-better-password"}, nil); code != 200 {
		t.Fatalf("change password: %d", code)
	}
	other := e.client(t)
	other.login("alice@example.com", "a-much-better-password")
}

func jsonInt(i int64) string { return url.PathEscape(strings.TrimSpace(string(mustJSON(i)))) }

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
