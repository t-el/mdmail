package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/t-el/mdmail/internal/mdrender"
	"github.com/t-el/mdmail/internal/store"
)

const checklistMD = "Release prep:\n\n- [ ] tag v1\n- [x] write notes\n- [ ] announce\n"

func (c *client) send(to, subject, md string) {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("to", to)
	_ = mw.WriteField("subject", subject)
	_ = mw.WriteField("markdown", md)
	mw.Close()
	resp := c.do("POST", "/api/send", &buf, mw.FormDataContentType(), nil)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.t.Fatalf("send: %d %s", resp.StatusCode, b)
	}
}

func (c *client) firstID(folder string) int64 {
	c.t.Helper()
	var list []store.Message
	c.json("GET", "/api/messages?folder="+folder, nil, &list)
	if len(list) == 0 {
		c.t.Fatalf("%s is empty", folder)
	}
	return list[0].ID
}

func (c *client) body(id int64) string {
	c.t.Helper()
	r := c.do("GET", "/api/messages/"+jsonInt(id)+"/body", nil, "", nil)
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestChecklistToggleAndAuthz(t *testing.T) {
	e := setup(t)
	e.srv.Cfg.ChecklistSharing = true
	alice, bob := e.client(t), e.client(t)
	alice.login("alice@example.com", "password-alice")
	bob.login("bob@example.com", "password-bob")
	// One local and one external recipient.
	alice.send("bob@example.com, carol@remote.test", "Checklist", checklistMD)

	bid := bob.firstID("INBOX")
	base := "/api/messages/" + jsonInt(bid)
	var mv messageView
	if bob.json("GET", base, nil, &mv); mv.Tasks != 3 {
		t.Fatalf("tasks = %d", mv.Tasks)
	}
	var cl checklistView
	if code := bob.json("GET", base+"/checklist", nil, &cl); code != 200 || cl.Total != 3 || cl.Done != 1 || !cl.Editable || !cl.VisibleToSender {
		t.Fatalf("checklist %d %+v", code, cl)
	}
	if cl.Items[0].Text != "tag v1" || cl.Items[1].Index != 1 || !cl.Items[1].Checked {
		t.Fatalf("items %+v", cl.Items)
	}

	// Toggle item 0 on.
	if code := bob.json("POST", base+"/checklist/0", map[string]bool{"checked": true}, &cl); code != 200 || cl.Done != 2 || !cl.Items[0].Checked {
		t.Fatalf("toggle %d %+v", code, cl)
	}
	// The sandboxed body reflects the stored state.
	if b := bob.body(bid); strings.Count(b, `<input type="checkbox" disabled checked>`) != 2 {
		t.Fatalf("body not updated: %s", b)
	}

	// Refusals; none may change state.
	noCSRF := e.client(t)
	noCSRF.hc = bob.hc // same session cookie, no CSRF token
	if code := noCSRF.json("POST", base+"/checklist/2", map[string]bool{"checked": true}, nil); code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", code)
	}
	r := bob.do("POST", base+"/checklist/2", strings.NewReader(`{"checked":true}`), "application/json", func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.test")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: %d", r.StatusCode)
	}
	if code := alice.json("POST", base+"/checklist/2", map[string]bool{"checked": true}, nil); code != 404 {
		t.Fatalf("non-owner toggle: %d", code)
	}
	if code := alice.json("GET", base+"/checklist", nil, nil); code != 404 {
		t.Fatalf("non-owner read: %d", code)
	}
	anon := e.client(t)
	if code := anon.json("POST", base+"/checklist/2", map[string]bool{"checked": true}, nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	for path, body := range map[string]any{
		base + "/checklist/3":   map[string]bool{"checked": true}, // beyond the message's items
		base + "/checklist/-1":  map[string]bool{"checked": true},
		base + "/checklist/x":   map[string]bool{"checked": true},
		base + "/checklist/999": map[string]bool{"checked": true},
		base + "/checklist/2":   map[string]any{},                 // missing field
		base + "/checklist/1":   map[string]any{"checked": "yes"}, // wrong type
	} {
		if code := bob.json("POST", path, body, nil); code < 400 || code >= 500 {
			t.Errorf("%s %v: %d", path, body, code)
		}
	}
	bob.json("GET", base+"/checklist", nil, &cl)
	if cl.Done != 2 || cl.Items[2].Checked {
		t.Fatalf("state changed by refused requests: %+v", cl)
	}

	// Sender: Sent copy is read-only and shows the local recipient only.
	sid := alice.firstID("Sent")
	sbase := "/api/messages/" + jsonInt(sid)
	if code := alice.json("POST", sbase+"/checklist/0", map[string]bool{"checked": true}, nil); code != http.StatusConflict {
		t.Fatalf("sent toggle: %d", code)
	}
	var scl checklistView
	alice.json("GET", sbase+"/checklist", nil, &scl)
	if scl.Editable || len(scl.Recipients) != 1 {
		t.Fatalf("sent view %+v", scl)
	}
	rp := scl.Recipients[0]
	if rp.Email != "bob@example.com" || rp.Done != 2 || rp.Total != 3 || len(rp.Checked) != 2 || rp.Checked[0] != 0 || rp.Checked[1] != 1 {
		t.Fatalf("progress %+v", rp)
	}
	// Bob cannot see Alice's recipient view of her own Sent message.
	if code := bob.json("GET", sbase+"/checklist", nil, nil); code != 404 {
		t.Fatalf("recipient reads sender view: %d", code)
	}
	// Nothing about checklists is queued for the external recipient: the
	// only queued mail is the original message.
	q, err := e.st.ListQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 1 || q[0].Rcpt != "carol@remote.test" {
		t.Fatalf("queue %+v", q)
	}

	// Sharing disabled: the sender sees nothing and the recipient is told so.
	e.srv.Cfg.ChecklistSharing = false
	scl = checklistView{}
	alice.json("GET", sbase+"/checklist", nil, &scl)
	if len(scl.Recipients) != 0 {
		t.Fatalf("sharing off but recipients shown: %+v", scl.Recipients)
	}
	cl = checklistView{}
	bob.json("GET", base+"/checklist", nil, &cl)
	if cl.VisibleToSender {
		t.Fatal("sharing off but visible_to_sender")
	}
	// Mail sent while sharing is off records no link at all.
	alice.send("bob@example.com", "Second", checklistMD)
	e.srv.Cfg.ChecklistSharing = true
	scl = checklistView{}
	alice.json("GET", "/api/messages/"+jsonInt(alice.firstID("Sent"))+"/checklist", nil, &scl)
	if scl.Total != 3 || len(scl.Recipients) != 0 {
		t.Fatalf("link recorded while sharing was off: %+v", scl)
	}
}

func TestChecklistRateLimited(t *testing.T) {
	e := setup(t)
	alice, bob := e.client(t), e.client(t)
	alice.login("alice@example.com", "password-alice")
	bob.login("bob@example.com", "password-bob")
	alice.send("bob@example.com", "c", checklistMD)
	path := "/api/messages/" + jsonInt(bob.firstID("INBOX")) + "/checklist/0"
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		limited = bob.json("POST", path, map[string]bool{"checked": i%2 == 0}, nil) == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("toggle not rate limited")
	}
}

func TestPreviewEndpoint(t *testing.T) {
	e := setup(t)
	alice := e.client(t)
	alice.login("alice@example.com", "password-alice")
	md := "# Hi\n\n<script>alert(1)</script>\n\n- [ ] task\n\n[x](javascript:alert(1))"
	var out map[string]string
	if code := alice.json("POST", "/api/preview", map[string]string{"markdown": md}, &out); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	want, _ := mdrender.RenderFragment(md)
	if out["html"] != want {
		t.Fatalf("preview differs from the outgoing render:\n%s\n---\n%s", out["html"], want)
	}
	if strings.Contains(out["html"], "<script") || strings.Contains(out["html"], "javascript:") || !strings.Contains(out["html"], `type="checkbox"`) {
		t.Fatalf("unsafe or incomplete preview: %s", out["html"])
	}
	// Same render path as the recipient's text/html part.
	full, _ := mdrender.RenderEmailHTML(md, "s")
	if !strings.Contains(full, want) {
		t.Fatal("email HTML does not embed the previewed fragment")
	}

	if code := e.client(t).json("POST", "/api/preview", map[string]string{"markdown": "x"}, nil); code != 401 {
		t.Fatalf("anonymous preview: %d", code)
	}
	noCSRF := e.client(t)
	noCSRF.hc = alice.hc
	if code := noCSRF.json("POST", "/api/preview", map[string]string{"markdown": "x"}, nil); code != 403 {
		t.Fatalf("preview without CSRF: %d", code)
	}
	r := alice.do("POST", "/api/preview", strings.NewReader(`{"markdown":"x"}`), "text/plain", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type: %d", r.StatusCode)
	}
	big, _ := json.Marshal(map[string]string{"markdown": strings.Repeat("a", mdrender.MaxMarkdownBytes+1)})
	r = alice.do("POST", "/api/preview", bytes.NewReader(big), "application/json", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized markdown: %d", r.StatusCode)
	}
	huge := bytes.Repeat([]byte(" "), maxPreviewBody+10)
	r = alice.do("POST", "/api/preview", bytes.NewReader(huge), "application/json", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", r.StatusCode)
	}
	limited := false
	for i := 0; i < 60 && !limited; i++ {
		limited = alice.json("POST", "/api/preview", map[string]string{"markdown": "x"}, nil) == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("preview not rate limited")
	}
}

func TestStaticAssetTypes(t *testing.T) {
	e := setup(t)
	for path, ct := range map[string]string{
		"/static/app.js":    "text/javascript; charset=utf-8",
		"/static/editor.js": "text/javascript; charset=utf-8",
		"/static/app.css":   "text/css; charset=utf-8",
	} {
		r, err := http.Get(e.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || r.Header.Get("Content-Type") != ct || r.Header.Get("X-Content-Type-Options") != "nosniff" || len(b) == 0 {
			t.Errorf("%s: %d %q %q", path, r.StatusCode, r.Header.Get("Content-Type"), r.Header.Get("X-Content-Type-Options"))
		}
	}
	r, _ := http.Get(e.ts.URL + "/static/nope.txt")
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Errorf("unknown asset type served: %d", r.StatusCode)
	}
	// No inline script or style anywhere in the shell.
	r, _ = http.Get(e.ts.URL + "/")
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	s := string(b)
	if strings.Contains(s, "<style") || strings.Contains(s, " style=") || regexp.MustCompile(`\son[a-z]+=`).MatchString(s) ||
		strings.Count(s, "<script") != strings.Count(s, `<script src="/static/`) {
		t.Fatal("inline script or style in index.html")
	}
	if !strings.Contains(s, `<script src="/static/editor.js" defer></script>`) || !strings.Contains(s, `<textarea id="c-body"`) {
		t.Fatal("editor markup missing")
	}
}
