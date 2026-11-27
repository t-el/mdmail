package mdrender

import (
	"strings"
	"testing"
)

func TestRenderGFMAndSanitize(t *testing.T) {
	src := "# Title\n\n**bold** ~~gone~~\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [x] done\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) <img src=x onerror=alert(1)>\n\n```go\nfmt.Println(\"<b>\")\n```\n"
	out, err := RenderFragment(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<h1 id=\"title\">Title</h1>", "<strong>bold</strong>", "<del>gone</del>", "<table>", "<td>1</td>", `type="checkbox"`, `class="language-go"`, "&lt;b&gt;"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	for _, bad := range []string{"<script", "javascript:", "onerror", "alert(1)</script>"} {
		if strings.Contains(strings.ToLower(out), bad) {
			t.Errorf("unsafe %q in output: %s", bad, out)
		}
	}
}

func TestRenderEmailHTMLEscapesTitle(t *testing.T) {
	doc, err := RenderEmailHTML("hi", "</title><script>x</script>")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "<script>") {
		t.Fatal("title not escaped")
	}
	if !strings.HasPrefix(doc, "<!DOCTYPE html>") {
		t.Fatal("not a document")
	}
}

func TestSanitizeIncoming(t *testing.T) {
	in := `<div style="background:url(https://track.example/p.gif)" onclick="x()">Hi <img src="https://track.example/pixel.gif"> <img src="data:image/png;base64,iVBORw0KGgo="><a href="https://example.com">l</a><form action="https://evil"><input name=p></form><iframe src="https://evil"></iframe><style>body{}</style></div>`
	out, remote := SanitizeIncoming(in, false, nil)
	if !remote {
		t.Error("remote content not detected")
	}
	for _, bad := range []string{"track.example", "onclick", "<form", "<iframe", "<style", "style="} {
		if strings.Contains(out, bad) {
			t.Errorf("found %q in %s", bad, out)
		}
	}
	if !strings.Contains(out, "data:image/png;base64") {
		t.Error("inline data image dropped")
	}
	if !strings.Contains(out, `rel="nofollow noreferrer noopener"`) || !strings.Contains(out, `target="_blank"`) {
		t.Errorf("link not hardened: %s", out)
	}
	withImages, _ := SanitizeIncoming(in, true, nil)
	if !strings.Contains(withImages, "https://track.example/pixel.gif") {
		t.Error("images not allowed when requested")
	}
	if strings.Contains(withImages, "background:url") {
		t.Error("CSS url survived")
	}
}

func TestTextToHTML(t *testing.T) {
	out := TextToHTML("see https://example.com/a?b=1&c=2 <b>x</b>")
	if !strings.Contains(out, `<a href="https://example.com/a?b=1&amp;c=2"`) || strings.Contains(out, "<b>") {
		t.Fatalf("bad output %s", out)
	}
}
