package mdrender

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/yuin/goldmark/ast"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"golang.org/x/net/html"
)

// MaxTasks bounds the number of task-list items tracked per message.
const MaxTasks = 500

// maxTaskText bounds the label returned for one task item.
const maxTaskText = 500

// Task is one GFM task-list item ("- [ ] text" / "- [x] text").
//
// Index is the item's stable identifier: its 0-based position among all
// task-list items of the document in source order. It is identical to the
// position of the corresponding checkbox in the HTML produced by
// RenderFragment for the same source, because both come from the same
// goldmark parse.
type Task struct {
	Index   int    `json:"id"`
	Text    string `json:"text"`
	Checked bool   `json:"checked"`
}

// Tasks extracts the task-list items of a Markdown document. At most
// MaxTasks items are returned; the input is truncated like RenderFragment.
func Tasks(src string) []Task {
	if len(src) > MaxMarkdownBytes {
		src = src[:MaxMarkdownBytes]
	}
	source := []byte(src)
	doc := md.Parser().Parse(text.NewReader(source))
	out := []Task{}
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		cb, ok := n.(*east.TaskCheckBox)
		if !ok {
			return ast.WalkContinue, nil
		}
		if len(out) >= MaxTasks {
			return ast.WalkStop, nil
		}
		var b strings.Builder
		for s := cb.NextSibling(); s != nil; s = s.NextSibling() {
			collectText(&b, s, source)
		}
		out = append(out, Task{Index: len(out), Text: clip(strings.Join(strings.Fields(b.String()), " "), maxTaskText), Checked: cb.IsChecked})
		return ast.WalkSkipChildren, nil
	})
	return out
}

func collectText(b *strings.Builder, n ast.Node, source []byte) {
	switch t := n.(type) {
	case *ast.Text:
		b.Write(t.Segment.Value(source))
		if t.SoftLineBreak() || t.HardLineBreak() {
			b.WriteByte(' ')
		}
		return
	case *ast.String:
		b.Write(t.Value)
		return
	case *ast.AutoLink:
		b.Write(t.Label(source))
		return
	case *ast.List: // a nested list belongs to its own items
		return
	}
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		collectText(b, c, source)
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// NormalizeCheckboxes rewrites already-sanitized HTML so that the only form
// controls left are inert, disabled checkboxes. Any other <input> is
// removed. When states is non-nil and has exactly as many entries as the
// document has checkboxes, the n-th checkbox is checked iff states[n];
// otherwise each checkbox keeps its original checked attribute (so a
// foreign HTML body whose structure does not match the Markdown part is
// never mislabelled). It returns the number of checkboxes found.
func NormalizeCheckboxes(sanitized string, states []bool) (string, int) {
	if !strings.Contains(sanitized, "<input") {
		return sanitized, 0
	}
	total := countCheckboxes(sanitized)
	apply := states != nil && len(states) == total
	var out bytes.Buffer
	out.Grow(len(sanitized))
	z := html.NewTokenizer(strings.NewReader(sanitized))
	n := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return "", 0 // fail closed on malformed input
		}
		raw := append([]byte(nil), z.Raw()...)
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			out.Write(raw)
			continue
		}
		tok := z.Token()
		if tok.Data != "input" {
			out.Write(raw)
			continue
		}
		if !isCheckbox(tok) {
			continue // drop non-checkbox inputs entirely
		}
		checked := hasAttr(tok, "checked")
		if apply {
			checked = states[n]
		}
		if checked {
			out.WriteString(`<input type="checkbox" disabled checked>`)
		} else {
			out.WriteString(`<input type="checkbox" disabled>`)
		}
		n++
	}
	return out.String(), n
}

func countCheckboxes(s string) int {
	z := html.NewTokenizer(strings.NewReader(s))
	n := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return n
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			if tok := z.Token(); tok.Data == "input" && isCheckbox(tok) {
				n++
			}
		}
	}
}

func isCheckbox(t html.Token) bool {
	for _, a := range t.Attr {
		if a.Key == "type" {
			return strings.EqualFold(a.Val, "checkbox")
		}
	}
	return false
}

func hasAttr(t html.Token, k string) bool {
	for _, a := range t.Attr {
		if a.Key == k {
			return true
		}
	}
	return false
}
