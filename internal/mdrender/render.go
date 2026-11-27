// Package mdrender turns Markdown into safe HTML for outgoing mail and
// sanitizes untrusted HTML from incoming mail for display.
package mdrender

import (
	"bytes"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

// MaxMarkdownBytes bounds the Markdown input accepted for rendering.
const MaxMarkdownBytes = 2 << 20

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM), // tables, strikethrough, autolinks, task lists
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	// goldmark omits raw HTML by default (no html.WithUnsafe): Markdown
	// authors cannot inject HTML; the output is sanitized again below.
)

// outgoingPolicy is the strict allow-list applied to rendered Markdown.
var outgoingPolicy = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "code",
		"em", "strong", "del", "s", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "sup", "sub")
	p.AllowAttrs("id").Matching(regexp.MustCompile(`^[a-z0-9-]{1,100}$`)).OnElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowAttrs("start").Matching(bluemonday.Integer).OnElements("ol")
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|right|center)$`)).OnElements("th", "td")
	p.AllowAttrs("class").Matching(regexp.MustCompile(`^language-[a-zA-Z0-9_+-]{1,40}$`)).OnElements("code")
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
	p.AllowAttrs("checked", "disabled").Matching(regexp.MustCompile(`^(|checked|disabled)$`)).OnElements("input")
	p.AllowElements("input")
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("https", "http", "mailto")
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.AllowAttrs("src", "alt", "title").OnElements("img")
	p.AllowAttrs("title").OnElements("a")
	return p
}()

const emailCSS = `body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;color:#1f2328;max-width:760px;margin:0 auto;padding:12px}` +
	`pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:90%;background:#f6f8fa;padding:.1em .3em;border-radius:4px}pre code{padding:0;background:none}` +
	`blockquote{margin:0;padding:0 1em;color:#59636e;border-left:.25em solid #d1d9e0}table{border-collapse:collapse}th,td{border:1px solid #d1d9e0;padding:6px 12px}a{color:#0969da}img{max-width:100%}`

// RenderFragment converts Markdown to sanitized HTML (body fragment only).
func RenderFragment(src string) (string, error) {
	if len(src) > MaxMarkdownBytes {
		src = src[:MaxMarkdownBytes]
	}
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "", err
	}
	return outgoingPolicy.Sanitize(buf.String()), nil
}

// RenderEmailHTML converts Markdown to a complete, self-contained HTML
// document suitable for the text/html part of an email.
func RenderEmailHTML(src, title string) (string, error) {
	frag, err := RenderFragment(src)
	if err != nil {
		return "", err
	}
	return "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
		"<title>" + html.EscapeString(title) + "</title><style>" + emailCSS + "</style></head><body>\n" + frag + "\n</body></html>\n", nil
}

// incomingPolicy sanitizes HTML received from the Internet. It allows common
// formatting but no scripts, forms, frames, styles blocks, event handlers or
// CSS (inline styles are a frequent exfiltration/phishing vector).
func incomingPolicy(allowRemoteImages bool) *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowStandardAttributes()
	p.AllowElements("article", "aside", "details", "section", "summary", "h1", "h2", "h3", "h4", "h5", "h6",
		"hgroup", "blockquote", "br", "div", "hr", "p", "span", "wbr", "abbr", "acronym", "cite", "code", "dfn",
		"em", "figcaption", "mark", "s", "samp", "strong", "sub", "sup", "var", "b", "i", "pre", "small", "strike",
		"tt", "u", "del", "ins", "q", "bdi", "bdo", "figure", "center", "font", "address", "time")
	p.AllowLists()
	p.AllowTables()
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("https", "http", "mailto")
	p.RequireParseableURLs(true)
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|right|center|justify)$`)).OnElements("p", "div", "td", "th", "table", "img")
	p.AllowAttrs("width", "height").Matching(bluemonday.Integer).OnElements("img", "table", "td", "th")
	p.AllowAttrs("colspan", "rowspan").Matching(bluemonday.Integer).OnElements("td", "th")
	p.AllowAttrs("color").Matching(regexp.MustCompile(`^#?[0-9a-zA-Z]{1,20}$`)).OnElements("font")
	p.AllowAttrs("alt").OnElements("img")
	// Task-list checkboxes. Any <input> that is not a checkbox is removed
	// afterwards by NormalizeCheckboxes, and all checkboxes are disabled.
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^(?i:checkbox)$`)).OnElements("input")
	p.AllowAttrs("checked").Matching(regexp.MustCompile(`^(|checked)$`)).OnElements("input")
	p.AllowElements("input")
	if allowRemoteImages {
		p.AllowAttrs("src").Matching(regexp.MustCompile(`^(https://|data:image/(png|gif|jpeg|webp);base64,)`)).OnElements("img")
	} else {
		p.AllowAttrs("src").Matching(regexp.MustCompile(`^data:image/(png|gif|jpeg|webp);base64,`)).OnElements("img")
	}
	p.AllowDataURIImages()
	return p
}

var (
	policyNoImages   = incomingPolicy(false)
	policyWithImages = incomingPolicy(true)
	remoteImgRe      = regexp.MustCompile(`(?i)<img[^>]+src\s*=\s*["']?\s*(https?:)?//`)
	cssURLRe         = regexp.MustCompile(`(?i)url\s*\(\s*["']?\s*(https?:)?//`)
)

// SanitizeIncoming sanitizes untrusted HTML. Remote images are removed unless
// allowRemoteImages is true. It also reports whether the original contained
// remote resources (to offer a "load images" action). The only form
// controls kept are disabled task-list checkboxes; taskStates, when it
// matches the number of checkboxes, overrides their checked state (see
// NormalizeCheckboxes).
func SanitizeIncoming(h string, allowRemoteImages bool, taskStates []bool) (clean string, hadRemote bool) {
	hadRemote = remoteImgRe.MatchString(h) || cssURLRe.MatchString(h)
	p := policyNoImages
	if allowRemoteImages {
		p = policyWithImages
	}
	clean, _ = NormalizeCheckboxes(p.Sanitize(h), taskStates)
	return clean, hadRemote
}

// TextToHTML renders a plain-text body for display: escaped, with URLs linkified.
func TextToHTML(text string) string {
	var b strings.Builder
	b.WriteString(`<pre class="plain">`)
	last := 0
	for _, loc := range urlRe.FindAllStringIndex(text, -1) {
		b.WriteString(html.EscapeString(text[last:loc[0]]))
		u := text[loc[0]:loc[1]]
		if pu, err := url.Parse(u); err == nil && (pu.Scheme == "https" || pu.Scheme == "http") {
			b.WriteString(`<a href="` + html.EscapeString(pu.String()) + `" rel="nofollow noreferrer noopener" target="_blank">` + html.EscapeString(u) + `</a>`)
		} else {
			b.WriteString(html.EscapeString(u))
		}
		last = loc[1]
	}
	b.WriteString(html.EscapeString(text[last:]))
	b.WriteString(`</pre>`)
	return b.String()
}

var urlRe = regexp.MustCompile(`https?://[^\s<>"'()]+`)
