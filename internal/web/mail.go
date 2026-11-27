package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message/mail"

	"github.com/t-el/mdmail/internal/mailer"
	"github.com/t-el/mdmail/internal/mailmsg"
	"github.com/t-el/mdmail/internal/mdrender"
	"github.com/t-el/mdmail/internal/store"
)

func (s *Server) handleFolders(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	fc, err := s.St.FolderCounts(r.Context(), rc.user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, fc)
}

func (s *Server) handleEmptyFolder(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := r.PathValue("folder")
	if f != store.FolderTrash && f != store.FolderJunk {
		writeErr(w, http.StatusBadRequest, "only Trash and Junk can be emptied")
		return
	}
	n, err := s.St.EmptyFolder(r.Context(), rc.user.ID, f)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := r.URL.Query()
	folder := q.Get("folder")
	if folder == "" {
		folder = store.FolderInbox
	}
	if !store.ValidFolder(folder) {
		writeErr(w, http.StatusBadRequest, "unknown folder")
		return
	}
	limit := 50
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	var before int64
	if v, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && v > 0 {
		before = v
	}
	search := strings.TrimSpace(q.Get("q"))
	if len(search) > 200 {
		search = search[:200]
	}
	msgs, err := s.St.ListMessages(r.Context(), rc.user.ID, folder, before, limit, search)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (s *Server) loadMessage(w http.ResponseWriter, r *http.Request, rc *reqCtx) (*store.Message, bool) {
	id, ok := pathID(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return nil, false
	}
	m, err := s.St.GetMessage(r.Context(), rc.user.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "message not found")
		return nil, false
	}
	if err != nil {
		s.internalError(w, r, err)
		return nil, false
	}
	return m, true
}

type messageView struct {
	*store.Message
	Parsed          *mailmsg.Parsed `json:"parsed"`
	HasRemoteImages bool            `json:"has_remote_images"`
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	p, err := mailmsg.Parse(m.Raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "message could not be parsed; download the raw source instead")
		return
	}
	_, remote := mdrender.SanitizeIncoming(p.HTML, false)
	writeJSON(w, http.StatusOK, messageView{Message: m, Parsed: p, HasRemoteImages: remote})
}

// handleBody serves a message body as a standalone, sandboxed HTML document
// that the client embeds in an <iframe sandbox>. It has its own CSP: no
// scripts at all, no network access except (optionally) HTTPS images.
func (s *Server) handleBody(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	p, err := mailmsg.Parse(m.Raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "unparseable message")
		return
	}
	images := r.URL.Query().Get("images") == "1"
	var body string
	if p.HasHTML {
		body, _ = mdrender.SanitizeIncoming(p.HTML, images)
	} else {
		body = mdrender.TextToHTML(p.Text)
	}
	nonceB := make([]byte, 16)
	if _, err := rand.Read(nonceB); err != nil {
		s.internalError(w, r, err)
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceB)
	img := "data:"
	if images {
		img = "data: https:"
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; img-src "+img+"; style-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-popups allow-popups-to-escape-sandbox")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// body was produced by bluemonday (HTML) or html.EscapeString (text); the
	// document is additionally sandboxed and script-free by CSP.
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>%s</title><style nonce="%s">%s</style></head><body>%s</body></html>`,
		html.EscapeString(p.Subject), nonce, bodyCSS, body) // #nosec G705 -- sanitized, see above
}

const bodyCSS = `body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;color:#1f2328;margin:0;padding:16px;word-wrap:break-word}` +
	`pre{white-space:pre-wrap;background:#f6f8fa;padding:12px;border-radius:6px}pre.plain{background:none;padding:0;font-family:inherit}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:90%}` +
	`blockquote{margin:0;padding:0 1em;color:#59636e;border-left:.25em solid #d1d9e0}table{border-collapse:collapse;max-width:100%}th,td{border:1px solid #d1d9e0;padding:4px 8px}img{max-width:100%;height:auto}a{color:#0969da}` +
	`@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}pre,code{background:#161b22}a{color:#4493f8}th,td{border-color:#30363d}}`

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mailmsg.ContentDisposition(fmt.Sprintf("message-%d.eml", m.ID)))
	_, _ = w.Write(m.Raw)
}

func (s *Server) handleAttachment(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 {
		writeErr(w, http.StatusBadRequest, "invalid attachment index")
		return
	}
	a, err := mailmsg.GetAttachment(m.Raw, idx, s.Cfg.MaxMessageBytes)
	if errors.Is(err, mailmsg.ErrNoAttachment) {
		writeErr(w, http.StatusNotFound, "attachment not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "attachment could not be decoded")
		return
	}
	// Never let the browser render attacker-controlled content inline.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mailmsg.ContentDisposition(a.Filename))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	_, _ = w.Write(a.Data)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Seen    *bool   `json:"seen"`
		Flagged *bool   `json:"flagged"`
		Folder  *string `json:"folder"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Folder != nil && !store.ValidFolder(*req.Folder) {
		writeErr(w, http.StatusBadRequest, "unknown folder")
		return
	}
	err := s.St.UpdateMessage(r.Context(), rc.user.ID, id, req.Seen, req.Flagged, req.Folder)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "message not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleDelete moves a message to Trash, or deletes it permanently when it
// is already in Trash.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	var err error
	if m.Folder == store.FolderTrash {
		err = s.St.DeleteMessage(r.Context(), rc.user.ID, m.ID)
	} else {
		trash := store.FolderTrash
		err = s.St.UpdateMessage(r.Context(), rc.user.ID, m.ID, nil, nil, &trash)
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	var req struct {
		Markdown string `json:"markdown"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	h, err := mdrender.RenderFragment(req.Markdown)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not render markdown")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": h})
}

const maxAttachments = 20

// handleSend accepts multipart/form-data with fields to, cc, bcc, subject,
// markdown, optional reply_to_id / forward_id, and files named "attachment".
// The form is streamed into memory with strict limits (no temp files, so it
// works on a read-only root filesystem).
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	limit := s.Cfg.MaxMessageBytes + (1 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}
	fields := map[string]string{}
	var atts []mailmsg.Attachment
	var total int64
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeErr(w, http.StatusRequestEntityTooLarge, "message too large")
			} else {
				writeErr(w, http.StatusBadRequest, "malformed form")
			}
			return
		}
		name := part.FormName()
		if part.FileName() != "" {
			if name != "attachment" || len(atts) >= maxAttachments {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d attachments", maxAttachments))
				return
			}
			data, err := io.ReadAll(part)
			if err != nil {
				writeErr(w, http.StatusRequestEntityTooLarge, "message too large")
				return
			}
			total += int64(len(data))
			ct := part.Header.Get("Content-Type")
			if _, _, err := mime.ParseMediaType(ct); err != nil {
				ct = "application/octet-stream"
			}
			atts = append(atts, mailmsg.Attachment{Filename: part.FileName(), ContentType: ct, Data: data})
			continue
		}
		switch name {
		case "to", "cc", "bcc", "subject", "markdown", "reply_to_id", "forward_id":
		default:
			writeErr(w, http.StatusBadRequest, "unknown field "+strconv.Quote(name))
			return
		}
		v, err := io.ReadAll(io.LimitReader(part, int64(mdrender.MaxMarkdownBytes)+1))
		if err != nil || len(v) > mdrender.MaxMarkdownBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "field too large")
			return
		}
		fields[name] = string(v)
	}

	d := &mailmsg.Draft{From: &mail.Address{Address: rc.user.Email}, Subject: fields["subject"], Markdown: fields["markdown"], Hostname: s.Cfg.Hostname}
	for key, dst := range map[string]*[]*mail.Address{"to": &d.To, "cc": &d.Cc, "bcc": &d.Bcc} {
		l, err := mailmsg.ParseAddressList(fields[key])
		if err != nil {
			writeErr(w, http.StatusBadRequest, key+": "+err.Error())
			return
		}
		*dst = l
	}
	ctx := r.Context()
	if v := fields["reply_to_id"]; v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid reply_to_id")
			return
		}
		orig, err := s.St.GetMessage(ctx, rc.user.ID, id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "original message not found")
			return
		}
		if p, err := mailmsg.Parse(orig.Raw); err == nil && p.MessageID != "" {
			d.InReplyTo, d.References = p.MessageID, p.References
		}
	}
	if v := fields["forward_id"]; v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid forward_id")
			return
		}
		orig, err := s.St.GetMessage(ctx, rc.user.ID, id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "original message not found")
			return
		}
		fa, err := mailmsg.AllAttachments(orig.Raw, s.Cfg.MaxMessageBytes)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "could not include original attachments")
			return
		}
		for _, a := range fa {
			total += int64(len(a.Data))
		}
		atts = append(atts, fa...)
	}
	if len(atts) > maxAttachments*2 {
		writeErr(w, http.StatusBadRequest, "too many attachments")
		return
	}
	// Base64 inflates attachments by 4/3; reject early when clearly too big.
	if total*4/3 > s.Cfg.MaxMessageBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "attachments too large")
		return
	}
	d.Attachments = atts
	d.Date = time.Now()
	raw, _, err := mailmsg.Build(d)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.Mailer.Submit(ctx, rc.user, d.Recipients(), raw, rc.ip, "HTTPS")
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.Is(err, mailer.ErrRateLimited):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, mailer.ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
	case errors.Is(err, mailer.ErrTooManyRcpts), errors.Is(err, mailer.ErrUnknownLocal), errors.Is(err, mailer.ErrInvalidAddress),
		errors.Is(err, mailer.ErrNoRecipients), errors.Is(err, mailer.ErrFromMismatch):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		s.internalError(w, r, err)
	}
}
