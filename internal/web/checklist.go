package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/t-el/mdmail/internal/mailmsg"
	"github.com/t-el/mdmail/internal/mdrender"
	"github.com/t-el/mdmail/internal/store"
)

// Interactive checklists.
//
// GFM task-list items ("- [ ] …") are taken from the Markdown/plain-text
// part of a stored message. A mailbox owner may toggle items of their own
// copy; the state lives only in this server's database, keyed by the stored
// copy (so it is per message and per recipient). Nothing is ever sent back
// to the sender's server: no read receipts, no pixels, no callbacks. When
// MDMAIL_CHECKLIST_SHARING is enabled and the sender is a local user of
// this server, the sender's Sent copy shows the local recipients'
// progress, using links recorded at submission time.

type checklistView struct {
	Items           []mdrender.Task     `json:"items"`
	Done            int                 `json:"done"`
	Total           int                 `json:"total"`
	Editable        bool                `json:"editable"`
	VisibleToSender bool                `json:"visible_to_sender"`
	Recipients      []recipientProgress `json:"recipients,omitempty"`
}

type recipientProgress struct {
	Email   string `json:"email"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Checked []int  `json:"checked"`
}

// effectiveTasks returns the message's task items with the owner's stored
// state applied.
func (s *Server) effectiveTasks(ctx context.Context, userID int64, m *store.Message, p *mailmsg.Parsed) ([]mdrender.Task, error) {
	tasks := mdrender.Tasks(p.Text)
	if len(tasks) == 0 {
		return tasks, nil
	}
	st, err := s.St.ChecklistState(ctx, userID, m.ID)
	if err != nil {
		return nil, err
	}
	for i := range tasks {
		if v, ok := st[tasks[i].Index]; ok {
			tasks[i].Checked = v
		}
	}
	return tasks, nil
}

func taskStates(tasks []mdrender.Task) []bool {
	if len(tasks) == 0 {
		return nil
	}
	out := make([]bool, len(tasks))
	for i, t := range tasks {
		out[i] = t.Checked
	}
	return out
}

func (s *Server) buildChecklist(ctx context.Context, rc *reqCtx, m *store.Message, p *mailmsg.Parsed) (*checklistView, error) {
	tasks, err := s.effectiveTasks(ctx, rc.user.ID, m, p)
	if err != nil {
		return nil, err
	}
	v := &checklistView{Items: tasks, Total: len(tasks), Editable: len(tasks) > 0 && m.Folder != store.FolderSent}
	for _, t := range tasks {
		if t.Checked {
			v.Done++
		}
	}
	if len(tasks) == 0 || !s.Cfg.ChecklistSharing {
		return v, nil
	}
	if m.Folder == store.FolderSent {
		rcs, err := s.St.RecipientChecklists(ctx, rc.user.ID, m.ID)
		if err != nil {
			return nil, err
		}
		// Recipients start from the state written in the message; their
		// own toggles override it.
		orig := mdrender.Tasks(p.Text)
		for _, r := range rcs {
			rp := recipientProgress{Email: r.Email, Total: len(orig), Checked: []int{}}
			for _, t := range orig {
				checked, ok := r.Checked[t.Index]
				if !ok {
					checked = t.Checked
				}
				if checked {
					rp.Done++
					rp.Checked = append(rp.Checked, t.Index)
				}
			}
			v.Recipients = append(v.Recipients, rp)
		}
		return v, nil
	}
	v.VisibleToSender, err = s.St.IsLocallyDelivered(ctx, rc.user.ID, m.ID)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Server) handleChecklist(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	m, ok := s.loadMessage(w, r, rc)
	if !ok {
		return
	}
	p, err := mailmsg.Parse(m.Raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "unparseable message")
		return
	}
	v, err := s.buildChecklist(r.Context(), rc, m, p)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleChecklistToggle sets one task-list item of the caller's own copy of
// a message. Every failure leaves the stored state unchanged.
func (s *Server) handleChecklistToggle(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.taskLimit.Allow(strconv.FormatInt(rc.user.ID, 10)) {
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	item, err := strconv.Atoi(r.PathValue("item"))
	if err != nil || item < 0 || item >= mdrender.MaxTasks {
		writeErr(w, http.StatusBadRequest, "invalid checklist item")
		return
	}
	var req struct {
		Checked *bool `json:"checked"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Checked == nil {
		writeErr(w, http.StatusBadRequest, "checked is required")
		return
	}
	m, ok := s.loadMessage(w, r, rc) // scoped to the owner: 404 otherwise
	if !ok {
		return
	}
	if m.Folder == store.FolderSent {
		writeErr(w, http.StatusConflict, "checklists of sent messages are read-only")
		return
	}
	p, err := mailmsg.Parse(m.Raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "unparseable message")
		return
	}
	if item >= len(mdrender.Tasks(p.Text)) {
		writeErr(w, http.StatusNotFound, "no such checklist item")
		return
	}
	err = s.St.SetChecklistItem(r.Context(), rc.user.ID, m.ID, item, *req.Checked)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "message not found")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	v, err := s.buildChecklist(r.Context(), rc, m, p)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
