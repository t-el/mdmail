// mdmail Markdown editor: progressive enhancement of the compose textarea.
// Without this script the compose form is a plain <textarea> that still
// sends. With it: toolbar, slash commands, keyboard shortcuts, a debounced
// live preview rendered by the server (the exact goldmark + bluemonday path
// used for outgoing mail), draft autosave and a tabbed mobile layout.
// No inline code; the Content-Security-Policy forbids it.
'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const ta = $('c-body');
  const editor = $('c-editor');
  if (!ta || !editor) return;
  const preview = $('c-preview');
  const status = $('c-status');
  const DRAFT_FIELDS = ['c-to', 'c-cc', 'c-bcc', 'c-subject', 'c-body'];
  const PREVIEW_DELAY = 250;
  const SAVE_DELAY = 800;
  let draftKey = '';

  // ------------------------------------------------------ text editing
  // execCommand keeps the browser's native undo stack; setRangeText is the
  // standards fallback.
  function replaceRange(start, end, text, selStart, selEnd) {
    ta.focus();
    ta.setSelectionRange(start, end);
    let ok = false;
    try { ok = document.execCommand('insertText', false, text); } catch (_) { ok = false; }
    if (!ok || ta.value.slice(start, start + text.length) !== text) {
      ta.setRangeText(text, start, end, 'end');
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    }
    const base = start;
    ta.setSelectionRange(base + (selStart ?? text.length), base + (selEnd ?? selStart ?? text.length));
  }

  function wrap(before, after, placeholder) {
    const s = ta.selectionStart; const e = ta.selectionEnd;
    const sel = ta.value.slice(s, e) || placeholder;
    replaceRange(s, e, before + sel + after, before.length, before.length + sel.length);
  }

  function lineStart(pos) { return ta.value.lastIndexOf('\n', pos - 1) + 1; }

  // prefixLines toggles a Markdown line prefix on every selected line.
  function prefixLines(prefix) {
    const s = lineStart(ta.selectionStart);
    let e = ta.value.indexOf('\n', ta.selectionEnd);
    if (e === -1) e = ta.value.length;
    const lines = ta.value.slice(s, e).split('\n');
    const all = lines.every((l) => l.startsWith(prefix));
    const out = lines.map((l) => (all ? l.slice(prefix.length) : prefix + l)).join('\n');
    replaceRange(s, e, out, out.length, out.length);
  }

  function block(text, selFrom, selTo) {
    const s = ta.selectionStart;
    const before = ta.value.slice(0, s);
    // A block must be separated from a preceding paragraph by a blank line.
    let needNL = '\n\n';
    if (before === '' || before.endsWith('\n\n')) needNL = '';
    else if (before.endsWith('\n')) needNL = '\n';
    replaceRange(s, ta.selectionEnd, needNL + text, needNL.length + selFrom, needNL.length + selTo);
  }

  const TABLE = '| Column | Column |\n| --- | --- |\n| Cell | Cell |\n';
  const commands = {
    bold: () => wrap('**', '**', 'bold text'),
    italic: () => wrap('_', '_', 'italic text'),
    strike: () => wrap('~~', '~~', 'text'),
    heading: () => prefixLines('## '),
    quote: () => prefixLines('> '),
    code: () => {
      const sel = ta.value.slice(ta.selectionStart, ta.selectionEnd);
      if (sel && !sel.includes('\n')) wrap('`', '`', 'code');
      else block('```\n' + (sel || '') + '\n```\n', 4, 4 + (sel || '').length);
    },
    link: () => {
      const s = ta.selectionStart; const e = ta.selectionEnd;
      const sel = ta.value.slice(s, e);
      if (/^https?:\/\/\S+$/.test(sel)) replaceRange(s, e, '[link text](' + sel + ')', 1, 10);
      else { const t = sel || 'link text'; replaceRange(s, e, '[' + t + '](https://)', t.length + 3, t.length + 11); }
    },
    ul: () => prefixLines('- '),
    ol: () => prefixLines('1. '),
    todo: () => prefixLines('- [ ] '),
    table: () => block(TABLE, 2, 8),
  };

  // ------------------------------------------------------------ toolbar
  const toolbar = $('c-toolbar');
  toolbar.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-cmd]');
    if (!b) return;
    ev.preventDefault();
    const fn = commands[b.dataset.cmd];
    if (fn) fn();
  });

  // ----------------------------------------------------- slash commands
  const slash = [
    { cmd: 'heading', label: 'Heading', insert: '## ', sel: [3, 3] },
    { cmd: 'todo', label: 'To-do item', insert: '- [ ] ', sel: [6, 6] },
    { cmd: 'table', label: 'Table', insert: TABLE, sel: [2, 8] },
    { cmd: 'code', label: 'Code block', insert: '```\n\n```\n', sel: [4, 4] },
    { cmd: 'quote', label: 'Quote', insert: '> ', sel: [2, 2] },
    { cmd: 'link', label: 'Link', insert: '[link text](https://)', sel: [1, 10] },
  ];
  const menu = $('c-slash');
  let menuItems = []; let menuIdx = 0; let menuFrom = -1;

  function slashQuery() {
    const pos = ta.selectionStart;
    if (pos !== ta.selectionEnd) return null;
    const ls = lineStart(pos);
    const m = /(^|\s)\/([a-z]{0,10})$/.exec(ta.value.slice(ls, pos));
    if (!m) return null;
    return { from: pos - m[2].length - 1, q: m[2] };
  }

  function closeMenu() { menu.classList.add('hidden'); menuItems = []; menuFrom = -1; ta.removeAttribute('aria-activedescendant'); }

  function renderMenu() {
    menu.replaceChildren();
    menuItems.forEach((it, i) => {
      const li = document.createElement('li');
      li.id = 'c-slash-' + it.cmd;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', i === menuIdx ? 'true' : 'false');
      if (i === menuIdx) { li.className = 'active'; ta.setAttribute('aria-activedescendant', li.id); }
      const k = document.createElement('code'); k.textContent = '/' + it.cmd;
      const l = document.createElement('span'); l.textContent = it.label;
      li.append(k, l);
      li.addEventListener('mousedown', (e) => { e.preventDefault(); applySlash(it); });
      menu.append(li);
    });
  }

  function updateMenu() {
    const q = slashQuery();
    if (!q) { closeMenu(); return; }
    menuItems = slash.filter((it) => it.cmd.startsWith(q.q));
    if (!menuItems.length) { closeMenu(); return; }
    menuFrom = q.from;
    if (menuIdx >= menuItems.length) menuIdx = 0;
    menu.classList.remove('hidden');
    renderMenu();
  }

  function applySlash(it) {
    const from = menuFrom; const to = ta.selectionStart;
    closeMenu();
    if (from < 0) return;
    replaceRange(from, to, it.insert, it.sel[0], it.sel[1]);
  }

  // --------------------------------------------------------- shortcuts
  ta.addEventListener('keydown', (ev) => {
    if (menuItems.length) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); menuIdx = (menuIdx + 1) % menuItems.length; renderMenu(); return; }
      if (ev.key === 'ArrowUp') { ev.preventDefault(); menuIdx = (menuIdx - 1 + menuItems.length) % menuItems.length; renderMenu(); return; }
      if (ev.key === 'Enter' || ev.key === 'Tab') { ev.preventDefault(); applySlash(menuItems[menuIdx]); return; }
      if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); closeMenu(); return; }
    }
    const mod = ev.ctrlKey || ev.metaKey;
    if (!mod || ev.altKey) return;
    const k = ev.key.toLowerCase();
    if (k === 'enter') { ev.preventDefault(); $('c-send').click(); return; }
    if (ev.shiftKey) return;
    if (k === 'b') { ev.preventDefault(); commands.bold(); } else if (k === 'i') { ev.preventDefault(); commands.italic(); } else if (k === 'k') { ev.preventDefault(); commands.link(); }
  });
  // Ctrl/Cmd+Enter from the header fields sends as well.
  $('compose-form').addEventListener('keydown', (ev) => {
    if (ev.target !== ta && (ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') { ev.preventDefault(); $('c-send').click(); }
  });
  ta.addEventListener('blur', () => setTimeout(() => { if (document.activeElement !== ta) closeMenu(); }, 150));
  ta.addEventListener('click', updateMenu);

  // ------------------------------------------------------ live preview
  let previewTimer; let previewSeq = 0;
  function schedulePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(renderPreview, PREVIEW_DELAY);
  }
  async function renderPreview() {
    const seq = ++previewSeq;
    const api = window.mdmailAPI;
    if (!api) return;
    try {
      const html = await api.preview(ta.value);
      // Server-rendered by goldmark and sanitized by the same bluemonday
      // allow-list as outgoing mail; the CSP additionally blocks scripts.
      if (seq === previewSeq) { preview.innerHTML = html; preview.classList.remove('stale'); }
    } catch (e) {
      if (seq === previewSeq) { preview.classList.add('stale'); status.textContent = 'Preview: ' + e.message; }
    }
  }

  // ------------------------------------------------------ draft autosave
  // Drafts stay in this browser's localStorage only (never on the server)
  // and are removed on send, on discard and on sign-out.
  let saveTimer;
  function storage() { try { return window.localStorage; } catch (_) { return null; } }
  function saveDraft() {
    const ls = storage(); if (!ls || !draftKey) return;
    const d = {}; let empty = true;
    for (const id of DRAFT_FIELDS) { d[id] = $(id).value; if (id === 'c-body' && d[id].trim()) empty = false; }
    try {
      if (empty) ls.removeItem(draftKey);
      else { d.saved = Date.now(); ls.setItem(draftKey, JSON.stringify(d)); status.textContent = 'Draft saved on this device'; }
    } catch (_) { /* quota or disabled storage: autosave is best effort */ }
  }
  function scheduleSave() { clearTimeout(saveTimer); saveTimer = setTimeout(saveDraft, SAVE_DELAY); }
  function loadDraft() {
    const ls = storage(); if (!ls || !draftKey) return false;
    let d;
    try { d = JSON.parse(ls.getItem(draftKey) || 'null'); } catch (_) { d = null; }
    if (!d || typeof d !== 'object' || typeof d['c-body'] !== 'string' || !d['c-body'].trim()) return false;
    for (const id of DRAFT_FIELDS) if (typeof d[id] === 'string') $(id).value = d[id].slice(0, 2 << 20);
    status.textContent = 'Restored your unsent draft';
    return true;
  }
  function clearDraft(key) {
    const ls = storage(); if (!ls) return;
    try { ls.removeItem(key || draftKey); } catch (_) { /* ignore */ }
  }
  function clearAllDrafts() {
    const ls = storage(); if (!ls) return;
    try { for (let i = ls.length - 1; i >= 0; i--) { const k = ls.key(i); if (k && k.startsWith('mdmail:draft:')) ls.removeItem(k); } } catch (_) { /* ignore */ }
  }

  // ------------------------------------------------------ mobile tabs
  function setView(v, keepFocus) {
    editor.dataset.view = v;
    $('tab-write').setAttribute('aria-selected', v === 'write' ? 'true' : 'false');
    $('tab-preview').setAttribute('aria-selected', v === 'preview' ? 'true' : 'false');
    if (v === 'preview') renderPreview(); else if (!keepFocus) ta.focus();
  }
  $('tab-write').addEventListener('click', () => setView('write'));
  $('tab-preview').addEventListener('click', () => setView('preview'));

  // ------------------------------------------------------ wiring
  ta.addEventListener('input', () => { schedulePreview(); scheduleSave(); updateMenu(); });
  for (const id of DRAFT_FIELDS) if (id !== 'c-body') $(id).addEventListener('input', scheduleSave);

  // app.js announces compose lifecycle events on the form.
  const form = $('compose-form');
  form.addEventListener('mdmail:compose-open', (ev) => {
    const d = ev.detail || {};
    draftKey = 'mdmail:draft:' + String(d.user || '') + ':' + String(d.context || 'new');
    closeMenu(); setView('write', true);
    loadDraft();
    renderPreview();
  });
  form.addEventListener('mdmail:compose-sent', () => { clearTimeout(saveTimer); clearDraft(); });
  form.addEventListener('mdmail:compose-discard', () => { clearTimeout(saveTimer); clearDraft(); });
  form.addEventListener('mdmail:compose-close', () => { clearTimeout(saveTimer); saveDraft(); });
  document.addEventListener('mdmail:logout', () => { clearTimeout(saveTimer); draftKey = ''; clearAllDrafts(); });

  toolbar.classList.remove('hidden');
  editor.classList.add('enhanced');
  editor.dataset.enhanced = '1';
})();
