// mdmail web client. Plain JavaScript, no dependencies, no inline code
// (the Content-Security-Policy forbids it). All untrusted text is inserted
// with textContent; message bodies are shown in a sandboxed iframe served
// with its own restrictive CSP.
'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { csrf: '', user: null, folder: 'INBOX', messages: [], current: null, query: '', compose: {} };

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of children) if (c != null) e.append(c);
    return e;
  }

  async function api(method, path, body, isForm) {
    const opts = { method, headers: {}, credentials: 'same-origin', cache: 'no-store' };
    if (method !== 'GET') opts.headers['X-CSRF-Token'] = state.csrf;
    if (body !== undefined) {
      if (isForm) opts.body = body;
      else { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    }
    const res = await fetch(path, opts);
    let data = null;
    const ct = res.headers.get('Content-Type') || '';
    if (ct.startsWith('application/json')) data = await res.json();
    if (res.status === 401 && path !== '/api/login') { showLogin(); }
    if (!res.ok) {
      let msg = data && data.error;
      if (!msg && res.status === 421) msg = 'this address does not match the server name (MDMAIL_HOSTNAME); open mdmail at its configured address';
      const err = new Error(msg || ('HTTP ' + res.status));
      err.code = data && data.code; err.status = res.status;
      throw err;
    }
    return data;
  }

  // ------------------------------------------------------------ login
  function showLogin() {
    state.user = null; state.csrf = '';
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    $('login-email').focus();
  }

  function showApp() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    loadFolders(); loadMessages(true);
  }

  $('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('login-error').textContent = '';
    try {
      const r = await api('POST', '/api/login', {
        email: $('login-email').value, password: $('login-password').value, totp: $('login-totp').value,
      });
      state.csrf = r.csrf; state.user = r.user;
      $('login-password').value = ''; $('login-totp').value = '';
      $('totp-row').classList.add('hidden');
      showApp();
    } catch (e) {
      if (e.code === 'totp_required') {
        $('totp-row').classList.remove('hidden'); $('login-totp').focus();
      } else {
        $('login-error').textContent = e.message;
      }
    }
  });

  $('btn-logout').addEventListener('click', async () => {
    try { await api('POST', '/api/logout', {}); } catch (_) { /* ignore */ }
    showLogin();
  });

  // ---------------------------------------------------------- folders
  async function loadFolders() {
    const folders = await api('GET', '/api/folders');
    const nav = $('folders'); nav.replaceChildren();
    for (const f of folders) {
      const a = el('a', { class: f.name === state.folder ? 'active' : '', role: 'button', tabindex: '0' },
        el('span', { text: f.name === 'INBOX' ? 'Inbox' : f.name }),
        el('span', { class: 'count', text: f.unread ? String(f.unread) : '' }));
      const open = () => { state.folder = f.name; state.current = null; loadFolders(); loadMessages(true); clearReader(); };
      a.addEventListener('click', open);
      a.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
      nav.append(a);
    }
    $('btn-empty').classList.toggle('hidden', !(state.folder === 'Trash' || state.folder === 'Junk'));
  }

  $('btn-empty').addEventListener('click', async () => {
    if (!confirm('Permanently delete every message in ' + state.folder + '?')) return;
    await api('POST', '/api/folders/' + encodeURIComponent(state.folder) + '/empty', {});
    clearReader(); loadFolders(); loadMessages(true);
  });

  // --------------------------------------------------------- messages
  function fmtDate(s) {
    const d = new Date(s); const now = new Date();
    return d.toDateString() === now.toDateString()
      ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString();
  }

  async function loadMessages(reset) {
    if (reset) state.messages = [];
    const last = state.messages[state.messages.length - 1];
    const params = new URLSearchParams({ folder: state.folder, limit: '50' });
    if (!reset && last) params.set('before', String(last.id));
    if (state.query) params.set('q', state.query);
    const list = await api('GET', '/api/messages?' + params);
    state.messages = state.messages.concat(list);
    renderList();
    $('btn-more').classList.toggle('hidden', list.length < 50);
  }

  function renderList() {
    const ul = $('messages'); ul.replaceChildren();
    for (const m of state.messages) {
      const who = state.folder === 'Sent' ? 'To: ' + m.to : m.from;
      const li = el('li', { class: (m.seen ? '' : 'unread ') + (state.current && state.current.id === m.id ? 'active' : '') },
        el('div', { class: 'row1' },
          el('span', { class: 'from', text: who || '(unknown)' }),
          m.flagged ? el('span', { class: 'flag', text: '★' }) : null,
          m.has_attachments ? el('span', { text: '📎' }) : null,
          el('span', { class: 'date', text: fmtDate(m.date) })),
        el('div', { class: 'subj', text: m.subject || '(no subject)' }));
      li.addEventListener('click', () => openMessage(m.id));
      ul.append(li);
    }
  }

  $('btn-more').addEventListener('click', () => loadMessages(false));

  let searchTimer;
  $('search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.query = $('search').value.trim(); loadMessages(true); }, 300);
  });

  function clearReader() {
    $('reader').replaceChildren(el('p', { class: 'placeholder', text: 'Select a message' }));
  }

  async function openMessage(id, images) {
    const m = await api('GET', '/api/messages/' + id);
    state.current = m;
    if (!m.seen) {
      await api('PATCH', '/api/messages/' + id, { seen: true });
      m.seen = true;
      const lm = state.messages.find((x) => x.id === id); if (lm) lm.seen = true;
      loadFolders();
    }
    renderList();
    const p = m.parsed;
    const r = $('reader'); r.replaceChildren();
    r.append(el('h2', { text: p.subject || '(no subject)' }));
    const meta = el('div', { class: 'meta' });
    const line = (label, value) => { if (value) meta.append(el('div', null, el('b', { text: label + ': ' }), document.createTextNode(value))); };
    line('From', p.from); line('Reply-To', p.reply_to); line('To', p.to); line('Cc', p.cc);
    line('Date', p.date ? new Date(p.date).toLocaleString() : '');
    r.append(meta);
    if (m.auth_summary && m.auth_summary !== 'local') {
      const bad = /=(fail|permerror|softfail)/.test(m.auth_summary);
      r.append(el('div', { class: 'auth' + (bad ? ' bad' : ''), text: (bad ? '⚠ ' : '✔ ') + m.auth_summary }));
    }
    const actions = el('div', { class: 'actions' });
    const btn = (label, fn) => actions.append(el('button', { text: label, onclick: fn }));
    btn('Reply', () => reply(false));
    btn('Reply all', () => reply(true));
    btn('Forward', forward);
    btn(m.flagged ? 'Unflag' : 'Flag', async () => { await api('PATCH', '/api/messages/' + id, { flagged: !m.flagged }); openMessage(id); loadMessages(true); });
    btn('Mark unread', async () => { await api('PATCH', '/api/messages/' + id, { seen: false }); loadFolders(); loadMessages(true); });
    if (m.folder !== 'Archive') btn('Archive', () => move(id, 'Archive'));
    if (m.folder !== 'Junk') btn('Junk', () => move(id, 'Junk'));
    if (m.folder === 'Junk' || m.folder === 'Trash') btn('Not junk / Restore', () => move(id, 'INBOX'));
    btn(m.folder === 'Trash' ? 'Delete forever' : 'Delete', async () => {
      if (m.folder === 'Trash' && !confirm('Delete permanently?')) return;
      await api('DELETE', '/api/messages/' + id); clearReader(); loadFolders(); loadMessages(true);
    });
    actions.append(el('a', { href: '/api/messages/' + id + '/raw', download: '', text: 'Source', class: 'muted' }));
    r.append(actions);
    if (p.attachments && p.attachments.length) {
      const box = el('div', { class: 'attachments' });
      for (const a of p.attachments) {
        box.append(el('a', { href: '/api/messages/' + id + '/attachments/' + a.index, download: '',
          text: '📎 ' + a.filename + ' (' + fmtSize(a.size) + ')' }));
      }
      r.append(box);
    }
    if (m.has_remote_images && !images) {
      r.append(el('div', { class: 'banner' }, el('span', { text: 'Remote images are blocked to protect your privacy.' }),
        el('button', { text: 'Load images', onclick: () => openMessage(id, true) })));
    }
    const frame = el('iframe', {
      sandbox: 'allow-popups allow-popups-to-escape-sandbox',
      referrerpolicy: 'no-referrer',
      title: 'Message body',
      src: '/api/messages/' + id + '/body' + (images ? '?images=1' : ''),
    });
    r.append(frame);
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  async function move(id, folder) {
    await api('PATCH', '/api/messages/' + id, { folder });
    clearReader(); loadFolders(); loadMessages(true);
  }

  // ---------------------------------------------------------- compose
  function quote(text) {
    return (text || '').split('\n').map((l) => '> ' + l).join('\n');
  }

  function openCompose(opts) {
    state.compose = opts || {};
    $('compose-title').textContent = opts && opts.title ? opts.title : 'New message';
    $('c-to').value = (opts && opts.to) || '';
    $('c-cc').value = (opts && opts.cc) || '';
    $('c-bcc').value = '';
    $('c-subject').value = (opts && opts.subject) || '';
    $('c-body').value = (opts && opts.body) || '';
    $('c-files').value = '';
    $('c-status').textContent = '';
    $('c-forward-note').textContent = opts && opts.forward_id ? 'Original attachments will be included.' : '';
    renderPreview();
    $('compose').showModal();
    ($('c-to').value ? $('c-body') : $('c-to')).focus();
  }

  function prefix(p, subj) {
    subj = subj || '';
    return subj.toLowerCase().startsWith(p.toLowerCase()) ? subj : p + ' ' + subj;
  }

  function addrList(s) { return (s || '').split(',').map((x) => x.trim()).filter(Boolean); }
  function bareAddr(s) { const m = /<([^>]+)>/.exec(s); return (m ? m[1] : s).trim().toLowerCase(); }

  function reply(all) {
    const m = state.current; const p = m.parsed;
    let to = p.reply_to || p.from; let cc = '';
    if (all) {
      const me = state.user.email.toLowerCase();
      const others = addrList(p.to).concat(addrList(p.cc)).filter((a) => bareAddr(a) !== me && bareAddr(a) !== bareAddr(to));
      cc = others.join(', ');
    }
    if (m.folder === 'Sent') to = p.to;
    const when = p.date ? new Date(p.date).toUTCString() : '';
    openCompose({
      title: all ? 'Reply all' : 'Reply', to, cc, subject: prefix('Re:', p.subject),
      body: '\n\nOn ' + when + ', ' + p.from + ' wrote:\n\n' + quote(p.text), reply_to_id: m.id,
    });
  }

  function forward() {
    const m = state.current; const p = m.parsed;
    const hdr = ['---------- Forwarded message ----------', 'From: ' + p.from, 'Date: ' + (p.date || ''),
      'Subject: ' + p.subject, 'To: ' + p.to].join('  \n');
    openCompose({ title: 'Forward', subject: prefix('Fwd:', p.subject), body: '\n\n' + hdr + '\n\n' + quote(p.text), forward_id: m.id });
  }

  let previewTimer; let previewSeq = 0;
  function renderPreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(async () => {
      const seq = ++previewSeq;
      try {
        const r = await api('POST', '/api/preview', { markdown: $('c-body').value });
        // The server returns HTML produced by goldmark and sanitized by a
        // strict bluemonday allow-list; CSP additionally blocks any script.
        if (seq === previewSeq) $('c-preview').innerHTML = r.html;
      } catch (e) { $('c-status').textContent = e.message; }
    }, 250);
  }
  $('c-body').addEventListener('input', renderPreview);
  $('compose-close').addEventListener('click', () => {
    if ($('c-body').value.trim() && !confirm('Discard this message?')) return;
    $('compose').close();
  });
  $('compose').addEventListener('cancel', (e) => { if ($('c-body').value.trim() && !confirm('Discard this message?')) e.preventDefault(); });

  $('c-send').addEventListener('click', async () => {
    const fd = new FormData();
    fd.append('to', $('c-to').value); fd.append('cc', $('c-cc').value); fd.append('bcc', $('c-bcc').value);
    fd.append('subject', $('c-subject').value); fd.append('markdown', $('c-body').value);
    if (state.compose.reply_to_id) fd.append('reply_to_id', String(state.compose.reply_to_id));
    if (state.compose.forward_id) fd.append('forward_id', String(state.compose.forward_id));
    for (const f of $('c-files').files) fd.append('attachment', f, f.name);
    $('c-send').disabled = true; $('c-status').textContent = 'Sending…';
    try {
      await api('POST', '/api/send', fd, true);
      $('compose').close(); loadFolders(); if (state.folder === 'Sent') loadMessages(true);
    } catch (e) {
      $('c-status').textContent = e.message;
    } finally { $('c-send').disabled = false; }
  });

  $('btn-compose').addEventListener('click', () => openCompose());

  // --------------------------------------------------------- settings
  function settingsMsg(t) { $('settings-msg').textContent = t; }

  async function loadSettings() {
    const a = await api('GET', '/api/account');
    state.user = a.user;
    $('totp-status').textContent = a.user.totp_enabled
      ? 'Enabled. SMTP clients must use an app password.'
      : 'Not enabled.';
    $('totp-on').classList.toggle('hidden', !a.user.totp_enabled);
    $('totp-off').classList.toggle('hidden', a.user.totp_enabled);
    $('totp-pending').classList.add('hidden');
    $('smtp-info').textContent = 'Server ' + a.smtp.host + ', port ' + a.smtp.submission_port + ' (STARTTLS) or ' +
      a.smtp.submissions_port + ' (TLS), username ' + a.user.email + '.';
    const ul = $('ap-list'); ul.replaceChildren();
    for (const ap of a.app_passwords) {
      ul.append(el('li', null, el('span', { text: ap.name + ' — last used ' + (ap.last_used && !ap.last_used.startsWith('0001') ? new Date(ap.last_used).toLocaleString() : 'never') }),
        el('button', { text: 'Revoke', onclick: async () => { await api('DELETE', '/api/account/app-passwords/' + ap.id); loadSettings(); } })));
    }
    const tb = $('events'); tb.replaceChildren();
    for (const e of a.events) tb.append(el('tr', null, el('td', { text: e.time.replace('T', ' ').replace('Z', '') }), el('td', { text: e.event }), el('td', { text: e.ip })));
  }

  $('btn-settings').addEventListener('click', async () => { settingsMsg(''); $('ap-new').classList.add('hidden'); await loadSettings(); $('settings').showModal(); });
  $('settings-close').addEventListener('click', () => $('settings').close());

  $('pw-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('POST', '/api/account/password', { current: $('pw-current').value, new: $('pw-new').value });
      $('pw-current').value = ''; $('pw-new').value = '';
      settingsMsg('Password changed. Other sessions were signed out.');
    } catch (e) { settingsMsg(e.message); }
  });

  $('totp-setup').addEventListener('click', async () => {
    try {
      const r = await api('POST', '/api/account/totp/setup', { password: $('totp-pw').value });
      $('totp-pw').value = '';
      $('totp-secret').textContent = r.secret.replace(/(.{4})/g, '$1 ').trim();
      $('totp-uri').textContent = r.uri;
      $('totp-pending').classList.remove('hidden');
    } catch (e) { settingsMsg(e.message); }
  });

  $('totp-enable').addEventListener('click', async () => {
    try {
      await api('POST', '/api/account/totp/enable', { code: $('totp-code').value });
      $('totp-code').value = '';
      settingsMsg('Two-factor authentication enabled.');
      loadSettings();
    } catch (e) { settingsMsg(e.message); }
  });

  $('totp-disable').addEventListener('click', async () => {
    try {
      await api('POST', '/api/account/totp/disable', { password: $('totp-dis-pw').value, code: $('totp-dis-code').value });
      $('totp-dis-pw').value = ''; $('totp-dis-code').value = '';
      settingsMsg('Two-factor authentication disabled.');
      loadSettings();
    } catch (e) { settingsMsg(e.message); }
  });

  $('ap-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const r = await api('POST', '/api/account/app-passwords', { name: $('ap-name').value, password: $('ap-pw').value });
      $('ap-name').value = ''; $('ap-pw').value = '';
      $('ap-new').textContent = r.password;
      $('ap-new').classList.remove('hidden');
      settingsMsg('Copy this app password now; it will not be shown again.');
      loadSettings();
    } catch (e) { settingsMsg(e.message); }
  });

  $('revoke-sessions').addEventListener('click', async () => {
    try { await api('POST', '/api/account/sessions/revoke', {}); settingsMsg('All other sessions were signed out.'); } catch (e) { settingsMsg(e.message); }
  });

  // ------------------------------------------------------------- boot
  (async () => {
    try {
      const s = await api('GET', '/api/session');
      state.csrf = s.csrf; state.user = s.user;
      showApp();
    } catch (_) { showLogin(); }
  })();

  setInterval(() => { if (state.user && document.visibilityState === 'visible') { loadFolders().catch(() => {}); if (!state.query) loadMessages(true).catch(() => {}); } }, 60000);
})();
