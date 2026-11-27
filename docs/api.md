# HTTPS API reference

The web client is built entirely on this JSON API, served at
`https://<MDMAIL_HOSTNAME>/api/`. It is designed for browser use with a
session cookie; scripts can use it by replaying the same headers.

## Conventions

- All responses carry `Cache-Control: no-store`. Errors are
  `{"error": "message", "code": "optional_code"}` with an appropriate status.
  State-changing requests that fail the CSRF token or origin check get
  `403` with `code:"csrf_failed"`, never a credentials error.
- Request bodies are JSON (`Content-Type: application/json`, max 256 KiB,
  unknown fields rejected) except `POST /api/send` (multipart).
- **Authentication:** `POST /api/login` sets the `__Host-mdmail` cookie and
  returns a CSRF token.
- **CSRF:** every non-GET request (except login) must send
  `X-CSRF-Token: <csrf>` and `Origin: https://<MDMAIL_HOSTNAME>` (browsers do
  this automatically; `Sec-Fetch-Site`, when present, must be `same-origin`).
- Rate limits: 20 req/s per IP (burst 100); login 5/min per IP (burst 10).
  `429` responses include `Retry-After`.
- Times are RFC 3339 in UTC.

Example with curl:

```sh
H=https://mail.example.com
curl -c jar -H "Origin: $H" -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"…","totp":"123456"}' $H/api/login
# → {"user":{…},"csrf":"<token>"}
curl -b jar "$H/api/messages?folder=INBOX&limit=20"
```

## Session

| Method & path | Body | Response |
|---|---|---|
| `POST /api/login` | `{"email","password","totp"?}` | `200 {"user":{"email","totp_enabled","is_admin"},"csrf"}`. `401` with `code:"totp_required"` when a second factor is needed. `401` with `code:"invalid_credentials"` and the single message "invalid email, password or code" for every credential failure (unknown user, wrong password or code, disabled or locked account); the precise reason is only logged server-side. `403` with `code:"origin_rejected"` when the request fails the same-origin check. `429` when rate limited. |
| `GET /api/session` | — | Same shape as login, for an existing session. `401` if none. |
| `POST /api/logout` | `{}` | `{"ok":true}`; deletes the server-side session. |

## Folders

Folders are fixed: `INBOX`, `Sent`, `Archive`, `Junk`, `Trash`.

| Method & path | Response |
|---|---|
| `GET /api/folders` | `[{"name","total","unread"}, …]` |
| `POST /api/folders/{Trash|Junk}/empty` | `{"deleted": n}` |

## Messages

| Method & path | Description |
|---|---|
| `GET /api/messages?folder=INBOX&limit=50&before=<id>&q=<text>` | Newest first. `limit` ≤ 200. `before` paginates by id. `q` searches subject/from/to. Returns `[Message]`. |
| `GET /api/messages/{id}` | `Message` plus `parsed` (see below), `has_remote_images` and `tasks` (number of task-list items). |
| `GET /api/messages/{id}/body?images=1` | Sanitized HTML document for an `<iframe sandbox>`. Remote HTTPS images only with `images=1`. |
| `GET /api/messages/{id}/raw` | Original RFC 5322 source as an attachment (`.eml`). |
| `GET /api/messages/{id}/attachments/{index}` | Attachment bytes, always `application/octet-stream` + `Content-Disposition: attachment`. |
| `GET /api/messages/{id}/checklist` | Task-list items of the message with your stored state (see [Checklists](#checklists)). |
| `POST /api/messages/{id}/checklist/{item}` | `{"checked":bool}` — tick or untick one item of your own copy. Returns the updated checklist. |
| `PATCH /api/messages/{id}` | `{"seen"?:bool,"flagged"?:bool,"folder"?:string}` |
| `DELETE /api/messages/{id}` | Moves to Trash; deletes permanently if already in Trash. |

`Message`:

```json
{"id":42,"folder":"INBOX","message_id":"abc@example.org","subject":"Hi",
 "from":"Bob <bob@example.org>","to":"alice@example.com","date":"2026-11-27T10:00:00Z",
 "size":2048,"seen":false,"flagged":false,"has_attachments":true,
 "auth_summary":"spf=pass dkim=pass dmarc=pass"}
```

`parsed`:

```json
{"subject":"Hi","from":"Bob <bob@example.org>","from_addr":"bob@example.org",
 "reply_to":"","to":"alice@example.com","cc":"","date":"…","message_id":"…",
 "in_reply_to":"","references":[],"text":"plain text / markdown source",
 "has_html":true,"attachments":[{"index":2,"filename":"report.pdf","content_type":"application/pdf","size":12345}],
 "auth_results":"mail.example.com; spf=pass …"}
```

All message endpoints are scoped to the logged-in user; ids of other users'
messages return `404`.

### Checklists

Task-list items (`- [ ] …`, `- [x] …`, also in ordered lists and quotes) are
read from the message's `text/plain` (Markdown) part. Each item's `id` is its
0-based position among all task items in the document; it is the same as the
position of the matching checkbox in the HTML part that mdmail renders from
that Markdown. At most 500 items per message are tracked.

```json
{"items":[{"id":0,"text":"tag v1","checked":true},{"id":1,"text":"write notes","checked":false}],
 "done":1,"total":2,"editable":true,"visible_to_sender":true,
 "recipients":[{"email":"bob@example.com","done":1,"total":2,"checked":[0]}]}
```

- `checked` is your stored state when you toggled the item, otherwise the
  state written in the message.
- `editable` is `false` for messages in `Sent` (a sender's copy is
  read-only; toggling it returns `409`).
- `visible_to_sender` tells a recipient that the sender is a local user who
  can see this progress (only with `MDMAIL_CHECKLIST_SHARING=true`).
- `recipients` appears only on your own `Sent` copies and lists local
  recipients on this server with their progress. External recipients never
  appear.

`POST …/checklist/{item}` errors: `400` (bad item or body), `403` (CSRF /
origin check), `404` (not your message, or no such item), `409` (Sent copy),
`429` (more than about 4 toggles per second). On any error nothing is
stored. The `/body` document shows the same state as disabled checkboxes.

## Composing

| Method & path | Description |
|---|---|
| `POST /api/preview` | `{"markdown"}` → `{"html"}` — sanitized HTML fragment, exactly as it will be sent (same renderer and sanitizer as the `text/html` part). Markdown ≤ 2 MiB (`413` above), per-user limit of about 5 requests per second (`429`). |
| `POST /api/send` | `multipart/form-data` (see below) → `{"ok":true}` |

`/api/send` fields:

| Field | Description |
|---|---|
| `to`, `cc`, `bcc` | Comma-separated RFC 5322 address lists (`Name <a@b.c>, d@e.f`). At least one recipient overall. |
| `subject` | Subject (no control characters, ≤ 998 bytes). |
| `markdown` | Body in GitHub-Flavored Markdown (≤ 2 MiB). |
| `reply_to_id` | Optional id of the message being answered (sets `In-Reply-To`/`References`). |
| `forward_id` | Optional id whose attachments are included. |
| `attachment` | Zero or more files (≤ 20). |

The sender is always the logged-in user. The message is DKIM-signed, stored
in `Sent`, delivered locally or queued for remote delivery. Errors: `400`
(validation, unknown local recipient), `413` (too large), `429` (sending rate
limit).

## Account

| Method & path | Body | Response |
|---|---|---|
| `GET /api/account` | — | `{"user", "app_passwords":[{"id","name","created_at","last_used"}], "events":[{"time","event","ip","detail"}], "smtp":{"host","submission_port","submissions_port"}}` |
| `POST /api/account/password` | `{"current","new"}` | Changes password; other sessions are revoked. |
| `POST /api/account/totp/setup` | `{"password"}` | `{"secret","uri"}` (otpauth URI). 2FA is not active until enabled. |
| `POST /api/account/totp/enable` | `{"code"}` | Activates 2FA; other sessions are revoked. |
| `POST /api/account/totp/disable` | `{"password","code"}` | Deactivates 2FA. |
| `POST /api/account/app-passwords` | `{"name","password"}` | `{"id","name","password"}` — the password is shown only once. Max 20. |
| `DELETE /api/account/app-passwords/{id}` | — | Revokes an app password. |
| `POST /api/account/sessions/revoke` | `{}` | Signs out all other sessions. |

## Other endpoints

| Endpoint | Description |
|---|---|
| `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` | MTA-STS policy (when `MDMAIL_MTASTS_MODE` ≠ `none`). |
| `GET http://127.0.0.1:9090/healthz` | Loopback-only health check (database ping). |
