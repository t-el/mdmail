# Security model and hardening

This document describes what mdmail protects against, how, and what the
operator must do. It reflects the code in this repository; tests covering each
control are referenced in parentheses.

## Assets and threats

| Asset | Threats considered |
|---|---|
| Mailbox contents | Account takeover, cross-user access (IDOR), XSS in received mail, tracking pixels, data at rest on stolen disks/backups |
| Credentials | Online guessing, credential stuffing, offline cracking after DB theft, phishing of SMTP passwords when 2FA is on |
| Sending reputation | Open relay abuse, sender spoofing by authenticated users, compromised accounts sending spam |
| Server | Remote code execution, SSRF via DNS, resource exhaustion, container escape |
| Recipients | Spoofed/forged mail (SPF/DKIM/DMARC), forged `Authentication-Results` |

Out of scope: a compromised host or Docker daemon, physical attacks,
volumetric network DoS (use your provider's protection).

## Controls

### Authentication
- Passwords hashed with **argon2id** (m=64 MiB, t=3, p=2, 16-byte salt, PHC
  format). Concurrent hash computations are bounded to prevent memory DoS.
  Hash parameters read from the DB are range-checked. (`auth_test.go`)
- Minimum 12 characters, maximum 1024 bytes (NIST SP 800-63B).
- Login for unknown users performs a dummy hash so timing does not reveal
  which accounts exist; all failures return the same message.
- **Account lockout**: after 5 consecutive failures the account is locked for
  5 minutes, doubling per further failure up to 24 hours. Failures of the
  second factor and re-authentication count too. (`store_test.go`)
- **Per-IP rate limits**: login (burst 10, then 5/min), all HTTP (burst 100,
  then 20 req/s), SMTP connections (burst 30, then 30/min), SMTP AUTH (burst
  10, then 2/min). Rate limiter memory is bounded and fails closed. (`web_test.go`, `ratelimit_test.go`)
- **TOTP 2FA** (RFC 6238, 6 digits, ±30 s skew, replay of an accepted code is
  rejected). Secrets are encrypted at rest with AES-256-GCM bound to the user
  id; the key lives in `secret.key` (or a Docker secret). Enabling 2FA logs
  out other sessions.
- **App passwords** for SMTP: 160-bit random, stored as SHA-256, revocable,
  last use recorded. When 2FA is enabled the account password is **not**
  accepted for SMTP AUTH, so 2FA cannot be bypassed over SMTP. (`auth_test.go`)
- Sensitive changes (password, 2FA, app passwords) require the current
  password. Changing the password signs out all other sessions.

### Web sessions and browser security
- Session token: 256-bit random, only its SHA-256 is stored. Cookie
  `__Host-mdmail`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no
  `Domain`. Absolute (12 h) and idle (30 min) expiry; logout deletes the
  server-side session.
- **CSRF**: every state-changing request needs the per-session token in
  `X-CSRF-Token` (constant-time compare) **and** a same-origin `Origin` /
  `Sec-Fetch-Site`. Login also requires same-origin. (`web_test.go`)
- Headers on every response: strict **CSP** without `unsafe-inline`/`unsafe-eval`
  (`default-src 'none'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; …`),
  `Strict-Transport-Security` (2 years), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`. API responses are `Cache-Control: no-store`.
- Requests for any `Host` other than `MDMAIL_HOSTNAME` (or the MTA-STS hosts)
  are refused, defeating DNS-rebinding and host-header attacks.
- JSON bodies are limited to 256 KiB with unknown fields rejected; uploads are
  streamed into memory with hard limits (no temp files).

### Displaying untrusted mail
- Received HTML is sanitized with a bluemonday allow-list: no scripts, styles,
  `style` attributes, forms, frames, event handlers or non-http(s)/mailto URLs.
  Links get `rel="nofollow noreferrer noopener"` and `target="_blank"`.
- **Remote images are blocked** by default (tracking pixels). "Load images"
  re-renders the message allowing HTTPS images only.
- The body is served as a separate document with its own CSP
  (`default-src 'none'; sandbox …`, nonce-based style, no script at all) and is
  embedded in an `<iframe sandbox>` without `allow-scripts` or
  `allow-same-origin`. Even a sanitizer bypass cannot run script or reach the
  application origin. (`render_test.go`, `web_test.go`)
- Attachments are always served as `application/octet-stream` with
  `Content-Disposition: attachment`, sanitized filenames and a sandbox CSP.
- The UI inserts all text with `textContent`. The only `innerHTML` use is the
  compose preview, which is server-rendered Markdown sanitized by the same
  strict policy used for outgoing mail.

### Outgoing mail
- Markdown is rendered by goldmark **without raw HTML** and then sanitized by
  a strict allow-list, so authors cannot inject markup.
- Header injection: CR/LF/control characters in subjects and addresses are
  rejected; addresses are parsed and validated. `Bcc` never appears in
  headers. (`mailmsg_test.go`)
- **Sender identity**: the envelope sender and the `From`/`Sender` header must
  equal the authenticated user's address. (`smtpserver_test.go`)
- **DKIM** signing (RSA-2048, SHA-256, relaxed/relaxed, From/Subject
  oversigned) for every hosted domain that has a key.
- Per-user sending rate limit (`MDMAIL_SUBMIT_PER_HOUR`), recipient cap and
  size cap; all submissions are audit-logged.

### SMTP
- **No open relay**: port 25 accepts only recipients that exist in hosted
  domains; it never offers AUTH. (`smtpserver_test.go`)
- Submission requires AUTH, which is only advertised and accepted after TLS.
- STARTTLS on 25/587, implicit TLS on 465; TLS 1.2+ with forward-secret AEAD
  ciphers only.
- Directory-harvest protection: after 10 invalid recipients a session gets only `421` replies.
- Timeouts (2 min), line length, message size and recipient limits enforced.
- Inbound mail gets SPF, DKIM and DMARC evaluation. Existing
  `Authentication-Results` headers claiming our hostname are removed before
  adding ours (RFC 8601 §5). Mail with multiple `From` headers fails DMARC.
  (`mailauth_test.go`)
- Loop detection (more than 100 `Received` headers).

### Outbound delivery
- STARTTLS policy (`MDMAIL_OUTBOUND_TLS`), default requires encryption.
- MX/A records pointing to loopback, private, link-local or unspecified
  addresses are refused (SSRF protection). (`delivery_test.go`)
- Null MX (RFC 7505) honoured. Bounces go only to local senders (no backscatter).

### Data at rest
- Files in the data directory are created `0600`/`0700`. SQLite runs with
  `secure_delete=ON`, so deleted mail is overwritten.
- TOTP secrets are encrypted; passwords and app passwords are hashed; session
  tokens are hashed.
- Mail bodies are **not** encrypted at rest. Use full-disk encryption on the
  host (LUKS) and encrypt backups (see [backup.md](backup.md)).

### Audit logging
Security events (logins, failures, lockout-related rate limiting, SMTP auth,
password/2FA/app-password changes, session revocation, message submission) are
written as JSON to stdout and stored in the database for 180 days. Users see
their last 50 events under *Settings*.

### Container and supply chain
- Multi-stage build, CGO disabled, static binary, `-trimpath`.
- Runtime image: `distroless/static` **nonroot** (UID 65532): no shell, no
  package manager. Base images pinned by digest.
- Compose runs with a **read-only root filesystem**, `cap_drop: [ALL]`,
  `no-new-privileges`, a small noexec `tmpfs` for `/tmp`, PID/memory/file
  limits and log rotation. No capabilities are needed because the container
  listens on unprivileged ports.
- Secrets come from `.env` / `*_FILE` and are never committed (`.gitignore`).
- CI runs `go vet`, `staticcheck`, `gosec`, `govulncheck` and the race-enabled
  test suite on every push.

## Operator hardening checklist

- [ ] Host: automatic security updates, SSH keys only, firewall allowing only 25/80/443/465/587 (+SSH from trusted IPs).
- [ ] Full-disk encryption on the host; encrypted, off-site backups.
- [ ] `.env` mode 0600, owned by root; consider Docker secrets for `MDMAIL_SECRET_KEY_FILE`.
- [ ] DNS: SPF `-all`, DKIM published, DMARC `p=reject` (after a testing period), MTA-STS `enforce`, TLS-RPT, matching PTR.
- [ ] CAA record restricting issuance to Let's Encrypt: `example.com. CAA 0 issue "letsencrypt.org"`.
- [ ] Consider submitting the domain to the HSTS preload list once stable.
- [ ] Enable 2FA for every account; use app passwords for SMTP clients.
- [ ] Ship logs to a central system and alert on `login_failure` / `smtp_auth_failure` bursts.
- [ ] Rebuild the image regularly (`docker compose build --pull`) to pick up Go and base-image fixes.

## Limitations

- **No IMAP/POP3/JMAP.** Mailboxes are accessed through the web client and the
  HTTPS API. Desktop/mobile clients can send via SMTP submission.
- No server-side spam/virus scanning beyond SPF/DKIM/DMARC; put a scanner in
  front (e.g. rspamd as a milter-capable proxy) if you need it.
- Mail bodies are not encrypted at rest (no OpenPGP/S/MIME support).
- Outbound MTA-STS/DANE enforcement for *remote* domains is not implemented;
  use `MDMAIL_OUTBOUND_TLS=verify` for strict certificate checking.
- No aliases, forwarding rules or custom folders.
- Single-node design (SQLite). Scale vertically.
- DMARC aggregate reports are not generated (they are received like any mail).
