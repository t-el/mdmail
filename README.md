# mdmail

A self-hosted email server where messages are **written in Markdown**.
One static Go binary provides an SMTP MX, authenticated submission, an
outbound delivery queue with DKIM signing, and a hardened web client with a
live Markdown preview. It ships as a distroless, non-root Docker image.

## Features

- **Markdown mail** — compose in Markdown (GitHub Flavored: tables, task
  lists, strikethrough, autolinks). Outgoing messages are
  `multipart/alternative`: `text/plain` carries the Markdown source,
  `text/html` is rendered by [goldmark](https://github.com/yuin/goldmark) and
  sanitized with a strict [bluemonday](https://github.com/microcosm-cc/bluemonday) allow-list.
- **SMTP** — inbound MX on port 25 (STARTTLS), submission on 587 (STARTTLS)
  and 465 (implicit TLS). AUTH is required and never offered over plaintext.
  No open relay.
- **Mail authentication** — DKIM signing of all outgoing mail; SPF, DKIM and
  DMARC verification of incoming mail with `Authentication-Results`
  (RFC 8601); DMARC `reject` enforced at SMTP time, `quarantine` → Junk.
- **Delivery** — persistent queue, MX resolution, STARTTLS with configurable
  policy, exponential back-off for 5 days, bounces to the local sender, SSRF
  protection against MX records pointing at private addresses.
- **Web client** — inbox/folders, search, read (HTML in a sandboxed iframe,
  remote images blocked by default), compose with live preview, reply /
  reply-all / forward (with attachments), attachments, flags, archive / junk /
  trash, account settings. Plain HTML + vanilla JS embedded in the binary.
- **Security** — argon2id passwords, optional TOTP 2FA (secrets encrypted at
  rest), per-device app passwords for SMTP, `__Host-` session cookies
  (HttpOnly, Secure, SameSite=Strict), CSRF tokens + Origin checks, strict CSP
  and security headers, rate limiting and exponential account lockout, audit
  log, TLS 1.2+ with ACME (Let's Encrypt) or your own certificates, MTA-STS
  policy hosting. See [docs/security.md](docs/security.md).
- **Storage** — SQLite (pure Go, no CGO) with embedded migrations; messages
  stored verbatim as MIME. Online backups with `mdmail backup`.

## Quick start (Docker)

Requirements: a server with a public IPv4 address, ports 25/80/443/465/587
reachable, reverse DNS you can set, and Docker with Compose v2.

```sh
git clone https://github.com/t-el/mdmail.git && cd mdmail
cp .env.example .env            # set MDMAIL_HOSTNAME, MDMAIL_DOMAINS, MDMAIL_ACME_EMAIL
docker compose up -d --build

# Create the DKIM key and print every DNS record to publish:
docker compose exec mdmail mdmail dkim generate example.com
docker compose exec -e MDMAIL_HOSTNAME=mail.example.com mdmail mdmail dns example.com

# Create users (password is read from the terminal):
docker compose exec mdmail mdmail user add postmaster@example.com --admin
docker compose exec mdmail mdmail user add you@example.com

docker compose restart mdmail   # load the new DKIM key
```

Then open `https://mail.example.com/`.

Publish the DNS records (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT) and set the
PTR record as described in [docs/deployment.md](docs/deployment.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Server prerequisites, DNS (MX, SPF, DKIM, DMARC, PTR, MTA-STS), Docker deployment, mail clients |
| [docs/configuration.md](docs/configuration.md) | Every environment variable |
| [docs/security.md](docs/security.md) | Threat model, controls, hardening checklist |
| [docs/backup.md](docs/backup.md) | Backup, restore, upgrades |
| [docs/api.md](docs/api.md) | HTTPS JSON API reference |
| [docs/cli.md](docs/cli.md) | Administration commands |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities |

## Building from source

```sh
go build -trimpath -ldflags "-s -w" -o mdmail ./cmd/mdmail
go test -race ./...
```

Go 1.27.4 or newer is required (pinned via `toolchain` in `go.mod`).

## License

[MIT](LICENSE)
