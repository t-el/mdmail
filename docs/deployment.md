# Deployment

This guide deploys mdmail for the domain `example.com` with the server name
`mail.example.com` and public IPv4 address `203.0.113.10`. Replace these
values with your own.

## 1. Server prerequisites

- A VPS or dedicated server with a **static public IPv4** (IPv6 optional).
- **Outbound and inbound TCP port 25** must be allowed. Many cloud providers
  block port 25 by default; request unblocking first.
- A provider that lets you set **reverse DNS (PTR)**.
- Docker Engine 24+ with the Compose v2 plugin.
- Firewall: allow inbound 25, 80, 443, 465, 587; deny everything else
  (including SSH from the whole Internet if you can restrict it).

### Preserving client IP addresses

SPF checks and rate limiting rely on the real client IP. With Docker's default
iptables-based port publishing the source IPv4 address is preserved. If your
host uses the userland proxy for some traffic (e.g. IPv6 to an IPv4-only
container), set `"userland-proxy": false` in `/etc/docker/daemon.json` and
enable IPv6 for the Docker network, or run the service with
`network_mode: host` (remove the `ports:` section; the container keeps
listening on its unprivileged ports, so redirect 25→2525, 587→5870,
465→4650, 443→8443 and 80→8080 with host firewall `REDIRECT` rules, or set the
host sysctl `net.ipv4.ip_unprivileged_port_start=25` and point the
`MDMAIL_*_ADDR` variables at the standard ports). Do **not** put mdmail behind an
HTTP or TCP proxy that hides client addresses.

## 2. DNS records

`mdmail dns example.com` prints all of these with your actual DKIM key.

| Name | Type | Value | Purpose |
|---|---|---|---|
| `mail.example.com.` | A | `203.0.113.10` | Server address |
| `mail.example.com.` | AAAA | your IPv6 (optional) | |
| `example.com.` | MX | `10 mail.example.com.` | Inbound mail |
| `example.com.` | TXT | `"v=spf1 mx -all"` | SPF: only the MX may send |
| `mdmail._domainkey.example.com.` | TXT | `"v=DKIM1; k=rsa; p=…"` | DKIM public key (`mdmail dkim show example.com`) |
| `_dmarc.example.com.` | TXT | `"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:postmaster@example.com"` | DMARC policy |
| `mta-sts.example.com.` | CNAME | `mail.example.com.` | Hosts the MTA-STS policy |
| `_mta-sts.example.com.` | TXT | `"v=STSv1; id=20261127T000000"` | MTA-STS (change `id` whenever the policy changes) |
| `_smtp._tls.example.com.` | TXT | `"v=TLSRPTv1; rua=mailto:postmaster@example.com"` | TLS reporting |
| `_submissions._tcp.example.com.` | SRV | `0 1 465 mail.example.com.` | Client autoconfiguration (RFC 6186/8314) |
| `_submission._tcp.example.com.` | SRV | `0 1 587 mail.example.com.` | |

**PTR (reverse DNS):** set the PTR of `203.0.113.10` to `mail.example.com`
in your provider's panel. Forward and reverse must match (FCrDNS); many
receivers reject mail otherwise.

**Rollout advice:** start with `p=none` in DMARC and `MDMAIL_MTASTS_MODE=testing`,
check aggregate reports for a week, then move to `p=reject` and `enforce`.

Create a `postmaster@` account (RFC 5321 requires it) so DMARC/TLS reports and
abuse mail can be read.

## 3. Configure and start

```sh
git clone https://github.com/t-el/mdmail.git
cd mdmail
cp .env.example .env
chmod 600 .env
$EDITOR .env          # MDMAIL_HOSTNAME, MDMAIL_DOMAINS, MDMAIL_ACME_EMAIL, ...
docker compose up -d --build
docker compose logs -f mdmail
```

With `MDMAIL_TLS_MODE=acme` a certificate for `mail.example.com` (and
`mta-sts.<domain>` when MTA-STS is enabled) is obtained automatically from
Let's Encrypt on the first HTTPS/SMTP TLS handshake. Port 80 must be reachable
for the HTTP-01 challenge. Certificates are cached in the data volume.

To use your own certificates instead, set `MDMAIL_TLS_MODE=files`, mount the
directory read-only (see the commented volume in `docker-compose.yml`) and set
`MDMAIL_TLS_CERT_FILE` / `MDMAIL_TLS_KEY_FILE`. Renewed files are picked up
automatically within a minute. The container runs as UID 65532; the key file
must be readable by that user.

## 4. DKIM and users

```sh
docker compose exec mdmail mdmail dkim generate example.com   # prints the TXT record
docker compose exec mdmail mdmail user add postmaster@example.com --admin
docker compose exec mdmail mdmail user add alice@example.com
docker compose restart mdmail                                  # loads new DKIM keys
```

Passwords must be at least 12 characters. When stdin is not a terminal the
password is read from the first line of stdin, e.g. for automation:
`printf '%s\n' "$PW" | docker compose exec -T mdmail mdmail user add bob@example.com`.

## 5. Verify

- `https://mail.example.com/` shows the login page.
- `docker compose ps` reports the container as `healthy`.
- Send a message to a Gmail/Outlook address and inspect its headers:
  `spf=pass`, `dkim=pass`, `dmarc=pass`.
- Test with external tools: mail-tester.com, `https://www.hardenize.com/`,
  `https://internet.nl/test-mail/`, `testssl.sh mail.example.com:465`.

## 6. Mail clients (Thunderbird, Apple Mail, phones)

mdmail provides **sending** via SMTP for desktop and mobile clients. Mailbox
access is through the web client and the HTTPS API; IMAP is not provided (see
Limitations in [security.md](security.md#limitations)).

| Setting | Value |
|---|---|
| SMTP server | `mail.example.com` |
| Port / security | 465 (SSL/TLS) or 587 (STARTTLS) |
| Username | full address, e.g. `alice@example.com` |
| Password | account password, or an **app password** (required when 2FA is on) |

Create app passwords under *Settings → App passwords* in the web client.

## 7. Updating

```sh
git pull
docker compose build --pull
docker compose up -d
```

Database migrations run automatically at start-up. Take a backup first
([backup.md](backup.md)).
