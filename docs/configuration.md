# Configuration reference

mdmail is configured exclusively through environment variables (never
command-line flags, which are visible to other local users). Each variable can
alternatively be supplied as `<NAME>_FILE=/path/to/file`; the file's content
(trimmed) is used. This works with Docker/Compose secrets.

Invalid values stop the server at start-up with a list of every problem.

## Identity

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_HOSTNAME` | — (required) | FQDN of the server: EHLO name, MX target, web host, `Authentication-Results` authserv-id. Requests for any other `Host` are refused (421). |
| `MDMAIL_DOMAINS` | — (required) | Comma-separated list of hosted mail domains. Only these domains are accepted as recipients on port 25. |
| `MDMAIL_DATA_DIR` | `/data` | Database, secret key, DKIM keys and ACME cache. Mode 0700. A relative path is resolved against the working directory at start; prefer an absolute path so the server and the admin CLI use the same database. |

## TLS

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_TLS_MODE` | `acme` | `acme` (Let's Encrypt, HTTP-01 on `MDMAIL_HTTP_ADDR`) or `files`. |
| `MDMAIL_ACME_EMAIL` | empty | Contact address for the ACME account (expiry notices). |
| `MDMAIL_ACME_DIRECTORY` | Let's Encrypt production | Alternative ACME directory URL, e.g. LE staging. |
| `MDMAIL_TLS_CERT_FILE` | — | PEM certificate chain (files mode). Reloaded on change. |
| `MDMAIL_TLS_KEY_FILE` | — | PEM private key (files mode). |

All listeners use TLS 1.2+ with forward-secret AEAD cipher suites only
(TLS 1.3 preferred, hybrid post-quantum key exchange X25519MLKEM768 offered).

## Listeners

Defaults below are for the bare binary; the Docker image overrides them with
unprivileged ports (shown in brackets) that compose maps to the standard ones.
Set any address to an empty string to disable that listener.

| Variable | Default [image] | Service |
|---|---|---|
| `MDMAIL_SMTP_ADDR` | `:25` [`:2525`] | Inbound MX, STARTTLS offered, no AUTH |
| `MDMAIL_SUBMISSION_ADDR` | `:587` [`:5870`] | Submission, STARTTLS, AUTH required |
| `MDMAIL_SUBMISSIONS_ADDR` | `:465` [`:4650`] | Submission, implicit TLS, AUTH required |
| `MDMAIL_HTTPS_ADDR` | `:443` [`:8443`] | Web client, API, MTA-STS policy |
| `MDMAIL_HTTP_ADDR` | `:80` [`:8080`] | ACME challenges and redirect to HTTPS. Required in `acme` mode. |
| `MDMAIL_HEALTH_ADDR` | `127.0.0.1:9090` | Plain-HTTP `/healthz`, **must be loopback**. Used by `mdmail healthcheck`. |

## Limits and policy

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_MAX_MESSAGE_BYTES` | `26214400` (25 MiB) | Maximum message size (SMTP `SIZE`, web uploads). Range 64 KiB–100 MiB. |
| `MDMAIL_MAX_RECIPIENTS` | `50` | Maximum recipients per message. |
| `MDMAIL_SUBMIT_PER_HOUR` | `200` | Per-user recipients per hour (token bucket) for SMTP and web sending. |
| `MDMAIL_INBOUND_REQUIRE_TLS` | `false` | Refuse inbound mail on port 25 without STARTTLS. Breaks delivery from the minority of servers without TLS. |
| `MDMAIL_DMARC_ENFORCE` | `true` | Reject (550) inbound mail failing DMARC with `p=reject`. When `false` such mail goes to Junk. `p=quarantine` always goes to Junk. |
| `MDMAIL_OUTBOUND_TLS` | `encrypt` | `verify`: require STARTTLS with a valid certificate for the MX name. `encrypt`: require STARTTLS, accept any certificate (protects against passive eavesdropping; most MX certificates do not match their names). `opportunistic`: use STARTTLS when offered, otherwise plaintext. |
| `MDMAIL_CHECKLIST_SHARING` | `true` | Let a sender who is a user of this server see the checklist progress of recipients who are also users of this server. Never affects external recipients and never sends anything off the server. See [security.md](security.md#checklists-and-privacy). |
| `MDMAIL_ALLOW_PRIVATE_MX` | `false` | Allow delivery to MX hosts resolving to private/loopback/link-local addresses. Keep `false` in production (SSRF protection). |

## DKIM

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_DKIM_SELECTOR` | `mdmail` | Selector used in signatures and DNS (`<selector>._domainkey.<domain>`). |
| `MDMAIL_DKIM_KEY_DIR` | `$MDMAIL_DATA_DIR/dkim` | Directory holding `<domain>.pem` private keys (PKCS#8 or PKCS#1). |

Signatures use RSA-SHA256, relaxed/relaxed canonicalisation and oversign
`From` and `Subject`.

## MTA-STS

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_MTASTS_MODE` | `none` | `none`, `testing` or `enforce`. When not `none`, `https://mta-sts.<domain>/.well-known/mta-sts.txt` is served for every hosted domain and included in the ACME certificate. |
| `MDMAIL_MTASTS_MAX_AGE` | `168h` | `max_age` of the policy. |

## Sessions and secrets

| Variable | Default | Description |
|---|---|---|
| `MDMAIL_SESSION_TTL` | `12h` | Absolute session lifetime. |
| `MDMAIL_SESSION_IDLE` | `30m` | Idle timeout. Must not exceed the TTL. |
| `MDMAIL_SECRET_KEY_FILE` | `$MDMAIL_DATA_DIR/secret.key` | Base64 32-byte key used to encrypt TOTP secrets (AES-256-GCM). Generated with mode 0600 on first start if missing. For stronger separation, provide it as a Docker secret outside the data volume. |
| `MDMAIL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. Logs are JSON on stdout. |
