# Troubleshooting

## Web login says "invalid email, password or code"

The web client shows one message for every credential failure, so that it
cannot be used to find out which accounts exist or are locked. The server
knows the exact reason. To see it:

1. Run the server with `MDMAIL_LOG_LEVEL=debug` and retry the login. A
   `"login failed"` log line carries `reason`:

   | `reason` | Meaning | Fix |
   |---|---|---|
   | `unknown_user` | No such account **in the database this server uses**. | Compare the `"database"` path in the server's startup log with the path printed by `mdmail user add`. Run `mdmail user list` with the server's `MDMAIL_DATA_DIR`. |
   | `wrong_password` | The password does not match. | `mdmail user passwd <email>` (also clears a lockout). |
   | `account_locked` | Too many failures: 5 lock the account for 5 minutes, doubling per further failure up to 24 h. **A correct password is refused while locked.** | `mdmail user unlock <email>`, or wait. `mdmail user list` shows `LOCKED UNTIL`. |
   | `wrong_totp_code` | Wrong or reused authenticator code. | Check the device clock. `mdmail user reset-2fa <email>`. |
   | `account_disabled` | The account was disabled. | `mdmail user enable <email>`. |

   Failures are also stored in the audit log with the same reason.

2. Different messages mean different problems:
   - "request blocked by a security check …" (`origin_rejected` or
     `csrf_failed`): the page was not loaded from `https://MDMAIL_HOSTNAME`,
     or it is stale. Open the server at exactly its configured host name
     (any port), then reload. The debug log line
     `"login refused by origin check"` shows the `Origin` the browser sent.
   - "misdirected request" / "this address does not match the server name":
     the URL's host is not `MDMAIL_HOSTNAME` (for example `localhost` or an IP
     address).
   - "too many login attempts": the per-IP rate limit; wait a minute.

## Running locally (no Docker)

All values go in one file that **both** terminals source, so the server and
the admin commands always use the same absolute data directory.

```sh
git pull && go build -trimpath -o mdmail ./cmd/mdmail
mkdir -p local
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout local/key.pem -out local/cert.pem -subj "/CN=mail.mdmail.localhost" \
  -addext "subjectAltName=DNS:mail.mdmail.localhost"

cat > local/env.sh <<ENV
export MDMAIL_HOSTNAME=mail.mdmail.localhost
export MDMAIL_DOMAINS=mdmail.localhost
export MDMAIL_TLS_MODE=files
export MDMAIL_TLS_CERT_FILE=$PWD/local/cert.pem
export MDMAIL_TLS_KEY_FILE=$PWD/local/key.pem
export MDMAIL_DATA_DIR=$PWD/local/data
export MDMAIL_SMTP_ADDR=:2525 MDMAIL_SUBMISSION_ADDR=:5870 MDMAIL_SUBMISSIONS_ADDR=:4650
export MDMAIL_HTTPS_ADDR=:8443 MDMAIL_HTTP_ADDR=:8080
export MDMAIL_LOG_LEVEL=debug
ENV
```

`$PWD` is expanded **once, when the file is written**, so the file contains
absolute paths and works from any directory.

Terminal 1:

```sh
. local/env.sh && ./mdmail serve      # note the "database" path it logs
```

Terminal 2 (after the server has started once):

```sh
. /path/to/mdmail/local/env.sh
./mdmail user add taha@mdmail.localhost --admin   # prints "created … (database …)"
./mdmail user list
```

Open `https://mail.mdmail.localhost:8443/` (accept the self-signed
certificate). Chrome, Edge and Firefox resolve `*.localhost` to the loopback
address. Other browsers and tools may not: add
`127.0.0.1 mail.mdmail.localhost` to `/etc/hosts` (Windows:
`C:\Windows\System32\drivers\etc\hosts`). Do not use `https://localhost:8443`
or `https://127.0.0.1:8443`; the server answers only to `MDMAIL_HOSTNAME`.

On Windows with Git Bash, run admin commands through `winpty`
(`winpty ./mdmail user add …`) so that the password prompt is hidden and asked
twice. Under WSL 2 run both terminals inside WSL; a Windows browser reaches
the server through `localhost` forwarding.
