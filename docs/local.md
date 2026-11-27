# Run mdmail locally (no Docker)

This guide runs a complete mdmail server on your own computer, for trying it
out or developing against it. Mail stays on your machine: two local users can
write to each other, but nothing is delivered to the internet and no DNS is
needed. For a real server, follow [deployment.md](deployment.md).

The local setup uses:

| | |
|---|---|
| Web client | `https://mail.mdmail.localhost:8443` (self-signed certificate) |
| Mail domain | `mdmail.localhost` (users like `alice@mdmail.localhost`) |
| SMTP inbound | port 2525 |
| Submission | 5870 (STARTTLS) and 4650 (implicit TLS), login required |
| HTTP | 8080 (redirects to HTTPS) |
| Data | `./local/data` (database, secret key) |

All ports are above 1024, so nothing needs root or administrator rights.

## 1. Prerequisites

- **Go 1.27.4 or newer** (`go version`). With an older Go, the toolchain line
  in `go.mod` downloads 1.27.4 automatically (`GOTOOLCHAIN=auto`, the default).
- **OpenSSL** for the certificate. It ships with macOS, most Linux
  distributions and Git for Windows (`C:\Program Files\Git\usr\bin\openssl.exe`).
- **git**, and optionally **curl** (built into macOS, Linux and Windows 10+)
  to test from the command line.

## 2. Build

```sh
git clone https://github.com/t-el/mdmail.git && cd mdmail
go build -trimpath -o mdmail ./cmd/mdmail        # Windows: -o mdmail.exe
./mdmail version
```

Run every following command from this `mdmail` directory unless noted.

## 3. Create a self-signed certificate

```sh
mkdir -p local
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout local/key.pem -out local/cert.pem \
  -subj "/CN=mail.mdmail.localhost" \
  -addext "subjectAltName=DNS:mail.mdmail.localhost"
```

## 4. Write one environment file

Both the server and the admin commands must read **the same** settings, or
`mdmail user add` will look at a different database than the server. Write
them once to `local.env`. The `$PWD` below is expanded **when the file is
written**, so the file contains absolute paths and works from any directory.

macOS, Linux and WSL:

```sh
cat > local.env <<EOF
MDMAIL_HOSTNAME="mail.mdmail.localhost"
MDMAIL_DOMAINS="mdmail.localhost"
MDMAIL_TLS_MODE="files"
MDMAIL_TLS_CERT_FILE="$PWD/local/cert.pem"
MDMAIL_TLS_KEY_FILE="$PWD/local/key.pem"
MDMAIL_DATA_DIR="$PWD/local/data"
MDMAIL_SMTP_ADDR=":2525"
MDMAIL_SUBMISSION_ADDR=":5870"
MDMAIL_SUBMISSIONS_ADDR=":4650"
MDMAIL_HTTPS_ADDR=":8443"
MDMAIL_HTTP_ADDR=":8080"
MDMAIL_MTASTS_MODE="none"
MDMAIL_LOG_LEVEL="debug"
EOF
cat local.env      # check: every path starts with /
```

Git Bash on Windows: the same command, but replace `$PWD` with `$(pwd -W)`
so the paths are Windows paths (`C:/Users/...`) that `mdmail.exe` understands.

Windows PowerShell: see [Shell variants](#shell-variants).

`local.env`, `local/` and the `mdmail` binary are in `.gitignore`.

## 5. Start the server (terminal 1)

```sh
set -a; . ./local.env; set +a
./mdmail serve
```

`set -a` exports every variable the file sets. The first log line shows the
database in use, for example
`"database":"/home/you/mdmail/local/data/mdmail.db"`, followed by one
`"listening"` line per port. Leave it running; stop it with Ctrl+C.

## 6. Create two users (terminal 2)

Open a second terminal. Load **the same file**, using its full path if you
are in another directory:

```sh
cd /path/to/mdmail
set -a; . ./local.env; set +a
./mdmail user add alice@mdmail.localhost --admin
./mdmail user add bob@mdmail.localhost
./mdmail user list
```

Each `user add` asks for the password twice, without echoing it (at least 12
characters), and prints `created alice@mdmail.localhost (database …)`. That path
must match the one in the server's first log line. If the command says
`no mdmail database at …`, this terminal did not load the same `local.env`,
or the server has not been started yet.

## 7. Open the web client

Open **https://mail.mdmail.localhost:8443/** and sign in as alice.

- **Certificate warning:** the certificate is self-signed, so the browser warns
  once. Choose *Advanced → Proceed* (Chrome/Edge) or *Accept the Risk and
  Continue* (Firefox). In Safari, *Show Details → visit this website*. To avoid
  the warning, trust `local/cert.pem` in your OS certificate store, or use a
  locally trusted CA such as [mkcert](https://github.com/FiloSottile/mkcert).
- **Use exactly this host name.** `https://localhost:8443` or
  `https://127.0.0.1:8443` is refused ("misdirected request"), because the
  server only answers to `MDMAIL_HOSTNAME`.
- **Name not found?** Chrome, Edge, Firefox and curl resolve `*.localhost` to
  your own machine by themselves. Safari and some other programs do not. Then
  add this line to your hosts file (`/etc/hosts` on macOS/Linux,
  `C:\Windows\System32\drivers\etc\hosts` on Windows, as administrator):

  ```
  127.0.0.1 mail.mdmail.localhost
  ```

Write a message in Markdown to `bob@mdmail.localhost` and send it. Then sign
out, sign in as bob, and it is in his Inbox. A private window lets you be
signed in as both users at once.

## 8. Test SMTP submission from the command line

Mail clients and scripts send through port 5870 (STARTTLS) or 4650 (TLS),
logging in with their mdmail address and password. With 2FA on, use an app
password instead (Settings in the web client).

**curl** (works the same on macOS, Linux and Windows):

```sh
printf 'From: alice@mdmail.localhost\r\nTo: bob@mdmail.localhost\r\nSubject: Hello from curl\r\n\r\n# Hi Bob\r\n\r\nThis is **Markdown** sent over SMTP.\r\n' > mail.txt

curl --url smtp://mail.mdmail.localhost:5870 --ssl-reqd -k \
     --user 'alice@mdmail.localhost:YOUR-PASSWORD' \
     --mail-from alice@mdmail.localhost --mail-rcpt bob@mdmail.localhost \
     --upload-file mail.txt
```

Implicit TLS on 4650: use `--url smtps://mail.mdmail.localhost:4650` instead.
`-k` accepts the self-signed certificate; use `--cacert local/cert.pem` to
verify it.

**swaks:**

```sh
swaks --server 127.0.0.1 --port 5870 --tls \
      --auth PLAIN --auth-user alice@mdmail.localhost \
      --from alice@mdmail.localhost --to bob@mdmail.localhost \
      --header 'Subject: Hello from swaks' --body 'Hi **Bob**'
```

(swaks asks for the password.)

**openssl s_client**, by hand. Create the AUTH token first:

```sh
printf '\0alice@mdmail.localhost\0YOUR-PASSWORD' | base64
openssl s_client -quiet -crlf -starttls smtp -connect 127.0.0.1:5870
```

Then type:

```
EHLO laptop
AUTH PLAIN <token from above>
MAIL FROM:<alice@mdmail.localhost>
RCPT TO:<bob@mdmail.localhost>
DATA
From: alice@mdmail.localhost
To: bob@mdmail.localhost
Subject: Hello from openssl

Hi Bob
.
QUIT
```

Expect `235 … Authentication succeeded` and `250 2.0.0 OK: queued`. The
server refuses AUTH before STARTTLS and refuses a From address other than
your own.

swaks and openssl use the system resolver, which often does not map
`*.localhost`; that is why they connect to `127.0.0.1`. That is fine for
SMTP.

## Shell variants

| Shell | Load `local.env` | Admin command |
|---|---|---|
| macOS / Linux (bash, zsh) | `set -a; . ./local.env; set +a` | `./mdmail user add …` |
| WSL 2 | Same as Linux. Run **both** terminals inside WSL; a Windows browser reaches the server through WSL's `localhost` forwarding. | `./mdmail user add …` |
| Git Bash (Windows) | `set -a; . ./local.env; set +a` (file written with `$(pwd -W)`, see step 4) | `winpty ./mdmail.exe user add …` (without `winpty` the password prompt is not hidden and is asked only once) |
| PowerShell (Windows) | see below | `.\mdmail.exe user add …` |

**PowerShell.** Write the file with Windows paths, once, from the repository
directory:

```powershell
$d = (Get-Location).Path
@"
MDMAIL_HOSTNAME="mail.mdmail.localhost"
MDMAIL_DOMAINS="mdmail.localhost"
MDMAIL_TLS_MODE="files"
MDMAIL_TLS_CERT_FILE="$d\local\cert.pem"
MDMAIL_TLS_KEY_FILE="$d\local\key.pem"
MDMAIL_DATA_DIR="$d\local\data"
MDMAIL_SMTP_ADDR=":2525"
MDMAIL_SUBMISSION_ADDR=":5870"
MDMAIL_SUBMISSIONS_ADDR=":4650"
MDMAIL_HTTPS_ADDR=":8443"
MDMAIL_HTTP_ADDR=":8080"
MDMAIL_MTASTS_MODE="none"
MDMAIL_LOG_LEVEL="debug"
"@ | Set-Content -Encoding utf8 local.env
```

Load it in **each** PowerShell window (it sets the variables for that window
only):

```powershell
Get-Content .\local.env | ForEach-Object {
  if ($_ -match '^\s*([A-Z0-9_]+)\s*=\s*"?(.*?)"?\s*$') {
    Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
  }
}
.\mdmail.exe serve          # terminal 1
.\mdmail.exe user add alice@mdmail.localhost --admin   # terminal 2
```

Native Windows gets less testing than macOS, Linux and WSL 2; WSL 2 is the
recommended way to run mdmail on Windows.

## Optional: local Docker run

`docker-compose.local.yml` is an overlay on the production compose file. It
replaces the public port mappings with loopback-only ports (the same
numbers as above) and uses the certificate from step 3. It ignores `.env`,
and its data goes in a separate `mdmail-local-data` volume. Needs Docker
Compose v2.24.4 or newer.

```sh
# Steps 1-3 first (Go is not needed for Docker). The container runs as an
# unprivileged user, which must be able to read the throwaway key:
chmod 0644 local/key.pem

docker compose -p mdmail-local -f docker-compose.yml -f docker-compose.local.yml up -d --build
docker compose -p mdmail-local -f docker-compose.yml -f docker-compose.local.yml \
  exec mdmail mdmail user add alice@mdmail.localhost --admin
docker compose -p mdmail-local -f docker-compose.yml -f docker-compose.local.yml \
  exec mdmail mdmail user add bob@mdmail.localhost
```

Then continue with steps 7 and 8. Do not run the native server at the same
time: both use the same ports. Logs:
`docker compose -p mdmail-local -f docker-compose.yml -f docker-compose.local.yml logs -f`.

## Troubleshooting

The login page shows one message for every credential problem. With
`MDMAIL_LOG_LEVEL=debug` (set above) the server log says which one; see
[troubleshooting.md](troubleshooting.md).

| Symptom | Likely cause | Fix |
|---|---|---|
| Log `reason=unknown_user`, or `user add` says `no mdmail database at …` | The second terminal loaded different settings, so it used another data directory | Load the same `local.env` (full path) in both terminals; compare the database paths |
| Log `reason=account_locked` | 5 wrong passwords lock the account for 5 minutes, then longer. A correct password is refused while locked. | `./mdmail user unlock alice@mdmail.localhost` |
| Log `reason=wrong_password` | Wrong password | `./mdmail user passwd alice@mdmail.localhost` |
| "misdirected request" or "does not match the server name" | Opened via `localhost` or an IP address | Use `https://mail.mdmail.localhost:8443/` |
| Page does not load at all | Browser does not resolve `*.localhost`, or the server is not running | Hosts-file line from step 7; check terminal 1 |
| `bind: address already in use` | Another mdmail (native or Docker) is running | Stop it |

## Clean up

```sh
# Ctrl+C in terminal 1 stops the server, then:
rm -rf local local.env mail.txt mdmail        # Windows: also mdmail.exe
# Docker run:
docker compose -p mdmail-local -f docker-compose.yml -f docker-compose.local.yml down -v
```

Remove the `mail.mdmail.localhost` line from your hosts file and any
certificate you trusted, if you added them.
