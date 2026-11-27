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

## Running locally

See [local.md](local.md) for running mdmail on `localhost`: one shared
`local.env` file for the server and the admin commands, the self-signed
certificate, and browser and hosts-file notes.
