# Command-line administration

The `mdmail` binary contains the server and all administration commands. In
Docker, run them with `docker compose exec mdmail mdmail <command>`. They
operate directly on the database in `MDMAIL_DATA_DIR` and are safe to run
while the server is up.

| Command | Description |
|---|---|
| `mdmail serve` | Run the server. |
| `mdmail healthcheck` | Exit 0 if `/healthz` on `MDMAIL_HEALTH_ADDR` is OK (used by the Docker health check). |
| `mdmail user add <email> [--admin]` | Create a user. The domain must be in `MDMAIL_DOMAINS`. Password from the terminal (asked twice) or the first line of stdin. |
| `mdmail user passwd <email>` | Set a new password, clear lockout and revoke all sessions. |
| `mdmail user list` | List users with admin/disabled/2FA/lockout state. |
| `mdmail user disable <email>` | Block login and inbound delivery; revokes sessions. |
| `mdmail user enable <email>` | Re-enable. |
| `mdmail user unlock <email>` | Clear a failed-login lockout. |
| `mdmail user reset-2fa <email>` | Remove TOTP (lost device). Verify the user's identity out of band first. |
| `mdmail user delete <email>` | Delete the user **and all their mail**. Irreversible. |
| `mdmail dkim generate <domain>` | Create a 2048-bit RSA DKIM key (`0600`) and print the TXT record. Refuses to overwrite. Restart the server afterwards. |
| `mdmail dkim show <domain>` | Print the TXT record for an existing key. |
| `mdmail dns <domain>` | Print every recommended DNS record (set `MDMAIL_HOSTNAME`). |
| `mdmail queue` | Show the outbound queue (recipient, attempts, next attempt, last error). |
| `mdmail backup <file>` | Consistent online database backup (see [backup.md](backup.md)). |
| `mdmail version` | Print the version. |

## DKIM key rotation

1. `MDMAIL_DKIM_SELECTOR=mdmail2026b mdmail dkim generate example.com` into a
   new key directory (`MDMAIL_DKIM_KEY_DIR=/data/dkim-new`), publish the new
   `mdmail2026b._domainkey` record and wait for DNS propagation.
2. Switch `MDMAIL_DKIM_SELECTOR` and `MDMAIL_DKIM_KEY_DIR` in `.env`,
   `docker compose up -d`.
3. Remove the old DNS record after a week.
