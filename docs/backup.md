# Backup and restore

All state lives in the data volume (`/data` in the container):

| Path | Content | Sensitivity |
|---|---|---|
| `mdmail.db` (+ `-wal`, `-shm`) | Users, password hashes, sessions, all mail, queue, audit log | **High** |
| `secret.key` | Key encrypting TOTP secrets | **High** — without it, 2FA must be reset for every user |
| `dkim/<domain>.pem` | DKIM private keys | **High** |
| `acme/` | Let's Encrypt account and certificates (re-obtainable) | Medium |

## Online backup (no downtime)

`mdmail backup` uses SQLite `VACUUM INTO`, producing a consistent, compacted
copy while the server keeps running:

```sh
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec mdmail mdmail backup /data/backup-$STAMP.db

# Copy database + keys out of the volume
docker compose cp mdmail:/data/backup-$STAMP.db ./backup-$STAMP.db
docker compose cp mdmail:/data/secret.key ./secret.key
docker compose cp mdmail:/data/dkim ./dkim

# Remove the temporary copy from the volume
docker run --rm -v mdmail_mdmail-data:/data alpine rm /data/backup-$STAMP.db
```

**Encrypt before storing off-site**, e.g. with [age](https://age-encryption.org):

```sh
tar -czf - backup-$STAMP.db secret.key dkim | age -r <your-age-public-key> > mdmail-$STAMP.tar.gz.age
shred -u backup-$STAMP.db secret.key && rm -rf dkim
```

Automate with a cron job or systemd timer on the host and keep several
generations (e.g. 7 daily, 4 weekly, 6 monthly). Test restores regularly.

## Restore

```sh
docker compose down
age -d -i key.txt mdmail-STAMP.tar.gz.age | tar -xzf -

# Write the files into the volume with the right owner and modes
docker run --rm -v mdmail_mdmail-data:/data -v "$PWD":/restore alpine sh -c '
  rm -f /data/mdmail.db /data/mdmail.db-wal /data/mdmail.db-shm &&
  cp /restore/backup-STAMP.db /data/mdmail.db &&
  cp /restore/secret.key /data/secret.key &&
  mkdir -p /data/dkim && cp /restore/dkim/*.pem /data/dkim/ &&
  chown -R 65532:65532 /data && chmod 700 /data /data/dkim &&
  chmod 600 /data/mdmail.db /data/secret.key /data/dkim/*.pem'

docker compose up -d
```

Sessions in the backup remain valid until they expire. To force everyone to
sign in again after a restore, run
`docker compose exec mdmail mdmail user passwd <email>` for affected users or
restore and then revoke sessions from *Settings*.

## Migrating to a new server

1. Lower the TTL of the MX/A records a day before.
2. Back up the old server, restore on the new one, start it.
3. Update A/AAAA/PTR records. Mail arriving at the old server in the meantime
   stays in its database; export it with a final backup if needed.

## Upgrades

Back up first. Schema migrations are embedded and applied automatically at
start-up inside a transaction; a failed migration leaves the database
unchanged and the server refuses to start.
