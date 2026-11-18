# credentials

A local credentials vault for development: an HTTP JSON API and an admin
interface backed by an encrypted SQLite database.

- Single static Go binary, pure-Go SQLite (`modernc.org/sqlite`): **no CGO, no
  system dependency**.
- The secret content of each credential is encrypted with **AES-256-GCM**; the
  key is derived from a passphrase with **Argon2id**.
- Listens on loopback only; meant for a single developer workstation.

```console
$ curl -s localhost:12345/credentials/1
{
  "id": 1,
  "name": "MyWebService",
  "description": "a description",
  "format": "json",
  "credentials": "{\"user\":\"bob\",\"password\":\"...\"}",
  "created_at": "2026-11-18T19:40:36+01:00",
  "updated_at": "2026-11-18T19:40:36+01:00"
}
```

## Quick start

```sh
make build
./credentials                 # prompts for the passphrase (confirmed on first run)
```

Then open the admin interface at <http://localhost:12345/admin>.

| Option | Default | |
|---|---|---|
| `-config` | none | TOML file with `addr` and `db` keys |
| `-addr` | `127.0.0.1:12345` | listen address, loopback only |
| `-db` | `$XDG_DATA_HOME/credentials/credentials.db` (`~/.local/share/...`) | database path |
| `-version` | | print the version |

Precedence: flags > config file > defaults.

The passphrase is read from, in order: the systemd credential `passphrase`
(`$CREDENTIALS_DIRECTORY/passphrase`), the `CREDENTIALS_PASSPHRASE` environment
variable, or an interactive prompt. New passphrases must be at least 12
characters long.

## API

| Method | Route | Description |
|---|---|---|
| GET | `/credentials` | list (without secrets) |
| GET | `/credentials/{id}` | full JSON, secret decrypted |
| GET | `/credentials/{id}/raw` | raw secret, `Content-Type` from its format |
| GET | `/by-name/{name}` · `/by-name/{name}/raw` | same, by name |
| POST | `/credentials` | create: `{"name","description","format","credentials"}` |
| PUT | `/credentials/{id}` | replace |
| DELETE | `/credentials/{id}` | delete |

Formats: `txt`, `json`, `yaml`, `toml`, `env`, `pem`. JSON, YAML, TOML and PEM
content is validated when saved.

```sh
curl -s localhost:12345/by-name/MyWebService/raw > config.json
curl -s -X POST localhost:12345/credentials \
  -H 'Content-Type: application/json' \
  -d '{"name":"api-token","format":"txt","credentials":"tok-123"}'
```

Limits: name ≤ 128 characters (no `/`), description ≤ 1024 characters,
content ≤ 1 MiB.

## Changing the passphrase

```sh
credentials rekey                           # default database, or -db / -config
printf '%s\n%s\n' "$OLD" "$NEW" | credentials rekey -stdin
```

Every credential is re-encrypted with a new salt in a single transaction: on
error the database is left untouched. The server must be stopped (the
database is locked while a server uses it). Old ciphertexts are wiped from the
file (`secure_delete`, WAL truncated).

## Debian package and systemd service

```sh
make deb VERSION=0.2.0                      # runs the tests, then builds dist/credentials_0.2.0_amd64.deb
sudo apt install ./dist/credentials_0.2.0_amd64.deb
```

- **Install**: creates the `credentials` system user and `/var/lib/credentials`
  (0700), asks for the passphrase (debconf), then enables and starts
  `credentials.service` at boot.
- **Upgrade**: build a higher version and `apt install` it again; the service
  restarts with the new binary, the configuration and passphrase are kept.
- **Configuration**: `/etc/credentials/config.toml` (`addr`, `db`), then
  `sudo systemctl restart credentials`.
- **Logs**: `journalctl -u credentials -f`
- **Removal**: `sudo apt remove credentials`; `apt purge` also deletes the
  configuration and the encrypted passphrase. The database in
  `/var/lib/credentials` is **never** deleted automatically.

### Service passphrase

The service must start unattended, so the passphrase has to be available on
the machine, but never in clear text. It is encrypted with `systemd-creds` in
`/etc/credentials/passphrase.cred`, using the **TPM2** chip and the host key
(`/var/lib/systemd/credential.secret`, readable by root only). At start-up,
systemd decrypts it and hands it to the service alone.

As a result, a copy of the database, the configuration and the `.cred` file
(backup, stolen disk) is useless on another machine. Keep the passphrase in
your password manager: it is what lets you restore the database elsewhere.

```sh
sudo credentials-passphrase           # set the passphrase (if skipped at install time,
                                      # after a motherboard change or a TPM reset)
sudo credentials-passphrase --change  # change it: stops the service, re-encrypts the
                                      # database, updates the .cred file, restarts
```

## Security model

- **At rest**: the `credentials` column is encrypted (AES-256-GCM, Argon2id
  key). Each ciphertext is bound to its row id (associated data), so values
  cannot be swapped between rows. Names, descriptions and formats are **not**
  encrypted. Database files are created with owner-only permissions.
- **Network**: refuses to listen on non-loopback addresses; rejects requests
  whose `Host` header is not local (DNS rebinding); rejects cross-origin
  browser writes (CSRF). Responses are sent with `Cache-Control: no-store`, a
  strict Content-Security-Policy and anti-framing headers.
- **Not covered**: there is no authentication, so any local process running on
  the machine can query the API. Losing the passphrase means losing the
  secrets.

## Development

```sh
make check        # gofmt, go vet, tests with the race detector
```

Layout:

```
cmd/credentials/   entry point: server, rekey command, passphrase input
internal/config/   flags + TOML configuration
internal/server/   HTTP API, admin interface, security middleware
internal/store/    SQLite storage, validation, rekey
internal/vault/    Argon2id + AES-256-GCM
packaging/         .deb build script, systemd unit, maintainer scripts
```

`internal/store/testdata/legacy.db` is a database created by the first version
of the program (test passphrase `legacy-passphrase`); it guards backward
compatibility of the storage format.
