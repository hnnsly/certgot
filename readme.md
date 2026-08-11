# certgot

Small Go utility for issuing and renewing wildcard certificates through ACME DNS-01.

## Happy path

```bash
certgot init --config ./config.yml --email admin@example.com \
  --domain example.com --provider cloudflare --env-file ./cloudflare.env
certgot doctor --config ./config.yml --offline
certgot setup --config ./config.yml --setup-interval 2w --yes
sudo certgot status --config /etc/certgot/config.yml
```

Use [config-example.yml](config-example.yml) for a minimal template. `init` never asks for provider secrets in terminal echo; put them in an env-file with `0600` or `0640` permissions.

## Commands

| Command | Purpose | ACME request |
| --- | --- | --- |
| `run` | Check all domains and renew those inside the renewal window | possible |
| `init` | Create one minimal config | no |
| `doctor` | Validate config, credentials, storage, account, certificates and host readiness | no order; connectivity check unless `--offline` |
| `status` | Inspect existing certificate state | no |
| `renew` | Renew one domain or all domains | possible |
| `setup` | Install managed systemd service and timer | no |
| `version` | Print build metadata | no |

Legacy calls remain valid: no subcommand means `run`, `--setup` means `setup`, and `--version` means `version`.

Common flags: `--config`, `--output text|json`, `--color auto|always|never`, `--quiet`, `--verbose`, `--log-format text|json`.

Examples:

```bash
certgot doctor --config ./config.yml --output json --offline
certgot status --config ./config.yml --domain example.com --output json
certgot renew --config ./config.yml --domain example.com --dry-run
certgot renew --config ./config.yml --domain example.com --force --staging
certgot renew --config ./config.yml --all --dry-run
certgot version --short
```

`renew --dry-run` reads config and existing state only. It creates no account, order, directory, lock, release, or ACME request. Repairable states return `would-renew` with a stable `reason`; `--force` requires explicit `--domain` or `--all`.

Staging and custom CAs are isolated from production. Staging uses `accounts/staging/` and `certs-staging/`; each `acme_directory_url` uses a URL-hashed account/certificate namespace. `--staging` and `acme_directory_url` are mutually exclusive. Non-production runs never change `certs/<domain>/current` and never execute reload hooks. JSON includes `"mode": "staging"` or `"mode": "custom"`.

## Support and install

Linux is the managed/systemd target. Darwin builds support manual runs; `setup` requires systemd and root. Published targets are Linux amd64/arm64 and Darwin amd64/arm64.

```bash
sudo install -m 0755 certgot /usr/local/bin/certgot
certgot run --config ./config.yml
certgot setup --config ./config.yml --setup-interval 2w --yes
```

Setup creates the `certgot` system user/group, `/var/lib/certgot`, `/etc/certgot/config.yml`, secret env-files, and systemd service/timer. It requests sudo itself and preserves only referenced Telegram environment variables. Existing config and unit files receive `.bak` backups.

After setup, inspect managed state with `sudo certgot status --config /etc/certgot/config.yml`. The source `./config.yml` keeps its original `storage_path` and may describe a different local state directory.

For automation, `--non-interactive` never reads stdin and never invokes sudo itself. It requires both root and `--setup-interval`:

```yaml
- name: Setup CertGOt
  ansible.builtin.command:
    argv:
      - certgot
      - setup
      - --config
      - /etc/certgot/source.yml
      - --setup-interval
      - 2w
      - --non-interactive
      - --yes
  become: true
```

Provider `env_file` and legacy inline `env` values are parsed and copied to `/etc/certgot/secrets/<index>-<domain>.env` as `root:certgot 0640`; installed YAML contains only the managed path. The source config and source env-file are unchanged. Telegram references remain references in YAML, while the resolved URL is stored in `/etc/certgot/secrets/telegram.env` and loaded by systemd. Plain legacy Telegram URLs are migrated to that environment file too.

## Configuration

- `email`: ACME account contact.
- `telegram_url`: legacy optional Telegram URL. `${TELEGRAM_URL}` references a process variable.
- `notifications.telegram_url`: preferred notification URL. `notifications.on` supports `always`, `renewed`, and `error`; an empty list disables reports.
- `storage_path`: state root containing `accounts/`, `certs/`, and `.certgot.lock`.
- `renew_before`: Go duration, default `720h` (30 days).
- `acme_directory_url`: optional HTTP(S) ACME directory for local/test CAs; production Let's Encrypt is the default.
- `certificates[].domain`: base DNS name only. Input is lowercased and one trailing dot is removed. Wildcard is added automatically.
- `certificates[].provider`: lego DNS provider name.
- `certificates[].env`: legacy inline provider environment. Prefer `env_file`.
- `certificates[].env_file`: plain `KEY=value` file. Relative paths resolve beside the config.
- `certificates[].permissions`: octal permissions for certificate/key files.
- `certificates[].group`: consumer group owning certificate/key files. Setup validates every group and adds the runtime user through `SupplementaryGroups=`.
- `certificates[].reload_units`: manual-mode `.service` reload targets. Managed setup rejects this field because the hardened `certgot` user is intentionally not granted system-service control.

Provider variables are documented in the [lego DNS docs](https://go-acme.github.io/lego/dns/).

## Output contracts

Text output is for operators. JSON is written only to stdout; logs go to stderr. `status --output json` returns:

```json
{
  "operation": "status",
  "results": [{
    "domain": "example.com",
    "status": "valid",
    "expiry": "2026-08-11T12:00:00Z",
    "days_left": 60,
    "provider": "cloudflare",
    "release_path": "/var/lib/certgot/certs/example.com/releases/release-1"
  }]
}
```

Status values: `valid`, `renewal`, `missing`, `malformed`, `wrong-domain`, `key-mismatch`, `not-yet-valid`, `error`. Machine enum values never contain spaces.

Dry-run records use `would-renew`, `forced`, `skipped`, or `failed`. `would-renew` includes `reason`, for example `missing`, `malformed`, `wrong-domain`, `key-mismatch`, `not-yet-valid`, or `renewal`.

Exit code `0` means success. Exit code `1` means invalid CLI/config, lock, account, certificate, ACME, save, reload, or notification failure. `status` returns `1` for anything other than all `valid`; doctor warnings do not fail, doctor errors do.

## State, renewal and recovery

Account state lives in `accounts/account.key` and `accounts/account.registration.json`. A corrupt account key stops the run; it is never silently replaced.

Certificates live under `certs/<domain>/releases/`. `current` is an atomic symlink to one complete certificate/key pair. New installations also get compatibility links `fullchain.pem` and `privkey.pem`.

The app uses a storage lock. It checks SANs, validity dates, renewal window, and private-key matching before treating a pair as valid. `run` processes all configured domains before returning failure.

Back up both the config and state together—the account key and registration must
remain paired:

```bash
sudo tar czf certgot-backup.tgz /etc/certgot /var/lib/certgot
```

To restore, stop `certgot.timer`, restore both paths with their original modes,
run `certgot doctor --config /etc/certgot/config.yml`, then re-enable the timer.
Legacy flat `fullchain.pem`/`privkey.pem` files remain readable; the next
successful renewal adds a `current` release symlink without replacing existing
regular files mid-run.

In manual mode, after successful publication every configured `reload_units`
entry is passed directly to `systemctl reload`; arbitrary shell hooks are never
accepted. Failed units remain in `.reload-pending.json` under the domain state
and are retried on the next run even when the certificate is still valid.
Managed setup rejects `reload_units`; use an independently reviewed root-owned
systemd path/service if automatic managed reload is required.

## Security

Managed runtime uses `User=certgot`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and writes only `/var/lib/certgot`. Provider `exec` is not recommended in managed mode because it executes configured commands.

Keep config and env-files private. Managed config is `root:certgot`; secret env-files are readable only by root and the runtime group. Do not commit credentials. If a token was exposed, rotate it.

## Logging and troubleshooting

```bash
certgot run --log-format text
certgot run --log-format json --verbose
systemctl status certgot.timer certgot.service
journalctl -u certgot.service -n 100 --no-pager
systemd-analyze verify /etc/systemd/system/certgot.service /etc/systemd/system/certgot.timer
```

Structured log fields include `operation`, `domain`, `provider`, `result`, `duration_ms`, and `error`. Secrets are not logged. Check provider credentials, DNS propagation, ACME rate limits, lock ownership, permissions, and Telegram configuration when doctor/status reports an error.

## Development

Go 1.24+ is required. Linux contributors additionally need `systemd-analyze`
for full unit verification. The local Pebble ACME integration test downloads and
builds its pinned test server automatically; Docker is optional.

```bash
just check
just build
just integration
```

`just check` runs formatting, unit tests, race/coverage tests, vet and a local
systemd check when available. Run `just tidy-check` before committing module
changes. The Pebble scenario uses only a local ACME server and fake DNS-01
provider; it never contacts a production ACME directory. A simple pre-commit
workflow is `just check && git diff --check`—no hidden tooling is required.

## Remove

Back up certificates and account state first. Then stop the timer and remove units; remove the user/group and `/var/lib/certgot` only after confirming no consumer still needs them:

```bash
sudo systemctl disable --now certgot.timer
sudo rm -f /etc/systemd/system/certgot.service /etc/systemd/system/certgot.timer
sudo systemctl daemon-reload
```

Only after independently confirming that no service needs the state:

```bash
sudo rm -rf /var/lib/certgot /etc/certgot
sudo userdel certgot
sudo groupdel certgot
```
