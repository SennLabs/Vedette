# Configuration

vedette reads two TOML files and the environment. Both files are meant to be committed
and neither holds a secret.

| File | Holds |
|---|---|
| `config/vedette.toml` | Daemon settings, source URLs, retry policy, notification channels |
| `config/watches.toml` | The watch list. See [Writing watches](watches.md) |

Settings are resolved in this order, later entries overriding earlier ones:

1. Built-in defaults (every value in the tables below).
2. `vedette.toml`, found via `--config`, `VEDETTE_CONFIG`, or `./config/vedette.toml`.
3. Environment variables prefixed `VEDETTE_`, with `__` between levels:
   `VEDETTE_NVD__POLL_INTERVAL=15m` sets `nvd.poll_interval`.
4. Command-line flags: `--watch-file`, `--database`, `--log`.

Relative paths resolve against the working directory. In the container that is `/app`;
under `cargo run` it is the repository root. The shipped config uses relative paths so
the same file works in both.

Durations are written as `30s`, `15m`, `6h`, `90d`.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `database_path` | `data/vedette.db` | SQLite file. Its directory is created if missing |
| `watch_file` | `config/watches.toml` | The watch list |
| `stale_after` | `6h` | `healthcheck` fails when either source has not synced successfully within this long |

## `[nvd]`

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `https://services.nvd.nist.gov/rest/json` | NVD API 2.0 root |
| `api_key` | unset | Secret. Usually left unset in favour of `NVD_API_KEY` |
| `api_key_file` | unset | Path to a file holding the key |
| `poll_interval` | `30m` | How often the daemon syncs |
| `backfill_from` | `90d` | How far back the first sync reaches, as a lookback (`90d`) or a date (`2025-01-01`) |
| `rate_limit` | `45` | Requests per `rate_window`. NVD allows 50 per 30 s with a key |
| `rate_window` | `30s` | |
| `page_size` | `500` | CVEs per request, 1 to 2000. Smaller pages retry cheaply when NVD stalls |
| `read_timeout` | `90s` | Idle time between reads before a request is abandoned and retried |
| `overlap` | `10m` | Each sync re-fetches this far behind its watermark, absorbing NVD's eventual consistency |

**The API key** is read from `NVD_API_KEY` if set, otherwise from whichever one of
`nvd.api_key` and `nvd.api_key_file` is set (both is an error). Without one the client
clamps itself to NVD's public limit of 5 requests per 30 s and logs a warning at startup.
Syncing then takes roughly ten times longer.

**The first sync** covers `backfill_from` and is a baseline. When it reaches the present,
every stored CVE is matched and its events are written to the outbox as `suppressed`:
never delivered, but recorded, so a later re-evaluation cannot announce the same history
as new. Alerts begin with the next sync. A baseline interrupted partway resumes from its
last completed window and is still a baseline. The first KEV fetch is treated the same
way. To pull older history later, run `vedette backfill --from <lookback|date>`, which
records matches the same quiet way and never alerts.

NVD caps a `lastModified` query at 120 days, so longer spans are walked in 110-day
windows, each committed before the next starts. If a `backfill` is interrupted, the
daemon's next sync continues from the last completed window; re-running `backfill`
starts again from `--from`. A backfill never moves the live watermark backwards.

## `[kev]`

| Key | Default | Meaning |
|---|---|---|
| `url` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | The catalog |
| `poll_interval` | `1h` | |

The fetch is conditional: an unchanged catalog costs one small 304 response. If
`www.cisa.gov` is unreachable from your network, CISA publishes the same file on GitHub,
lagging by up to a few days:

```
VEDETTE_KEV__URL=https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
```

A CVE that appears in KEV before NVD has published it is stored as a placeholder, so a
KEV addition is matched and alerted immediately rather than waiting for NVD. The first
fetch on a new database is a baseline: every catalog entry back to 2021 is "new" then,
and matches are recorded without alerting.

## `[notify]`

| Key | Default | Meaning |
|---|---|---|
| `max_attempts` | `6` | Delivery attempts before a notification is marked `failed` |
| `retry_base` | `30s` | First retry delay; doubles each attempt, capped at one hour |
| `max_batch` | `50` | Alerts per digest. A larger batch is split into several messages |
| `dry_run` | `false` | Log every delivery instead of sending it, on every channel, in the daemon and in `notify drain` |

Retries are only for retryable failures: a connection error, a 5xx, a 429, an SMTP 4xx.
A rejected credential or a 4xx is permanent and the row is marked `failed` at once, so a
misconfigured endpoint is not hammered for hours. `vedette notify status` shows failed
rows and `vedette notify requeue` returns them to the queue once the cause is fixed.

## Channels

Each `[[channel]]` table is one destination. A watch notifies every enabled channel unless
it lists `channels` explicitly. Channel names must be unique.

Fields common to every kind:

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Referenced from `watches.toml` and shown in `notify status` |
| `kind` | required | `smtp`, `webhook`, `ntfy`, `gotify`, `telegram` or `file` |
| `enabled` | `true` | A disabled channel receives nothing, is not built at startup, and is skipped even when a watch names it |
| `batch_window` | `15m` | Alerts are held this long so one poll cycle produces one digest |
| `urgent_immediate` | `true` | KEV additions, exploit references and CRITICAL findings skip the window |

Test any channel end to end with `vedette notify test --channel <name>`.

### `smtp`

A multipart HTML and plain-text digest, one email per batch.

| Key | Default | Meaning |
|---|---|---|
| `host` | required | |
| `port` | `587` | |
| `tls` | `starttls` | `starttls` (587: upgrade, refuses to continue without it), `implicit` (465), or `none` (plaintext; local sinks only) |
| `username` | unset | Set both `username` and a password, or neither |
| `password` / `password_file` | unset | Secret |
| `from` | required | `Name <addr>` or a bare address |
| `to` | required | List of recipients |

### `webhook`

One JSON `POST` per batch:

```json
{
  "source": "vedette",
  "version": "0.1.0",
  "count": 1,
  "alerts": [ { ...see "Alert payload" below... } ]
}
```

| Key | Default | Meaning |
|---|---|---|
| `url` | required | |
| `headers` | `{}` | Extra request headers, as a `[channel.headers]` table |
| `hmac_secret` / `hmac_secret_file` | unset | Secret. When set, the body is signed and sent as `X-Vedette-Signature: sha256=<hex>` |

The signature is HMAC-SHA256 over the exact bytes of the body. A receiver verifies it by
recomputing over the raw request body before parsing.

### `ntfy`

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `https://ntfy.sh` | Self-hosted servers work |
| `topic` | required | Treat a public-server topic as a password: anyone who guesses it can read your alerts |
| `token` / `token_file` | unset | Secret, sent as a bearer token |

A KEV addition is sent at ntfy's `urgent` priority, which bypasses a phone's quiet hours;
other urgent alerts at `high`; the rest at `default`.

### `gotify`

| Key | Default | Meaning |
|---|---|---|
| `base_url` | required | |
| `token` / `token_file` | required | Secret. An application token |

### `telegram`

| Key | Default | Meaning |
|---|---|---|
| `token` / `token_file` | required | Secret. The bot token |
| `chat_id` | required | A user, group or channel id |
| `api_base` | `https://api.telegram.org` | |

Long digests are split across several messages to stay under Telegram's size limit.

### `file`

Appends every batch to a local file. A development channel: nothing reads the file, so an
alert written here is an alert nobody sees. Useful with `tail -f` while tuning watches.

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Relative to the working directory |
| `format` | `text` | `text` (the plain-text digest under a timestamp) or `jsonl` (one line per alert: `{"ts": ..., "channel": ..., "alert": {...}}`) |

## Secrets

Every field marked *Secret* accepts three spellings:

```toml
password = "${SMTP_PASSWORD}"             # ${VAR} segments interpolated from the environment
password = { env = "SMTP_PASSWORD" }       # one environment variable
password = { file = "/run/secrets/smtp" }  # a file; trailing newline stripped
```

Fields also have a `<field>_file` twin that takes a path directly. Setting both the
field and its `_file` twin is an error, not a precedence rule.

Secrets resolve once at startup. A missing variable fails the process immediately with
the name of the variable, rather than failing at the first alert. Resolved values are held
in a type that cannot be printed, so they do not reach the log.

With Docker Compose, the `.env` file supplies the variables; with Docker or Kubernetes
secrets, mount the secret file and use the `file` form.

## Environment variables

Besides `VEDETTE_*` overrides of any setting:

| Variable | Meaning |
|---|---|
| `NVD_API_KEY` | The NVD API key. Takes precedence over the config |
| `VEDETTE_CONFIG` | Path to `vedette.toml` |
| `VEDETTE_WATCH_FILE` | Overrides `watch_file` |
| `VEDETTE_DATABASE_PATH` | Overrides `database_path` |
| `VEDETTE_LOG` | `trace`, `debug`, `info`, `warn` or `error`. Default `info` |
| `RUST_LOG` | A full tracing filter; when set it replaces `VEDETTE_LOG` |
| `VEDETTE_VERSION` | Compose only: the image tag to run |
| `HTTPS_PROXY`, `NO_PROXY` | Honoured for every outbound request |
| `SQLITE_TMPDIR` | Where SQLite writes temporary files; the compose file points it at the data volume |

Timestamps in logs and alerts are UTC. The container has no timezone database.

Note that the top level of `vedette.toml` tolerates unknown keys, because the same
environment prefix carries `VEDETTE_CONFIG` and `VEDETTE_LOG`. A misspelt
`database_path`, `watch_file` or `stale_after` is silently ignored. Every nested table
and every channel rejects unknown keys.

## Alert payload

The webhook body carries this object once per alert under `alerts`; the `jsonl` file
format carries it under `alert`. It is frozen when the alert is queued, so a later NVD
change cannot rewrite an alert already waiting.

| Field | Type | Meaning |
|---|---|---|
| `watch` | string | The watch name |
| `cve_id` | string | |
| `event.kind` | string | `new`, `kev_added`, `exploit_ref`, `score_increase` or `severity_threshold` |
| `event.detail` | string | Human-readable reason, as shown in the digest |
| `event.fingerprint` | string | Stable per (CVE, event); the same escalation is never sent twice |
| `confidence` | string | `high` or `review` |
| `match_kind` | string | `cpe`, `kev` or `keyword` |
| `evidence` | string | The CPE criteria, KEV product or keyword that matched |
| `severity` | string or null | NVD's `baseSeverity` |
| `score` | number or null | Always null in this version; the CVSS score is in `event.detail` |
| `description` | string or null | The CVE description |
| `in_kev` | bool | |
| `kev_due_date` | string or null | CISA's remediation due date |
| `kev_ransomware` | bool | CISA marks it as used in ransomware campaigns |
| `urgent` | bool | Skipped the batch window |
| `url` | string | The NVD detail page |
