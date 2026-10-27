# Changelog

## 0.1.0

Initial development release; not yet 1.0, so the config format and CLI may still change.

### Added
- The tool is named `vedette` (a mounted sentry posted to watch and raise the alarm).
  The binary, image (`ghcr.io/sennlabs/vedette`), config files (`config/vedette.toml`),
  database (`data/vedette.db`), environment prefix (`VEDETTE_`) and webhook signature
  header (`X-Vedette-Signature`) all carry it.
- NVD CVE API 2.0 and CISA KEV catalog ingestion into a local SQLite store, with
  resumable chunked backfill (NVD caps `lastModified` windows at 120 days) and
  conditional KEV refetch (ETag + Last-Modified; CISA honours only the latter).
- Hybrid watch matching: CPE vendor/product (version-aware, confidence `high`), KEV
  catalog text (`high`), and keyword/regex (`review`) — keywords exist because only
  ~36% of CVEs carry CPE data in their first days.
- Escalation detection (new match, KEV addition, CVSS increase, severity threshold
  crossed, exploit reference published); a bare `lastModified` bump is silent.
- Durable outbox: matches and notifications commit together, a separate dispatcher
  drains with per-channel batching and retryable/permanent failure classification.
  Delivery is at-least-once and idempotent under re-run.
- Notification channels: SMTP (HTML+text digest), generic webhook (optional
  HMAC-SHA256 signature), ntfy, Gotify, Telegram, and a development `file` channel
  that appends each batch to a local file as the plain-text digest or as JSON lines.
- `nvd.backfill_from` defaults to `90d` and accepts a lookback as well as a date;
  `backfill --from` and `sync --since` take the same forms. A fixed date made every new
  install's first sync larger (2024-01-01 had grown to ~333k CVEs; 90 days is ~87k).
- The first NVD sync and the first KEV fetch on a fresh database are a baseline: every
  stored CVE is matched and its events are written to the outbox as `suppressed`, so a
  new install does not email its whole history and a later re-evaluation cannot announce
  that history as new. Alerts start with the next sync. An interrupted baseline resumes
  from its last completed window. `backfill` records its matches the same quiet way and
  no longer takes `--no-notify` (it never alerted). Migration 002 marks databases that
  pre-date the baseline as complete.
- `vedette db backup <path>` takes a consistent copy of the database through SQLite's
  online backup API while the daemon runs.
- The daemon stops promptly on SIGTERM even mid-sync, by abandoning the current cycle;
  every completed NVD window is already committed. A watch file that fails to parse is
  logged and the last good watch list stays in use, instead of failing every cycle.
- A watch edit noticed on a poll cycle now triggers the same corpus re-evaluation as a
  `SIGHUP`; previously the cycle recorded the new definition and the re-evaluation never
  ran. `vedette match --dry-run` writes nothing at all. `notify drain` honours
  `notify.dry_run`. A watch naming a disabled channel skips it rather than queueing for
  it. A watch with only `none` keywords is rejected by `watch validate`. A lookback past
  jiff's span bounds or of zero length is an error rather than a panic or an empty
  baseline.
- `cpe` selectors in `watches.toml` take a `"vendor:product"` shorthand, or
  `{ cpe = "vendor:product", versions = "..." }` when a version bound is needed; the
  `[[watch.cpe]]` table form also parses. `watch suggest` prints a ready-to-paste
  `cpe = [...]` list.
- CLI: `run`, `sync`, `backfill`, `match`, `watch {list,validate,test,suggest}`,
  `query`, `notify {test,drain,status,requeue}`, `healthcheck`, `db {stats,vacuum}`.
- Docker image: multi-stage build onto a distroless runtime (no shell, no system
  OpenSSL or SQLite), run as non-root with a `HEALTHCHECK`. Published to
  `ghcr.io/sennlabs/vedette` by the release workflow on every `v*` tag.
- `docker-compose.yml` is the production deployment (pulls the release image, read-only
  root filesystem, all capabilities dropped, process limit). `docker-compose.dev.yml`
  layers a from-source build plus Mailpit and ntfy sinks on top of it for local
  end-to-end testing, under its own project name. The health check allows a four-hour
  start period so the first sync is never mistaken for a broken container.
- Documentation under `docs/`: getting started, writing watches, configuration
  reference, operations, development.

### Known gaps
- The compose stacks have been validated with `docker compose config` and the image
  built in CI, but a full end-to-end run against a live inbox is still outstanding.
- Exercised only against NVD's public (keyless) rate limit; the keyed 50/30s path is
  unit-tested but not run against the live API with a real key.
- `config/watches.toml` ships an illustrative example (nginx/wordpress) demonstrating
  every matching mechanism — it is not a recommended or default watch list.
