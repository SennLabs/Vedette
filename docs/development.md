# Development

Building, testing and changing vedette, and how a release reaches the registry.

## Prerequisites

- Rust 1.90 or newer (`rust-version` in `Cargo.toml`). `rustup` is the easiest route.
- Docker with Compose v2, for the local stack and for checking the image. Optional.

There is no system dependency: SQLite is compiled in, TLS is rustls.

## Build and test

```bash
cargo build
cargo test --locked                           # no network access needed
cargo clippy --all-targets --locked -- -D warnings
```

The test suite runs entirely against in-memory SQLite and mock HTTP servers. Tests are
named as sentences describing the behaviour they protect; read a module's tests to learn
its contract.

CI (`.github/workflows/ci.yml`) runs exactly the clippy and test commands above on every
push to `main` and every pull request. It also builds the image, starts it to prove the
binary runs on the distroless base, and validates both compose files.

## Running from source

The shipped config uses paths relative to the working directory, so run from the
repository root:

```bash
export NVD_API_KEY=...
cargo run -- watch validate
cargo run -- sync --source kev
cargo run -- run
```

The production config points its channel at a real mail relay. For local work either
use the file channel, which needs no infrastructure:

```toml
[[channel]]
name = "log"
kind = "file"
path = "data/alerts.log"
batch_window = "0s"
```

or set `VEDETTE_NOTIFY__DRY_RUN=true`, which logs every delivery instead of sending it.
Use `--database data/dev.db` to keep a scratch database apart from anything real.

## The development stack

`docker-compose.dev.yml` layers on the production compose file. It builds the image from
the checkout instead of pulling it, switches the config to `config/vedette.dev.toml`, and
adds two local sinks so delivery can be checked end to end without touching a real inbox:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f vedette
```

| Service | Where | What it does |
|---|---|---|
| vedette | | The daemon, built from this checkout, with a 7-day lookback so the baseline finishes in minutes |
| Mailpit | <http://localhost:8025> | Catches every email the `email` channel sends |
| ntfy | <http://localhost:8080> | Receives the `push` channel on topic `vedette-kev` |
| file channel | `data/dev/alerts.log` | Every alert as text; `tail -f` it |

`data/dev` is bind-mounted over the container's data directory so the database and the
alert log are inspectable from the host. A one-shot `dev-init` service creates the
directory and gives it to the daemon's uid before the daemon starts, so a missing or
root-owned directory never produces `unable to open database file`. The container runs
as your uid so the files stay yours; if your uid is not 1000, pass it through (shells
reserve `UID` and `GID`, so the variables carry a prefix):

```bash
VEDETTE_UID=$(id -u) VEDETTE_GID=$(id -g) docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

The overlay uses its own project name, `vedette-dev`, so it never collides with a
production stack started from the same checkout.

Send a test alert through the stack and watch it land in Mailpit:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec vedette \
  vedette notify test --channel email
```

Only ports on `127.0.0.1` are published, and the dev config's channels resolve only
inside the compose network, so nothing in this stack can reach a real destination.

## Architecture

```
scheduler ──> sources ──> db ──> matcher ──> events ──> outbox ──> notify
              NVD, KEV   upsert   watches   escalation   queue    channels
```

| Module | Responsibility |
|---|---|
| `scheduler` | The daemon loop: one interval per source, a drain tick, `SIGHUP` reload, a stop that cancels the running cycle, a last-good watch list |
| `sources::nvd` | NVD API 2.0 client: rate limiting, backoff, 110-day windows, watermark per window, the baseline flag, CPE suggestions |
| `sources::kev` | Conditional fetch of the KEV catalog, placeholder CVEs for entries NVD has not published |
| `db` | One guarded SQLite connection; every call runs on the blocking pool. `migrations/` hold the schema |
| `matcher` | CPE, KEV and keyword passes over one CVE; version ranges; compiled once per watch |
| `events` | Decides which changes between two sightings of a CVE deserve an alert, with a fingerprint each |
| `pipeline` | Candidates to matches to events to outbox rows, and watch reconciliation |
| `outbox` | Drains the queue per channel with batching, urgency, retries and failure classification |
| `notify` | One `Notifier` implementation per channel kind, and the digest renderers |
| `config` | Settings, channels, watches and secret resolution |
| `cli`, `main` | The command surface |

### Invariants worth knowing before changing anything

**Nothing sends inline.** Matches and their notification rows are committed first; a
separate dispatcher delivers them. A crash mid-send can lose nothing. Delivery is
at-least-once and `UNIQUE(match_id, channel, event_fingerprint)` collapses repeats, so
running `vedette match` twice enqueues nothing the second time. The pipeline tests guard
this directly.

**A `lastModified` bump alone is silent.** NVD re-touches old CVEs in bulk. `events`
reports only a first match, a KEV addition, an exploit reference, a score increase or a
severity threshold crossing. Keeping the quiet case quiet is what keeps the feed read.

**The first sync is a baseline.** When the first NVD sync reaches the present, every
stored CVE is run through the pipeline with `Enqueue::Suppressed`: matches are recorded
and the outbox rows are written in state `suppressed`, so the `UNIQUE` constraint stops
the same event from ever being queued live by a later re-evaluation or KEV cycle. Only
then is `baseline_complete` written to `sync_state.extra`; a failure before that leaves
the next sync a baseline too. The first KEV fetch is suppressed the same way, keyed on
its `last_success` being empty. Migration 002 marks pre-existing databases complete.

**Watch definitions are hashed.** `Watch::def_hash` covers `cpe`, `keywords` and
`severity_min`. Reconciling the file into the database reports which hashes changed,
and whoever reconciles must act on it, because the next reconcile will see no change:
the daemon re-evaluates the 20,000 most recently published CVEs and prunes matches the
watch no longer produces, whether the change was noticed on a cycle or on `SIGHUP`.
`vedette match --dry-run` therefore reconciles nothing. Routing changes do not count.

**Secrets resolve at startup.** A missing variable fails the process immediately with the
variable's name, and resolved values live in `secrecy::SecretString`.

**A cycle is cancellable.** The daemon runs each source cycle under a `select!` against
the stop signals, so `SIGTERM` during an hours-long first sync drops the cycle rather
than waiting for it. That is safe because `run_windows` commits one window at a time and
only then advances the cursor.

### Measurements that shaped the design

Three observations against the live upstreams, taken in October 2026, invalidated the
obvious simpler designs. They are recorded here because they are easy to re-litigate.

- **CPE-only matching misses most of the data.** Of 6516 CVEs synced from NVD, 2343 (36%)
  had any CPE data; 1932 sat in *Awaiting Analysis* and 1982 in *Deferred*. A CVE spends
  its first days with no structured product data, so matching is a hybrid of CPE (`high`)
  and keyword (`review`), and every alert says which.
- **Product names are not unique.** `nginx` appears under three vendors across 3342
  dictionary entries, and F5 ships it under five product names. `watch suggest` exists
  to find them all.
- **NVD is slow and strict.** A 2000-result page was 7.2 MB and took 143 s to stream, so
  the default page size is 500 and the client uses an idle `read_timeout` rather than a
  whole-request timeout. A `lastModified` window wider than 120 days is answered with a
  bare 404 and no body, exactly like "no results", so windows are chunked to 110 days
  and a 404 is a loud error.

## Templates and rendering

`templates/` holds the two bodies of the email digest, `alert.html` and `alert.txt`.
They are compiled into the binary by `askama` at build time, so they are not read from
disk at runtime and are not present as files in the image.

Every channel receives the same input, a batch of `Alert` values from the outbox, and
turns it into a message through `notify::render`:

| Function | Source | Used by |
|---|---|---|
| `heading` | Rust | Email subject; ntfy and Gotify title; Telegram's first line |
| `html` | `templates/alert.html` | Email, HTML part |
| `text` | `templates/alert.txt` | Email, plain-text part; the `file` channel's `text` format |
| `markdown` | Rust, capped at ten items | ntfy and Gotify body |
| Telegram | Rust, HTML-escaped and split into 4096-character chunks | Telegram |
| none | The `Alert` struct serialized as JSON | Webhook; the `file` channel's `jsonl` format |

The email templates are the only full-fidelity rendering. The HTML one is a table layout
with inline styles, which mail clients require; it is not reusable as a web page. Both
templates receive the heading and the alert list, and both use the custom filters at the
top of `render.rs` (`truncate_chars`, `severity_colour`, `event_colour`). The field names
they reference are the `Alert` struct's fields, so adding a field to the alert payload
means deciding whether each template shows it. The `alert()` fixture in the `render`
tests is shared by every channel's tests, which is why a template change shows up in the
SMTP tests too.

## Database

The schema is in `migrations/`. Tables: `cves`, `cve_cpes`, `cve_refs`, `kev`,
`watches`, `matches`, `notifications` (the outbox, with states `pending`, `sent`,
`failed` and `suppressed`) and `sync_state` (one row per source: cursor, last attempt,
last success, last error, and `extra`, which holds the NVD baseline flag and the KEV
catalog version). The schema version is SQLite's `user_version` pragma.

To add a migration, append a file to `migrations/` and an entry to `MIGRATIONS` in
`src/db/migrate.rs`. Never edit an entry that has shipped. Migrations are forward only
and a database from a newer build is refused at startup, so a schema change is a reason
to tell operators to back up in the changelog.

## Adding a channel

1. Add a config struct and a `ChannelKind` variant in `src/config/channel.rs`. Use
   `Secret` for anything sensitive and give it a `<field>_file` twin.
2. Implement `Notifier` in a new `src/notify/<kind>.rs`. Render with the helpers in
   `notify::render`. Map failures to `NotifyError::Retryable` or `Permanent`; the outbox
   relies on that distinction to avoid hammering a misconfigured endpoint.
3. Wire it into `notify::build_one`.
4. Add it to the commented examples in `config/vedette.toml` and to the channel table in
   `docs/configuration.md`.

Test against a `wiremock` server as the existing channels do, including one retryable
and one permanent failure.

## Adding an event kind

Add the variant to `EventKind` in `src/events.rs`, classify it in `events::classify`
with a fingerprint over the values that make it distinct, and decide whether it is
urgent. Then add it to the payload table in `docs/configuration.md`. The fingerprint is
the idempotency key: two sightings that should alert once must fingerprint the same.

## Releasing

Releases are container images on the GitHub Container Registry, built by
`.github/workflows/release.yml` when a version tag is pushed.

1. Set `version` in `Cargo.toml` and run `cargo build` so `Cargo.lock` follows.
2. Add the release to `CHANGELOG.md`, including any configuration change and how to
   migrate.
3. Commit, then tag and push:

```bash
git tag v0.1.1
git push origin main v0.1.1
```

The workflow refuses a tag that does not match `Cargo.toml`, runs clippy and the tests,
then builds and pushes `ghcr.io/sennlabs/vedette:0.1.1`, `:0.1` and `:latest`. A
pre-release tag such as `v0.2.0-rc1` publishes only `0.2.0-rc1`. The image is
`linux/amd64` only. Dependabot proposes bumps for the actions, the crates and the base
images weekly.

Two things to know about GHCR:

- A package is **private the first time it is pushed**. After the first release, open the
  package settings on GitHub and set its visibility to public, or `docker pull` on
  deployments will be refused.
- The workflow authenticates with the repository's own `GITHUB_TOKEN`; no secret needs
  configuring. The package is linked to the repository through the image's `source`
  label.

## Conventions

- Comments explain why, not what. Several carry measurements from the live APIs; keep
  them accurate when the code changes.
- Tests are named as sentences and assert behaviour, not implementation.
- `clippy -D warnings` is the bar; CI enforces it.
- Nested configuration structs and channels use `deny_unknown_fields` so a typo in TOML
  is an error, not a silently ignored key. Keep that when adding fields. The top-level
  `Settings` deliberately does not, because the `VEDETTE_` environment prefix also
  carries non-settings such as `VEDETTE_CONFIG`.
