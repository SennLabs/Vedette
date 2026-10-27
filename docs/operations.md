# Operations

Running vedette day to day: commands, health, upgrades, backups and troubleshooting.
Everything here assumes the Compose deployment from [Getting started](getting-started.md).

## Running the CLI

The container's entrypoint is the `vedette` binary, so any subcommand runs in it. Two
forms, depending on whether the daemon is up:

```bash
docker compose exec vedette vedette <command>     # inside the running daemon container
docker compose run --rm vedette <command>         # a one-off container; works while stopped
```

`exec` bypasses the image entrypoint, so the binary name is repeated: the first `vedette`
is the Compose service, the second is the command. `run` uses the entrypoint, so it is
not. Both see the same database and configuration. The image has no shell.

SQLite runs in WAL mode, so a read-only command (`query`, `db stats`, `watch test`) never
blocks the daemon. Commands that write (`match`, `sync`, `notify drain`, `db vacuum`)
take the write lock briefly; the daemon waits up to ten seconds for it.

| Command | Purpose |
|---|---|
| `db stats` | Row counts, schema version, and each source's watermark and last success |
| `db backup <path>` | A consistent copy of the database while the daemon runs |
| `db vacuum` | Reclaim space after a large delete. Needs an exclusive lock; retry if the daemon is mid-write |
| `healthcheck` | Exit non-zero when a source is stale. What the Docker health check runs |
| `query [--watch N] [--since 30d] [--min-severity high] [--kev-only] [--json] [--limit N]` | Browse stored matches, 50 by default |
| `watch list` / `validate` / `test [N] [--since 90d]` / `suggest <term>` | Inspect, check, dry-run and discover watches |
| `notify status` | Outbox rows per channel and state, with the last error |
| `notify drain [--force]` | Deliver everything due now; `--force` ignores batch windows |
| `notify requeue [--channel N]` | Return failed rows to the queue after fixing the cause |
| `notify test --channel N` | Send one synthetic alert directly, bypassing the queue |
| `sync [--source nvd\|kev\|all] [--since ...] [--no-notify]` | Fetch once and exit |
| `backfill [--from ...]` | Pull older NVD history and record its matches quietly. Never alerts |
| `match [--since 90d] [--limit N] [--dry-run]` | Re-run matching over stored CVEs; `--dry-run` writes nothing |

## Signals and lifecycle

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read `watches.toml` now instead of at the next cycle |
| `SIGTERM`, `SIGINT` | Stop: abandon any fetch in progress, drain anything due, close the database |

`docker compose stop` sends `SIGTERM` and waits `stop_grace_period` (30 s) before
killing. A stop that lands during a sync abandons it; that is safe, because every
completed NVD window and every KEV catalog is committed as a unit, and the next start
resumes from the last completed window.

The daemon re-reads the watch file whenever a cycle has CVEs to match, so `SIGHUP` is
only needed to apply a change immediately:

```bash
docker compose kill -s HUP vedette
```

A broken edit is logged, on `SIGHUP` and on every cycle, and the daemon keeps matching
with the last watch list that parsed until the file is fixed.

## Health

The image declares a health check that runs `vedette healthcheck` every five minutes. It
passes when both sources have synced successfully within `stale_after` (6 hours by
default), and fails otherwise:

```
$ docker compose exec vedette vedette healthcheck
nvd  last_success=2026-10-27T03:10:04Z ok
kev  last_success=2026-10-27T03:00:01Z ok
```

The first NVD sync can take hours, so the image allows a four-hour start period during
which a failing check does not count; the status reads `starting`, and flips to `healthy`
as soon as the first window succeeds. Orchestrators that restart unhealthy containers
therefore leave the baseline alone. A `backfill_from` longer than 110 days turns healthy
after its first window, before the baseline is complete.

After an outage longer than `stale_after`, the status turns `unhealthy`. NVD and CISA
both have slow days; the daemon keeps retrying with backoff and recovers on its own, and
the status is there so your monitoring notices if it does not. Docker itself does not
restart a container for being unhealthy. Read the status from
`docker inspect --format '{{.State.Health.Status}}'` or let your orchestrator do so.

## Logs

The daemon logs to stdout in a single-line format, at `VEDETTE_LOG` level (`info` by
default), with UTC timestamps. Compose caps the log at five 10 MB files. The lines worth
alerting on:

| Line | Meaning |
|---|---|
| `NVD cycle failed` / `KEV cycle failed` | One poll failed. If the fetch failed, nothing moved and the next tick retries. If matching failed after the fetch (an unknown channel in a watch, say), the data is stored but unmatched: fix the cause and run `vedette match` |
| `outbox drained ... failed=N` | N notifications were marked failed: retries exhausted, a permanent rejection, or an unreadable row. See `notify status` |
| `no NVD API key: clamping the request rate` | Set `NVD_API_KEY` |
| `watch file does not parse` | `watches.toml` is broken; the previous watches are in use |
| `no enabled notification channels` | Matches are being stored but nothing is sent |

Set `VEDETTE_LOG=debug` in `.env` to see batch-window decisions and per-request detail.

## Alerts that did not arrive

Work through the queue from the outside in:

1. `vedette notify status`. A `failed` row with an error is the usual answer: a wrong
   password, a rejected recipient, a bot token revoked. Fix the configuration, then
   `vedette notify requeue`.
2. A `pending` row with no error is waiting out its `batch_window`. `notify drain --force`
   sends it now.
3. `suppressed` rows are the baseline's record of history. They are never sent.
4. Nothing queued at all: the CVE did not match, or matched during the baseline. Check
   with `vedette query --watch <name>` and `vedette watch test <name>`.

Changing a channel's address or credential takes a restart (`docker compose up -d` after
editing); channels are built once at startup. Changing watches does not.

## Upgrading

Images are tagged with the full version (`0.1.3`), the minor version (`0.1`) and
`latest`. The compose file pins the minor version through `VEDETTE_VERSION` in `.env`,
because before 1.0 a minor release may change the configuration format.

1. Read the [changelog](../CHANGELOG.md) for the versions you are skipping. It records
   every configuration change and how to migrate.
2. Back up the database (below) if the release notes mention a schema migration.
3. Edit `VEDETTE_VERSION` in `.env`, then:

```bash
docker compose pull
docker compose up -d
```

Schema migrations run automatically at startup, inside a transaction. They are forward
only: a database written by a newer vedette is refused with `it was written by a newer
vedette` rather than silently misread. Rolling back a version therefore means restoring
the database from before the upgrade.

## Backups

The database is a cache of public data plus one thing that is not: the record of what
has already been matched and alerted. Losing it means the next start runs a fresh
baseline, which is quiet, and then alerts on every subsequent change as if new. That is
usually acceptable, so backups are optional. To take one, with the daemon running:

```bash
docker compose exec vedette vedette db backup /app/data/backup.db
docker cp "$(docker compose ps -q vedette)":/app/data/backup.db ./vedette-backup.db
```

The copy is made through SQLite's online backup API, so it is consistent even mid-write.
To restore, stop the daemon, replace `vedette.db` in the volume (and delete any
`vedette.db-wal` and `vedette.db-shm` beside it), and start it again. The volume is named
`vedette_vedette-data`; `docker volume ls` confirms it.

## Resource use

One process, one SQLite file, no other services. The database grows with the lookback:
the 90-day default stores roughly 90 thousand CVEs, and each year of extra history via
`backfill` adds several times that. `db stats` reports the counts and `du` on the volume
reports the size. During a sync, one NVD window (up to 110 days of CVEs) is held in
memory before it is written, so do not set a container memory limit below about 1 GB.
Afterwards each NVD poll fetches only what changed, and an unchanged KEV catalog costs
one 304.

## Troubleshooting

**`unable to open database file`.** The data directory is not writable by the
container's user (uid 65532). With a bind mount, `chown 65532:65532` the host directory.
With a named volume created by an older image, fix the ownership in place:

```bash
docker run --rm -v vedette_vedette-data:/d alpine chown -R 65532:65532 /d
```

**`config file ... does not exist`.** The config directory is not mounted, or
`VEDETTE_CONFIG` points at the wrong file. The container expects `/app/config`.

**`environment variable `SMTP_PASSWORD` is not set`.** A channel references a secret that
`.env` does not define. Compose reads `.env` from the directory holding the compose file.

**Connection refused or timeout to every host.** The host needs a proxy; set
`HTTPS_PROXY` (and `NO_PROXY`) in `.env`.

**NVD answers 403 or 503 repeatedly.** Without a key the public rate limit is tiny and
NVD throttles aggressively; set `NVD_API_KEY`. With a key, NVD still has outages; the
client backs off and retries, and the health check tolerates `stale_after` of them.

**NVD answers 404.** vedette never sends a window wider than 110 days, so a 404 means
`nvd.base_url` is wrong (it must end in `/rest/json`) or NVD rejected another
parameter. Run with `VEDETTE_LOG=debug` to see the request.

**`www.cisa.gov` is blocked.** Point `kev.url` at CISA's GitHub copy; see
[Configuration](configuration.md#kev).

**SMTP: `STARTTLS` refused or a TLS handshake error.** The relay does not offer STARTTLS
on that port. Use `port = 465` with `tls = "implicit"`, or the port the relay documents.
`tls = "none"` exists for local mail sinks and sends credentials in the clear.

**Every poll logs `matched a batch` but nothing is sent.** Either every channel is
disabled, `notify.dry_run` is on, or the alerts are being held for a `batch_window`.
`notify status` distinguishes the last case.

**A watch I added alerted on hundreds of old CVEs.** Re-evaluating the stored corpus
against a new watch announces every match as `new`. Test with `watch test` first, and
tighten the terms before saving.

**`database is locked` from `db vacuum`.** It needs the whole file to itself; retry when
the daemon is between cycles, or stop the container first.

## Security notes

The compose file runs the container read-only, as a non-root user, with every
capability dropped, `no-new-privileges` set and a process limit. The only writable paths
are the data volume and a small `tmpfs` on `/tmp`. The image is built on a distroless
base with no shell.

The daemon makes outbound connections only to the two source hosts and the channels you
configure. It listens on nothing. Secrets are read from the environment or files at
startup and never written to the database or the log.

To report a vulnerability in vedette itself, open a private security advisory on the
GitHub repository rather than a public issue.
