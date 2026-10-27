# Getting started

This guide takes a fresh host from nothing to a running vedette that has sent its first
alert. It assumes Docker. To build from source instead, see [Development](development.md).

## Before you begin

You need:

- **Docker Engine with Compose v2** (`docker compose version` prints `v2.x`).
- **Somewhere to send alerts.** An SMTP relay is the usual choice; ntfy, Gotify, Telegram
  and a generic webhook are also supported. See [Configuration](configuration.md#channels).
- **An NVD API key.** It is free and issued within minutes at
  <https://nvd.nist.gov/developers/request-an-api-key>. Without one NVD allows 5 requests
  per 30 seconds and the first sync takes roughly ten times longer.
- **Outbound HTTPS** to `services.nvd.nist.gov`, `www.cisa.gov` and your channels. The
  standard `HTTPS_PROXY` and `NO_PROXY` variables are honoured if your host needs a proxy.

A few terms the rest of this guide uses:

| Term | Meaning |
|---|---|
| **CVE** | One published vulnerability record, such as `CVE-2026-1234` |
| **NVD** | The US National Vulnerability Database. It scores each CVE (**CVSS**, giving a severity of LOW, MEDIUM, HIGH or CRITICAL) and, after analysis, tags it with structured product identifiers (**CPE**, written `vendor:product`) |
| **KEV** | CISA's Known Exploited Vulnerabilities catalog: CVEs confirmed to be exploited in the wild, each with a remediation due date |
| **Confidence** | Every alert says whether it matched on CPE or KEV data (`high`) or on a keyword in the text (`review`, meaning a human should check it) |

## 1. Get the deployment files

The image is published to the GitHub Container Registry, so nothing is built on the host.
The repository is cloned only for its compose file and example configuration:

```bash
git clone https://github.com/SennLabs/Vedette.git vedette
cd vedette
```

Everything the deployment uses lives in four places:

| Path | Purpose |
|---|---|
| `docker-compose.yml` | The production stack: one container, one data volume |
| `.env` | Image tag and secrets. Created from `.env.example`, never committed |
| `config/vedette.toml` | Daemon settings and notification channels |
| `config/watches.toml` | The products to watch |

On an SELinux host (Fedora, RHEL), add `,z` to the config mount in the compose file:
`./config:/app/config:ro,z`.

## 2. Set the image tag and secrets, and pull the image

```bash
cp .env.example .env
```

Open `.env` and set `NVD_API_KEY`. Leave `VEDETTE_VERSION` at the minor version in the
example; it pins the image so upgrades are deliberate. The
[package page](https://github.com/SennLabs/Vedette/pkgs/container/vedette) lists
the published tags.

Any secret your channels need goes in this file too (`SMTP_PASSWORD`, `NTFY_TOKEN`, and so
on). The TOML config refers to these by name and never holds the value itself.

Then confirm the host can reach the registry and the pinned tag exists, before spending
time on configuration:

```bash
docker compose pull
```

## 3. Configure where alerts go

Edit `config/vedette.toml`. The shipped file has one `email` channel with the fields that
need changing marked `EDIT`, and commented-out examples of every other channel kind.

Prove the channel works before going further. This sends one synthetic alert straight
through the channel, bypassing the queue and the batch window, and records nothing, so it
is safe to repeat:

```bash
docker compose run --rm vedette notify test --channel email
```

If it fails, the error names the problem (a refused STARTTLS upgrade, a rejected
credential, an unresolvable host). Fix it and run the command again.

Channels are built when the daemon starts, so a later change to a channel takes effect on
`docker compose up -d`. Changes to the watch list, below, are picked up live.

## 4. Declare what to watch

Edit `config/watches.toml`. The shipped file is a worked example covering nginx and
WordPress. It is not a default watch list: replace its entries with the software you run.

A watch names the product two ways. Structured CPE selectors give exact, version-aware
matches; keywords catch the CVEs that NVD has not yet analysed. Product names are not
unique in NVD, so look the CPE names up rather than guessing. This queries NVD's CPE
dictionary live, using the API key from `.env`, and takes a few seconds:

```bash
docker compose run --rm vedette watch suggest "apache http server"
```

It prints the vendor/product pairs with the most dictionary entries under that term
(twenty by default) and a ready-to-paste `cpe = [...]` list. Then check the file parses
and every channel it refers to exists:

```bash
docker compose run --rm vedette watch validate
```

[Writing watches](watches.md) covers the full format and how to tune out false positives.

## 5. Start the daemon

```bash
docker compose up -d
docker compose logs -f vedette
```

The daemon immediately starts both a KEV fetch and an NVD sync covering the last 90 days,
in either order, one after the other. **These first fetches are a baseline.** They record
which stored CVEs match your watches but send nothing, so a new install does not email
three months of history or the whole KEV catalog. The log says so:

```
KEV baseline: recording matches without alerting
NVD baseline: recording matches without alerting
NVD baseline complete; alerts start with the next sync
```

How long the baseline takes depends on NVD, which serves pages slowly. With an API key,
expect somewhere between twenty minutes and two hours; without one, most of a day. The
container's health status reads `starting` until the first sync succeeds, which is
expected: health means "both sources have synced". If your host runs something that
restarts unhealthy containers, it is safe, because the image allows four hours before a
failing check counts.

Press `Ctrl-C` to stop following the log. The daemon keeps running. Stopping the
container during the baseline is also safe: the sync is abandoned and resumes from its
last completed window on the next start.

## 6. See what it found

The image has no shell, so `docker compose exec vedette sh` does not work. Every
subcommand runs through the binary instead. `docker compose exec` bypasses the image's
entrypoint, so the name is repeated: the first `vedette` is the Compose service, the
second is the command.

```bash
# Sync watermarks and row counts
docker compose exec vedette vedette db stats

# Stored matches, newest first (50 by default; --limit for more)
docker compose exec vedette vedette query --since 90d

# Dry-run one watch against the stored CVEs, to judge its noise level
docker compose exec vedette vedette watch test nginx
```

Those matches are what the daemon would have alerted on had it been running, and they
are the thing to show whoever is waiting for alerts. The first real alert arrives when a
watched product next changes in NVD or KEV, which for a short watch list can be days.

From here on, each poll cycle (every 30 minutes for NVD, hourly for KEV) alerts on what
changed: a new match, a CVE entering the KEV catalog, a published exploit, a CVSS
increase, or a severity crossing a watch's floor. Alerts are held for the channel's
`batch_window` (15 minutes by default) so one cycle produces one digest; KEV additions,
exploit references and CRITICAL matches skip the wait.

To exercise the whole pipeline once, add a temporary watch for something with recent
activity, and watch the next cycle announce its stored matches as `new`. Remove the
watch afterwards.

## 7. Keep it running

Day-to-day commands, upgrades, backups and what to do when something fails are in
[Operations](operations.md). The two to remember:

```bash
docker compose exec vedette vedette notify status   # what is queued, what failed
docker compose pull && docker compose up -d         # upgrade, after editing VEDETTE_VERSION
```

## Running without Compose

`docker run` works with the same image. The container needs the config directory mounted
read-only, a volume for the database, and the API key in the environment. The hardening
flags are the ones the compose file sets:

```bash
docker run -d --name vedette --restart unless-stopped \
  -e NVD_API_KEY=... -e SMTP_PASSWORD=... \
  -v "$PWD/config":/app/config:ro -v vedette-data:/app/data \
  --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/sennlabs/vedette:0.1
```
