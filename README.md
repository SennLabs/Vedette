# vedette

[![CI](https://github.com/SennLabs/Vedette/actions/workflows/ci.yml/badge.svg)](https://github.com/SennLabs/Vedette/actions/workflows/ci.yml)
[![Image](https://img.shields.io/badge/image-ghcr.io%2Fsennlabs%2Fvedette-blue)](https://github.com/SennLabs/Vedette/pkgs/container/vedette)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Get notified when a vulnerability affects the software you run.

vedette watches the [NVD](https://nvd.nist.gov/) and the
[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(KEV) catalog, matches every new or changed CVE against a list of products you declare,
and sends an alert by email, push notification, chat or webhook.

```
[KEV] CVE-2026-1234 — nginx (CRITICAL)
  reason    : added to the CISA KEV catalog: actively exploited
  evidence  : cpe / high — cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*
  KEV       : actively exploited, remediation due 2026-11-10
```

The binary, image and configuration are all called `vedette`. The repository is
`SennLabs/Vedette`.

## How it works

```
NVD + KEV  ──>  SQLite  ──>  match against your watches  ──>  queue  ──>  email / push / webhook
```

Both sources are polled on their own intervals. Every CVE is stored, matched against the
watch list, and anything that changed in a way worth knowing about is queued and
delivered as a digest. The first sync on a new install is a silent baseline, so you are
not emailed three months of history.

## Features

- **Two sources.** NVD for every published CVE, and CISA KEV for vulnerabilities known
  to be exploited in the wild.
- **Matching that does not wait for NVD.** Most new CVEs have no product data for their
  first days. vedette matches on NVD's structured CPE data where it exists and falls
  back to keyword matching where it does not, and labels every alert with which one it
  was.
- **Alerts on what changed, not on noise.** A first match, a KEV addition, a published
  exploit, a CVSS increase, a severity threshold crossed. NVD's routine bulk updates stay
  silent.
- **Six channels.** SMTP, ntfy, Gotify, Telegram, signed webhooks, and a file channel
  for development. Alerts are batched into digests; urgent ones skip the queue.
- **Durable delivery.** Alerts are written to a queue before anything is sent, so a
  crash or an outage never loses one. Failed sends are retried with backoff.
- **Built to run unattended.** One small container, a SQLite database, a health check,
  a watch list that reloads without a restart.

## Requirements

- Docker Engine with Compose v2.
- Outbound HTTPS to `services.nvd.nist.gov`, `www.cisa.gov` and your notification
  channels. Standard proxy variables are honoured.
- A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key). The first
  sync is roughly ten times slower without one.
- One CPU and about 1 GB of memory available during the first sync, which holds a
  window of CVEs in memory before writing it. Disk grows with how much history you keep;
  see [Operations](docs/operations.md#resource-use).

## Quick start

```bash
git clone https://github.com/SennLabs/Vedette.git vedette && cd vedette
cp .env.example .env                  # add NVD_API_KEY and SMTP_PASSWORD
$EDITOR config/vedette.toml           # where alerts go
docker compose run --rm vedette notify test --channel email
$EDITOR config/watches.toml           # what to watch
docker compose run --rm vedette watch validate
docker compose up -d
```

The first sync is a silent baseline that takes twenty minutes to a few hours; alerts
begin after it. The [getting started guide](docs/getting-started.md) walks through each
step, including choosing what to watch and what to expect on the first day.

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Deploy with Docker, from clone to first alert |
| [Writing watches](docs/watches.md) | Declare what to watch, and tune out false positives |
| [Configuration](docs/configuration.md) | Every setting, channel and environment variable |
| [Operations](docs/operations.md) | Upgrades, backups, monitoring and troubleshooting |
| [Development](docs/development.md) | Building, testing, architecture and releasing |

## Status

vedette is pre-1.0. The configuration format and command line may change between minor
versions; [the changelog](CHANGELOG.md) records every change and how to migrate. As of
0.1.0 the channels have been exercised against local sinks and the keyed NVD rate limit
is unit-tested but not yet run against the live API for long. Reports from real
deployments are welcome as [issues](https://github.com/SennLabs/Vedette/issues).

## Security

The container runs read-only as a non-root user with every capability dropped, listens
on nothing, and connects only to the two source hosts and your channels. Secrets come
from the environment or files and never reach the database or the log. To report a
vulnerability in vedette itself, open a private security advisory on GitHub rather than
a public issue.

## License

[MIT](LICENSE)
