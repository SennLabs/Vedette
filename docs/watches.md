# Writing watches

A watch names one product you run and decides which CVEs about it are worth an alert.
Watches live in `config/watches.toml`. The daemon re-reads the file whenever it has CVEs
to match and on `SIGHUP`, so editing it never needs a restart.

Commands below are shown bare. Under Compose, prefix them with
`docker compose exec vedette` while the daemon is running, or
`docker compose run --rm vedette` while it is stopped.

The shipped file is a worked example (nginx and WordPress) that exercises every mechanism
described here.

## The shape of a watch

```toml
[[watch]]
name         = "nginx"            # unique; appears in every alert
severity_min = "medium"           # optional floor: none | low | medium | high | critical
channels     = ["email"]          # optional; omit to notify every enabled channel
enabled      = true               # optional; false keeps the watch but silences it

cpe = [
  "f5:nginx",                                              # any version
  { cpe = "nginx:nginx", versions = ">=1.24.0, <1.27.0" }, # version-bounded
]

[watch.keywords]
any    = ['\bnginx\b', '\bnjs\b']        # any one of these matches
all    = []                              # every one of these must match
none   = ['nginx proxy manager']         # any one of these vetoes the CVE
fields = ["description", "cpe", "kev_product"]
regex  = true
```

A watch must declare at least one `cpe` selector or one `any`/`all` keyword;
`watch validate` rejects one that could never match.

## How a CVE is matched

Each CVE is tested three ways, and the strongest result wins. Every alert says which one
it was, as `cpe`, `kev` or `keyword`, with a confidence of `high` or `review`.

| Pass | Evidence | Confidence |
|---|---|---|
| **CPE** | NVD's structured `configurations` data, compared on vendor and product, intersected with `versions` if given | `high` |
| **KEV** | The CISA catalog's own vendor/product text contains the selector's product name, or a keyword hits the catalog entry | `high` |
| **Keyword** | A term from `any`/`all` found in the chosen `fields` | `review` |

The keyword pass exists because NVD is slow to analyse. Measured in October 2026 against
a live sample of 6516 CVEs, only 2343 (36%) had any CPE data at all; the rest sat in
*Awaiting Analysis* or *Deferred*. A CVE spends its first days, when an alert matters
most, with no structured product data. CPE-only matching would be blind to exactly those.
The cost is noise, which is what `watch test` and the `none` list are for.

Two rules apply across all three passes:

- **`none` is absolute.** A `none` hit vetoes the CVE even when the CPE evidence is exact.
  The list exists to kill known false-positive sources, so it must win.
- **KEV ignores the severity floor.** A CVE in the KEV catalog is being exploited now; a
  low CVSS score is not a reason to stay quiet. An unscored CVE also passes the floor,
  downgraded to `review`, because "unscored" usually means "not analysed yet".

## CPE selectors

A selector is `"vendor:product"` as NVD spells it, lowercase with underscores. The same
product often appears under several vendors and names: nginx is listed under `f5`,
`nginx` and `igor_sysoev`, and F5 alone ships `nginx`, `nginx_plus`,
`nginx_open_source`, `nginx_ingress_controller` and `nginx_gateway_fabric`. A watch on
one pair silently misses the rest, so look them up. This queries NVD's CPE dictionary
live and needs network access:

```
$ vedette watch suggest nginx
vendor                   product                      entries  title
f5                       nginx                            582  F5 NGINX
nginx                    nginx                            543  NGINX
f5                       nginx_open_source                504  F5 NGINX Open Source
...

Add the vendor/product pairs you want to the watch's `cpe` list in watches.toml:
  cpe = [
    "f5:nginx",
    "nginx:nginx",
    ...
  ]
```

`entries` is how many dictionary entries share the pair. It is a proxy for how much
history NVD files under that name, and the pairs with the most entries are usually the
ones to include. Twenty pairs are shown by default; `--limit` raises it.

### Version bounds

Add `versions` when only some releases matter:

```toml
cpe = [{ cpe = "nginx:nginx", versions = ">=1.24.0, <1.27.0" }]
```

The syntax is a comma-separated list of `>=`, `>`, `<=`, `<` and `=` constraints.
Versions compare segment by segment, so `1.25.0`, `8.0.0p1` and `1.0.0-beta2` all order
sensibly even though they are not semver. When NVD's CPE row says "all versions" there
is nothing to intersect, so the match is kept but downgraded to `review` rather than
dropped.

The long form `{ vendor = "f5", product = "nginx", version_range = "..." }` and the
`[[watch.cpe]]` table syntax are also accepted.

## Keywords

Terms are case-insensitive substrings by default. With `regex = true` they are
case-insensitive regular expressions, and `watch validate` compiles them so a typo fails
there rather than in the daemon.

`fields` limits where terms are looked for:

| Field | Text searched |
|---|---|
| `description` | The CVE's English description |
| `cpe` | Every CPE criteria string attached to the CVE |
| `kev_product` | The KEV catalog's vendor, product and vulnerability name |
| `refs` | Reference URLs. **Off by default**: a product name inside a URL path matched unrelated CVEs in testing |

Three things do most of the work when tuning keywords:

- **Use word boundaries.** A bare `njs` substring matched inside a URL; `'\bnjs\b'` with
  `regex = true` does not.
- **Put recurring noise in `none`.** Every exclusion in the shipped file came from a real
  false positive: products that merely mention nginx in their description.
- **Prefer a tight phrase to a broad one, and measure.** In one 5000-CVE window,
  `'\bwordpress\b'` produced 38 matches, 35 of them plugin CVEs. `'wordpress core'`
  produced 3, all genuine. Note that `none = ['plugin']` cannot narrow the broad term:
  plugin CVEs are phrased *"XSS in \<Plugin Name\> WordPress <= 5.2 versions"* and never
  say "plugin".

## Testing a watch before it alerts

`watch test` evaluates a watch against CVEs already stored and prints what would have
matched, strongest evidence first. It records nothing and sends nothing:

```
$ vedette watch test nginx --since 90d
scanning 4312 CVE(s) published since 90d against 1 watch(es)

== nginx : 3 match(es) (1 high, 2 review)
   CVE-2026-1234      HIGH     high   cpe      cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*
   CVE-2026-2345      MEDIUM   review keyword  `\bnginx\b` in description
   ...
```

Read the `review` rows. Each one is either coverage you want or a `none` term you need.
A watch is tuned when a window this size produces a list you would actually read.

The workflow when adding or changing a watch:

1. `vedette watch suggest <product>` to find the CPE names.
2. Write the `[[watch]]` block.
3. `vedette watch validate` to check it parses and every channel exists.
4. `vedette watch test <name>` and iterate on `none` until the noise is gone.
5. Save the file. The daemon applies it on its next cycle, or immediately on `SIGHUP`.

## What happens when a watch changes

The daemon keeps a hash of each watch's matching definition (`cpe`, `keywords` and
`severity_min`). When it reads a file whose hash has changed, it re-evaluates the stored
corpus against the new definition: the 20,000 most recently published CVEs, which covers
months of history. That is how a new or widened watch surfaces CVEs already in the
database without refetching from NVD. Matches a tightened watch no longer produces are
dropped, so adding an exclusion also cleans up old false positives in `query` output.

Changing only `channels` or `enabled` does not trigger that work. Removing a watch
removes its matches and anything of theirs still in the outbox.

Alerts from a re-evaluation are real alerts. Adding a watch to a mature install announces
every stored match as `new`, which for a broad term can be a lot. Run `watch test` first.
To re-evaluate more than the daemon's cap, or to do it on demand, run `vedette match`
(`--since` and `--limit` set the window; `--dry-run` prints counts and writes nothing).

If a saved edit does not parse, the daemon logs the error and keeps matching with the
previous watch list until the file is fixed. `vedette watch validate` shows the error.

## Severity floors

`severity_min` drops matches whose CVSS severity is below the floor. It also adds an
event: a CVE that was below the floor and later rises above it (a MEDIUM re-scored to
HIGH under `severity_min = "high"`) produces a `severity_threshold` alert when it crosses.

Floors apply to CVSS as NVD reports it, which lags. A brand-new CVE is unscored, passes
the floor as `review`, and is alerted on again when NVD scores it: as `score_increase`,
and as `severity_threshold` if the score lands above the floor.
