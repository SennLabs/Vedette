use anyhow::{Context, Result};
use clap::Parser;
use vedette::cli::{
    BackfillArgs, Cli, Command, DbBackupArgs, DbCmd, DrainArgs, MatchArgs, NotifyCmd,
    NotifyRequeueArgs, NotifyTestArgs, QueryArgs, Source, SyncArgs, WatchCmd, WatchSuggestArgs,
    WatchTestArgs,
};
use vedette::config::Settings;
use vedette::db::{queries, Db};
use vedette::pipeline::Enqueue;
use std::collections::HashMap;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let mut settings = Settings::load(cli.config.as_deref())?;
    if let Some(p) = &cli.watch_file {
        settings.watch_file = p.clone();
    }
    if let Some(p) = &cli.database {
        settings.database_path = p.clone();
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(dispatch(cli, settings))
}

fn init_tracing(filter: &str) {
    let env = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("vedette={filter},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_target(false)
        .init();
}

async fn dispatch(cli: Cli, settings: Settings) -> Result<()> {
    match cli.command {
        Command::Watch(WatchCmd::Validate) => {
            let watches = settings.load_watches()?;
            // Also prove every referenced channel exists, which parsing alone cannot.
            for w in &watches.watches {
                settings
                    .channels_for(&w.channels)
                    .with_context(|| format!("watch `{}`", w.name))?;
            }
            println!(
                "OK: {} watch(es), {} channel(s)",
                watches.watches.len(),
                settings.channel.len()
            );
            Ok(())
        }
        Command::Sync(args) => sync(&settings, args).await,
        Command::Backfill(args) => backfill(&settings, args).await,
        Command::Watch(WatchCmd::Suggest(args)) => suggest(&settings, args).await,
        Command::Watch(WatchCmd::Test(args)) => watch_test(&settings, args).await,
        Command::Match(args) => run_match(&settings, args).await,
        Command::Query(args) => query(&settings, args).await,
        Command::Run => {
            let db = Db::open(&settings.database_path)?;
            // Validate before starting so a typo fails now rather than at the first alert.
            let watches = settings.load_watches()?;
            for w in &watches.watches {
                settings
                    .channels_for(&w.channels)
                    .with_context(|| format!("watch `{}`", w.name))?;
            }
            vedette::scheduler::Daemon::new(db, settings)?.run().await
        }
        Command::Notify(NotifyCmd::Test(args)) => notify_test(&settings, args).await,
        Command::Notify(NotifyCmd::Drain(args)) => notify_drain(&settings, args).await,
        Command::Notify(NotifyCmd::Status) => notify_status(&settings).await,
        Command::Notify(NotifyCmd::Requeue(args)) => notify_requeue(&settings, args).await,
        Command::Healthcheck => healthcheck(&settings).await,
        Command::Watch(WatchCmd::List) => {
            let watches = settings.load_watches()?;
            for w in &watches.watches {
                let cpes: Vec<String> = w
                    .cpe
                    .iter()
                    .map(|c| match &c.version_range {
                        Some(r) => format!("{}:{} {r}", c.vendor, c.product),
                        None => format!("{}:{}", c.vendor, c.product),
                    })
                    .collect();
                println!(
                    "{:<18} {} cpe=[{}] any=[{}] none=[{}] min={}",
                    w.name,
                    if w.enabled { "on " } else { "off" },
                    cpes.join(", "),
                    w.keywords.any.join(", "),
                    w.keywords.none.join(", "),
                    w.severity_min.map(|s| s.as_str()).unwrap_or("-"),
                );
            }
            Ok(())
        }
        Command::Db(DbCmd::Stats) => {
            let db = Db::open(&settings.database_path)?;
            db.call(|c| {
                println!("schema version : {}", vedette::db::migrate::current_version(c)?);
                for t in ["cves", "cve_cpes", "cve_refs", "kev", "watches", "matches", "notifications"] {
                    println!("{t:<14} : {}", queries::count(c, t)?);
                }
                for src in ["nvd", "kev"] {
                    let s = queries::get_sync_state(c, src)?;
                    println!(
                        "sync {src:<9} : cursor={} last_success={} extra={}",
                        s.cursor.as_deref().unwrap_or("-"),
                        s.last_success.as_deref().unwrap_or("never"),
                        s.extra.as_deref().unwrap_or("-"),
                    );
                }
                Ok(())
            })
            .await
        }
        Command::Db(DbCmd::Backup(args)) => db_backup(&settings, args).await,
        Command::Db(DbCmd::Vacuum) => {
            let db = Db::open(&settings.database_path)?;
            db.call(|c| {
                c.execute_batch("VACUUM")?;
                println!("vacuumed");
                Ok(())
            })
            .await
        }
    }
}

async fn sync(settings: &Settings, args: SyncArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let http = vedette::sources::http_client()?;

    if matches!(args.source, Source::Kev | Source::All) {
        let client = vedette::sources::kev::KevClient::new(http.clone(), &settings.kev.url);
        // `--since` on KEV has no date filter to apply, so it means "ignore the ETag".
        let out = vedette::sources::kev::sync(&db, &client, args.since.is_some()).await?;
        let newly_added = out.newly_added.clone();
        if out.not_modified {
            println!("kev: unchanged (304)");
        } else {
            println!(
                "kev: {} entries, catalog {}, {} newly exploited",
                out.total,
                out.catalog_version.as_deref().unwrap_or("?"),
                out.newly_added.len()
            );
            for id in out.newly_added.iter().take(10) {
                println!("  + {id}");
            }
            if out.newly_added.len() > 10 {
                println!("  ... and {} more", out.newly_added.len() - 10);
            }
        }
        if out.baseline && !newly_added.is_empty() {
            // The whole catalog is "new" on a first fetch. Record it, alert on none of it.
            let p = process_ids(&db, settings, newly_added, &HashMap::new(), Enqueue::Suppressed)
                .await?;
            println!(
                "     first fetch: {} matched, recorded without alerting",
                p.matched
            );
        } else if !args.no_notify && !newly_added.is_empty() {
            // A KEV addition is the most urgent signal there is; match it immediately
            // rather than waiting for the next NVD poll.
            let p = process_ids(&db, settings, newly_added, &HashMap::new(), Enqueue::Live)
                .await?;
            println!(
                "     matched {} ({} new), {} enqueued",
                p.matched, p.new_matches, p.enqueued
            );
        }
    }

    if matches!(args.source, Source::Nvd | Source::All) {
        let since = args
            .since
            .as_deref()
            .map(|s| vedette::timeutil::parse_start(s, jiff::Timestamp::now()))
            .transpose()?;
        let out =
            vedette::sources::nvd::sync(&db, &nvd_client(settings)?, &settings.nvd, since).await?;
        println!(
            "nvd: {} window(s), {} fetched, {} new, {} updated",
            out.windows, out.fetched, out.new, out.updated
        );
        let mut snapshots = HashMap::new();
        let mut ids = Vec::with_capacity(out.deltas.len());
        for d in out.deltas {
            ids.push(d.id.clone());
            snapshots.insert(d.id, (d.old, d.new));
        }
        if out.baseline {
            // Quiet pass over everything stored, then close the baseline. Runs even with
            // --no-notify: it enqueues nothing deliverable, and skipping it would leave
            // the history unrecorded so that it alerts as `new` later.
            let p = quiet_pass(&db, settings, &snapshots).await?;
            println!(
                "     initial sync: {} matched, recorded without alerting",
                p.matched
            );
        } else if !args.no_notify && !ids.is_empty() {
            let p = process_ids(&db, settings, ids, &snapshots, Enqueue::Live).await?;
            println!(
                "     matched {} ({} new), {} enqueued",
                p.matched, p.new_matches, p.enqueued
            );
        }
    }
    Ok(())
}

/// Records matches for every stored CVE with their events suppressed, then marks the NVD
/// baseline complete. The order matters: the flag must not be set until the corpus is
/// recorded, or a failure in between would leave history that later alerts as `new`.
async fn quiet_pass(
    db: &Db,
    settings: &Settings,
    snapshots: &HashMap<
        String,
        (
            Option<vedette::sources::model::CveSnapshot>,
            vedette::sources::model::CveSnapshot,
        ),
    >,
) -> Result<vedette::pipeline::Outcome> {
    let all = db.call(|c| queries::all_cve_ids(c)).await?;
    let out = process_ids(db, settings, all, snapshots, Enqueue::Suppressed).await?;
    vedette::sources::nvd::complete_baseline(db).await?;
    Ok(out)
}

/// Shared "load these CVEs and run the pipeline over them" step, used by `sync`.
/// With `Enqueue::Suppressed`, matches and events are still recorded so they cannot later
/// alert as new.
async fn process_ids(
    db: &Db,
    settings: &Settings,
    ids: Vec<String>,
    snapshots: &HashMap<
        String,
        (
            Option<vedette::sources::model::CveSnapshot>,
            vedette::sources::model::CveSnapshot,
        ),
    >,
    mode: Enqueue,
) -> Result<vedette::pipeline::Outcome> {
    let watches = settings.load_watches()?.watches;
    vedette::pipeline::reconcile_watches(db, &watches).await?;
    let mut total = vedette::pipeline::Outcome::default();
    for chunk in ids.chunks(2_000) {
        let chunk = chunk.to_vec();
        let candidates = db.call(move |c| queries::load_candidates(c, &chunk)).await?;
        let out =
            vedette::pipeline::process(db, settings, &watches, candidates, snapshots, mode)
                .await?;
        total.evaluated += out.evaluated;
        total.matched += out.matched;
        total.new_matches += out.new_matches;
        total.events += out.events;
        total.enqueued += out.enqueued;
        total.suppressed += out.suppressed;
    }
    Ok(total)
}

fn nvd_client(settings: &Settings) -> Result<vedette::sources::nvd::NvdClient> {
    vedette::sources::nvd::NvdClient::new(
        vedette::sources::http_client_with(settings.nvd.read_timeout)?,
        &settings.nvd,
        settings.nvd_api_key()?,
    )
}

async fn backfill(settings: &Settings, args: BackfillArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let from = args.from.as_deref().unwrap_or(&settings.nvd.backfill_from);
    let start = vedette::timeutil::parse_start(from, jiff::Timestamp::now())?;
    let result = vedette::sources::nvd::run_windows(
        &db,
        &nvd_client(settings)?,
        start,
        jiff::Timestamp::now(),
    )
    .await;
    // Record what was stored even if the walk failed partway: every completed window is
    // already committed, and leaving it unmatched means it alerts as `new` on re-touch.
    let all = db.call(|c| queries::all_cve_ids(c)).await?;
    let p = process_ids(&db, settings, all, &HashMap::new(), Enqueue::Suppressed).await?;
    let out = result?;
    println!(
        "backfill: {} window(s), {} fetched, {} new, {} updated; {} matched, recorded without alerting",
        out.windows, out.fetched, out.new, out.updated, p.matched
    );
    println!("(run `vedette watch test` to review the matches; `vedette query` lists them)");
    Ok(())
}

/// A consistent copy of the live database via SQLite's online backup API, so operators
/// never have to stop the daemon to take one.
async fn db_backup(settings: &Settings, args: DbBackupArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let dest = args.path.clone();
    db.call(move |c| {
        let mut target = rusqlite::Connection::open(&dest)
            .with_context(|| format!("creating {}", dest.display()))?;
        let backup = rusqlite::backup::Backup::new(c, &mut target)?;
        backup.run_to_completion(1_000, std::time::Duration::from_millis(50), None)?;
        Ok(())
    })
    .await?;
    println!("backed up to {}", args.path.display());
    Ok(())
}

async fn suggest(settings: &Settings, args: WatchSuggestArgs) -> Result<()> {
    let out = nvd_client(settings)?.suggest_cpes(&args.term, args.limit).await?;
    if out.is_empty() {
        println!("no CPE entries matched `{}`", args.term);
        return Ok(());
    }
    println!("{:<24} {:<28} {:>7}  title", "vendor", "product", "entries");
    for s in &out {
        println!(
            "{:<24} {:<28} {:>7}  {}",
            s.vendor,
            s.product,
            s.entries,
            s.title.as_deref().unwrap_or("-")
        );
    }
    println!("\nAdd the vendor/product pairs you want to the watch's `cpe` list in watches.toml:");
    println!("  cpe = [");
    for s in &out {
        println!("    \"{}:{}\",", s.vendor, s.product);
    }
    println!("  ]");
    Ok(())
}

/// Re-evaluates stored CVEs against the current watches and enqueues what escalated.
/// With `--dry-run` nothing is written at all, not even the watch definitions: recording
/// them would make the daemon's next reload see "no change" and skip its re-evaluation.
async fn run_match(settings: &Settings, args: MatchArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let watches = settings.load_watches()?.watches;
    if !args.dry_run {
        vedette::pipeline::reconcile_watches(&db, &watches).await?;
    }

    let lookback = vedette::timeutil::parse_lookback(&args.since)?;
    let since = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().seconds(lookback.as_secs() as i64))
        .context("lookback window is too large")?;
    let since_str = vedette::timeutil::nvd_format(since)
        .trim_end_matches('Z')
        .to_string();
    let limit = args.limit;
    let ids = db
        .call(move |c| queries::cve_ids_published_since(c, &since_str, limit))
        .await?;

    if args.dry_run {
        let compiled = vedette::matcher::CompiledWatch::compile_all(&watches)?;
        let (mut evaluated, mut matched) = (0usize, 0usize);
        for chunk in ids.chunks(2_000) {
            let chunk = chunk.to_vec();
            let candidates = db.call(move |c| queries::load_candidates(c, &chunk)).await?;
            evaluated += candidates.len();
            for cand in &candidates {
                matched += compiled.iter().filter(|w| w.evaluate(cand).is_some()).count();
            }
        }
        println!("match: {evaluated} evaluated, {matched} matched");
        println!("(dry run: nothing was recorded or enqueued; `watch test` shows the hits)");
        return Ok(());
    }

    let mut total = vedette::pipeline::Outcome::default();
    let mut pruned = 0usize;
    // Chunked so a large corpus does not all sit in memory at once.
    for chunk in ids.chunks(2_000) {
        let chunk = chunk.to_vec();
        let candidates = db.call(move |c| queries::load_candidates(c, &chunk)).await?;
        // Retire matches a tightened watch no longer produces, so an added exclusion
        // actually takes effect on what is already stored.
        pruned += vedette::pipeline::prune_stale_matches(&db, &watches, &candidates).await?;
        let out = vedette::pipeline::process(
            &db,
            settings,
            &watches,
            candidates,
            &HashMap::new(),
            Enqueue::Live,
        )
        .await?;
        total.evaluated += out.evaluated;
        total.matched += out.matched;
        total.new_matches += out.new_matches;
        total.events += out.events;
        total.enqueued += out.enqueued;
    }
    println!(
        "match: {} evaluated, {} matched ({} new), {} event(s), {} enqueued, {} stale dropped",
        total.evaluated, total.matched, total.new_matches, total.events, total.enqueued, pruned
    );
    Ok(())
}

/// Sends one synthetic alert so a channel can be proven end to end before relying on it.
async fn notify_test(settings: &Settings, args: NotifyTestArgs) -> Result<()> {
    let cfg = settings
        .channel_by_name(&args.channel)
        .ok_or_else(|| anyhow::anyhow!("no channel named `{}` in the config", args.channel))?;
    let notifier =
        vedette::notify::build_one(cfg, &vedette::sources::http_client()?)?;

    let alert = vedette::pipeline::Alert {
        watch: "test".into(),
        cve_id: "CVE-1999-0001".into(),
        event: vedette::events::Event {
            kind: vedette::events::EventKind::KevAdded,
            detail: "this is a vedette test alert; no action is required".into(),
            fingerprint: "test".into(),
        },
        confidence: "high".into(),
        match_kind: "kev".into(),
        evidence: "vedette notify test".into(),
        severity: Some("CRITICAL".into()),
        score: Some(9.8),
        description: Some(
            "A synthetic alert used to verify that this notification channel is wired up \
             correctly. If you can read this, delivery works."
                .into(),
        ),
        in_kev: true,
        kev_due_date: Some("2026-12-31".into()),
        kev_ransomware: false,
        urgent: true,
        url: "https://nvd.nist.gov/vuln/detail/CVE-1999-0001".into(),
    };

    println!(
        "sending a test alert via `{}` ({})...",
        cfg.name,
        cfg.kind_name()
    );
    notifier
        .send(&[alert])
        .await
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .with_context(|| format!("channel `{}` failed", cfg.name))?;
    println!("delivered");
    Ok(())
}

async fn notify_drain(settings: &Settings, args: DrainArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let notifiers = vedette::notify::build_for(settings)?;
    let s = vedette::outbox::drain(&db, settings, &notifiers, args.force).await?;
    println!(
        "outbox: {} considered, {} sent, {} held, {} retrying, {} failed",
        s.considered, s.sent, s.held, s.retried, s.failed
    );
    if s.held > 0 && !args.force {
        println!("(held alerts are waiting out their batch window; use --force to send now)");
    }
    Ok(())
}

async fn notify_status(settings: &Settings) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let rows = db.call(|c| queries::outbox_by_channel(c)).await?;
    if rows.is_empty() {
        println!("outbox is empty");
        return Ok(());
    }
    println!("{:<18} {:<9} {:>6}  last error", "channel", "state", "count");
    for (channel, state, count, err) in &rows {
        println!(
            "{:<18} {:<9} {:>6}  {}",
            channel,
            state,
            count,
            err.as_deref().unwrap_or("-").lines().next().unwrap_or("-")
        );
    }
    Ok(())
}

async fn notify_requeue(settings: &Settings, args: NotifyRequeueArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let channel = args.channel.clone();
    let n = db
        .call(move |c| queries::requeue_failed(c, channel.as_deref()))
        .await?;
    println!("requeued {n} failed notification(s)");
    Ok(())
}

/// Exits non-zero when a source has not synced recently. Used by Docker HEALTHCHECK.
async fn healthcheck(settings: &Settings) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let stale_after = settings.stale_after;
    let states = db
        .call(|c| {
            Ok([
                ("nvd", queries::get_sync_state(c, "nvd")?),
                ("kev", queries::get_sync_state(c, "kev")?),
            ])
        })
        .await?;

    let mut problems = Vec::new();
    for (name, st) in &states {
        let stale = vedette::scheduler::is_stale(st.last_success.as_deref(), stale_after);
        println!(
            "{name:<4} last_success={} {}",
            st.last_success.as_deref().unwrap_or("never"),
            if stale { "STALE" } else { "ok" }
        );
        if stale {
            problems.push(*name);
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "stale source(s): {} (nothing synced within {:?})",
            problems.join(", "),
            stale_after
        )
    }
}

/// Dry-run watches against CVEs already in SQLite. Records nothing and sends nothing —
/// this is where the noise/coverage tradeoff gets dialled in.
async fn watch_test(settings: &Settings, args: WatchTestArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let all = settings.load_watches()?.watches;
    let selected: Vec<_> = match &args.name {
        Some(n) => all.into_iter().filter(|w| &w.name == n).collect(),
        None => all,
    };
    if selected.is_empty() {
        anyhow::bail!("no watch matched that name; try `vedette watch list`");
    }

    let lookback = vedette::timeutil::parse_lookback(&args.since)?;
    let since = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().seconds(lookback.as_secs() as i64))
        .context("lookback window is too large")?;
    // Stored timestamps are NVD's own format, which sorts lexicographically.
    let since_str = vedette::timeutil::nvd_format(since)
        .trim_end_matches('Z')
        .to_string();

    // Scan a generous slice of the corpus, then cap the printed hits.
    let scan_limit = args.limit.saturating_mul(400).max(5_000);
    let ids = db
        .call(move |c| vedette::db::queries::cve_ids_published_since(c, &since_str, scan_limit))
        .await?;
    let candidates = db
        .call(move |c| vedette::db::queries::load_candidates(c, &ids))
        .await?;

    println!(
        "scanning {} CVE(s) published since {} against {} watch(es)\n",
        candidates.len(),
        args.since,
        selected.len()
    );

    for w in &selected {
        // Compile once per watch; compiling inside the per-CVE loop makes a 5000-CVE
        // pass spend minutes building the same regexes over and over.
        let compiled = vedette::matcher::CompiledWatch::new(w)?;
        let mut hits: Vec<(String, vedette::matcher::Match, Option<String>)> = Vec::new();
        for c in &candidates {
            if let Some(m) = compiled.evaluate(c) {
                hits.push((c.id.clone(), m, c.severity.map(|s| s.as_str().to_string())));
            }
        }
        let high = hits
            .iter()
            .filter(|(_, m, _)| m.confidence == vedette::matcher::Confidence::High)
            .count();

        println!(
            "== {} : {} match(es) ({} high, {} review)",
            w.name,
            hits.len(),
            high,
            hits.len() - high
        );
        // Strongest evidence first: that is what a reviewer wants to see.
        hits.sort_by(|a, b| b.1.confidence.cmp(&a.1.confidence).then(a.0.cmp(&b.0)));
        for (id, m, sev) in hits.iter().take(args.limit) {
            println!(
                "   {:<18} {:<8} {:<6} {:<8} {}",
                id,
                sev.as_deref().unwrap_or("-"),
                m.confidence.as_str(),
                m.kind.as_str(),
                m.evidence
            );
        }
        if hits.len() > args.limit {
            println!("   ... and {} more (raise --limit)", hits.len() - args.limit);
        }
        println!();
    }
    Ok(())
}

async fn query(settings: &Settings, args: QueryArgs) -> Result<()> {
    let db = Db::open(&settings.database_path)?;
    let lookback = vedette::timeutil::parse_lookback(&args.since)?;
    let since = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().seconds(lookback.as_secs() as i64))
        .context("lookback window is too large")?;
    let since_str = vedette::timeutil::nvd_format(since)
        .trim_end_matches('Z')
        .to_string();
    let (watch, kev_only, min_sev, limit) = (
        args.watch.clone(),
        args.kev_only,
        args.min_severity,
        args.limit,
    );

    let rows = db
        .call(move |c| {
            let mut sql = String::from(
                "SELECT m.watch_name, m.cve_id, c.cvss_severity, c.cvss_score, m.confidence,
                        m.match_kind, c.published, (k.cve_id IS NOT NULL) AS in_kev,
                        k.due_date, substr(COALESCE(c.description, ''), 1, 110)
                   FROM matches m
                   JOIN cves c ON c.id = m.cve_id
                   LEFT JOIN kev k ON k.cve_id = m.cve_id
                  WHERE c.published >= :since",
            );
            if watch.is_some() {
                sql.push_str(" AND m.watch_name = :watch");
            }
            if kev_only {
                sql.push_str(" AND k.cve_id IS NOT NULL");
            }
            sql.push_str(" ORDER BY c.published DESC LIMIT :limit");

            let mut stmt = c.prepare(&sql)?;
            let limit_i = limit as i64;
            let mut params: Vec<(&str, &dyn rusqlite::ToSql)> =
                vec![(":since", &since_str), (":limit", &limit_i)];
            if let Some(w) = &watch {
                params.push((":watch", w));
            }
            let out = stmt
                .query_map(&params[..], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<f64>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, i64>(7)? != 0,
                        r.get::<_, Option<String>>(8)?,
                        r.get::<_, String>(9)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(out)
        })
        .await?;

    // The severity floor is applied here rather than in SQL because NVD severity is a
    // text column with no useful ordering.
    let filtered: Vec<_> = rows
        .into_iter()
        .filter(|r| match min_sev {
            None => true,
            Some(floor) => r
                .2
                .as_deref()
                .and_then(vedette::config::Severity::parse_nvd)
                .is_some_and(|s| s >= floor),
        })
        .collect();

    if args.json {
        let items: Vec<_> = filtered
            .iter()
            .map(|r| {
                serde_json::json!({
                    "watch": r.0, "cve_id": r.1, "severity": r.2, "score": r.3,
                    "confidence": r.4, "match_kind": r.5, "published": r.6,
                    "in_kev": r.7, "kev_due_date": r.8, "description": r.9,
                    "url": format!("https://nvd.nist.gov/vuln/detail/{}", r.1),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if filtered.is_empty() {
        println!("no matches stored in that window");
        return Ok(());
    }
    println!(
        "{:<14} {:<18} {:<9} {:>5} {:<7} {:<4} description",
        "watch", "cve", "severity", "score", "conf", "kev"
    );
    for r in &filtered {
        println!(
            "{:<14} {:<18} {:<9} {:>5} {:<7} {:<4} {}",
            r.0,
            r.1,
            r.2.as_deref().unwrap_or("-"),
            r.3.map(|v| format!("{v:.1}")).unwrap_or_else(|| "-".into()),
            r.4,
            if r.7 { "yes" } else { "-" },
            r.9.replace('\n', " ")
        );
    }
    println!("\n{} match(es)", filtered.len());
    Ok(())
}

