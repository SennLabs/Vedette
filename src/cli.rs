//! Command-line surface.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "vedette",
    about = "Watch NVD and the CISA KEV catalog; notify on CVEs matching declared products",
    version
)]
pub struct Cli {
    /// Path to vedette.toml (default: ./config/vedette.toml)
    #[arg(short, long, global = true, env = "VEDETTE_CONFIG")]
    pub config: Option<PathBuf>,

    /// Override the watch file from the config.
    #[arg(long, global = true, env = "VEDETTE_WATCH_FILE")]
    pub watch_file: Option<PathBuf>,

    /// Override the database path from the config.
    #[arg(long, global = true, env = "VEDETTE_DATABASE_PATH")]
    pub database: Option<PathBuf>,

    #[arg(long, global = true, env = "VEDETTE_LOG", default_value = "info")]
    pub log: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon: poll both sources, match, and dispatch notifications.
    Run,
    /// Fetch one source once and exit.
    Sync(SyncArgs),
    /// Pull NVD history from a start date in <=110-day windows. Records matches without
    /// alerting, so a large backfill never produces a digest.
    Backfill(BackfillArgs),
    /// Inspect and test the watch list.
    #[command(subcommand)]
    Watch(WatchCmd),
    /// Re-run matching over CVEs already stored, enqueuing anything that escalated.
    ///
    /// The enqueuing counterpart to `watch test`. Use it after editing watches.toml to
    /// catch up without refetching from NVD. `--dry-run` prints counts and writes nothing.
    Match(MatchArgs),
    /// Query stored CVEs that matched a watch.
    Query(QueryArgs),
    /// Notification channel operations.
    #[command(subcommand)]
    Notify(NotifyCmd),
    /// Exit non-zero when a source has not synced recently. Used by Docker HEALTHCHECK.
    Healthcheck,
    /// Database maintenance.
    #[command(subcommand)]
    Db(DbCmd),
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Source {
    Nvd,
    Kev,
    All,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[arg(long, value_enum, default_value = "all")]
    pub source: Source,
    /// Ignore the stored watermark and pull everything modified since this lookback
    /// (`7d`), `YYYY-MM-DD` date or RFC 3339 timestamp.
    #[arg(long)]
    pub since: Option<String>,
    /// Fetch and store, but enqueue nothing.
    #[arg(long)]
    pub no_notify: bool,
}

#[derive(Debug, Args)]
pub struct BackfillArgs {
    /// Oldest `lastModified` to reach: a lookback like `365d`, or a `YYYY-MM-DD` date.
    /// Defaults to nvd.backfill_from.
    #[arg(long)]
    pub from: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum WatchCmd {
    /// List configured watches and their stored match counts.
    List,
    /// Parse and compile the watch file. Exits non-zero on any problem.
    Validate,
    /// Dry-run a watch against already-stored CVEs. Sends nothing.
    Test(WatchTestArgs),
    /// Resolve a product name to CPE vendor/product candidates via the NVD dictionary.
    Suggest(WatchSuggestArgs),
}

#[derive(Debug, Args)]
pub struct WatchTestArgs {
    /// Watch name. Omit to test every watch.
    pub name: Option<String>,
    /// Only consider CVEs published within this window, e.g. `90d`.
    #[arg(long, default_value = "90d")]
    pub since: String,
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct WatchSuggestArgs {
    /// Product name to look up, e.g. `nginx`.
    pub term: String,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct MatchArgs {
    /// Only consider CVEs published within this window, e.g. `90d`.
    #[arg(long, default_value = "90d")]
    pub since: String,
    /// Evaluate and print counts only: record no matches, write no watch definitions,
    /// enqueue nothing.
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, default_value_t = 20_000)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    #[arg(long)]
    pub watch: Option<String>,
    #[arg(long, default_value = "30d")]
    pub since: String,
    #[arg(long, value_enum)]
    pub min_severity: Option<crate::config::Severity>,
    /// Only CVEs present in the KEV catalog.
    #[arg(long)]
    pub kev_only: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Debug, Subcommand)]
pub enum NotifyCmd {
    /// Send a synthetic alert through one channel to prove it is wired up.
    Test(NotifyTestArgs),
    /// Attempt delivery of everything pending in the outbox, then exit.
    Drain(DrainArgs),
    /// Show pending and failed outbox rows.
    Status,
    /// Return failed rows to the queue, e.g. after fixing a credential.
    Requeue(NotifyRequeueArgs),
}

#[derive(Debug, Args)]
pub struct NotifyRequeueArgs {
    /// Limit to one channel. Omit to requeue every failed row.
    #[arg(long)]
    pub channel: Option<String>,
}

#[derive(Debug, Args)]
pub struct NotifyTestArgs {
    #[arg(long)]
    pub channel: String,
}

#[derive(Debug, Args)]
pub struct DrainArgs {
    /// Ignore batch windows and send everything pending now.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Subcommand)]
pub enum DbCmd {
    /// Show row counts, schema version and sync watermarks.
    Stats,
    /// Copy the database to a file, consistently, while the daemon keeps running.
    Backup(DbBackupArgs),
    /// VACUUM the database file.
    Vacuum,
}

#[derive(Debug, Args)]
pub struct DbBackupArgs {
    /// Destination file. Overwritten if it exists.
    pub path: PathBuf,
}
