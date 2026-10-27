//! SQLite access. Every call runs on the blocking pool; the write path is inherently
//! serialized so one guarded connection is enough for a single-process daemon.

pub mod migrate;
pub mod queries;

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        Self::tune(&conn)?;
        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.blocking(migrate::apply)?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::tune(&conn)?;
        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.blocking(migrate::apply)?;
        Ok(db)
    }

    fn tune(conn: &Connection) -> Result<()> {
        // WAL keeps readers (the CLI) from blocking the writer (the daemon).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(())
    }

    /// Runs `f` against the connection on the current thread.
    pub fn blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("database mutex was poisoned by an earlier panic"))?;
        f(&mut guard)
    }

    /// Runs `f` on the blocking pool so the async runtime is never stalled by SQLite.
    pub async fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn
                .lock()
                .map_err(|_| anyhow::anyhow!("database mutex was poisoned by an earlier panic"))?;
            f(&mut guard)
        })
        .await
        .context("database task panicked")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_applies_the_schema() {
        let db = Db::open_in_memory().unwrap();
        let tables: Vec<String> = db
            .blocking(|c| {
                let mut stmt =
                    c.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
        for expected in [
            "cve_cpes",
            "cve_refs",
            "cves",
            "kev",
            "matches",
            "notifications",
            "sync_state",
            "watches",
        ] {
            assert!(tables.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn migrations_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.db");
        Db::open(&p).unwrap();
        // A second open re-runs the migrator against an already-current schema.
        Db::open(&p).unwrap();
    }
}
