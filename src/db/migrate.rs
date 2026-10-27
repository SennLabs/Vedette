//! Schema migrations, tracked in SQLite's own `user_version` counter so there is no
//! bookkeeping table to keep in sync.
//!
//! Each entry is applied exactly once, in order, inside a transaction. To add one: append
//! the file to `MIGRATIONS` and never edit an entry that has already shipped.

use anyhow::{Context, Result};
use rusqlite::Connection;

const MIGRATIONS: &[(&str, &str)] = &[
    ("001_init", include_str!("../../migrations/001_init.sql")),
    ("002_baseline_flag", include_str!("../../migrations/002_baseline_flag.sql")),
];

pub fn apply(conn: &mut Connection) -> Result<()> {
    let applied = current_version(conn)?;
    if applied > MIGRATIONS.len() {
        anyhow::bail!(
            "database is at schema version {applied} but this build only knows {}; \
             it was written by a newer vedette",
            MIGRATIONS.len()
        );
    }
    for (idx, (name, sql)) in MIGRATIONS.iter().enumerate().skip(applied) {
        let version = idx + 1;
        tracing::info!(migration = name, version, "applying migration");
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .with_context(|| format!("applying migration {name}"))?;
        // PRAGMA cannot be parameterized, and `version` is derived from a constant array.
        tx.pragma_update(None, "user_version", version as i64)?;
        tx.commit()?;
    }
    Ok(())
}

pub fn current_version(conn: &Connection) -> Result<usize> {
    let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    Ok(v as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_once_and_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), MIGRATIONS.len());
        // Re-running must be a no-op rather than a "table already exists" error.
        apply(&mut conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), MIGRATIONS.len());
    }

    #[test]
    fn refuses_a_database_from_a_newer_build() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99i64).unwrap();
        let err = apply(&mut conn).unwrap_err().to_string();
        assert!(err.contains("newer vedette"), "{err}");
    }
}
