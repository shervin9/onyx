//! Durable job records — Phase 02 of the agent pivot (see `ROADMAP.md`).
//!
//! `onyx-server` keeps live job state (the output ring buffer, watch channels,
//! kill handles) in memory; that is correct for streaming but is lost on
//! restart. This module persists the *lifecycle metadata* of every job to a
//! small SQLite database so history and audit survive restarts. Output buffers
//! are intentionally not persisted — a job's child process dies with the
//! server, so on restart any record still marked running is reconciled to
//! `Expired` rather than resurrected.
//!
//! Writes are best-effort: the process-global helpers swallow and log errors so
//! a storage failure can never break a running job. The DB is a process
//! singleton, initialized once from `main`.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use rusqlite::Connection;
use shared::JobStatus;

static DB: OnceLock<Db> = OnceLock::new();

/// A durable job record as stored on disk — the read model for `onyx audit`.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct JobRecord {
    pub job_id: String,
    pub command_display: String,
    pub status: String,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).context("opening job database")?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Db> {
        let conn = Connection::open_in_memory()?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                 job_id           TEXT PRIMARY KEY,
                 command          TEXT NOT NULL,
                 command_display  TEXT NOT NULL,
                 status           TEXT NOT NULL,
                 started_at_unix  INTEGER NOT NULL,
                 finished_at_unix INTEGER,
                 exit_code        INTEGER,
                 timed_out        INTEGER NOT NULL DEFAULT 0,
                 last_seq         INTEGER NOT NULL DEFAULT 0,
                 updated_at_unix  INTEGER NOT NULL
             );",
        )
        .context("creating jobs table")?;
        Ok(())
    }

    /// Record a newly started job. `command` is stored NUL-joined so the raw
    /// argv round-trips losslessly without pulling in a JSON dependency.
    pub fn insert_started(
        &self,
        job_id: &str,
        command: &[String],
        command_display: &str,
        started_at_unix: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO jobs
                 (job_id, command, command_display, status, started_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, 'running', ?4, ?4)",
            rusqlite::params![
                job_id,
                command.join("\u{0}"),
                command_display,
                started_at_unix as i64,
            ],
        )?;
        Ok(())
    }

    pub fn mark_finished(
        &self,
        job_id: &str,
        status: JobStatus,
        exit_code: Option<i32>,
        finished_at_unix: u64,
        timed_out: bool,
        last_seq: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET status = ?2, exit_code = ?3, finished_at_unix = ?4,
                 timed_out = ?5, last_seq = ?6, updated_at_unix = ?4
             WHERE job_id = ?1",
            rusqlite::params![
                job_id,
                status_str(status),
                exit_code,
                finished_at_unix as i64,
                timed_out as i64,
                last_seq as i64,
            ],
        )?;
        Ok(())
    }

    /// Reconcile records left running/detached by a previous process that
    /// exited without finishing them. Their child processes are gone, so mark
    /// them expired. Returns the number of rows reconciled.
    pub fn recover_interrupted(&self, now_unix: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE jobs SET status = 'expired', updated_at_unix = ?1
             WHERE status IN ('running', 'detached')",
            rusqlite::params![now_unix as i64],
        )?;
        Ok(n)
    }

    /// The most recent `limit` job records, newest first.
    pub fn list_recent(&self, limit: u32) -> Result<Vec<JobRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT job_id, command_display, status, started_at_unix,
                    finished_at_unix, exit_code, timed_out
             FROM jobs ORDER BY started_at_unix DESC, job_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit], |r| {
            Ok(JobRecord {
                job_id: r.get(0)?,
                command_display: r.get(1)?,
                status: r.get(2)?,
                started_at_unix: r.get::<_, i64>(3)? as u64,
                finished_at_unix: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                exit_code: r.get(5)?,
                timed_out: r.get::<_, i64>(6)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    #[cfg(test)]
    fn get(&self, job_id: &str) -> Result<Option<JobRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT job_id, command_display, status, started_at_unix,
                    finished_at_unix, exit_code, timed_out
             FROM jobs WHERE job_id = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![job_id])?;
        match rows.next()? {
            Some(r) => Ok(Some(JobRecord {
                job_id: r.get(0)?,
                command_display: r.get(1)?,
                status: r.get(2)?,
                started_at_unix: r.get::<_, i64>(3)? as u64,
                finished_at_unix: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                exit_code: r.get(5)?,
                timed_out: r.get::<_, i64>(6)? != 0,
            })),
            None => Ok(None),
        }
    }
}

fn status_str(s: JobStatus) -> &'static str {
    match s {
        JobStatus::Running => "running",
        JobStatus::Detached => "detached",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::Expired => "expired",
    }
}

// ── Process-global, best-effort helpers ─────────────────────────────────────

/// Initialize the durable store at `path`. Logs and disables persistence on
/// failure rather than aborting the server — durability is best-effort.
pub fn init(path: &Path) {
    match Db::open(path) {
        Ok(db) => {
            if DB.set(db).is_err() {
                eprintln!("[server] job store already initialized");
            }
        }
        Err(e) => eprintln!("[server] durable job store disabled: {e:#}"),
    }
}

fn handle() -> Option<&'static Db> {
    DB.get()
}

pub fn recover_interrupted(now_unix: u64) {
    if let Some(db) = handle() {
        match db.recover_interrupted(now_unix) {
            Ok(n) if n > 0 => {
                println!("[server] reconciled {n} interrupted job(s) to expired")
            }
            Ok(_) => {}
            Err(e) => eprintln!("[server] job store recovery failed: {e:#}"),
        }
    }
}

pub fn record_started(
    job_id: &str,
    command: &[String],
    command_display: &str,
    started_at_unix: u64,
) {
    if let Some(db) = handle() {
        if let Err(e) = db.insert_started(job_id, command, command_display, started_at_unix) {
            eprintln!("[server] job store write failed (start {job_id}): {e:#}");
        }
    }
}

pub fn record_finished(
    job_id: &str,
    status: JobStatus,
    exit_code: Option<i32>,
    finished_at_unix: u64,
    timed_out: bool,
    last_seq: u64,
) {
    if let Some(db) = handle() {
        if let Err(e) =
            db.mark_finished(job_id, status, exit_code, finished_at_unix, timed_out, last_seq)
        {
            eprintln!("[server] job store write failed (finish {job_id}): {e:#}");
        }
    }
}

/// The most recent `limit` job records, newest first. Returns empty if the
/// store is disabled or the read fails (best-effort, like the writers).
pub fn recent(limit: u32) -> Vec<JobRecord> {
    match handle() {
        Some(db) => match db.list_recent(limit) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[server] job store read failed: {e:#}");
                Vec::new()
            }
        },
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_then_finished_round_trips() {
        let db = Db::open_in_memory().unwrap();
        db.insert_started("job_1", &["echo".into(), "hi".into()], "echo hi", 100)
            .unwrap();

        let rec = db.get("job_1").unwrap().unwrap();
        assert_eq!(rec.status, "running");
        assert_eq!(rec.command_display, "echo hi");
        assert_eq!(rec.exit_code, None);
        assert_eq!(rec.finished_at_unix, None);

        db.mark_finished("job_1", JobStatus::Succeeded, Some(0), 200, false, 7)
            .unwrap();
        let rec = db.get("job_1").unwrap().unwrap();
        assert_eq!(rec.status, "succeeded");
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(rec.finished_at_unix, Some(200));
        assert!(!rec.timed_out);
    }

    #[test]
    fn timed_out_failure_is_recorded() {
        let db = Db::open_in_memory().unwrap();
        db.insert_started("job_2", &["sleep".into(), "99".into()], "sleep 99", 0)
            .unwrap();
        db.mark_finished("job_2", JobStatus::Failed, None, 60, true, 0)
            .unwrap();
        let rec = db.get("job_2").unwrap().unwrap();
        assert_eq!(rec.status, "failed");
        assert_eq!(rec.exit_code, None);
        assert!(rec.timed_out);
    }

    #[test]
    fn recover_expires_only_unfinished_jobs() {
        let db = Db::open_in_memory().unwrap();
        db.insert_started("running_job", &["a".into()], "a", 0)
            .unwrap();
        db.insert_started("done_job", &["b".into()], "b", 0).unwrap();
        db.mark_finished("done_job", JobStatus::Succeeded, Some(0), 5, false, 1)
            .unwrap();

        let reconciled = db.recover_interrupted(1000).unwrap();
        assert_eq!(reconciled, 1, "only the unfinished job should be reconciled");
        assert_eq!(db.get("running_job").unwrap().unwrap().status, "expired");
        assert_eq!(db.get("done_job").unwrap().unwrap().status, "succeeded");
    }

    #[test]
    fn missing_job_is_none() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get("nope").unwrap().is_none());
    }

    #[test]
    fn list_recent_is_newest_first_and_respects_limit() {
        let db = Db::open_in_memory().unwrap();
        db.insert_started("old", &["a".into()], "a", 100).unwrap();
        db.insert_started("mid", &["b".into()], "b", 200).unwrap();
        db.insert_started("new", &["c".into()], "c", 300).unwrap();

        let all = db.list_recent(10).unwrap();
        let ids: Vec<&str> = all.iter().map(|r| r.job_id.as_str()).collect();
        assert_eq!(ids, ["new", "mid", "old"]);

        let limited = db.list_recent(2).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].job_id, "new");
    }
}
