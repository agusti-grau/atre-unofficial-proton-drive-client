//! Persistent local state database for the sync engine.
//!
//! SQLite-backed store for:
//! - **Nodes** — mapping between local paths and remote link IDs, with cached
//!   metadata (PGP-encrypted names, hashes, timestamps).
//! - **Meta** — key-value store for sync state (last sync time, etc.).
//! - **Jobs** — queue of pending/completed sync operations.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

use crate::{Error, Result};

// ── Node ───────────────────────────────────────────────────────────────────

/// Sync state for a single local path.
#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub local_path: PathBuf,
    pub link_id: Option<String>,
    pub share_id: Option<String>,
    pub name_encrypted: String,
    pub size: i64,
    pub modified_time: i64,
    pub hash: Option<String>,
    pub is_file: bool,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Fields used when inserting or updating a node.
#[derive(Debug, Clone)]
pub struct NodeFields {
    pub local_path: PathBuf,
    pub link_id: Option<String>,
    pub share_id: Option<String>,
    pub name_encrypted: String,
    pub size: i64,
    pub modified_time: i64,
    pub hash: Option<String>,
    pub is_file: bool,
    pub state: String,
}

// ── Meta ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetaRow {
    pub key: String,
    pub value: String,
}

// ── Job ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: i64,
    pub job_type: String,
    pub local_path: PathBuf,
    pub link_id: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Fields used when enqueuing a job.
#[derive(Debug, Clone)]
pub struct JobFields {
    pub job_type: String,
    pub local_path: PathBuf,
    pub link_id: Option<String>,
}

// ── StateDb ────────────────────────────────────────────────────────────────

pub struct StateDb {
    conn: Mutex<Connection>,
}

impl StateDb {
    /// Open (or create) the database at `dir/state.db`.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            Error::Io(format!("create db directory {}: {e}", dir.display()))
        })?;

        let path = dir.join("state.db");
        let conn = Connection::open(&path).map_err(|e| {
        Error::Db(format!("open {}: {e}", path.display()))
    })?;

        let db = Self { conn: Mutex::new(conn) };
        db.migrate()?;
        Ok(db)
    }

    /// Returns the default data directory for the database.
    pub fn default_dir() -> PathBuf {
        let base = dirs_data_home().unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local/share")
        });
        base.join("proton-drive")
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS nodes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                local_path      TEXT NOT NULL,
                link_id         TEXT,
                share_id        TEXT,
                name_encrypted  TEXT NOT NULL DEFAULT '',
                size            INTEGER NOT NULL DEFAULT 0,
                modified_time   INTEGER NOT NULL DEFAULT 0,
                hash            TEXT,
                is_file         INTEGER NOT NULL DEFAULT 0,
                state           TEXT NOT NULL DEFAULT 'pending',
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(local_path)
            );

            CREATE INDEX IF NOT EXISTS idx_nodes_link_id ON nodes(link_id);
            CREATE INDEX IF NOT EXISTS idx_nodes_state   ON nodes(state);

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_type    TEXT NOT NULL,
                local_path  TEXT NOT NULL,
                link_id     TEXT,
                state       TEXT NOT NULL DEFAULT 'queued',
                error       TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
            ",
        )
        .map_err(|e| Error::Db(format!("migrate: {e}")))?;
        Ok(())
    }

    // ── Node CRUD ─────────────────────────────────────────────────────────

    /// Insert or update a node by local_path.
    pub fn upsert_node(&self, fields: &NodeFields) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let path_s = path_to_string(&fields.local_path);
        conn.execute(
            "
            INSERT INTO nodes (local_path, link_id, share_id, name_encrypted, size, modified_time, hash, is_file, state)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(local_path) DO UPDATE SET
                link_id        = COALESCE(?2, link_id),
                share_id       = COALESCE(?3, share_id),
                name_encrypted = ?4,
                size           = ?5,
                modified_time  = ?6,
                hash           = ?7,
                is_file        = ?8,
                state          = ?9,
                updated_at     = datetime('now')
            ",
            rusqlite::params![
                path_s,
                fields.link_id,
                fields.share_id,
                fields.name_encrypted,
                fields.size,
                fields.modified_time,
                fields.hash,
                fields.is_file as i32,
                fields.state,
            ],
        )
        .map_err(|e| Error::Db(format!("upsert_node: {e}")))?;

        let id: i64 = conn
            .query_row(
                "SELECT id FROM nodes WHERE local_path = ?1",
                rusqlite::params![path_s],
                |row| row.get(0),
            )
            .map_err(|e| Error::Db(format!("get node id: {e}")))?;
        Ok(id)
    }

    /// Get a single node by local_path.
    pub fn get_node(&self, local_path: &Path) -> Result<Option<NodeRow>> {
        let conn = self.conn.lock().unwrap();
        let path_s = path_to_string(local_path);
        let mut stmt = conn
            .prepare("SELECT id, local_path, link_id, share_id, name_encrypted, size, modified_time, hash, is_file, state, created_at, updated_at FROM nodes WHERE local_path = ?1")
            .map_err(|e| Error::Db(format!("prepare get_node: {e}")))?;

        let mut rows = stmt
            .query_map(rusqlite::params![path_s], row_to_node)
            .map_err(|e| Error::Db(format!("query get_node: {e}")))?;

        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(Error::Db(format!("read node: {e}"))),
            None => Ok(None),
        }
    }

    /// Get a single node by link_id.
    pub fn get_node_by_link_id(&self, link_id: &str) -> Result<Option<NodeRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, local_path, link_id, share_id, name_encrypted, size, modified_time, hash, is_file, state, created_at, updated_at FROM nodes WHERE link_id = ?1")
            .map_err(|e| Error::Db(format!("prepare get_node_by_link_id: {e}")))?;

        let mut rows = stmt
            .query_map(rusqlite::params![link_id], row_to_node)
            .map_err(|e| Error::Db(format!("query get_node_by_link_id: {e}")))?;

        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(Error::Db(format!("read node: {e}"))),
            None => Ok(None),
        }
    }

    /// List all nodes in a given sync state (or all if state is "").
    pub fn list_nodes(&self, state: &str) -> Result<Vec<NodeRow>> {
        let conn = self.conn.lock().unwrap();
        let (sql, params): (&str, Vec<&dyn rusqlite::types::ToSql>) = if state.is_empty() {
            ("SELECT id, local_path, link_id, share_id, name_encrypted, size, modified_time, hash, is_file, state, created_at, updated_at FROM nodes ORDER BY local_path", vec![])
        } else {
            ("SELECT id, local_path, link_id, share_id, name_encrypted, size, modified_time, hash, is_file, state, created_at, updated_at FROM nodes WHERE state = ?1 ORDER BY local_path", vec![&state as &dyn rusqlite::types::ToSql])
        };

        let mut stmt = conn.prepare(sql).map_err(|e| Error::Db(format!("prepare list_nodes: {e}")))?;
        let rows = stmt
            .query_map(params.as_slice(), row_to_node)
            .map_err(|e| Error::Db(format!("query list_nodes: {e}")))?;

        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(row.map_err(|e| Error::Db(format!("read node: {e}")))?);
        }
        Ok(nodes)
    }

    /// Delete a node by local_path.
    pub fn delete_node(&self, local_path: &Path) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let path_s = path_to_string(local_path);
        let n = conn
            .execute("DELETE FROM nodes WHERE local_path = ?1", rusqlite::params![path_s])
            .map_err(|e| Error::Db(format!("delete_node: {e}")))?;
        Ok(n > 0)
    }

    /// Count nodes in a given state.
    pub fn count_nodes(&self, state: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let (sql, params): (&str, Vec<&dyn rusqlite::types::ToSql>) = if state.is_empty() {
            ("SELECT COUNT(*) FROM nodes", vec![])
        } else {
            ("SELECT COUNT(*) FROM nodes WHERE state = ?1", vec![&state as &dyn rusqlite::types::ToSql])
        };
        conn.query_row(sql, params.as_slice(), |row| row.get(0))
            .map_err(|e| Error::Db(format!("count_nodes: {e}")))
    }

    // ── Meta key-value ──────────────────────────────────────────────────

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![key, value],
        )
        .map_err(|e| Error::Db(format!("set_meta: {e}")))?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM meta WHERE key = ?1")
            .map_err(|e| Error::Db(format!("prepare get_meta: {e}")))?;

        let mut rows = stmt
            .query_map(rusqlite::params![key], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Db(format!("query get_meta: {e}")))?;

        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(Error::Db(format!("read meta: {e}"))),
            None => Ok(None),
        }
    }

    /// Remove all meta keys.
    pub fn clear_meta(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM meta", [])
            .map_err(|e| Error::Db(format!("clear_meta: {e}")))?;
        Ok(())
    }

    // ── Job queue ───────────────────────────────────────────────────────

    /// Enqueue a new sync job.
    pub fn enqueue_job(&self, fields: &JobFields) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs (job_type, local_path, link_id) VALUES (?1, ?2, ?3)",
            rusqlite::params![fields.job_type, path_to_string(&fields.local_path), fields.link_id],
        )
        .map_err(|e| Error::Db(format!("enqueue_job: {e}")))?;

        let id = conn.last_insert_rowid();
        Ok(id)
    }

    /// Dequeue the oldest pending job.
    pub fn dequeue_job(&self) -> Result<Option<JobRow>> {
        let conn = self.conn.lock().unwrap();
        // Atomically claim the oldest queued job.
        let id: Option<i64> = conn
            .query_row(
                "SELECT id FROM jobs WHERE state = 'queued' ORDER BY id ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        let id = match id {
            Some(id) => id,
            None => return Ok(None),
        };

        conn.execute(
            "UPDATE jobs SET state = 'running', updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| Error::Db(format!("claim job: {e}")))?;

        let job = conn
            .query_row(
                "SELECT id, job_type, local_path, link_id, state, error, created_at, updated_at FROM jobs WHERE id = ?1",
                rusqlite::params![id],
                row_to_job,
            )
            .map_err(|e| Error::Db(format!("read job: {e}")))?;

        Ok(Some(job))
    }

    /// Mark a job as completed.
    pub fn complete_job(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'done', updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| Error::Db(format!("complete_job: {e}")))?;
        Ok(())
    }

    /// Mark a job as failed.
    pub fn fail_job(&self, id: i64, error: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET state = 'failed', error = ?2, updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id, error],
        )
        .map_err(|e| Error::Db(format!("fail_job: {e}")))?;
        Ok(())
    }

    /// Count pending jobs.
    pub fn pending_jobs(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE state = 'queued' OR state = 'running'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| Error::Db(format!("pending_jobs: {e}")))
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn row_to_node(row: &rusqlite::Row) -> rusqlite::Result<NodeRow> {
    Ok(NodeRow {
        id: row.get(0)?,
        local_path: PathBuf::from(row.get::<_, String>(1)?),
        link_id: row.get(2)?,
        share_id: row.get(3)?,
        name_encrypted: row.get(4)?,
        size: row.get(5)?,
        modified_time: row.get(6)?,
        hash: row.get(7)?,
        is_file: row.get::<_, i32>(8)? != 0,
        state: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn row_to_job(row: &rusqlite::Row) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        id: row.get(0)?,
        job_type: row.get(1)?,
        local_path: PathBuf::from(row.get::<_, String>(2)?),
        link_id: row.get(3)?,
        state: row.get(4)?,
        error: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn dirs_data_home() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    std::env::var("HOME").ok().map(|home| PathBuf::from(home).join(".local/share"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> StateDb {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("proton-db-test-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        StateDb::open(&dir).unwrap()
    }

    #[test]
    fn open_creates_tables() {
        let db = temp_db();
        // Tables should exist after open.
        db.upsert_node(&NodeFields {
            local_path: PathBuf::from("test.txt"),
            link_id: None,
            share_id: None,
            name_encrypted: String::new(),
            size: 0,
            modified_time: 0,
            hash: None,
            is_file: true,
            state: "pending".into(),
        })
        .unwrap();
    }

    #[test]
    fn upsert_and_get_node() {
        let db = temp_db();
        let path = PathBuf::from("foo/bar.txt");

        let id = db
            .upsert_node(&NodeFields {
                local_path: path.clone(),
                link_id: Some("link-123".into()),
                share_id: Some("share-abc".into()),
                name_encrypted: "enc-name".into(),
                size: 1024,
                modified_time: 1_700_000_000,
                hash: Some("abc123".into()),
                is_file: true,
                state: "synced".into(),
            })
            .unwrap();

        let node = db.get_node(&path).unwrap().expect("node should exist");
        assert_eq!(node.id, id);
        assert_eq!(node.link_id.unwrap(), "link-123");
        assert_eq!(node.share_id.unwrap(), "share-abc");
        assert_eq!(node.name_encrypted, "enc-name");
        assert_eq!(node.size, 1024);
        assert_eq!(node.modified_time, 1_700_000_000);
        assert_eq!(node.hash.unwrap(), "abc123");
        assert!(node.is_file);
        assert_eq!(node.state, "synced");
    }

    #[test]
    fn upsert_updates_existing() {
        let db = temp_db();
        let path = PathBuf::from("update.txt");

        db.upsert_node(&NodeFields {
            local_path: path.clone(),
            link_id: Some("link-1".into()),
            share_id: None,
            name_encrypted: "old".into(),
            size: 100,
            modified_time: 0,
            hash: None,
            is_file: true,
            state: "pending".into(),
        })
        .unwrap();

        db.upsert_node(&NodeFields {
            local_path: path.clone(),
            link_id: Some("link-2".into()),
            share_id: None,
            name_encrypted: "new".into(),
            size: 200,
            modified_time: 0,
            hash: Some("new-hash".into()),
            is_file: true,
            state: "synced".into(),
        })
        .unwrap();

        let node = db.get_node(&path).unwrap().unwrap();
        assert_eq!(node.link_id.unwrap(), "link-2");
        assert_eq!(node.name_encrypted, "new");
        assert_eq!(node.size, 200);
        assert_eq!(node.hash.unwrap(), "new-hash");
        assert_eq!(node.state, "synced");
    }

    #[test]
    fn get_node_by_link_id() {
        let db = temp_db();
        let path = PathBuf::from("by-link.txt");
        db.upsert_node(&NodeFields {
            local_path: path.clone(),
            link_id: Some("link-42".into()),
            share_id: None,
            name_encrypted: "x".into(),
            size: 0,
            modified_time: 0,
            hash: None,
            is_file: false,
            state: "synced".into(),
        })
        .unwrap();

        let node = db.get_node_by_link_id("link-42").unwrap().unwrap();
        assert_eq!(node.local_path, path);
    }

    #[test]
    fn list_nodes_by_state() {
        let db = temp_db();
        for i in 0..3 {
            db.upsert_node(&NodeFields {
                local_path: PathBuf::from(format!("f{i}.txt")),
                link_id: None,
                share_id: None,
                name_encrypted: String::new(),
                size: 0,
                modified_time: 0,
                hash: None,
                is_file: true,
                state: if i == 0 { "synced".into() } else { "pending".into() },
            })
            .unwrap();
        }

        let pending = db.list_nodes("pending").unwrap();
        assert_eq!(pending.len(), 2);

        let synced = db.list_nodes("synced").unwrap();
        assert_eq!(synced.len(), 1);

        let all = db.list_nodes("").unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn delete_node() {
        let db = temp_db();
        let path = PathBuf::from("delete-me.txt");
        db.upsert_node(&NodeFields {
            local_path: path.clone(),
            link_id: None,
            share_id: None,
            name_encrypted: String::new(),
            size: 0,
            modified_time: 0,
            hash: None,
            is_file: true,
            state: "pending".into(),
        })
        .unwrap();

        assert!(db.delete_node(&path).unwrap());
        assert!(db.get_node(&path).unwrap().is_none());
        assert!(!db.delete_node(&path).unwrap());
    }

    #[test]
    fn count_nodes() {
        let db = temp_db();
        assert_eq!(db.count_nodes("").unwrap(), 0);

        db.upsert_node(&NodeFields {
            local_path: PathBuf::from("a.txt"),
            link_id: None,
            share_id: None,
            name_encrypted: String::new(),
            size: 0,
            modified_time: 0,
            hash: None,
            is_file: true,
            state: "pending".into(),
        })
        .unwrap();
        assert_eq!(db.count_nodes("").unwrap(), 1);
        assert_eq!(db.count_nodes("pending").unwrap(), 1);
        assert_eq!(db.count_nodes("synced").unwrap(), 0);
    }

    #[test]
    fn meta_key_value() {
        let db = temp_db();
        assert!(db.get_meta("last_sync").unwrap().is_none());

        db.set_meta("last_sync", "2025-01-15T10:00:00Z").unwrap();
        assert_eq!(
            db.get_meta("last_sync").unwrap().unwrap(),
            "2025-01-15T10:00:00Z"
        );

        // Overwrite
        db.set_meta("last_sync", "2025-01-15T11:00:00Z").unwrap();
        assert_eq!(
            db.get_meta("last_sync").unwrap().unwrap(),
            "2025-01-15T11:00:00Z"
        );

        db.clear_meta().unwrap();
        assert!(db.get_meta("last_sync").unwrap().is_none());
    }

    #[test]
    fn job_enqueue_dequeue() {
        let db = temp_db();
        assert_eq!(db.pending_jobs().unwrap(), 0);

        let id = db
            .enqueue_job(&JobFields {
                job_type: "download".into(),
                local_path: PathBuf::from("remote-file.txt"),
                link_id: Some("link-99".into()),
            })
            .unwrap();
        assert!(id > 0);
        assert_eq!(db.pending_jobs().unwrap(), 1);

        let job = db.dequeue_job().unwrap().expect("should have a job");
        assert_eq!(job.job_type, "download");
        assert_eq!(job.local_path, PathBuf::from("remote-file.txt"));
        assert_eq!(job.link_id.unwrap(), "link-99");
        assert_eq!(job.state, "running");
        assert!(job.error.is_none());
        assert_eq!(db.pending_jobs().unwrap(), 1); // still running

        db.complete_job(job.id).unwrap();
        assert_eq!(db.pending_jobs().unwrap(), 0);
    }

    #[test]
    fn job_fail() {
        let db = temp_db();
        db.enqueue_job(&JobFields {
            job_type: "upload".into(),
            local_path: PathBuf::from("doc.pdf"),
            link_id: None,
        })
        .unwrap();

        let job = db.dequeue_job().unwrap().unwrap();
        db.fail_job(job.id, "network error").unwrap();

        let failed = db.dequeue_job().unwrap(); // should be None
        assert!(failed.is_none());

        // Verify the job is marked as failed by checking pending count
        assert_eq!(db.pending_jobs().unwrap(), 0);
    }

    #[test]
    fn dequeue_empty_when_no_pending() {
        let db = temp_db();
        let job = db.dequeue_job().unwrap();
        assert!(job.is_none());
    }

    #[test]
    fn directory_node() {
        let db = temp_db();
        let path = PathBuf::from("mydir");
        db.upsert_node(&NodeFields {
            local_path: path.clone(),
            link_id: Some("dir-link".into()),
            share_id: Some("share".into()),
            name_encrypted: "encrypted-folder-name".into(),
            size: 0,
            modified_time: 1_700_000_000,
            hash: None,
            is_file: false,
            state: "synced".into(),
        })
        .unwrap();

        let node = db.get_node(&path).unwrap().unwrap();
        assert!(!node.is_file);
        assert!(node.hash.is_none());
    }

    #[test]
    fn default_dir_resolves() {
        let dir = StateDb::default_dir();
        assert!(dir.ends_with("proton-drive"));
    }
}
