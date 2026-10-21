use anyhow::{bail, Context, Result};
use fs2::FileExt;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: i64,
    pub timestamp: i64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub mode: String,
    pub status: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_ms: u64,
    pub flags: Vec<String>,
    pub error_code: String,
}

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    records: i64,
    flagged: i64,
    request_bytes: i64,
    response_bytes: i64,
    dropped: u64,
    queued: usize,
}

#[derive(Default)]
pub struct Filter {
    pub limit: usize,
    pub before: i64,
    pub host: String,
    pub flagged: bool,
}

pub struct Store {
    reader: Mutex<Connection>,
    sender: Mutex<Option<SyncSender<Record>>>,
    writer: Mutex<Option<JoinHandle<Result<()>>>>,
    dropped: Arc<AtomicU64>,
    queued: Arc<AtomicUsize>,
    error: Arc<Mutex<Option<String>>>,
    totals: Arc<Mutex<Stats>>,
    _lock: File,
}

impl Store {
    pub fn open(
        dir: &Path,
        max_records: i64,
        max_age: Duration,
        capacity: usize,
        fatal: CancellationToken,
    ) -> Result<Arc<Self>> {
        crate::ca::private_dir(dir)?;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let lock = opts.open(dir.join("rust-metadata.db.lock"))?;
        lock.try_lock_exclusive()
            .context("Rust data directory already has a writer")?;
        let path = dir.join("rust-metadata.db");
        let file = opts.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let mut db = Connection::open(&path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 0 && version != 101 {
            bail!("not a supported Rust metadata schema");
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
            method TEXT NOT NULL, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
            mode TEXT NOT NULL, status INTEGER NOT NULL, request_bytes INTEGER NOT NULL,
            response_bytes INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
            flags TEXT NOT NULL, flagged INTEGER NOT NULL, error_code TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS timestamp_idx ON records(timestamp);
            CREATE INDEX IF NOT EXISTS flagged_idx ON records(flagged,id);
            PRAGMA user_version=101;",
        )?;
        let mut totals = db.query_row("SELECT count(*),coalesce(sum(flagged),0),coalesce(sum(request_bytes),0),coalesce(sum(response_bytes),0) FROM records", [], |row| Ok(Stats {
            records: row.get(0)?, flagged: row.get(1)?, request_bytes: row.get(2)?, response_bytes: row.get(3)?,
            ..Default::default()
        }))?;
        flush(&mut db, &[], max_records, max_age, &mut totals)?;
        let totals = Arc::new(Mutex::new(totals));
        let writer_totals = totals.clone();
        let reader = Connection::open(&path)?;
        reader.busy_timeout(Duration::from_secs(5))?;
        reader.execute_batch("PRAGMA query_only=ON;")?;
        let (tx, rx) = mpsc::sync_channel(capacity);
        let queued = Arc::new(AtomicUsize::new(0));
        let q = queued.clone();
        let error = Arc::new(Mutex::new(None));
        let err = error.clone();
        let writer = std::thread::Builder::new()
            .name("traceglass-sqlite".into())
            .spawn(move || {
                let result = (|| -> Result<()> {
                    let mut batch = Vec::with_capacity(256);
                    let mut deadline = Instant::now() + Duration::from_millis(250);
                    loop {
                        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                            Ok(r) => {
                                q.fetch_sub(1, Ordering::AcqRel);
                                batch.push(r);
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                flush(
                                    &mut db,
                                    &batch,
                                    max_records,
                                    max_age,
                                    &mut writer_totals.lock().expect("totals mutex"),
                                )?;
                                db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                                return Ok(());
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                        }
                        if batch.len() >= 256 || Instant::now() >= deadline {
                            flush(
                                &mut db,
                                &batch,
                                max_records,
                                max_age,
                                &mut writer_totals.lock().expect("totals mutex"),
                            )?;
                            batch.clear();
                            deadline = Instant::now() + Duration::from_millis(250);
                        }
                    }
                })();
                if let Err(e) = &result {
                    eprintln!("fatal metadata writer error: {e:#}");
                    *err.lock().expect("error mutex") = Some(format!("{e:#}"));
                    fatal.cancel();
                }
                result
            })?;
        Ok(Arc::new(Self {
            reader: Mutex::new(reader),
            sender: Mutex::new(Some(tx)),
            writer: Mutex::new(Some(writer)),
            dropped: Arc::new(AtomicU64::new(0)),
            queued,
            error,
            totals,
            _lock: lock,
        }))
    }

    pub fn enqueue(&self, record: Record) {
        let sender = self.sender.lock().expect("sender mutex");
        let Some(sender) = sender.as_ref() else {
            eprintln!("metadata rejected after close");
            return;
        };
        self.queued.fetch_add(1, Ordering::AcqRel);
        match sender.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_power_of_two() {
                    eprintln!("metadata queue full; dropped={n}; forwarding continues");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued.fetch_sub(1, Ordering::AcqRel);
                eprintln!("metadata writer disconnected");
            }
        }
    }

    pub fn stats(&self) -> Result<Stats> {
        if let Some(e) = &*self.error.lock().expect("error mutex") {
            bail!("metadata writer failed: {e}");
        }
        let mut stats = self.totals.lock().expect("totals mutex").clone();
        stats.dropped = self.dropped.load(Ordering::Relaxed);
        stats.queued = self.queued.load(Ordering::Acquire);
        Ok(stats)
    }

    pub fn list(&self, f: Filter) -> Result<Vec<Record>> {
        if !(1..=200).contains(&f.limit) || f.before < 0 || f.host.len() > 253 {
            bail!("invalid metadata filter");
        }
        let db = self.reader.lock().expect("reader mutex");
        let mut stmt = db.prepare("SELECT id,timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,error_code FROM records
            WHERE (?1=0 OR id<?1) AND instr(host,?2)>0 AND (?3=0 OR flagged=1) ORDER BY id DESC LIMIT ?4")?;
        let rows = stmt.query_map(params![f.before, f.host, f.flagged, f.limit as i64], |r| {
            let flags: String = r.get(11)?;
            let flags = serde_json::from_str(&flags).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(Record {
                id: r.get(0)?,
                timestamp: r.get(1)?,
                method: r.get(2)?,
                scheme: r.get(3)?,
                host: r.get(4)?,
                port: r.get(5)?,
                mode: r.get(6)?,
                status: r.get(7)?,
                request_bytes: r.get(8)?,
                response_bytes: r.get(9)?,
                duration_ms: r.get(10)?,
                flags,
                error_code: r.get(12)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn close(&self) -> Result<()> {
        self.sender.lock().expect("sender mutex").take();
        if let Some(writer) = self.writer.lock().expect("writer mutex").take() {
            writer
                .join()
                .map_err(|_| anyhow::anyhow!("metadata writer panicked"))??;
        }
        Ok(())
    }
}

fn flush(
    db: &mut Connection,
    batch: &[Record],
    max_records: i64,
    max_age: Duration,
    totals: &mut Stats,
) -> Result<()> {
    let mut updated = totals.clone();
    let tx = db.transaction()?;
    {
        let mut insert = tx.prepare_cached("INSERT INTO records(timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,flagged,error_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
        for r in batch {
            insert.execute(params![
                r.timestamp,
                r.method,
                r.scheme,
                r.host,
                r.port,
                r.mode,
                r.status,
                r.request_bytes.min(i64::MAX as u64),
                r.response_bytes.min(i64::MAX as u64),
                r.duration_ms.min(i64::MAX as u64),
                serde_json::to_string(&r.flags)?,
                !r.flags.is_empty(),
                r.error_code
            ])?;
            updated.records += 1;
            updated.flagged += i64::from(!r.flags.is_empty());
            updated.request_bytes += r.request_bytes.min(i64::MAX as u64) as i64;
            updated.response_bytes += r.response_bytes.min(i64::MAX as u64) as i64;
        }
    }
    prune(
        &tx,
        &mut updated,
        "timestamp < ?1",
        now().saturating_sub(max_age.as_millis().min(i64::MAX as u128) as i64),
    )?;
    if updated.records > max_records {
        let excess = updated.records - max_records;
        prune(
            &tx,
            &mut updated,
            "id IN (SELECT id FROM records ORDER BY id LIMIT ?1)",
            excess,
        )?;
    }
    tx.commit()?;
    *totals = updated;
    Ok(())
}

fn prune(
    tx: &rusqlite::Transaction<'_>,
    totals: &mut Stats,
    condition: &str,
    value: i64,
) -> Result<()> {
    let removed = tx.query_row(&format!("SELECT count(*),coalesce(sum(flagged),0),coalesce(sum(request_bytes),0),coalesce(sum(response_bytes),0) FROM records WHERE {condition}"), [value], |row| Ok(Stats {
        records: row.get(0)?, flagged: row.get(1)?, request_bytes: row.get(2)?, response_bytes: row.get(3)?,
        ..Default::default()
    }))?;
    if removed.records != 0 {
        tx.execute(&format!("DELETE FROM records WHERE {condition}"), [value])?;
        totals.records -= removed.records;
        totals.flagged -= removed.flagged;
        totals.request_bytes -= removed.request_bytes;
        totals.response_bytes -= removed.response_bytes;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_privacy_and_lock() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!(".test-store-{}", rand::random::<u64>()));
        let cancel = CancellationToken::new();
        let store = Store::open(&path, 2, Duration::from_secs(3600), 256, cancel.clone()).unwrap();
        assert!(Store::open(&path, 2, Duration::from_secs(3600), 256, cancel).is_err());
        for i in 0..5 {
            store.enqueue(Record {
                timestamp: now(),
                host: format!("h{i}.example"),
                flags: vec![],
                ..Default::default()
            });
        }
        store.close().unwrap();
        assert_eq!(store.stats().unwrap().records, 2);
        let rows = store
            .list(Filter {
                limit: 100,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows[0].host, "h4.example");
        assert_eq!(rows[1].host, "h3.example");
        assert!(!serde_json::to_string(&rows).unwrap().contains("headers"));
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn bounded_queue_loss_is_counted() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.try_send(Record::default()).unwrap();
        assert!(matches!(
            tx.try_send(Record::default()),
            Err(TrySendError::Full(_))
        ));
    }
}
