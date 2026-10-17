//! SQLite store. The hub is the only writer: ops queue on a channel and a
//! dedicated thread applies them in batched transactions, so the UDP loop
//! never waits on the disk. The portal opens the same file read-only (WAL).
//!
//! Nothing private is stored: frames are kept as metadata only (type, route,
//! hops, signal), and text only for public channels the hub holds keys for.

use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::Value;

use crate::config::Retention;
use crate::core::{PktHash, Pub};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS repeaters (
    pub TEXT PRIMARY KEY,
    callsign TEXT NOT NULL,
    roles_allowed INTEGER NOT NULL DEFAULT 0,
    allowlisted INTEGER NOT NULL DEFAULT 1,
    online INTEGER NOT NULL DEFAULT 0,
    roles INTEGER NOT NULL DEFAULT 0,
    session_since INTEGER,
    last_seen INTEGER,
    last_down INTEGER,
    down_reason TEXT,
    sessions INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    fw TEXT,
    lat REAL,
    lon REAL,
    uptime INTEGER,
    status_ts INTEGER,
    status TEXT
);
CREATE TABLE IF NOT EXISTS status_history (
    repeater TEXT NOT NULL,
    ts INTEGER NOT NULL,
    uptime INTEGER, rx_total INTEGER, rx_dup INTEGER, crc_err INTEGER,
    tx_total INTEGER, airtime_tx INTEGER, airtime_rx INTEGER, neighbours INTEGER,
    fwd_flood INTEGER, fwd_direct INTEGER, denied INTEGER,
    PRIMARY KEY (repeater, ts)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nodes (
    pub TEXT PRIMARY KEY,
    name TEXT,
    type INTEGER NOT NULL DEFAULT 0,
    lat REAL,
    lon REAL,
    advert_ts INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    adverts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS heard (
    repeater TEXT NOT NULL,
    node TEXT NOT NULL,
    hops INTEGER, rssi INTEGER, snr REAL,
    last_heard INTEGER, count INTEGER, reported INTEGER,
    PRIMARY KEY (repeater, node)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS frames (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    repeater TEXT NOT NULL,
    hash TEXT NOT NULL,
    route INTEGER, ptype INTEGER, hops INTEGER,
    rssi INTEGER, snr REAL,
    disposition INTEGER, backbone INTEGER, len INTEGER
);
CREATE INDEX IF NOT EXISTS frames_ts ON frames (ts);
CREATE TABLE IF NOT EXISTS messages (
    hash TEXT PRIMARY KEY,
    channel TEXT, sender TEXT, text TEXT,
    sent_ts INTEGER,
    first_heard INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_first ON messages (first_heard);
CREATE TABLE IF NOT EXISTS receptions (
    hash TEXT NOT NULL,
    repeater TEXT NOT NULL,
    ts INTEGER, rssi INTEGER, snr REAL, hops INTEGER,
    PRIMARY KEY (hash, repeater)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bridged (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    hash TEXT, src TEXT, dst TEXT,
    route INTEGER, ptype INTEGER
);
CREATE INDEX IF NOT EXISTS bridged_ts ON bridged (ts);
CREATE TABLE IF NOT EXISTS sessions_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    repeater TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS sessions_log_ts ON sessions_log (ts);
"#;

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Meta(Vec<(String, String)>),
    /// The full allowlist: (pub, callsign, roles). Repeaters not in it are
    /// marked as no longer allowlisted.
    Allowlist(Vec<(Pub, String, u8)>),
    Up { pk: Pub, ts: u32, roles: u8, name: String },
    Down { pk: Pub, ts: u32, reason: String },
    Seen { pk: Pub, ts: u32 },
    Status { pk: Pub, ts: u32, json: Value },
    Heard { repeater: Pub, node: Pub, name: Option<String>, node_type: u8, hops: u8, rssi: i32, snr: f64, last_heard: u32, count: u32, ts: u32 },
    Node { pk: Pub, name: Option<String>, node_type: u8, lat: Option<f64>, lon: Option<f64>, advert_ts: u32, ts: u32 },
    Frame { ts: u32, repeater: Pub, hash: PktHash, route: u8, ptype: u8, hops: u8, rssi: i16, snr: f32, disposition: u8, backbone: bool, len: u8 },
    Message { hash: PktHash, channel: String, sender: Option<String>, text: String, sent_ts: u32, ts: u32, repeater: Pub, rssi: i16, snr: f32, hops: u8 },
    Bridged { ts: u32, hash: PktHash, src: Pub, dst: Pub, route: u8, ptype: u8 },
}

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let db = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.pragma_update(None, "synchronous", "NORMAL")?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.execute_batch(SCHEMA)?;
    // SQLite creates files 0644 & ~umask; the portal (group) also needs to
    // write the WAL index, so make them group-writable.
    for suffix in ["", "-wal", "-shm"] {
        use std::os::unix::fs::PermissionsExt;
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660));
    }
    // Nobody is connected right after a (re)start.
    db.execute("UPDATE repeaters SET online = 0 WHERE online != 0", [])?;
    Ok(db)
}

/// Run the writer until every sender is dropped.
pub fn run(mut db: Connection, rx: Receiver<Op>, retention: Retention) {
    let mut last_purge = Instant::now() - Duration::from_secs(3600);
    loop {
        let first = match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(op) => Some(op),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let mut batch: Vec<Op> = first.into_iter().collect();
        let deadline = Instant::now() + Duration::from_millis(250);
        while batch.len() < 1000 {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(op) => batch.push(op),
                Err(_) => break,
            }
        }
        if !batch.is_empty()
            && let Err(e) = apply_batch(&mut db, &batch)
        {
            tracing::error!("store: {e:#}");
        }
        if last_purge.elapsed() >= Duration::from_secs(3600) {
            last_purge = Instant::now();
            if let Err(e) = purge(&db, &retention) {
                tracing::error!("store purge: {e:#}");
            }
        }
    }
    tracing::info!("store: writer stopped");
}

/// Spawn the writer thread.
pub fn spawn(path: &Path, retention: Retention) -> Result<(Sender<Op>, std::thread::JoinHandle<()>)> {
    let db = open(path)?;
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::Builder::new().name("store".into()).spawn(move || run(db, rx, retention))?;
    Ok((tx, h))
}

pub fn apply_batch(db: &mut Connection, ops: &[Op]) -> Result<()> {
    let tx = db.transaction()?;
    for op in ops {
        apply(&tx, op)?;
    }
    tx.commit()?;
    Ok(())
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn num(v: &Value, path: &[&str]) -> Option<i64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_i64().or_else(|| cur.as_f64().map(|f| f as i64))
}

fn apply(db: &Connection, op: &Op) -> Result<()> {
    match op {
        Op::Meta(kv) => {
            for (k, v) in kv {
                db.execute("INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT (k) DO UPDATE SET v = excluded.v", params![k, v])?;
            }
        }
        Op::Allowlist(list) => {
            db.execute("UPDATE repeaters SET allowlisted = 0", [])?;
            for (pk, callsign, roles) in list {
                db.execute(
                    "INSERT INTO repeaters (pub, callsign, roles_allowed, allowlisted) VALUES (?1, ?2, ?3, 1)
                     ON CONFLICT (pub) DO UPDATE SET callsign = excluded.callsign,
                         roles_allowed = excluded.roles_allowed, allowlisted = 1",
                    params![hx(pk), callsign, roles],
                )?;
            }
        }
        Op::Up { pk, ts, roles, name } => {
            db.execute(
                "UPDATE repeaters SET online = 1, roles = ?2, session_since = ?3, last_seen = ?3,
                     sessions = sessions + 1, name = ?4 WHERE pub = ?1",
                params![hx(pk), roles, ts, name],
            )?;
            db.execute(
                "INSERT INTO sessions_log (ts, repeater, event, detail) VALUES (?1, ?2, 'up', ?3)",
                params![ts, hx(pk), format!("roles {roles}")],
            )?;
        }
        Op::Down { pk, ts, reason } => {
            db.execute(
                "UPDATE repeaters SET online = 0, roles = 0, last_down = ?2, down_reason = ?3 WHERE pub = ?1",
                params![hx(pk), ts, reason],
            )?;
            db.execute(
                "INSERT INTO sessions_log (ts, repeater, event, detail) VALUES (?1, ?2, 'down', ?3)",
                params![ts, hx(pk), reason],
            )?;
        }
        Op::Seen { pk, ts } => {
            db.execute("UPDATE repeaters SET last_seen = ?2 WHERE pub = ?1", params![hx(pk), ts])?;
        }
        Op::Status { pk, ts, json } => {
            let lat = json.get("lat").and_then(Value::as_f64);
            let lon = json.get("lon").and_then(Value::as_f64);
            db.execute(
                "UPDATE repeaters SET last_seen = ?2, status_ts = ?2, status = ?3, name = COALESCE(?4, name),
                     fw = ?5, uptime = ?6, lat = ?7, lon = ?8 WHERE pub = ?1",
                params![
                    hx(pk),
                    ts,
                    json.to_string(),
                    json.get("name").and_then(Value::as_str),
                    json.get("fw").and_then(Value::as_str),
                    num(json, &["uptime"]),
                    lat,
                    lon
                ],
            )?;
            db.execute(
                "INSERT OR REPLACE INTO status_history (repeater, ts, uptime, rx_total, rx_dup, crc_err, tx_total,
                     airtime_tx, airtime_rx, neighbours, fwd_flood, fwd_direct, denied)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    hx(pk),
                    ts,
                    num(json, &["uptime"]),
                    num(json, &["rx", "total"]),
                    num(json, &["rx", "dup"]),
                    num(json, &["rx", "crc_err"]),
                    num(json, &["tx", "total"]),
                    num(json, &["airtime_ms", "tx"]),
                    num(json, &["airtime_ms", "rx"]),
                    num(json, &["neighbours"]),
                    num(json, &["fwd", "flood"]),
                    num(json, &["fwd", "direct"]),
                    num(json, &["fwd", "denied"]),
                ],
            )?;
        }
        Op::Heard { repeater, node, name, node_type, hops, rssi, snr, last_heard, count, ts } => {
            db.execute(
                "INSERT INTO heard (repeater, node, hops, rssi, snr, last_heard, count, reported)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (repeater, node) DO UPDATE SET hops = excluded.hops, rssi = excluded.rssi,
                     snr = excluded.snr, last_heard = excluded.last_heard, count = excluded.count,
                     reported = excluded.reported",
                params![hx(repeater), hx(node), hops, rssi, snr, last_heard, count, ts],
            )?;
            db.execute(
                "INSERT INTO nodes (pub, name, type, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT (pub) DO UPDATE SET name = COALESCE(nodes.name, excluded.name),
                     type = CASE WHEN nodes.type = 0 THEN excluded.type ELSE nodes.type END,
                     last_seen = MAX(nodes.last_seen, excluded.last_seen)",
                params![hx(node), name, node_type, last_heard],
            )?;
        }
        Op::Node { pk, name, node_type, lat, lon, advert_ts, ts } => {
            // An older (replayed) advert never overrides a newer one.
            db.execute(
                "INSERT INTO nodes (pub, name, type, lat, lon, advert_ts, first_seen, last_seen, adverts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1)
                 ON CONFLICT (pub) DO UPDATE SET
                     name = CASE WHEN excluded.advert_ts >= nodes.advert_ts THEN COALESCE(excluded.name, nodes.name) ELSE nodes.name END,
                     type = CASE WHEN excluded.advert_ts >= nodes.advert_ts THEN excluded.type ELSE nodes.type END,
                     lat = CASE WHEN excluded.advert_ts >= nodes.advert_ts THEN excluded.lat ELSE nodes.lat END,
                     lon = CASE WHEN excluded.advert_ts >= nodes.advert_ts THEN excluded.lon ELSE nodes.lon END,
                     advert_ts = MAX(nodes.advert_ts, excluded.advert_ts),
                     last_seen = MAX(nodes.last_seen, excluded.last_seen),
                     adverts = nodes.adverts + 1",
                params![hx(pk), name, node_type, lat, lon, advert_ts, ts],
            )?;
        }
        Op::Frame { ts, repeater, hash, route, ptype, hops, rssi, snr, disposition, backbone, len } => {
            db.execute(
                "INSERT INTO frames (ts, repeater, hash, route, ptype, hops, rssi, snr, disposition, backbone, len)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![ts, hx(repeater), hx(hash), route, ptype, hops, rssi, snr, disposition, backbone, len],
            )?;
        }
        Op::Message { hash, channel, sender, text, sent_ts, ts, repeater, rssi, snr, hops } => {
            db.execute(
                "INSERT OR IGNORE INTO messages (hash, channel, sender, text, sent_ts, first_heard)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![hx(hash), channel, sender, text, sent_ts, ts],
            )?;
            db.execute(
                "INSERT OR REPLACE INTO receptions (hash, repeater, ts, rssi, snr, hops) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![hx(hash), hx(repeater), ts, rssi, snr, hops],
            )?;
        }
        Op::Bridged { ts, hash, src, dst, route, ptype } => {
            db.execute(
                "INSERT INTO bridged (ts, hash, src, dst, route, ptype) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![ts, hx(hash), hx(src), hx(dst), route, ptype],
            )?;
        }
    }
    Ok(())
}

pub fn purge(db: &Connection, r: &Retention) -> Result<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let day = 86_400i64;
    let frames = now - r.frames_days as i64 * day;
    let msgs = now - r.messages_days as i64 * day;
    let hist = now - r.history_days as i64 * day;
    db.execute("DELETE FROM frames WHERE ts < ?1", [frames])?;
    db.execute("DELETE FROM receptions WHERE hash IN (SELECT hash FROM messages WHERE first_heard < ?1)", [msgs])?;
    db.execute("DELETE FROM messages WHERE first_heard < ?1", [msgs])?;
    db.execute("DELETE FROM status_history WHERE ts < ?1", [hist])?;
    db.execute("DELETE FROM bridged WHERE ts < ?1", [hist])?;
    db.execute("DELETE FROM sessions_log WHERE ts < ?1", [hist])?;
    db.execute("DELETE FROM nodes WHERE last_seen < ?1", [hist])?;
    db.execute("DELETE FROM heard WHERE last_heard < ?1", [now - 7 * day])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_op_applies() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let (r, n) = ([1u8; 32], [2u8; 32]);
        let ops = vec![
            Op::Meta(vec![("hub_pub".into(), "ab".into())]),
            Op::Allowlist(vec![(r, "ON0RFG".into(), 3)]),
            Op::Up { pk: r, ts: 100, roles: 3, name: "ON0RFG".into() },
            Op::Seen { pk: r, ts: 101 },
            Op::Status { pk: r, ts: 102, json: serde_json::json!({"name": "ON0RFG", "uptime": 5, "lat": 51.0, "lon": 4.2, "rx": {"total": 9}, "airtime_ms": {"tx": 100}}) },
            Op::Heard { repeater: r, node: n, name: Some("ON4XYZ".into()), node_type: 1, hops: 0, rssi: -90, snr: 4.5, last_heard: 100, count: 3, ts: 102 },
            Op::Node { pk: n, name: Some("ON4XYZ".into()), node_type: 1, lat: Some(50.9), lon: Some(4.1), advert_ts: 99, ts: 102 },
            Op::Node { pk: n, name: Some("OLD".into()), node_type: 1, lat: None, lon: None, advert_ts: 50, ts: 103 },
            Op::Frame { ts: 103, repeater: r, hash: [3; 8], route: 1, ptype: 5, hops: 1, rssi: -90, snr: 4.5, disposition: 0, backbone: false, len: 40 },
            Op::Message { hash: [3; 8], channel: "Public".into(), sender: Some("ON4XYZ".into()), text: "hi".into(), sent_ts: 99, ts: 103, repeater: r, rssi: -90, snr: 4.5, hops: 1 },
            Op::Bridged { ts: 104, hash: [3; 8], src: r, dst: n, route: 1, ptype: 5 },
            Op::Down { pk: r, ts: 105, reason: "timeout".into() },
        ];
        apply_batch(&mut db, &ops).unwrap();

        let (online, lat, reason): (i64, f64, String) = db
            .query_row("SELECT online, lat, down_reason FROM repeaters", [], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)))
            .unwrap();
        assert_eq!((online, lat, reason.as_str()), (0, 51.0, "timeout"));
        // The older advert did not overwrite the newer name or position.
        let (name, nlat, adverts): (String, f64, i64) =
            db.query_row("SELECT name, lat, adverts FROM nodes", [], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?))).unwrap();
        assert_eq!((name.as_str(), nlat, adverts), ("ON4XYZ", 50.9, 2));
        let n: i64 = db.query_row("SELECT COUNT(*) FROM sessions_log", [], |x| x.get(0)).unwrap();
        assert_eq!(n, 2);
        purge(&db, &Retention::default()).unwrap();
    }
}
