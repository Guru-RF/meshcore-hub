//! JSON API over the hub's SQLite file. Every handler opens the file
//! read-only on a blocking thread; the hub is the only writer.
//!
//! Nothing here exposes addresses or private traffic: the store holds frame
//! metadata only, and text only for public channels.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Shared;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/overview", get(overview))
        .route("/api/repeaters", get(repeaters))
        .route("/api/repeater/{pub}", get(repeater))
        .route("/api/nodes", get(nodes))
        .route("/api/links", get(links))
        .route("/api/messages", get(messages))
        .route("/api/activity", get(activity))
        .route("/api/channels", get(channels))
}

const DAY: i64 = 86_400;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn open(st: &Shared) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(&st.db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(db)
}

/// Run a query on a blocking thread and answer with JSON.
async fn query<F>(st: Shared, f: F) -> Response
where
    F: FnOnce(&Connection) -> rusqlite::Result<Value> + Send + 'static,
{
    let r = tokio::task::spawn_blocking(move || {
        let db = open(&st)?;
        f(&db)
    })
    .await;
    match r {
        Ok(Ok(v)) => {
            let mut resp = Json(v).into_response();
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=5"));
            resp
        }
        Ok(Err(rusqlite::Error::QueryReturnedNoRows)) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Ok(Err(e)) => {
            tracing::warn!("api: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable").into_response()
        }
        Err(e) => {
            tracing::error!("api task: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A row as a JSON object keyed by column name.
pub(crate) fn row_json(row: &Row<'_>) -> rusqlite::Result<Value> {
    let mut m = Map::new();
    let stmt = row.as_ref();
    for (i, name) in stmt.column_names().iter().enumerate() {
        let v = match row.get_ref(i)? {
            rusqlite::types::ValueRef::Null => Value::Null,
            rusqlite::types::ValueRef::Integer(n) => json!(n),
            rusqlite::types::ValueRef::Real(f) => json!(f),
            rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
            rusqlite::types::ValueRef::Blob(_) => Value::Null,
        };
        m.insert(name.to_string(), v);
    }
    Ok(Value::Object(m))
}

pub(crate) fn rows(db: &Connection, sql: &str, p: impl rusqlite::Params) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = db.prepare_cached(sql)?;
    let it = stmt.query_map(p, row_json)?;
    it.collect()
}

fn count(db: &Connection, sql: &str, p: impl rusqlite::Params) -> rusqlite::Result<i64> {
    db.query_row(sql, p, |r| r.get(0))
}

async fn overview(State(st): State<Shared>) -> Response {
    query(st, |db| {
        let t = now();
        let mut meta = Map::new();
        for r in rows(db, "SELECT k, v FROM meta", [])? {
            if let (Some(k), Some(v)) = (r["k"].as_str(), r.get("v")) {
                meta.insert(k.to_string(), v.clone());
            }
        }
        let (total, online): (i64, i64) = db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(online), 0) FROM repeaters WHERE allowlisted = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(json!({
            "now": t,
            "hub": meta,
            "repeaters": {"total": total, "online": online},
            "nodes_24h": count(db, "SELECT COUNT(*) FROM nodes WHERE last_seen >= ?1", [t - DAY])?,
            "messages_24h": count(db, "SELECT COUNT(*) FROM messages WHERE first_heard >= ?1", [t - DAY])?,
            "frames_24h": count(db, "SELECT COUNT(*) FROM frames WHERE ts >= ?1 AND backbone = 0", [t - DAY])?,
            "bridged_24h": count(db, "SELECT COUNT(*) FROM bridged WHERE ts >= ?1", [t - DAY])?,
        }))
    })
    .await
}

/// Counter deltas between the latest status report and one about `span`
/// seconds earlier, ignoring a span that crosses a repeater restart.
fn rates(db: &Connection, pk: &str, span: i64) -> rusqlite::Result<Value> {
    const COLS: &str = "ts, uptime, rx_total, rx_dup, crc_err, tx_total, airtime_tx, airtime_rx";
    let latest = db
        .query_row(
            &format!("SELECT {COLS} FROM status_history WHERE repeater = ?1 ORDER BY ts DESC LIMIT 1"),
            [pk],
            row_json,
        )
        .optional()?;
    let Some(latest) = latest else { return Ok(Value::Null) };
    let t1 = latest["ts"].as_i64().unwrap_or(0);
    let earlier = db
        .query_row(
            &format!("SELECT {COLS} FROM status_history WHERE repeater = ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT 1"),
            params![pk, t1 - span],
            row_json,
        )
        .optional()?;
    let earlier = match earlier {
        Some(e) => Some(e),
        // Younger than the span: compare with the oldest report there is.
        None => db
            .query_row(
                &format!("SELECT {COLS} FROM status_history WHERE repeater = ?1 AND ts < ?2 ORDER BY ts ASC LIMIT 1"),
                params![pk, t1],
                row_json,
            )
            .optional()?,
    };
    let Some(e) = earlier else { return Ok(Value::Null) };
    let g = |v: &Value, k: &str| v[k].as_i64().unwrap_or(0);
    let dt = g(&latest, "ts") - g(&e, "ts");
    if dt <= 0 || g(&latest, "uptime") < g(&e, "uptime") {
        return Ok(Value::Null);
    }
    let per_h = |k: &str| (g(&latest, k) - g(&e, k)) as f64 * 3600.0 / dt as f64;
    Ok(json!({
        "span_s": dt,
        "duty_tx": (g(&latest, "airtime_tx") - g(&e, "airtime_tx")) as f64 / (dt as f64 * 1000.0),
        "duty_rx": (g(&latest, "airtime_rx") - g(&e, "airtime_rx")) as f64 / (dt as f64 * 1000.0),
        "rx_per_h": per_h("rx_total"),
        "dup_per_h": per_h("rx_dup"),
        "crc_per_h": per_h("crc_err"),
        "tx_per_h": per_h("tx_total"),
    }))
}

fn repeater_row(db: &Connection, mut r: Value) -> rusqlite::Result<Value> {
    let pk = r["pub"].as_str().unwrap_or_default().to_string();
    if let Some(s) = r["status"].as_str() {
        r["status"] = serde_json::from_str(s).unwrap_or(Value::Null);
    }
    // Kind: what the node reports itself; the hub's guess from the callsign
    // until its first STATUS.
    if let Some(role) = r["status"]["role"].as_str().filter(|k| matches!(*k, "repeater" | "hotspot")) {
        r["kind"] = json!(role);
    }
    // Position: the repeater's own status, else its own signed advert.
    if r["lat"].is_null()
        && let Some((lat, lon)) = db
            .query_row("SELECT lat, lon FROM nodes WHERE pub = ?1 AND lat IS NOT NULL", [&pk], |x| {
                Ok((x.get::<_, f64>(0)?, x.get::<_, f64>(1)?))
            })
            .optional()?
    {
        r["lat"] = json!(lat);
        r["lon"] = json!(lon);
    }
    r["rates_1h"] = rates(db, &pk, 3600)?;
    r["heard_direct"] = json!(count(
        db,
        "SELECT COUNT(*) FROM heard WHERE repeater = ?1 AND hops = 0 AND last_heard >= ?2",
        params![pk, now() - DAY]
    )?);
    Ok(r)
}

const REPEATER_COLS: &str = "pub, callsign, kind, roles_allowed, online, roles, session_since, last_seen, last_down, \
     down_reason, sessions, name, fw, lat, lon, uptime, status_ts, status";

async fn repeaters(State(st): State<Shared>) -> Response {
    query(st, |db| {
        let list = rows(db, &format!("SELECT {REPEATER_COLS} FROM repeaters WHERE allowlisted = 1 ORDER BY callsign"), [])?;
        let list = list.into_iter().map(|r| repeater_row(db, r)).collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!(list))
    })
    .await
}

fn valid_pub(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn repeater(State(st): State<Shared>, Path(pk): Path<String>) -> Response {
    let pk = pk.to_ascii_lowercase();
    if !valid_pub(&pk) {
        return (StatusCode::BAD_REQUEST, "bad key").into_response();
    }
    query(st, move |db| {
        let r = db.query_row(
            &format!("SELECT {REPEATER_COLS} FROM repeaters WHERE pub = ?1 AND allowlisted = 1"),
            [&pk],
            row_json,
        )?;
        let mut r = repeater_row(db, r)?;
        let t = now();
        r["history"] = json!(rows(
            db,
            "SELECT ts, uptime, rx_total, rx_dup, crc_err, tx_total, airtime_tx, airtime_rx, neighbours
             FROM status_history WHERE repeater = ?1 AND ts >= ?2 ORDER BY ts",
            params![pk, t - DAY]
        )?);
        r["heard"] = json!(rows(
            db,
            "SELECT h.node AS pub, h.hops, h.rssi, h.snr, h.last_heard, h.count, n.name, n.type, n.lat, n.lon
             FROM heard h LEFT JOIN nodes n ON n.pub = h.node
             WHERE h.repeater = ?1 AND h.last_heard >= ?2 ORDER BY h.hops, h.snr DESC",
            params![pk, t - 7 * DAY]
        )?);
        r["sessions_log"] = json!(rows(
            db,
            "SELECT ts, event, detail FROM sessions_log WHERE repeater = ?1 ORDER BY id DESC LIMIT 20",
            [&pk]
        )?);
        Ok(r)
    })
    .await
}

async fn nodes(State(st): State<Shared>) -> Response {
    query(st, |db| {
        let list = rows(
            db,
            "SELECT pub, name, type, lat, lon, last_seen, adverts FROM nodes WHERE last_seen >= ?1
             ORDER BY last_seen DESC LIMIT 3000",
            [now() - 7 * DAY],
        )?;
        Ok(json!(list))
    })
    .await
}

async fn links(State(st): State<Shared>) -> Response {
    query(st, |db| {
        // A link heard before either end last moved (with a few minutes'
        // slack for report timing) says nothing about where they are now.
        let list = rows(
            db,
            "SELECT h.repeater, h.node, h.rssi, h.snr, h.last_heard, h.count FROM heard h
             LEFT JOIN nodes n ON n.pub = h.node LEFT JOIN nodes r ON r.pub = h.repeater
             WHERE h.hops = 0 AND h.last_heard >= ?1
               AND h.last_heard >= COALESCE(n.moved_ts, 0) - 300 AND h.last_heard >= COALESCE(r.moved_ts, 0) - 300",
            [now() - 2 * DAY],
        )?;
        Ok(json!(list))
    })
    .await
}

#[derive(Deserialize)]
struct MsgQuery {
    limit: Option<u32>,
    before: Option<i64>,
}

async fn messages(State(st): State<Shared>, Query(q): Query<MsgQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let before = q.before.unwrap_or(i64::MAX);
    query(st, move |db| {
        let mut list = rows(
            db,
            // Blocked senders' messages are not shown (the hub stops keeping
            // them once blocked; this hides what came before).
            "SELECT hash, channel, sender, text, sent_ts, first_heard FROM messages m
             WHERE first_heard < ?1 AND NOT EXISTS (
                 SELECT 1 FROM blocks b WHERE b.kind = 'name' AND b.value = m.sender AND (b.expires_ts IS NULL OR b.expires_ts > ?3))
             ORDER BY first_heard DESC LIMIT ?2",
            params![before, limit, now()],
        )?;
        let mut heard: HashMap<String, Vec<Value>> = HashMap::new();
        if let (Some(first), Some(last)) = (list.last(), list.first()) {
            let lo = first["first_heard"].as_i64().unwrap_or(0);
            let hi = last["first_heard"].as_i64().unwrap_or(0);
            for r in rows(
                db,
                "SELECT r.hash, p.callsign AS rep, r.rssi, r.snr, r.hops FROM receptions r
                 JOIN messages m ON m.hash = r.hash
                 LEFT JOIN repeaters p ON p.pub = r.repeater
                 WHERE m.first_heard BETWEEN ?1 AND ?2",
                params![lo, hi],
            )? {
                let h = r["hash"].as_str().unwrap_or_default().to_string();
                heard.entry(h).or_default().push(r);
            }
        }
        for m in &mut list {
            let h = m["hash"].as_str().unwrap_or_default().to_string();
            m["heard"] = json!(heard.remove(&h).unwrap_or_default());
        }
        Ok(json!(list))
    })
    .await
}

async fn activity(State(st): State<Shared>) -> Response {
    query(st, |db| {
        let t = now();
        let start = (t / 3600 - 23) * 3600;
        let bucket = |sql: &str| -> rusqlite::Result<Vec<i64>> {
            let mut v = vec![0i64; 24];
            let mut stmt = db.prepare_cached(sql)?;
            let it = stmt.query_map([start], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
            for x in it {
                let (h, n) = x?;
                let i = (h * 3600 - start) / 3600;
                if (0..24).contains(&i) {
                    v[i as usize] = n;
                }
            }
            Ok(v)
        };
        let mut offers = Map::new();
        for r in rows(db, "SELECT outcome, COUNT(*) AS n FROM offers WHERE ts >= ?1 GROUP BY 1", [t - DAY])? {
            if let (Some(k), Some(n)) = (r["outcome"].as_str(), r.get("n")) {
                offers.insert(k.to_string(), n.clone());
            }
        }
        Ok(json!({
            "start": start,
            "heard": bucket("SELECT ts / 3600, COUNT(*) FROM frames WHERE ts >= ?1 AND backbone = 0 GROUP BY 1")?,
            "forwarded": bucket("SELECT ts / 3600, COUNT(*) FROM frames WHERE ts >= ?1 AND backbone = 0 AND disposition = 0 GROUP BY 1")?,
            "bridged": bucket("SELECT ts / 3600, COUNT(*) FROM bridged WHERE ts >= ?1 GROUP BY 1")?,
            "messages": bucket("SELECT first_heard / 3600, COUNT(*) FROM messages WHERE first_heard >= ?1 GROUP BY 1")?,
            "recent_bridged": rows(
                db,
                "SELECT b.ts, b.hash, s.callsign AS src, d.callsign AS dst, b.route, b.ptype FROM bridged b
                 LEFT JOIN repeaters s ON s.pub = b.src LEFT JOIN repeaters d ON d.pub = b.dst
                 ORDER BY b.id DESC LIMIT 50",
                [],
            )?,
            // Offered frames the hub did not bridge, and why.
            "recent_skipped": rows(
                db,
                "SELECT o.ts, o.hash, s.callsign AS src, o.route, o.ptype, o.own, o.outcome, o.detail FROM offers o
                 LEFT JOIN repeaters s ON s.pub = o.src WHERE o.outcome != 'bridged' ORDER BY o.id DESC LIMIT 50",
                [],
            )?,
            "offers_24h": offers,
            "recent_sessions": rows(
                db,
                "SELECT l.ts, p.callsign AS rep, l.event, l.detail FROM sessions_log l
                 LEFT JOIN repeaters p ON p.pub = l.repeater ORDER BY l.id DESC LIMIT 30",
                [],
            )?,
        }))
    })
    .await
}

/// Every channel the network carries (hub.toml's and the admins' rooms, as
/// the hub publishes them), with the MeshCore app's channel link and its QR.
async fn channels(State(st): State<Shared>) -> Response {
    query(st, |db| {
        let raw: Option<String> = db.query_row("SELECT v FROM meta WHERE k = 'channels'", [], |r| r.get(0)).optional()?;
        let list: Vec<Value> = raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let out: Vec<Value> = list
            .iter()
            .map(|c| {
                let name = c["name"].as_str().unwrap_or_default();
                let key = c["key"].as_str().unwrap_or_default();
                // docs/qr_codes.md in MeshCore; the app takes 16-byte keys only.
                let uri = (key.len() == 32).then(|| format!("meshcore://channel/add?name={}&secret={key}", query_component(name)));
                json!({
                    "name": name, "key": key, "hash": c["hash"], "hashtag": name.starts_with('#'),
                    "uri": uri, "qr": uri.as_deref().map(qr_svg),
                })
            })
            .collect();
        Ok(json!(out))
    })
    .await
}

/// A query value the way the MeshCore app (Dart's `Uri`) writes it: letters,
/// digits and `-._~` as they are, space as `+`, everything else `%XX`.
fn query_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// An inline SVG QR code (no XML prolog, so it can go straight into HTML).
fn qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    let Ok(code) = qrcode::QrCode::new(data.as_bytes()) else { return String::new() };
    let s = code.render::<svg::Color>().min_dimensions(176, 176).dark_color(svg::Color("#000")).light_color(svg::Color("#fff")).build();
    s.find("<svg").map(|i| s[i..].to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_links_match_the_app() {
        assert_eq!(query_component("#ora"), "%23ora");
        assert_eq!(query_component("Public"), "Public");
        assert_eq!(query_component("a b~c"), "a+b~c");
        let svg = qr_svg("meshcore://channel/add?name=%23ora&secret=d476062ced6481b5733e7cd1b196ed89");
        assert!(svg.starts_with("<svg") && svg.contains("</svg>"));
    }
}
