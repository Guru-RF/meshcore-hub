//! Room admins: invite only, signing in with a passkey (WebAuthn), no
//! passwords.
//!
//! Admins manage the network's rooms and blocked users. Those go into the
//! hub's database (`rooms`, `blocks`); the hub reads them, applies the blocks
//! itself and pushes the set to every backbone node with POLICY
//! (docs/backbone.md, "Rooms and blocks"). Accounts, passkeys, invites,
//! sessions and the audit log live in the portal's own database, which
//! nothing else reads.
//!
//! Every request that changes something must come from the portal's own
//! origin (the `Origin` header), on top of a `SameSite=Strict` session cookie.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{
    CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::Shared;
use crate::api::rows;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    user_id TEXT NOT NULL UNIQUE,
    created_ts INTEGER NOT NULL,
    invited_by TEXT,
    last_login INTEGER
);
CREATE TABLE IF NOT EXISTS passkeys (
    cred_id TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    passkey TEXT NOT NULL,
    created_ts INTEGER NOT NULL,
    last_used INTEGER
);
CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL COLLATE NOCASE,
    invited_by TEXT NOT NULL,
    created_ts INTEGER NOT NULL,
    expires_ts INTEGER NOT NULL,
    used_ts INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    created_ts INTEGER NOT NULL,
    expires_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    admin TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
"#;

const INVITE_DAYS: i64 = 7;
const SESSION_S: i64 = 12 * 3600;
const CEREMONY: Duration = Duration::from_secs(300);
const MAX_CEREMONIES: usize = 10_000;
const MAX_ROOMS: i64 = 32;
const MAX_BLOCKS: i64 = 256;

enum Ceremony {
    Register { state: PasskeyRegistration, email: String, invite: String, user_id: Uuid },
    Login(DiscoverableAuthentication),
}

pub struct Admin {
    webauthn: Webauthn,
    /// The portal's own origin, e.g. `https://be.mesh73.net`.
    origin: String,
    db: PathBuf,
    ceremonies: Mutex<HashMap<String, (Instant, Ceremony)>>,
}

impl Admin {
    pub fn new(db: PathBuf, origin: &str) -> Result<Self> {
        let url = Url::parse(origin).with_context(|| format!("--origin {origin:?}"))?;
        let rp_id = url.host_str().context("--origin needs a host name")?.to_string();
        let webauthn = WebauthnBuilder::new(&rp_id, &url)?.rp_name("MeshCore Backbone").build()?;
        let a = Admin { webauthn, origin: origin.trim_end_matches('/').to_string(), db, ceremonies: Mutex::new(HashMap::new()) };
        a.open().with_context(|| format!("opening {}", a.db.display()))?;
        Ok(a)
    }

    fn open(&self) -> rusqlite::Result<Connection> {
        open_admin_db(&self.db)
    }

    fn secure(&self) -> bool {
        self.origin.starts_with("https://")
    }

    /// `__Host-` binds the cookie to this exact host; it needs `Secure`,
    /// which a plain-http development origin can't have.
    fn cookie_name(&self) -> &'static str {
        if self.secure() { "__Host-mch_admin" } else { "mch_admin" }
    }

    fn put(&self, c: Ceremony) -> Result<String, ApiError> {
        let mut m = self.ceremonies.lock().unwrap();
        m.retain(|_, (t, _)| t.elapsed() < CEREMONY);
        if m.len() >= MAX_CEREMONIES {
            return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "too many sign-ins at once, try again in a minute".into()));
        }
        let id = token();
        m.insert(id.clone(), (Instant::now(), c));
        Ok(id)
    }

    fn take(&self, id: &str) -> Result<Ceremony, ApiError> {
        match self.ceremonies.lock().unwrap().remove(id) {
            Some((t, c)) if t.elapsed() < CEREMONY => Ok(c),
            _ => Err(bad("this passkey request expired, start again")),
        }
    }
}

fn open_admin_db(path: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.pragma_update(None, "foreign_keys", true)?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/admin/invite", post(invite_check))
        .route("/api/admin/register/start", post(register_start))
        .route("/api/admin/register/finish", post(register_finish))
        .route("/api/admin/login/start", post(login_start))
        .route("/api/admin/login/finish", post(login_finish))
        .route("/api/admin/logout", post(logout))
        .route("/api/admin/state", get(state))
        .route("/api/admin/messages", get(messages))
        .route("/api/admin/rooms", post(room_add))
        .route("/api/admin/rooms/{name}", delete(room_remove))
        .route("/api/admin/blocks", post(block_add))
        .route("/api/admin/blocks/{id}", delete(block_remove))
        .route("/api/admin/invites", post(invite_create))
        .route("/api/admin/invites/{id}", delete(invite_revoke))
        .route("/api/admin/admins/{id}", delete(admin_remove))
}

// ------------------------------------------------------------- plumbing --

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (self.0, Json(json!({"error": self.1}))).into_response();
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::warn!("admin db: {e}");
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "database unavailable".into())
    }
}

impl From<WebauthnError> for ApiError {
    fn from(e: WebauthnError) -> Self {
        tracing::info!("admin passkey: {e}");
        bad("the passkey could not be verified")
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

type ApiResult<T = Response> = Result<T, ApiError>;

fn ok(v: Value) -> Response {
    let mut r = Json(v).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 32 random bytes, base64url.
fn token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random source");
    B64.encode(b)
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Changes must come from the portal's own pages.
fn same_origin(st: &Shared, h: &HeaderMap) -> ApiResult<()> {
    match h.get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
        Some(o) if o == st.admin.origin => Ok(()),
        _ => Err(ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into())),
    }
}

fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

struct Me {
    id: i64,
    email: String,
}

/// The signed-in admin.
fn me(st: &Shared, h: &HeaderMap) -> ApiResult<Me> {
    let unauth = || ApiError(StatusCode::UNAUTHORIZED, "sign in first".into());
    let t = cookie(h, st.admin.cookie_name()).ok_or_else(unauth)?;
    let db = st.admin.open()?;
    db.query_row(
        "SELECT a.id, a.email FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ?1 AND s.expires_ts > ?2",
        params![sha(t), now()],
        |r| Ok(Me { id: r.get(0)?, email: r.get(1)? }),
    )
    .optional()?
    .ok_or_else(unauth)
}

/// A change by `me`: checked for origin and session.
fn admin_change(st: &Shared, h: &HeaderMap) -> ApiResult<Me> {
    same_origin(st, h)?;
    me(st, h)
}

fn audit(db: &Connection, who: &str, action: &str, detail: &str) -> rusqlite::Result<()> {
    db.execute("INSERT INTO audit (ts, admin, action, detail) VALUES (?1, ?2, ?3, ?4)", params![now(), who, action, detail])?;
    Ok(())
}

/// Start a session for `admin_id` and answer with its cookie.
fn signed_in(st: &Shared, db: &Connection, admin_id: i64, email: &str) -> ApiResult {
    let t = token();
    let n = now();
    db.execute("DELETE FROM sessions WHERE expires_ts <= ?1", [n])?;
    db.execute(
        "INSERT INTO sessions (token_hash, admin_id, created_ts, expires_ts) VALUES (?1, ?2, ?3, ?4)",
        params![sha(&t), admin_id, n, n + SESSION_S],
    )?;
    db.execute("UPDATE admins SET last_login = ?2 WHERE id = ?1", params![admin_id, n])?;
    let mut r = ok(json!({"email": email}));
    let c = format!(
        "{}={t}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_S}{}",
        st.admin.cookie_name(),
        if st.admin.secure() { "; Secure" } else { "" }
    );
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&c).expect("cookie"));
    Ok(r)
}

/// The hub's database, for the rooms and blocks.
fn hub_db(st: &Shared) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(&st.db, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(Duration::from_secs(5))?;
    Ok(db)
}

fn valid_email(e: &str) -> bool {
    e.len() <= 254 && e.split_once('@').is_some_and(|(u, d)| !u.is_empty() && d.contains('.')) && !e.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn create_invite(db: &Connection, origin: &str, email: &str, by: &str) -> rusqlite::Result<(String, i64)> {
    let t = token();
    let n = now();
    let expires = n + INVITE_DAYS * 86_400;
    db.execute(
        "INSERT INTO invites (token_hash, email, invited_by, created_ts, expires_ts) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![sha(&t), email, by, n, expires],
    )?;
    audit(db, by, "invite", email)?;
    // In the fragment: never sent to the server, so never in a log.
    Ok((format!("{origin}/admin#invite={t}"), expires))
}

/// `meshcore-portal invite <email>`: the first admin, or a way back in.
pub fn cli_invite(admin_db: &Path, origin: &str, email: &str) -> Result<()> {
    anyhow::ensure!(valid_email(email), "{email:?} is not an email address");
    let db = open_admin_db(admin_db).with_context(|| format!("opening {}", admin_db.display()))?;
    let (link, expires) = create_invite(&db, origin.trim_end_matches('/'), email, "command line")?;
    println!("Invite for {email}, valid {INVITE_DAYS} days (until unix {expires}). Open it to create a passkey:\n{link}");
    Ok(())
}

// --------------------------------------------------------- invites, keys --

#[derive(Deserialize)]
struct TokenReq {
    token: String,
}

/// An open invite: (token hash, email).
fn open_invite(db: &Connection, t: &str) -> ApiResult<(String, String)> {
    let h = sha(t);
    db.query_row(
        "SELECT email FROM invites WHERE token_hash = ?1 AND used_ts IS NULL AND expires_ts > ?2",
        params![h, now()],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|e| (h, e))
    .ok_or_else(|| bad("this invite is not valid any more: ask an admin for a new one"))
}

async fn invite_check(State(st): State<Shared>, h: HeaderMap, Json(q): Json<TokenReq>) -> ApiResult {
    same_origin(&st, &h)?;
    let db = st.admin.open()?;
    let (_, email) = open_invite(&db, &q.token)?;
    let existing: bool = db.query_row("SELECT COUNT(*) > 0 FROM admins WHERE email = ?1", [&email], |r| r.get(0))?;
    Ok(ok(json!({"email": email, "existing": existing})))
}

async fn register_start(State(st): State<Shared>, h: HeaderMap, Json(q): Json<TokenReq>) -> ApiResult {
    same_origin(&st, &h)?;
    let db = st.admin.open()?;
    let (invite, email) = open_invite(&db, &q.token)?;
    let existing: Option<(i64, String)> =
        db.query_row("SELECT id, user_id FROM admins WHERE email = ?1", [&email], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let (user_id, exclude) = match existing {
        Some((id, uid)) => {
            let uid = Uuid::parse_str(&uid).map_err(|_| bad("stored user id is damaged"))?;
            let creds: Vec<CredentialID> = passkeys_of(&db, id)?.iter().map(|p| p.cred_id().clone()).collect();
            (uid, Some(creds))
        }
        None => {
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("OS random source");
            (Uuid::from_bytes(b), None)
        }
    };
    let (ccr, state) = st.admin.webauthn.start_passkey_registration(user_id, &email, &email, exclude)?;
    // Ask for a discoverable credential, so signing in needs no email.
    let mut options = serde_json::to_value(&ccr).map_err(|_| bad("options"))?;
    if let Some(sel) = options.pointer_mut("/publicKey/authenticatorSelection").and_then(Value::as_object_mut) {
        sel.insert("residentKey".into(), json!("required"));
        sel.insert("requireResidentKey".into(), json!(true));
    }
    let ceremony = st.admin.put(Ceremony::Register { state, email: email.clone(), invite, user_id })?;
    Ok(ok(json!({"ceremony": ceremony, "options": options, "email": email})))
}

#[derive(Deserialize)]
struct RegisterFinish {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

async fn register_finish(State(st): State<Shared>, h: HeaderMap, Json(q): Json<RegisterFinish>) -> ApiResult {
    same_origin(&st, &h)?;
    let Ceremony::Register { state, email, invite, user_id } = st.admin.take(&q.ceremony)? else {
        return Err(bad("not a registration"));
    };
    let pk = st.admin.webauthn.finish_passkey_registration(&q.credential, &state)?;
    let mut db = st.admin.open()?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let n = now();
    // The invite can be used once; check again inside the transaction.
    let by: Option<String> = tx
        .query_row(
            "SELECT invited_by FROM invites WHERE token_hash = ?1 AND used_ts IS NULL AND expires_ts > ?2",
            params![invite, n],
            |r| r.get(0),
        )
        .optional()?;
    let Some(by) = by else { return Err(bad("this invite was used or withdrawn meanwhile")) };
    tx.execute(
        "INSERT INTO admins (email, user_id, created_ts, invited_by) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (email) DO NOTHING",
        params![email, user_id.to_string(), n, by],
    )?;
    let admin_id: i64 = tx.query_row("SELECT id FROM admins WHERE email = ?1", [&email], |r| r.get(0))?;
    let json = serde_json::to_string(&pk).map_err(|_| bad("passkey"))?;
    tx.execute(
        "INSERT INTO passkeys (cred_id, admin_id, passkey, created_ts) VALUES (?1, ?2, ?3, ?4)",
        params![B64.encode(pk.cred_id()), admin_id, json, n],
    )?;
    tx.execute("UPDATE invites SET used_ts = ?2 WHERE token_hash = ?1", params![invite, n])?;
    audit(&tx, &email, "passkey added", &format!("invited by {by}"))?;
    tx.commit()?;
    tracing::info!("admin {email}: passkey registered");
    signed_in(&st, &db, admin_id, &email)
}

fn passkeys_of(db: &Connection, admin_id: i64) -> rusqlite::Result<Vec<Passkey>> {
    let mut stmt = db.prepare("SELECT passkey FROM passkeys WHERE admin_id = ?1")?;
    let out = stmt
        .query_map([admin_id], |r| r.get::<_, String>(0))?
        .filter_map(|j| j.ok().and_then(|j| serde_json::from_str::<Passkey>(&j).ok()))
        .collect();
    Ok(out)
}

async fn login_start(State(st): State<Shared>, h: HeaderMap) -> ApiResult {
    same_origin(&st, &h)?;
    let (rcr, state) = st.admin.webauthn.start_discoverable_authentication()?;
    let ceremony = st.admin.put(Ceremony::Login(state))?;
    Ok(ok(json!({"ceremony": ceremony, "options": rcr})))
}

#[derive(Deserialize)]
struct LoginFinish {
    ceremony: String,
    credential: PublicKeyCredential,
}

async fn login_finish(State(st): State<Shared>, h: HeaderMap, Json(q): Json<LoginFinish>) -> ApiResult {
    same_origin(&st, &h)?;
    let Ceremony::Login(state) = st.admin.take(&q.ceremony)? else {
        return Err(bad("not a sign-in"));
    };
    let (user_id, _) = st.admin.webauthn.identify_discoverable_authentication(&q.credential)?;
    let db = st.admin.open()?;
    let unknown = || ApiError(StatusCode::UNAUTHORIZED, "this passkey is not registered here".into());
    let (admin_id, email): (i64, String) = db
        .query_row("SELECT id, email FROM admins WHERE user_id = ?1", [user_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(unknown)?;
    let mut keys = passkeys_of(&db, admin_id)?;
    if keys.is_empty() {
        return Err(unknown());
    }
    let creds: Vec<DiscoverableKey> = keys.iter().map(DiscoverableKey::from).collect();
    let res = st.admin.webauthn.finish_discoverable_authentication(&q.credential, state, &creds)?;
    // Keep the signature counter current (it detects cloned authenticators).
    for k in keys.iter_mut() {
        if k.cred_id() == res.cred_id() {
            k.update_credential(&res);
            let json = serde_json::to_string(&*k).map_err(|_| bad("passkey"))?;
            db.execute(
                "UPDATE passkeys SET passkey = ?2, last_used = ?3 WHERE cred_id = ?1",
                params![B64.encode(k.cred_id()), json, now()],
            )?;
        }
    }
    signed_in(&st, &db, admin_id, &email)
}

async fn logout(State(st): State<Shared>, h: HeaderMap) -> ApiResult {
    same_origin(&st, &h)?;
    if let Some(t) = cookie(&h, st.admin.cookie_name()) {
        st.admin.open()?.execute("DELETE FROM sessions WHERE token_hash = ?1", [sha(t)])?;
    }
    let mut r = ok(json!({}));
    let c = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        st.admin.cookie_name(),
        if st.admin.secure() { "; Secure" } else { "" }
    );
    r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&c).expect("cookie"));
    Ok(r)
}

// ------------------------------------------------------------ the state --

async fn state(State(st): State<Shared>, h: HeaderMap) -> ApiResult {
    let me = me(&st, &h)?;
    let adb = st.admin.open()?;
    let hdb = hub_db(&st)?;
    let t = now();
    let version: Option<String> = hdb.query_row("SELECT v FROM meta WHERE k = 'policy_version'", [], |r| r.get(0)).optional()?;
    let mut nodes = rows(
        &hdb,
        "SELECT callsign, kind, online, status FROM repeaters WHERE allowlisted = 1 ORDER BY online DESC, callsign",
        [],
    )?;
    for n in nodes.iter_mut() {
        let s: Value = n["status"].as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
        n["policy"] = s["policy"].clone();
        if let Some(role) = s["role"].as_str() {
            n["kind"] = json!(role);
        }
        n.as_object_mut().map(|o| o.remove("status"));
    }
    Ok(ok(json!({
        "me": {"id": me.id, "email": me.email},
        "policy_version": version.and_then(|v| v.parse::<u64>().ok()),
        "rooms": rows(&hdb, "SELECT name, created_ts, created_by FROM rooms ORDER BY name", [])?,
        "blocks": rows(&hdb, "SELECT id, kind, value, reason, created_ts, created_by, expires_ts FROM blocks ORDER BY id DESC", [])?,
        "senders": rows(
            &hdb,
            "SELECT m.sender, COUNT(*) AS n, MAX(m.first_heard) AS last, GROUP_CONCAT(DISTINCT m.channel) AS channels,
                    EXISTS (SELECT 1 FROM blocks b WHERE b.kind = 'name' AND b.value = m.sender
                            AND (b.expires_ts IS NULL OR b.expires_ts > ?2)) AS blocked
             FROM messages m WHERE m.first_heard >= ?1 AND m.sender IS NOT NULL
             GROUP BY m.sender COLLATE NOCASE ORDER BY last DESC LIMIT 100",
            params![t - 7 * 86_400, t],
        )?,
        "nodes": nodes,
        "admins": rows(
            &adb,
            "SELECT a.id, a.email, a.created_ts, a.invited_by, a.last_login, COUNT(p.cred_id) AS passkeys
             FROM admins a LEFT JOIN passkeys p ON p.admin_id = a.id GROUP BY a.id ORDER BY a.email",
            [],
        )?,
        "invites": rows(
            &adb,
            "SELECT id, email, invited_by, created_ts, expires_ts FROM invites WHERE used_ts IS NULL AND expires_ts > ?1 ORDER BY id DESC",
            [t],
        )?,
        "audit": rows(&adb, "SELECT ts, admin, action, detail FROM audit ORDER BY id DESC LIMIT 100", [])?,
        "limits": {"rooms": MAX_ROOMS, "blocks": MAX_BLOCKS},
    })))
}

#[derive(Deserialize)]
struct MsgQuery {
    limit: Option<u32>,
    before: Option<i64>,
    channel: Option<String>,
}

/// Every decoded channel's messages, blocked senders included (marked).
async fn messages(State(st): State<Shared>, h: HeaderMap, axum::extract::Query(q): axum::extract::Query<MsgQuery>) -> ApiResult {
    me(&st, &h)?;
    let hdb = hub_db(&st)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let channel = q.channel.filter(|c| !c.is_empty());
    let list = crate::api::message_list(&hdb, q.before.unwrap_or(i64::MAX), limit, channel.as_deref(), false)?;
    Ok(ok(json!(list)))
}

// --------------------------------------------------------- rooms, blocks --

/// A room as the MeshCore app keys it: `#`, then lowercase a-z, 0-9 and
/// single dashes, 2-31 bytes (the app lowercases what is typed).
fn room_name(input: &str) -> Option<String> {
    let s = input.trim().trim_start_matches('#').to_ascii_lowercase();
    let ok = !s.is_empty()
        && s.len() <= 30
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--");
    ok.then(|| format!("#{s}"))
}

#[derive(Deserialize)]
struct RoomReq {
    name: String,
}

async fn room_add(State(st): State<Shared>, h: HeaderMap, Json(q): Json<RoomReq>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let name = room_name(&q.name).ok_or_else(|| bad("a room name is a-z, 0-9 and single dashes, at most 30 characters"))?;
    let hdb = hub_db(&st)?;
    let n: i64 = hdb.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get(0))?;
    if n >= MAX_ROOMS {
        return Err(bad(format!("at most {MAX_ROOMS} rooms")));
    }
    let added = hdb.execute(
        "INSERT INTO rooms (name, created_ts, created_by) VALUES (?1, ?2, ?3) ON CONFLICT (name) DO NOTHING",
        params![name, now(), me.email],
    )?;
    if added == 0 {
        return Err(bad(format!("{name} is already a room")));
    }
    audit(&st.admin.open()?, &me.email, "room added", &name)?;
    Ok(ok(json!({"name": name})))
}

async fn room_remove(State(st): State<Shared>, h: HeaderMap, UrlPath(name): UrlPath<String>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let name = room_name(&name).ok_or_else(|| bad("no such room"))?;
    if hub_db(&st)?.execute("DELETE FROM rooms WHERE name = ?1", [&name])? == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "no such room".into()));
    }
    audit(&st.admin.open()?, &me.email, "room removed", &name)?;
    Ok(ok(json!({})))
}

#[derive(Deserialize)]
struct BlockReq {
    kind: String,
    value: String,
    #[serde(default)]
    reason: String,
    /// 0 or absent: until removed.
    #[serde(default)]
    days: u32,
}

async fn block_add(State(st): State<Shared>, h: HeaderMap, Json(q): Json<BlockReq>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let hdb = hub_db(&st)?;
    let value = q.value.trim().to_string();
    // Never a backbone node: one typo would silence it everywhere.
    let ours: bool = match q.kind.as_str() {
        "name" => {
            if value.is_empty() || value.len() > 31 || value.chars().any(char::is_control) {
                return Err(bad("a name is 1 to 31 bytes"));
            }
            hdb.query_row(
                "SELECT COUNT(*) > 0 FROM repeaters WHERE allowlisted = 1 AND (lower(callsign) = lower(?1) OR lower(name) = lower(?1))",
                [&value],
                |r| r.get(0),
            )?
        }
        "key" => {
            if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad("a key is 64 hex characters"));
            }
            hdb.query_row("SELECT COUNT(*) > 0 FROM repeaters WHERE allowlisted = 1 AND pub = lower(?1)", [&value], |r| r.get(0))?
        }
        _ => return Err(bad("kind is name or key")),
    };
    if ours {
        return Err(bad(format!("{value} is a backbone node: it can't be blocked")));
    }
    let value = if q.kind == "key" { value.to_ascii_lowercase() } else { value };
    let reason: String = q.reason.trim().chars().take(200).collect();
    let n = now();
    let active: i64 = hdb.query_row("SELECT COUNT(*) FROM blocks WHERE expires_ts IS NULL OR expires_ts > ?1", [n], |r| r.get(0))?;
    if active >= MAX_BLOCKS {
        return Err(bad(format!("at most {MAX_BLOCKS} blocks")));
    }
    let expires = (q.days > 0).then(|| n + q.days.min(3650) as i64 * 86_400);
    // A block on the same name or key replaces the earlier one.
    hdb.execute(
        "INSERT INTO blocks (kind, value, reason, created_ts, created_by, expires_ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (kind, value) DO UPDATE SET reason = excluded.reason, created_ts = excluded.created_ts,
             created_by = excluded.created_by, expires_ts = excluded.expires_ts",
        params![q.kind, value, reason, n, me.email, expires],
    )?;
    let until = expires.map_or("until removed".to_string(), |_| format!("{} days", q.days));
    audit(&st.admin.open()?, &me.email, "blocked", &format!("{} {value}, {until}{}", q.kind, if reason.is_empty() { String::new() } else { format!(": {reason}") }))?;
    Ok(ok(json!({})))
}

async fn block_remove(State(st): State<Shared>, h: HeaderMap, UrlPath(id): UrlPath<i64>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let hdb = hub_db(&st)?;
    let row: Option<(String, String)> =
        hdb.query_row("SELECT kind, value FROM blocks WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let Some((kind, value)) = row else { return Err(ApiError(StatusCode::NOT_FOUND, "no such block".into())) };
    hdb.execute("DELETE FROM blocks WHERE id = ?1", [id])?;
    audit(&st.admin.open()?, &me.email, "unblocked", &format!("{kind} {value}"))?;
    Ok(ok(json!({})))
}

// ---------------------------------------------------------------- admins --

#[derive(Deserialize)]
struct InviteReq {
    email: String,
}

async fn invite_create(State(st): State<Shared>, h: HeaderMap, Json(q): Json<InviteReq>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let email = q.email.trim().to_string();
    if !valid_email(&email) {
        return Err(bad("that is not an email address"));
    }
    let (link, expires) = create_invite(&st.admin.open()?, &st.admin.origin, &email, &me.email)?;
    Ok(ok(json!({"email": email, "link": link, "expires_ts": expires})))
}

async fn invite_revoke(State(st): State<Shared>, h: HeaderMap, UrlPath(id): UrlPath<i64>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let db = st.admin.open()?;
    let email: Option<String> = db.query_row("SELECT email FROM invites WHERE id = ?1 AND used_ts IS NULL", [id], |r| r.get(0)).optional()?;
    let Some(email) = email else { return Err(ApiError(StatusCode::NOT_FOUND, "no such invite".into())) };
    db.execute("DELETE FROM invites WHERE id = ?1", [id])?;
    audit(&db, &me.email, "invite withdrawn", &email)?;
    Ok(ok(json!({})))
}

async fn admin_remove(State(st): State<Shared>, h: HeaderMap, UrlPath(id): UrlPath<i64>) -> ApiResult {
    let me = admin_change(&st, &h)?;
    let db = st.admin.open()?;
    let email: Option<String> = db.query_row("SELECT email FROM admins WHERE id = ?1", [id], |r| r.get(0)).optional()?;
    let Some(email) = email else { return Err(ApiError(StatusCode::NOT_FOUND, "no such admin".into())) };
    let n: i64 = db.query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0))?;
    if n <= 1 {
        return Err(bad("the last admin can't be removed"));
    }
    // Passkeys and sessions go with it (ON DELETE CASCADE).
    db.execute("DELETE FROM admins WHERE id = ?1", [id])?;
    audit(&db, &me.email, "admin removed", &email)?;
    Ok(ok(json!({"self": id == me.id})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_names_as_the_app_keys_them() {
        assert_eq!(room_name("pra").as_deref(), Some("#pra"));
        assert_eq!(room_name(" #SysOps ").as_deref(), Some("#sysops"));
        assert_eq!(room_name("be-west").as_deref(), Some("#be-west"));
        for bad in ["", "#", "a--b", "-a", "a-", "a b", "é", "#a#b", &"x".repeat(31)] {
            assert_eq!(room_name(bad), None, "{bad:?}");
        }
        assert_eq!(room_name(&"x".repeat(30)).map(|s| s.len()), Some(31));
    }

    #[test]
    fn emails_and_cookies() {
        assert!(valid_email("ure@moreorless.be"));
        assert!(!valid_email("ure@localhost") && !valid_email("no at") && !valid_email("@x.be"));
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; __Host-mch_admin=tok; b=2"));
        assert_eq!(cookie(&h, "__Host-mch_admin"), Some("tok"));
        assert_eq!(cookie(&h, "mch_admin"), None);
    }

    #[test]
    fn invites_are_one_link_per_email_and_hashed() {
        let dir = std::env::temp_dir().join(format!("portal-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.db");
        let _ = std::fs::remove_file(&path);
        let db = open_admin_db(&path).unwrap();
        let (link, _) = create_invite(&db, "https://be.mesh73.net", "ure@moreorless.be", "command line").unwrap();
        let t = link.split_once("#invite=").unwrap().1;
        assert_eq!(open_invite(&db, t).unwrap().1, "ure@moreorless.be");
        let stored: String = db.query_row("SELECT token_hash FROM invites", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, t, "only the hash is stored");
        assert!(open_invite(&db, "nope").is_err());
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
