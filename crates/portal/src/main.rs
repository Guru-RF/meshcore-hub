//! meshcore-portal: the public map and monitor for the IP backbone.
//!
//! Reads the hub's SQLite file read-only, relays the hub's live events
//! (a Unix socket of JSON lines) to browsers over a WebSocket, and serves
//! the single-page map from `web/`, compiled into the binary.
//!
//! ```text
//! meshcore-portal [--listen 127.0.0.1:8080] [--db /var/lib/meshcore-hub/hub.db]
//!                 [--events /run/meshcore-hub/events.sock]
//! ```

mod api;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::io::AsyncBufReadExt;
use tokio::sync::{Semaphore, broadcast};
use tracing::{info, warn};

pub struct AppState {
    pub db: PathBuf,
    live: broadcast::Sender<Arc<str>>,
    ws_slots: Arc<Semaphore>,
}

pub type Shared = Arc<AppState>;

struct Args {
    listen: String,
    db: PathBuf,
    events: PathBuf,
}

fn args() -> Result<Args> {
    let mut a = Args {
        listen: "127.0.0.1:8080".into(),
        db: "/var/lib/meshcore-hub/hub.db".into(),
        events: "/run/meshcore-hub/events.sock".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().ok_or_else(|| anyhow::anyhow!("{k} needs a value"));
        match k.as_str() {
            "--listen" => a.listen = v()?,
            "--db" => a.db = v()?.into(),
            "--events" => a.events = v()?.into(),
            "-h" | "--help" => {
                println!("usage: meshcore-portal [--listen ADDR] [--db FILE] [--events SOCKET]");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    Ok(a)
}

fn main() -> Result<()> {
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let fmt = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if journald {
        fmt.without_time().with_ansi(false).init();
    } else {
        fmt.init();
    }
    let a = args()?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?.block_on(serve(a))
}

async fn serve(a: Args) -> Result<()> {
    let (live, _) = broadcast::channel(1024);
    let state = Arc::new(AppState { db: a.db.clone(), live: live.clone(), ws_slots: Arc::new(Semaphore::new(512)) });
    tokio::spawn(relay_events(a.events.clone(), live));

    let app = Router::new()
        .route("/", get(|| asset("index.html")))
        .route("/app.js", get(|| asset("app.js")))
        .route("/style.css", get(|| asset("style.css")))
        .route("/favicon.svg", get(|| asset("favicon.svg")))
        .route("/api/live", get(ws))
        .merge(api::routes())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&a.listen).await?;
    info!("portal on http://{} (db {}, events {})", listener.local_addr()?, a.db.display(), a.events.display());
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("signal");
    let mut int = signal(SignalKind::interrupt()).expect("signal");
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
}

/// Keep a connection to the hub's event socket and fan its lines out.
async fn relay_events(path: PathBuf, live: broadcast::Sender<Arc<str>>) {
    let mut warned = false;
    loop {
        match tokio::net::UnixStream::connect(&path).await {
            Ok(s) => {
                info!("connected to hub events {}", path.display());
                warned = false;
                let mut lines = tokio::io::BufReader::new(s).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = live.send(Arc::from(line));
                }
                warn!("hub events closed, reconnecting");
            }
            Err(e) if !warned => {
                warn!("hub events {}: {e} (retrying)", path.display());
                warned = true;
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn ws(State(st): State<Shared>, up: WebSocketUpgrade) -> Response {
    let Ok(slot) = st.ws_slots.clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many live viewers").into_response();
    };
    let rx = st.live.subscribe();
    up.on_upgrade(move |sock| async move {
        live(sock, rx).await;
        drop(slot);
    })
}

async fn live(mut sock: WebSocket, mut rx: broadcast::Receiver<Arc<str>>) {
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(line) => {
                    if sock.send(Message::Text(line.as_ref().into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            msg = sock.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}

macro_rules! web {
    ($($name:literal => $mime:literal),* $(,)?) => {
        fn web_file(name: &str) -> Option<(&'static [u8], &'static str)> {
            match name {
                $($name => Some((include_bytes!(concat!("../../../web/", $name)), $mime)),)*
                _ => None,
            }
        }
    };
}

web! {
    "index.html" => "text/html; charset=utf-8",
    "app.js" => "text/javascript; charset=utf-8",
    "style.css" => "text/css; charset=utf-8",
    "favicon.svg" => "image/svg+xml",
}

async fn asset(name: &'static str) -> Response {
    let Some((body, mime)) = web_file(name) else { return StatusCode::NOT_FOUND.into_response() };
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // Mesh names and message text are untrusted; keep scripts to our own and Leaflet's.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; \
             style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; \
             img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    r
}
