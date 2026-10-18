//! meshcore-hubd: the I/O shell around [`hubd::core::Hub`].
//!
//! ```text
//! meshcore-hubd [-c hub.toml]            run the hub (default)
//! meshcore-hubd genkey <file>            write a new hub identity, print its public key
//! meshcore-hubd pubkey [-c hub.toml]     print the hub public key (backbone_hub_key)
//! meshcore-hubd check [-c hub.toml]      validate the config and allowlist
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use hubd::config::{self, Config};
use hubd::core::{Hub, Now, Out};
use hubd::store::{self, Op};
use tokio::io::AsyncWriteExt;
use tokio::net::{UdpSocket, UnixListener};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

const DEFAULT_CONFIG: &str = "/etc/meshcore-hub/hub.toml";
const USAGE: &str = "\
usage: meshcore-hubd [-c hub.toml] [command]
  run                 run the hub (default)
  genkey <file>       write a new hub identity, print its public key
  pubkey              print the hub public key (the repeaters' backbone_hub_key)
  check               validate the config and print the allowlist
";

fn main() {
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let fmt = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if journald {
        fmt.without_time().with_ansi(false).init();
    } else {
        fmt.init();
    }
    if let Err(e) = cli() {
        error!("{e:#}");
        std::process::exit(1);
    }
}

fn cli() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    if let Some(i) = args.iter().position(|a| a == "-c" || a == "--config") {
        let Some(p) = args.get(i + 1).cloned() else { bail!("-c needs a file") };
        config = p.into();
        args.drain(i..=i + 1);
    }
    match args.first().map(String::as_str) {
        None | Some("run") => run(&config),
        Some("genkey") => {
            let Some(path) = args.get(1) else { bail!("usage: meshcore-hubd genkey <file>") };
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            let key = SigningKey::from_bytes(&seed);
            config::write_key(Path::new(path), &key)?;
            println!("{}", hex::encode(key.verifying_key().as_bytes()));
            Ok(())
        }
        Some("pubkey") => {
            let cfg = Config::load(&config)?;
            let key = config::load_key(&cfg.key_path())?;
            println!("{}", hex::encode(key.verifying_key().as_bytes()));
            Ok(())
        }
        Some("check") => {
            let cfg = Config::load(&config)?;
            println!("config ok: {}", config.display());
            for (pk, a) in cfg.allowlist()? {
                println!("  {:<10} {:<8} {}  {}", a.callsign, a.kind.name(), hex::encode(pk), hubd::core::role_names(a.roles).join("+"));
            }
            for c in cfg.decode_channels()? {
                println!("  channel {} (hash {:02x})", c.name, c.hash);
            }
            Ok(())
        }
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => bail!("unknown command {other:?} (run, genkey, pubkey, check)"),
    }
}

struct Clock {
    start: Instant,
}

impl Clock {
    fn now(&self) -> Now {
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Now { ms: self.start.elapsed().as_millis() as u64 + 1, unix: unix as u32 }
    }
}

fn run(config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    let key_path = cfg.key_path();
    let key = config::load_key(&key_path)?;
    let hub_pub = hex::encode(key.verifying_key().as_bytes());
    let allow = cfg.allowlist()?;
    let channels = cfg.decode_channels()?;
    info!("hub key {hub_pub} ({})", key_path.display());
    info!("allowlist: {} repeater(s); decoding {}", allow.len(), channels.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "));
    if allow.is_empty() {
        warn!("the allowlist is empty: every HELLO will be dropped");
    }

    let (store_tx, store_thread) = store::spawn(&cfg.database, cfg.retention.clone())?;
    let rng: hubd::core::Rng = Box::new(|b: &mut [u8]| getrandom::fill(b).expect("OS random source"));
    let mut hub = Hub::new(key, cfg.params(), allow, channels, rng);
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    store_tx.send(Op::Meta(vec![
        ("hub_pub".into(), hub_pub.clone()),
        ("hub_started".into(), started.to_string()),
        ("hub_version".into(), env!("CARGO_PKG_VERSION").into()),
        ("backbone_listen".into(), cfg.listen.clone()),
    ]))?;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = rt.block_on(serve(&cfg, config, &mut hub, &store_tx));
    drop(store_tx);
    let _ = store_thread.join();
    result
}

async fn serve(cfg: &Config, config_path: &Path, hub: &mut Hub, store_tx: &Sender<Op>) -> Result<()> {
    let sock = UdpSocket::bind(&cfg.listen).await.with_context(|| format!("binding UDP {}", cfg.listen))?;
    info!("backbone listening on udp {}", sock.local_addr()?);

    let (events, _) = broadcast::channel::<Arc<str>>(2048);
    let listener = bind_events(&cfg.events_socket)?;
    info!("events on {}", cfg.events_socket.display());
    tokio::spawn(accept_events(listener, events.clone()));

    let clock = Clock { start: Instant::now() };
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut buf = vec![0u8; 2048];

    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, src)) => hub.handle(clock.now(), src, &buf[..n]),
                Err(e) => warn!("udp recv: {e}"),
            },
            _ = tick.tick() => hub.tick(clock.now()),
            _ = hup.recv() => match Config::load(config_path).and_then(|c| c.allowlist()) {
                Ok(allow) => {
                    info!("SIGHUP: reloaded allowlist, {} repeater(s)", allow.len());
                    hub.set_allowlist(Some(clock.now()), allow);
                }
                Err(e) => error!("SIGHUP: keeping the old allowlist: {e:#}"),
            },
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
        flush(hub, &sock, store_tx, &events).await;
    }

    info!("shutting down");
    hub.shutdown(clock.now());
    flush(hub, &sock, store_tx, &events).await;
    let _ = std::fs::remove_file(&cfg.events_socket);
    Ok(())
}

async fn flush(hub: &mut Hub, sock: &UdpSocket, store_tx: &Sender<Op>, events: &broadcast::Sender<Arc<str>>) {
    for out in hub.drain() {
        match out {
            Out::Send(to, d) => {
                if let Err(e) = sock.send_to(&d, to).await {
                    warn!("udp send to {to}: {e}");
                }
            }
            Out::Store(op) => {
                if store_tx.send(op).is_err() {
                    error!("store writer is gone");
                }
            }
            Out::Event(v) => {
                let _ = events.send(Arc::from(v.to_string()));
            }
        }
    }
}

fn bind_events(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // The portal runs as another user in the hub's group.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// Each client gets every event as one JSON line. A client that falls too
/// far behind skips ahead; the hub never waits for it.
async fn accept_events(listener: UnixListener, events: broadcast::Sender<Arc<str>>) {
    loop {
        let Ok((mut conn, _)) = listener.accept().await else { continue };
        let mut rx = events.subscribe();
        tokio::spawn(async move {
            loop {
                let line = match rx.recv().await {
                    Ok(l) => l,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("events client lagged, skipped {n}");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                let ok = tokio::time::timeout(Duration::from_secs(5), async {
                    conn.write_all(line.as_bytes()).await?;
                    conn.write_all(b"\n").await
                })
                .await;
                if !matches!(ok, Ok(Ok(()))) {
                    break;
                }
            }
        });
    }
}
