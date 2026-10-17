//! A simulated repeater for exercising a hub over real UDP: it does the
//! handshake, keepalives, STATUS and NEIGHBOURS like meshcore-repeater, and
//! makes up RF traffic (adverts, public messages, DMs) around a position.
//!
//! ```text
//! cargo run --example simrep -- pub <name>                  print the key for <name>
//! cargo run --example simrep -- <hub:port> <hub_pub> <name> <lat> <lon> [observe|bridge|both]
//! ```
//! The identity is derived from the name, so `pub <name>` gives the key to allowlist.

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use meshcore_proto::meshcore::{Channel, Packet, build_advert, node_type};
use meshcore_proto::wire::{self, Replay, ty};
use sha2::{Digest, Sha256};

fn key_for(name: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(format!("simrep:{name}")).into())
}

fn unix() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
}

struct Session {
    sid: u32,
    k_up: [u8; 32],
    k_down: [u8; 32],
    seq: u32,
    rx: Replay,
    roles: u8,
    w: wire::Welcome,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("pub") {
        println!("{}", hex::encode(key_for(&args[1]).verifying_key().as_bytes()));
        return;
    }
    if args.len() < 5 {
        eprintln!("usage: simrep <hub:port> <hub_pub> <name> <lat> <lon> [observe|bridge|both]");
        std::process::exit(2);
    }
    let hub_pub = meshcore_proto::unhex::<32>(&args[1]).expect("hub_pub: 64 hex");
    let name = args[2].clone();
    let (lat, lon): (f64, f64) = (args[3].parse().unwrap(), args[4].parse().unwrap());
    let roles = match args.get(5).map(String::as_str).unwrap_or("both") {
        "observe" => wire::ROLE_OBSERVE,
        "bridge" => wire::ROLE_BRIDGE,
        _ => wire::ROLES_ALL,
    };
    let key = key_for(&name);
    let me = key.verifying_key().to_bytes();
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(&args[0]).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut rng = Rng(u64::from_le_bytes(me[..8].try_into().unwrap()) | 1);
    let start = Instant::now();

    // A few made-up nodes around us.
    let nodes: Vec<(SigningKey, String, u8, f64, f64)> = (0..5)
        .map(|i| {
            let k = SigningKey::from_bytes(&Sha256::digest(format!("{name}/node{i}")).into());
            let t = [node_type::CHAT, node_type::CHAT, node_type::REPEATER, node_type::ROOM, node_type::SENSOR][i];
            let dl = (rng.below(400) as f64 - 200.0) / 2000.0;
            let dn = (rng.below(400) as f64 - 200.0) / 1400.0;
            (k, format!("{}-{}", name.trim_start_matches("ON0"), i + 1), t, lat + dl, lon + dn)
        })
        .collect();
    let public = Channel::public();
    let mut last_hello_ts = 0u32;
    let mut buf = [0u8; 1500];

    loop {
        // Handshake.
        let eph: [u8; 32] = rng.bytes();
        last_hello_ts = last_hello_ts.max(unix() - 1) + 1;
        let hello = wire::build_hello(&key, roles, last_hello_ts, &wire::x25519_public(&eph), &name);
        sock.send(&hello).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sess = None;
        while Instant::now() < deadline {
            let Ok(n) = sock.recv(&mut buf) else { continue };
            if let Ok(w) = wire::check_welcome(&buf[..n], &hub_pub, &wire::sha256(&[&hello]), roles) {
                let (k_up, k_down) = wire::derive_keys(&wire::x25519(&eph, &w.eph_pub), &hello, &buf[..n]).unwrap();
                sess = Some(Session { sid: w.session_id, k_up, k_down, seq: 0, rx: Replay::default(), roles: w.roles, w });
                break;
            }
        }
        let Some(mut s) = sess else {
            eprintln!("{name}: no WELCOME, retrying");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        };
        eprintln!("{name}: session {:08x} up, roles {}", s.sid, s.roles);

        let send = |s: &mut Session, t: u8, body: &[u8]| {
            s.seq += 1;
            let _ = sock.send(&wire::seal(t, s.sid, s.seq, body, &s.k_up));
        };
        send(&mut s, ty::KEEPALIVE, &[]);
        let up = Instant::now();
        let mut next_ka = up + Duration::from_secs(s.w.keepalive_s as u64);
        let mut next_status = up;
        let mut next_nb = up + Duration::from_secs(5);
        let mut next_rf = up + Duration::from_secs(2);
        let mut last_rx = Instant::now();
        let (mut rx_total, mut tx_total, mut air_tx, mut crc) = (0u64, 0u64, 0u64, 0u64);
        let mut msg_n = 0;

        'session: loop {
            let now = Instant::now();
            if now >= next_ka {
                send(&mut s, ty::KEEPALIVE, &[]);
                next_ka = now + Duration::from_secs(s.w.keepalive_s as u64);
            }
            if now >= next_status && s.roles & wire::ROLE_OBSERVE != 0 {
                let st = serde_json::json!({
                    "name": name, "fw": "simrep", "uptime": start.elapsed().as_secs(), "role": "repeater",
                    "lat": lat, "lon": lon,
                    "radio": {"freq": 434.890, "bw": 62.5, "sf": 8, "cr": 8, "tx_power": 22},
                    "rx": {"total": rx_total, "dup": rx_total / 3, "bad": 0, "crc_err": crc, "hdr_err": 0, "adverts": 0, "adverts_bad": 0},
                    "fwd": {"flood": tx_total, "direct": 0, "dropped": 0, "denied": 0, "grp_public": 0, "region": 0},
                    "tx": {"total": tx_total, "failed": 0, "cad_busy": 0, "queue_full": 0, "radio_resets": 0, "adverts": 0},
                    "airtime_ms": {"tx": air_tx, "rx": rx_total * 400},
                    "neighbours": nodes.len(),
                    "backbone": {"observed": 0, "offered": 0, "injected": 0, "limited": 0, "rejected": 0}
                });
                send(&mut s, ty::STATUS, st.to_string().as_bytes());
                next_status = now + Duration::from_secs(s.w.status_s as u64);
            }
            if now >= next_nb && s.roles & wire::ROLE_OBSERVE != 0 {
                let list: Vec<_> = nodes
                    .iter()
                    .enumerate()
                    .map(|(i, (k, n, t, _, _))| serde_json::json!({
                        "pub": hex::encode(k.verifying_key().as_bytes()), "name": n, "type": t,
                        "hops": if i < 4 { 0 } else { 1 }, "rssi": -80 - 8 * i as i32, "snr": 9.5 - 4.0 * i as f64,
                        "age": 30 + i * 60, "count": 10 + i,
                    }))
                    .collect();
                let body = serde_json::json!({"page": 1, "pages": 1, "list": list});
                send(&mut s, ty::NEIGHBOURS, body.to_string().as_bytes());
                next_nb = now + Duration::from_secs(s.w.neighbours_s as u64);
            }
            if now >= next_rf {
                next_rf = now + Duration::from_millis(2000 + rng.below(4000));
                let (frame, own) = match rng.below(4) {
                    0 => {
                        let (k, n, t, la, lo) = &nodes[rng.below(nodes.len() as u64) as usize];
                        (build_advert(k, unix(), *t, Some((*la, *lo)), n), false)
                    }
                    1 | 2 => {
                        msg_n += 1;
                        let (_, n, ..) = &nodes[rng.below(2) as usize];
                        (public.build_txt(n, &format!("test {msg_n} via {name}"), unix()), false)
                    }
                    _ => {
                        let mut f = vec![(0x02 << 2) | 0x02, 1, rng.below(256) as u8];
                        f.extend_from_slice(&rng.bytes::<24>());
                        (f, false)
                    }
                };
                rx_total += 1;
                crc += rng.below(2);
                let pkt = Packet::parse(&frame).unwrap();
                if s.roles & wire::ROLE_OBSERVE != 0 {
                    let o = wire::Observe {
                        flags: 0,
                        disposition: if pkt.is_flood() { wire::disp::FORWARDED } else { wire::disp::POLICY },
                        rssi: -70 - rng.below(50) as i16,
                        snr_q: (rng.below(60) as i16 - 30) as i8,
                        pkt_hash: pkt.pkt_hash(),
                        frame: &frame,
                    };
                    send(&mut s, ty::OBSERVE, &wire::build_observe(&o));
                }
                if pkt.is_flood() {
                    // Relay it: append our hash, then offer it to the hub.
                    let mut relayed = frame.clone();
                    relayed[1] += 1;
                    relayed.insert(2 + pkt.path.len(), me[0]);
                    tx_total += 1;
                    air_tx += 600;
                    if s.roles & wire::ROLE_BRIDGE != 0 {
                        let b = wire::Bridge { flags: if own { wire::BRIDGE_OWN } else { 0 }, pkt_hash: pkt.pkt_hash(), frame: &relayed };
                        send(&mut s, ty::BRIDGE, &wire::build_bridge(&b));
                    }
                }
            }

            match sock.recv(&mut buf) {
                Ok(n) => {
                    let d = &buf[..n];
                    match wire::datagram_type(d) {
                        Ok(ty::RESET) => {
                            if let Ok((sid, _, _)) = wire::check_reset(d, &hub_pub)
                                && sid == s.sid
                            {
                                eprintln!("{name}: RESET, new handshake");
                                break 'session;
                            }
                        }
                        Ok(t) if ty::is_down(t) => {
                            let Ok((_, sid, seq)) = wire::peek(d) else { continue };
                            if sid != s.sid {
                                continue;
                            }
                            let Ok(body) = wire::open(d, &s.k_down) else { continue };
                            if !s.rx.check(seq) {
                                continue;
                            }
                            last_rx = Instant::now();
                            match t {
                                ty::FRAME => {
                                    let (src, f) = wire::parse_frame(body).unwrap();
                                    let pkt = Packet::parse(f).unwrap();
                                    eprintln!("{name}: FRAME from {} {} {} bytes", hex::encode(src), meshcore_proto::meshcore::ptype::name(pkt.ptype()), f.len());
                                    tx_total += 1;
                                    air_tx += 600;
                                    if s.roles & wire::ROLE_OBSERVE != 0 {
                                        let o = wire::Observe { flags: wire::OBS_FROM_BACKBONE, disposition: wire::disp::FORWARDED, rssi: 0, snr_q: 0, pkt_hash: pkt.pkt_hash(), frame: f };
                                        let body = wire::build_observe(&o);
                                        send(&mut s, ty::OBSERVE, &body);
                                    }
                                }
                                ty::BYE_DOWN => {
                                    eprintln!("{name}: hub said bye ({})", wire::bye::name(body.first().copied().unwrap_or(0)));
                                    std::thread::sleep(Duration::from_secs(5));
                                    break 'session;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    if last_rx.elapsed() > Duration::from_secs(3 * s.w.keepalive_s as u64 + 5) {
                        eprintln!("{name}: hub silent, reconnecting");
                        break 'session;
                    }
                }
            }
        }
    }
}
