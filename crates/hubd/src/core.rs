//! The hub as a pure state machine: datagrams and clock ticks in, effects
//! ([`Out`]) out. No sockets, files or clocks of its own, so the tests can
//! drive it with simulated repeaters and a fake clock.
//!
//! Sections in comments refer to meshcore-repeater `docs/backbone.md`.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use ed25519_dalek::SigningKey;
use meshcore_proto::meshcore::{Advert, Channel, Packet, ptype};
use meshcore_proto::wire::{self, ROLE_BRIDGE, ROLE_OBSERVE, Replay, bye, disp, ty};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::store::Op;

pub type Pub = [u8; 32];
pub type PktHash = [u8; 8];

/// Monotonic milliseconds and wall-clock Unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct Now {
    pub ms: u64,
    pub unix: u32,
}

#[derive(Debug, Clone)]
pub struct Params {
    pub keepalive_s: u16,
    pub status_s: u16,
    pub neighbours_s: u16,
    pub hold_ms: u64,
    pub rate_per_min: u32,
    pub own_replies: bool,
    pub dedup_ms: u64,
    pub path_memory_ms: u64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            keepalive_s: 25,
            status_s: 60,
            neighbours_s: 300,
            hold_ms: 1000,
            rate_per_min: 25,
            own_replies: false,
            dedup_ms: 600_000,
            path_memory_ms: 24 * 3600 * 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    pub callsign: String,
    pub roles: u8,
}

/// An effect for the I/O shell.
#[derive(Debug)]
pub enum Out {
    Send(SocketAddr, Vec<u8>),
    Store(Op),
    Event(Value),
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub rx: u64,
    pub tx: u64,
    pub malformed: u64,
    pub hello_ok: u64,
    pub hello_unknown: u64,
    pub hello_rejected: u64,
    pub sessions: u64,
    pub bad_mac: u64,
    pub replay: u64,
    pub unknown_session: u64,
    pub resets: u64,
    pub role_denied: u64,
    pub bad_body: u64,
    pub observed: u64,
    pub offered: u64,
    pub bridged: u64,
    pub rate_limited: u64,
    pub direct_unrouted: u64,
    pub own_skipped: u64,
}

struct Session {
    sid: u32,
    roles: u8,
    k_up: [u8; 32],
    k_down: [u8; 32],
    addr: SocketAddr,
    rx: Replay,
    seq_out: u32,
    keepalive_s: u16,
    created_ms: u64,
    last_rx_ms: u64,
    tokens: f64,
    tokens_ms: u64,
}

struct Rep {
    callsign: String,
    roles_allowed: u8,
    /// Node name from the last accepted HELLO.
    name: String,
    last_hello_ts: u32,
    cur: Option<Session>,
    pending: Option<Session>,
    /// (hash size, flood path before this repeater's own hash) -> last seen ms.
    /// Feeds the path-tail rule for direct frames.
    flood_paths: HashMap<(u8, Vec<u8>), u64>,
    last_warn_ms: u64,
}

impl Rep {
    fn new(a: &Allowed) -> Self {
        Rep {
            callsign: a.callsign.clone(),
            roles_allowed: a.roles,
            name: String::new(),
            last_hello_ts: 0,
            cur: None,
            pending: None,
            flood_paths: HashMap::new(),
            last_warn_ms: 0,
        }
    }

    fn bridge_up(&self) -> bool {
        self.cur.as_ref().is_some_and(|s| s.roles & ROLE_BRIDGE != 0)
    }
}

/// What the hub knows about one packet hash ("Hub rules" 2).
#[derive(Default)]
struct Entry {
    touched_ms: u64,
    /// The first BRIDGE: frame bytes, offering repeater, OWN flag.
    frame: Option<(Vec<u8>, Pub, bool)>,
    reported: HashSet<Pub>,
    sent: HashSet<Pub>,
    fanned: bool,
}

pub type Rng = Box<dyn FnMut(&mut [u8]) + Send>;

pub struct Hub {
    key: SigningKey,
    hub_pub: Pub,
    p: Params,
    reps: HashMap<Pub, Rep>,
    sids: HashMap<u32, Pub>,
    dedup: HashMap<PktHash, Entry>,
    due: BinaryHeap<Reverse<(u64, PktHash)>>,
    hello_rl: HashMap<IpAddr, u64>,
    reset_rl: HashMap<IpAddr, u64>,
    unknown_warned: HashMap<Pub, u64>,
    channels: Vec<Channel>,
    rng: Rng,
    out: Vec<Out>,
    stats: Stats,
    last_sweep_ms: u64,
    last_slow_ms: u64,
}

const PENDING_MS: u64 = 30_000;
const HELLO_RL_MS: u64 = 1000;
const RESET_RL_MS: u64 = 5000;
const WARN_EVERY_MS: u64 = 600_000;
const FLOOD_PATHS_MAX: usize = 20_000;

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

impl Hub {
    pub fn new(key: SigningKey, p: Params, allow: Vec<(Pub, Allowed)>, channels: Vec<Channel>, rng: Rng) -> Self {
        let hub_pub = key.verifying_key().to_bytes();
        let mut hub = Hub {
            key,
            hub_pub,
            p,
            reps: HashMap::new(),
            sids: HashMap::new(),
            dedup: HashMap::new(),
            due: BinaryHeap::new(),
            hello_rl: HashMap::new(),
            reset_rl: HashMap::new(),
            unknown_warned: HashMap::new(),
            channels,
            rng,
            out: Vec::new(),
            stats: Stats::default(),
            last_sweep_ms: 0,
            last_slow_ms: 0,
        };
        hub.set_allowlist(None, allow);
        hub
    }

    pub fn hub_pub(&self) -> Pub {
        self.hub_pub
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Effects produced since the last drain.
    pub fn drain(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    pub fn connected(&self) -> usize {
        self.reps.values().filter(|r| r.cur.is_some()).count()
    }

    fn store(&mut self, op: Op) {
        self.out.push(Out::Store(op));
    }

    fn event(&mut self, v: Value) {
        self.out.push(Out::Event(v));
    }

    fn send(&mut self, to: SocketAddr, d: Vec<u8>) {
        self.stats.tx += 1;
        self.out.push(Out::Send(to, d));
    }

    fn random<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        (self.rng)(&mut b);
        b
    }

    /// Replace the allowlist. Repeaters that were removed, or lost a role
    /// they hold in their session, get BYE "not allowed" (with `now`).
    pub fn set_allowlist(&mut self, now: Option<Now>, allow: Vec<(Pub, Allowed)>) {
        let new: HashMap<Pub, Allowed> = allow.into_iter().collect();
        let gone: Vec<Pub> = self
            .reps
            .iter()
            .filter(|(pk, r)| match new.get(*pk) {
                None => true,
                Some(a) => r.cur.as_ref().is_some_and(|s| s.roles & !a.roles != 0),
            })
            .map(|(pk, _)| *pk)
            .collect();
        for pk in gone {
            if let Some(now) = now
                && self.reps[&pk].cur.is_some()
            {
                self.send_session(&pk, ty::BYE_DOWN, &[bye::NOT_ALLOWED]);
                self.drop_session(now, &pk, "not allowed");
            }
            if let Some(r) = self.reps.get_mut(&pk)
                && let Some(p) = r.pending.take()
            {
                self.sids.remove(&p.sid);
            }
            if !new.contains_key(&pk) {
                self.reps.remove(&pk);
            }
        }
        for (pk, a) in &new {
            let r = self.reps.entry(*pk).or_insert_with(|| Rep::new(a));
            r.callsign = a.callsign.clone();
            r.roles_allowed = a.roles;
        }

        // "Hub rules" 8: shared first public-key bytes are worth knowing about.
        let mut by_first: HashMap<u8, Vec<&str>> = HashMap::new();
        for (pk, a) in &new {
            by_first.entry(pk[0]).or_default().push(&a.callsign);
        }
        for (b, calls) in by_first {
            if calls.len() > 1 {
                warn!("repeaters {} share first public-key byte {b:02x} (path hashes collide; the path-tail rule copes)", calls.join(", "));
            }
        }

        let mut list: Vec<(Pub, String, u8)> = new.iter().map(|(pk, a)| (*pk, a.callsign.clone(), a.roles)).collect();
        list.sort_by(|a, b| a.1.cmp(&b.1));
        self.store(Op::Allowlist(list));
    }

    // ------------------------------------------------------------ input --

    pub fn handle(&mut self, now: Now, src: SocketAddr, d: &[u8]) {
        self.stats.rx += 1;
        if d.len() > wire::MAX_DGRAM {
            self.stats.malformed += 1;
            return;
        }
        match wire::datagram_type(d) {
            Ok(ty::HELLO) => self.on_hello(now, src, d),
            Ok(t) if ty::is_up(t) => self.on_session(now, src, d),
            _ => self.stats.malformed += 1,
        }
    }

    fn on_hello(&mut self, now: Now, src: SocketAddr, d: &[u8]) {
        let Ok(h) = wire::parse_hello(d) else {
            self.stats.malformed += 1;
            return;
        };
        let Some(rep) = self.reps.get(&h.node_pub) else {
            self.stats.hello_unknown += 1;
            let last = self.unknown_warned.get(&h.node_pub).copied();
            if last.is_none_or(|t| now.ms.saturating_sub(t) >= WARN_EVERY_MS) {
                self.unknown_warned.insert(h.node_pub, now.ms);
                info!("HELLO from {src} by {:?}, key {} is not on the allowlist", h.name, hx(&h.node_pub));
            }
            return;
        };
        let allowed = rep.roles_allowed;
        let callsign = rep.callsign.clone();

        // A signature check costs CPU: at most one per source per second.
        let ip = src.ip();
        if self.hello_rl.get(&ip).is_some_and(|&t| now.ms.saturating_sub(t) < HELLO_RL_MS) {
            self.stats.hello_rejected += 1;
            return;
        }
        self.hello_rl.insert(ip, now.ms);

        if wire::verify_hello(d, &h).is_err() {
            self.stats.hello_rejected += 1;
            warn!("{callsign}: HELLO with a bad signature from {src}");
            return;
        }
        let skew = h.ts as i64 - now.unix as i64;
        if skew.unsigned_abs() > wire::TS_WINDOW_S as u64 {
            self.stats.hello_rejected += 1;
            self.warn_rep(now, &h.node_pub, &format!("HELLO clock is {skew:+} s off the hub's (limit ±120 s); check NTP on the repeater"));
            return;
        }
        let rep = self.reps.get_mut(&h.node_pub).expect("checked above");
        if h.ts <= rep.last_hello_ts {
            self.stats.hello_rejected += 1;
            debug!("{callsign}: HELLO ts {} not after {}", h.ts, rep.last_hello_ts);
            return;
        }
        rep.last_hello_ts = h.ts;
        if !h.name.eq_ignore_ascii_case(&callsign) {
            let msg = format!("HELLO names itself {:?}, allowlisted as {callsign}", h.name);
            self.warn_rep(now, &h.node_pub, &msg);
        }

        let eph_secret: [u8; 32] = self.random();
        let eph_pub = wire::x25519_public(&eph_secret);
        let shared = wire::x25519(&eph_secret, &h.eph_pub);
        let sid = loop {
            let s = u32::from_le_bytes(self.random());
            if s != 0 && !self.sids.contains_key(&s) {
                break s;
            }
        };
        let roles = h.roles & allowed & wire::ROLES_ALL;
        let w = wire::Welcome {
            roles,
            ts: now.unix,
            session_id: sid,
            eph_pub,
            keepalive_s: self.p.keepalive_s,
            status_s: self.p.status_s,
            neighbours_s: self.p.neighbours_s,
        };
        let welcome = wire::build_welcome(&self.key, &w, &wire::sha256(&[d]));
        let Some((k_up, k_down)) = wire::derive_keys(&shared, d, &welcome) else {
            self.stats.hello_rejected += 1;
            warn!("{callsign}: HELLO with a low-order X25519 key");
            return;
        };

        let burst = self.burst();
        let rep = self.reps.get_mut(&h.node_pub).expect("checked above");
        if let Some(old) = rep.pending.take() {
            self.sids.remove(&old.sid);
        }
        rep.name = h.name.clone();
        rep.pending = Some(Session {
            sid,
            roles,
            k_up,
            k_down,
            addr: src,
            rx: Replay::default(),
            seq_out: 0,
            keepalive_s: self.p.keepalive_s,
            created_ms: now.ms,
            last_rx_ms: now.ms,
            tokens: burst,
            tokens_ms: now.ms,
        });
        self.sids.insert(sid, h.node_pub);
        self.stats.hello_ok += 1;
        debug!("{callsign}: HELLO from {src}, roles asked {} granted {roles}, session {sid:08x} pending", h.roles);
        self.send(src, welcome.to_vec());
    }

    fn warn_rep(&mut self, now: Now, pk: &Pub, msg: &str) {
        if let Some(r) = self.reps.get_mut(pk)
            && (r.last_warn_ms == 0 || now.ms.saturating_sub(r.last_warn_ms) >= WARN_EVERY_MS)
        {
            r.last_warn_ms = now.ms.max(1);
            warn!("{}: {msg}", r.callsign);
        }
    }

    fn on_session(&mut self, now: Now, src: SocketAddr, d: &[u8]) {
        let Ok((t, sid, seq)) = wire::peek(d) else {
            self.stats.malformed += 1;
            return;
        };
        let Some(&pk) = self.sids.get(&sid) else {
            self.stats.unknown_session += 1;
            self.maybe_reset(now, src, sid, seq);
            return;
        };

        // Authenticate against the current or the pending session.
        let promoted = {
            let rep = self.reps.get_mut(&pk).expect("sids and reps agree");
            let is_cur = rep.cur.as_ref().is_some_and(|s| s.sid == sid);
            let sess = if is_cur { rep.cur.as_mut() } else { rep.pending.as_mut().filter(|s| s.sid == sid) };
            let Some(sess) = sess else {
                self.stats.unknown_session += 1;
                return;
            };
            if wire::open(d, &sess.k_up).is_err() {
                self.stats.bad_mac += 1;
                return;
            }
            if !sess.rx.check(seq) {
                self.stats.replay += 1;
                return;
            }
            // NAT roaming: answer wherever the last good datagram came from.
            sess.addr = src;
            sess.last_rx_ms = now.ms;
            if is_cur {
                None
            } else {
                // The first valid datagram confirms a pending session.
                let new = rep.pending.take().expect("pending checked");
                let roles = new.roles;
                let old = rep.cur.replace(new);
                Some((old.map(|o| o.sid), roles, rep.callsign.clone(), rep.name.clone()))
            }
        };
        if let Some((old_sid, roles, callsign, name)) = promoted {
            if let Some(o) = old_sid {
                self.sids.remove(&o);
            }
            self.stats.sessions += 1;
            info!("{callsign}: session {sid:08x} up from {src}, roles {}", role_names(roles).join("+"));
            self.store(Op::Up { pk, ts: now.unix, roles, name });
            self.event(json!({"t": "up", "rep": callsign, "pub": hx(&pk), "roles": role_names(roles), "ts": now.unix}));
        }

        let roles = self.reps[&pk].cur.as_ref().map_or(0, |s| s.roles);
        let body = &d[wire::HDR..d.len() - wire::MAC_LEN];
        match t {
            ty::KEEPALIVE => {
                self.send_session(&pk, ty::KEEPALIVE_ACK, &[]);
                self.store(Op::Seen { pk, ts: now.unix });
            }
            ty::OBSERVE | ty::STATUS | ty::NEIGHBOURS if roles & ROLE_OBSERVE == 0 => self.stats.role_denied += 1,
            ty::BRIDGE if roles & ROLE_BRIDGE == 0 => self.stats.role_denied += 1,
            ty::OBSERVE => self.on_observe(now, pk, body),
            ty::BRIDGE => self.on_bridge(now, pk, body),
            ty::STATUS => self.on_status(now, pk, body),
            ty::NEIGHBOURS => self.on_neighbours(now, pk, body),
            ty::BYE_UP => {
                let reason = body.first().copied().unwrap_or(0);
                self.drop_session(now, &pk, &format!("repeater said bye: {}", bye::name(reason)));
            }
            _ => {} // a later version's type: ignore
        }
    }

    fn maybe_reset(&mut self, now: Now, src: SocketAddr, sid: u32, seq: u32) {
        let ip = src.ip();
        if self.reset_rl.get(&ip).is_some_and(|&t| now.ms.saturating_sub(t) < RESET_RL_MS) {
            return;
        }
        self.reset_rl.insert(ip, now.ms);
        self.stats.resets += 1;
        debug!("unknown session {sid:08x} from {src}: RESET");
        let d = wire::build_reset(&self.key, sid, seq, now.unix);
        self.send(src, d.to_vec());
    }

    /// Seal and send under the repeater's confirmed session.
    fn send_session(&mut self, pk: &Pub, t: u8, body: &[u8]) -> bool {
        let Some(s) = self.reps.get_mut(pk).and_then(|r| r.cur.as_mut()) else {
            return false;
        };
        s.seq_out += 1;
        let d = wire::seal(t, s.sid, s.seq_out, body, &s.k_down);
        let to = s.addr;
        let rekey = s.seq_out >= 1 << 31;
        self.send(to, d);
        if rekey && t != ty::BYE_DOWN {
            self.send_session(pk, ty::BYE_DOWN, &[bye::REKEY]);
            if let Some(r) = self.reps.get_mut(pk) {
                let cs = r.callsign.clone();
                info!("{cs}: hub sequence numbers used up, asking for a new handshake");
            }
        }
        true
    }

    fn drop_session(&mut self, now: Now, pk: &Pub, reason: &str) {
        let Some(r) = self.reps.get_mut(pk) else { return };
        let Some(s) = r.cur.take() else { return };
        let callsign = r.callsign.clone();
        self.sids.remove(&s.sid);
        info!("{callsign}: session {:08x} down ({reason})", s.sid);
        self.store(Op::Down { pk: *pk, ts: now.unix, reason: reason.to_string() });
        self.event(json!({"t": "down", "rep": callsign, "pub": hx(pk), "reason": reason, "ts": now.unix}));
    }

    // ---------------------------------------------------------- bodies --

    fn callsign(&self, pk: &Pub) -> String {
        self.reps.get(pk).map(|r| r.callsign.clone()).unwrap_or_default()
    }

    fn entry(&mut self, h: PktHash, now: Now) -> &mut Entry {
        let e = self.dedup.entry(h).or_default();
        e.touched_ms = now.ms;
        e
    }

    fn on_observe(&mut self, now: Now, pk: Pub, body: &[u8]) {
        let Ok(o) = wire::parse_observe(body) else {
            self.stats.bad_body += 1;
            return;
        };
        self.stats.observed += 1;
        let Some(pkt) = Packet::parse(o.frame) else {
            self.stats.bad_body += 1;
            return;
        };
        let h = pkt.pkt_hash();
        if h != o.pkt_hash {
            let msg = format!("OBSERVE pkt_hash {} but the frame hashes to {}", hx(&o.pkt_hash), hx(&h));
            self.warn_rep(now, &pk, &msg);
        }
        self.entry(h, now).reported.insert(pk);

        let callsign = self.callsign(&pk);
        let (rssi, snr) = (o.rssi, o.snr());
        let hops = pkt.hops() as u8;
        self.store(Op::Frame {
            ts: now.unix,
            repeater: pk,
            hash: h,
            route: pkt.route(),
            ptype: pkt.ptype(),
            hops,
            rssi,
            snr,
            disposition: o.disposition,
            backbone: o.from_backbone(),
            len: o.frame.len() as u8,
        });
        self.event(json!({
            "t": "frame", "rep": callsign, "hash": hx(&h), "type": ptype::name(pkt.ptype()),
            "route": if pkt.is_flood() { "flood" } else { "direct" }, "hops": hops,
            "rssi": rssi, "snr": snr, "disp": disp::name(o.disposition), "bb": o.from_backbone(), "ts": now.unix,
        }));

        // What came down from the hub was decoded when it was first heard on RF.
        if o.from_backbone() {
            return;
        }
        match pkt.ptype() {
            ptype::ADVERT => {
                let Some(a) = Advert::decode(pkt.payload).filter(|a| a.verified) else { return };
                self.store(Op::Node {
                    pk: a.public_key,
                    name: a.name.clone(),
                    node_type: a.node_type,
                    lat: a.lat,
                    lon: a.lon,
                    advert_ts: a.timestamp,
                    ts: now.unix,
                });
                self.event(json!({
                    "t": "node", "pub": hx(&a.public_key), "name": a.name, "type": a.node_type,
                    "lat": a.lat, "lon": a.lon, "via": callsign, "rssi": rssi, "snr": snr, "hops": hops, "ts": now.unix,
                }));
            }
            ptype::GRP_TXT => {
                let Some((chan, t)) = self.channels.iter().find_map(|c| c.decrypt(pkt.payload).map(|t| (c.name.clone(), t))) else {
                    return;
                };
                self.store(Op::Message {
                    hash: h,
                    channel: chan.clone(),
                    sender: t.sender.clone(),
                    text: t.text.clone(),
                    sent_ts: t.timestamp,
                    ts: now.unix,
                    repeater: pk,
                    rssi,
                    snr,
                    hops,
                });
                self.event(json!({
                    "t": "msg", "hash": hx(&h), "channel": chan, "sender": t.sender, "text": t.text,
                    "sent": t.timestamp, "rep": callsign, "rssi": rssi, "snr": snr, "hops": hops, "ts": now.unix,
                }));
            }
            _ => {}
        }
    }

    fn on_bridge(&mut self, now: Now, pk: Pub, body: &[u8]) {
        let Ok(b) = wire::parse_bridge(body) else {
            self.stats.bad_body += 1;
            return;
        };
        let Some(pkt) = Packet::parse(b.frame) else {
            self.stats.bad_body += 1;
            return;
        };
        if pkt.is_direct() && pkt.hops() == 0 {
            self.stats.bad_body += 1;
            return;
        }
        self.stats.offered += 1;
        let h = pkt.pkt_hash();
        if h != b.pkt_hash {
            let msg = format!("BRIDGE pkt_hash {} but the frame hashes to {}", hx(&b.pkt_hash), hx(&h));
            self.warn_rep(now, &pk, &msg);
        }

        // Remember the path a relayed flood took to this repeater, for the
        // path-tail rule ("Hub rules" 5).
        if pkt.is_flood() && !b.own() && pkt.hops() >= 1 {
            let hs = pkt.hash_size();
            let n = pkt.hops();
            if pkt.path[(n - 1) * hs..] == pk[..hs] {
                let before = pkt.path[..(n - 1) * hs].to_vec();
                if let Some(r) = self.reps.get_mut(&pk) {
                    if r.flood_paths.len() >= FLOOD_PATHS_MAX {
                        prune_oldest(&mut r.flood_paths);
                    }
                    r.flood_paths.insert((hs as u8, before), now.ms);
                }
            }
        }

        let (first, fanned) = {
            let e = self.entry(h, now);
            e.reported.insert(pk);
            let first = e.frame.is_none();
            if first {
                e.frame = Some((b.frame.to_vec(), pk, b.own()));
            }
            (first, e.fanned)
        };
        if first {
            // "Hub rules" 3: give the other repeaters a moment to report it.
            self.due.push(Reverse((now.ms + self.p.hold_ms, h)));
        } else if fanned {
            // Covers repeaters that connected after the first fan-out.
            self.fanout(now, h);
        }
    }

    fn on_status(&mut self, now: Now, pk: Pub, body: &[u8]) {
        let Ok(v) = serde_json::from_slice::<Value>(body) else {
            self.stats.bad_body += 1;
            return;
        };
        if !v.is_object() {
            self.stats.bad_body += 1;
            return;
        }
        let callsign = self.callsign(&pk);
        self.store(Op::Status { pk, ts: now.unix, json: v.clone() });
        self.event(json!({"t": "status", "rep": callsign, "pub": hx(&pk), "s": v, "ts": now.unix}));
    }

    fn on_neighbours(&mut self, now: Now, pk: Pub, body: &[u8]) {
        let Ok(v) = serde_json::from_slice::<Value>(body) else {
            self.stats.bad_body += 1;
            return;
        };
        let list = v.get("list").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut n = 0;
        for e in &list {
            let Some(node) = e.get("pub").and_then(Value::as_str).and_then(meshcore_proto::unhex::<32>) else {
                continue;
            };
            let int = |k: &str| e.get(k).and_then(Value::as_i64).unwrap_or(0);
            let age = int("age").clamp(0, u32::MAX as i64) as u32;
            self.store(Op::Heard {
                repeater: pk,
                node,
                name: e.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string),
                node_type: int("type").clamp(0, 15) as u8,
                hops: int("hops").clamp(0, 63) as u8,
                rssi: int("rssi").clamp(-200, 50) as i32,
                snr: e.get("snr").and_then(Value::as_f64).unwrap_or(0.0),
                last_heard: now.unix.saturating_sub(age),
                count: int("count").clamp(0, u32::MAX as i64) as u32,
                ts: now.unix,
            });
            n += 1;
        }
        let callsign = self.callsign(&pk);
        self.event(json!({
            "t": "neighbours", "rep": callsign, "pub": hx(&pk), "n": n,
            "page": v.get("page"), "pages": v.get("pages"), "ts": now.unix,
        }));
    }

    // -------------------------------------------------------- bridging --

    fn burst(&self) -> f64 {
        (self.p.rate_per_min / 3).max(1) as f64
    }

    /// One FRAME token from the target's bucket ("Hub rules" 7).
    fn take_token(&mut self, now: Now, pk: &Pub) -> bool {
        let rate = self.p.rate_per_min as f64;
        let cap = self.burst();
        let Some(s) = self.reps.get_mut(pk).and_then(|r| r.cur.as_mut()) else { return false };
        let dt = now.ms.saturating_sub(s.tokens_ms) as f64;
        s.tokens = (s.tokens + dt * rate / 60_000.0).min(cap);
        s.tokens_ms = now.ms;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn fanout(&mut self, now: Now, h: PktHash) {
        let Some(e) = self.dedup.get_mut(&h) else { return };
        e.fanned = true;
        let Some((frame, src, own)) = e.frame.clone() else { return };
        let skip: HashSet<Pub> = e.reported.union(&e.sent).copied().collect();
        let Some(pkt) = Packet::parse(&frame) else { return };

        let candidates = self.reps.iter().filter(|(pk, r)| **pk != src && r.bridge_up() && !skip.contains(*pk));
        let targets: Vec<Pub> = if pkt.is_flood() {
            if own && pkt.ptype() != ptype::ADVERT && !self.p.own_replies {
                self.stats.own_skipped += 1;
                return;
            }
            candidates.map(|(pk, _)| *pk).collect()
        } else {
            // Direct: route by path only. The next hop's hash picks the
            // candidates, and the path-tail rule keeps only a repeater the
            // route actually went through.
            let hs = pkt.hash_size();
            let first = &pkt.path[..hs];
            let tail: Vec<u8> = pkt.path[hs..].chunks(hs).rev().flatten().copied().collect();
            let key = (hs as u8, tail);
            let mem = self.p.path_memory_ms;
            let t: Vec<Pub> = candidates
                .filter(|(pk, r)| {
                    pk[..hs] == *first && r.flood_paths.get(&key).is_some_and(|&seen| now.ms.saturating_sub(seen) <= mem)
                })
                .map(|(pk, _)| *pk)
                .collect();
            if t.is_empty() && !skip.iter().any(|pk| pk[..hs] == *first) {
                self.stats.direct_unrouted += 1;
            }
            t
        };

        let mut src8 = [0u8; 8];
        src8.copy_from_slice(&src[..8]);
        let body = wire::build_frame(&src8, &frame);
        let src_call = self.callsign(&src);
        for t in targets {
            if !self.take_token(now, &t) {
                self.stats.rate_limited += 1;
                let msg = "bridge rate limit reached, frame not sent".to_string();
                self.warn_rep(now, &t, &msg);
                continue;
            }
            if !self.send_session(&t, ty::FRAME, &body) {
                continue;
            }
            self.stats.bridged += 1;
            if let Some(e) = self.dedup.get_mut(&h) {
                e.sent.insert(t);
            }
            let dst_call = self.callsign(&t);
            self.store(Op::Bridged { ts: now.unix, hash: h, src, dst: t, route: pkt.route(), ptype: pkt.ptype() });
            self.event(json!({
                "t": "bridged", "hash": hx(&h), "from": src_call, "to": dst_call,
                "type": ptype::name(pkt.ptype()), "route": if pkt.is_flood() { "flood" } else { "direct" }, "ts": now.unix,
            }));
        }
    }

    // ----------------------------------------------------------- timers --

    pub fn tick(&mut self, now: Now) {
        while let Some(&Reverse((at, h))) = self.due.peek() {
            if at > now.ms {
                break;
            }
            self.due.pop();
            if self.dedup.get(&h).is_some_and(|e| !e.fanned) {
                self.fanout(now, h);
            }
        }

        if now.ms.saturating_sub(self.last_sweep_ms) >= 1000 {
            self.last_sweep_ms = now.ms;
            let mut dead = Vec::new();
            let mut stale = Vec::new();
            for (pk, r) in &self.reps {
                if let Some(s) = &r.cur
                    && now.ms.saturating_sub(s.last_rx_ms) > (3 * s.keepalive_s as u64 + 5) * 1000
                {
                    dead.push(*pk);
                }
                if let Some(p) = &r.pending
                    && now.ms.saturating_sub(p.created_ms) > PENDING_MS
                {
                    stale.push(*pk);
                }
            }
            for pk in dead {
                self.drop_session(now, &pk, "timeout");
            }
            for pk in stale {
                if let Some(p) = self.reps.get_mut(&pk).and_then(|r| r.pending.take()) {
                    self.sids.remove(&p.sid);
                }
            }
        }

        if now.ms.saturating_sub(self.last_slow_ms) >= 60_000 {
            self.last_slow_ms = now.ms;
            let (dedup_ms, mem) = (self.p.dedup_ms, self.p.path_memory_ms);
            self.dedup.retain(|_, e| now.ms.saturating_sub(e.touched_ms) <= dedup_ms);
            for r in self.reps.values_mut() {
                r.flood_paths.retain(|_, &mut t| now.ms.saturating_sub(t) <= mem);
            }
            self.hello_rl.retain(|_, &mut t| now.ms.saturating_sub(t) < 10_000);
            self.reset_rl.retain(|_, &mut t| now.ms.saturating_sub(t) < 10_000);
            self.unknown_warned.retain(|_, &mut t| now.ms.saturating_sub(t) < WARN_EVERY_MS);
            let ev = json!({"t": "hub", "connected": self.connected(), "stats": self.stats, "ts": now.unix});
            self.event(ev);
        }
    }

    /// BYE "shutting down" to everyone.
    pub fn shutdown(&mut self, now: Now) {
        let up: Vec<Pub> = self.reps.iter().filter(|(_, r)| r.cur.is_some()).map(|(pk, _)| *pk).collect();
        for pk in up {
            self.send_session(&pk, ty::BYE_DOWN, &[bye::SHUTDOWN]);
            self.drop_session(now, &pk, "hub shutting down");
        }
    }

    /// Connected repeaters, for the hub's own status.
    pub fn sessions(&self) -> Vec<Value> {
        self.reps
            .iter()
            .filter_map(|(pk, r)| {
                r.cur.as_ref().map(|s| json!({"rep": r.callsign, "pub": hx(pk), "roles": role_names(s.roles)}))
            })
            .collect()
    }
}

fn prune_oldest(m: &mut HashMap<(u8, Vec<u8>), u64>) {
    let mut times: Vec<u64> = m.values().copied().collect();
    times.sort_unstable();
    let cut = times[times.len() / 4];
    m.retain(|_, &mut t| t > cut);
}

pub fn role_names(roles: u8) -> Vec<&'static str> {
    let mut v = Vec::new();
    if roles & ROLE_OBSERVE != 0 {
        v.push("observe");
    }
    if roles & ROLE_BRIDGE != 0 {
        v.push("bridge");
    }
    v
}
