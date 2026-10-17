//! The hub core driven by simulated repeaters that speak the wire format the
//! way meshcore-repeater does (docs/backbone.md), on a fake clock.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use hubd::core::{Allowed, Hub, Now, Out, Params, Pub};
use hubd::store::Op;
use meshcore_proto::meshcore::{Channel, Packet, build_advert, node_type};
use meshcore_proto::wire::{self, ROLE_BRIDGE, ROLE_OBSERVE, Replay, ty};

const T0: u32 = 1_792_000_000;

fn hub_key() -> SigningKey {
    SigningKey::from_bytes(&std::array::from_fn(|i| 0x20 + i as u8))
}

/// Deterministic "random" bytes for the hub.
fn rng() -> hubd::core::Rng {
    let mut n: u8 = 1;
    Box::new(move |b: &mut [u8]| {
        for x in b.iter_mut() {
            n = n.wrapping_mul(31).wrapping_add(7);
            *x = n;
        }
    })
}

struct Clock {
    ms: u64,
}

impl Clock {
    fn now(&self) -> Now {
        Now { ms: self.ms, unix: T0 + (self.ms / 1000) as u32 }
    }
}

/// A repeater's backbone client, reduced to what the tests need.
struct Sim {
    key: SigningKey,
    name: String,
    addr: SocketAddr,
    roles: u8,
    hello_ts: u32,
    eph: [u8; 32],
    hello: Vec<u8>,
    sid: u32,
    k_up: [u8; 32],
    k_down: [u8; 32],
    seq: u32,
    rx: Replay,
}

impl Sim {
    fn new(seed: [u8; 32], name: &str, port: u16, roles: u8) -> Self {
        Sim {
            key: SigningKey::from_bytes(&seed),
            name: name.into(),
            addr: format!("192.0.2.{}:{port}", port % 200 + 1).parse().unwrap(),
            roles,
            hello_ts: 0,
            eph: [0; 32],
            hello: vec![],
            sid: 0,
            k_up: [0; 32],
            k_down: [0; 32],
            seq: 0,
            rx: Replay::default(),
        }
    }

    fn public(&self) -> Pub {
        self.key.verifying_key().to_bytes()
    }

    fn allowed(&self, roles: u8) -> (Pub, Allowed) {
        (self.public(), Allowed { callsign: self.name.clone(), roles })
    }

    fn make_hello(&mut self, now: Now) -> Vec<u8> {
        self.hello_ts = self.hello_ts.max(now.unix - 1) + 1;
        self.eph = std::array::from_fn(|i| self.key.to_bytes()[i] ^ (self.hello_ts as u8) ^ 0x5a);
        self.hello = wire::build_hello(&self.key, self.roles, self.hello_ts, &wire::x25519_public(&self.eph), &self.name);
        self.hello.clone()
    }

    fn accept_welcome(&mut self, d: &[u8]) -> wire::Welcome {
        let w = wire::check_welcome(d, &hub_key().verifying_key().to_bytes(), &wire::sha256(&[&self.hello]), self.roles).unwrap();
        let shared = wire::x25519(&self.eph, &w.eph_pub);
        let (up, down) = wire::derive_keys(&shared, &self.hello, d).unwrap();
        self.sid = w.session_id;
        self.k_up = up;
        self.k_down = down;
        self.seq = 0;
        self.rx = Replay::default();
        w
    }

    fn seal(&mut self, t: u8, body: &[u8]) -> Vec<u8> {
        self.seq += 1;
        wire::seal(t, self.sid, self.seq, body, &self.k_up)
    }

    /// Open a hub -> repeater session datagram: (type, body).
    fn open(&mut self, d: &[u8]) -> (u8, Vec<u8>) {
        let (t, sid, seq) = wire::peek(d).unwrap();
        assert_eq!(sid, self.sid);
        let body = wire::open(d, &self.k_down).expect("hub MAC");
        assert!(self.rx.check(seq), "hub seq replayed");
        (t, body.to_vec())
    }

    fn observe(&mut self, frame: &[u8], rssi: i16, flags: u8) -> Vec<u8> {
        let o = wire::Observe {
            flags,
            disposition: wire::disp::FORWARDED,
            rssi,
            snr_q: 20,
            pkt_hash: Packet::parse(frame).unwrap().pkt_hash(),
            frame,
        };
        self.seal(ty::OBSERVE, &wire::build_observe(&o))
    }

    fn bridge(&mut self, frame: &[u8], own: bool) -> Vec<u8> {
        let b = wire::Bridge {
            flags: if own { wire::BRIDGE_OWN } else { 0 },
            pkt_hash: Packet::parse(frame).unwrap().pkt_hash(),
            frame,
        };
        self.seal(ty::BRIDGE, &wire::build_bridge(&b))
    }
}

struct World {
    hub: Hub,
    clock: Clock,
    out: Vec<Out>,
}

impl World {
    fn new(allow: Vec<(Pub, Allowed)>) -> Self {
        World { hub: Hub::new(hub_key(), Params::default(), allow, vec![Channel::public(), Channel::hashtag("mesh")], rng()), clock: Clock { ms: 1_000 }, out: vec![] }
    }

    fn now(&self) -> Now {
        self.clock.now()
    }

    fn feed(&mut self, from: SocketAddr, d: &[u8]) {
        let now = self.now();
        self.hub.handle(now, from, d);
        self.out.extend(self.hub.drain());
    }

    fn advance(&mut self, ms: u64) {
        let end = self.clock.ms + ms;
        while self.clock.ms < end {
            self.clock.ms = (self.clock.ms + 100).min(end);
            let now = self.now();
            self.hub.tick(now);
            self.out.extend(self.hub.drain());
        }
    }

    /// Datagrams sent to `to` since the last take, in order.
    fn sent_to(&mut self, to: SocketAddr) -> Vec<Vec<u8>> {
        let mut got = vec![];
        self.out.retain(|o| match o {
            Out::Send(a, d) if *a == to => {
                got.push(d.clone());
                false
            }
            _ => true,
        });
        got
    }

    fn ops(&mut self) -> Vec<Op> {
        let mut got = vec![];
        self.out.retain(|o| match o {
            Out::Store(op) => {
                got.push(op.clone());
                false
            }
            _ => true,
        });
        got
    }

    /// HELLO -> WELCOME -> KEEPALIVE -> KEEPALIVE_ACK.
    fn connect(&mut self, s: &mut Sim) -> wire::Welcome {
        let now = self.now();
        let hello = s.make_hello(now);
        self.feed(s.addr, &hello);
        let replies = self.sent_to(s.addr);
        assert_eq!(replies.len(), 1, "{} expected one WELCOME", s.name);
        let w = s.accept_welcome(&replies[0]);
        let ka = s.seal(ty::KEEPALIVE, &[]);
        self.feed(s.addr, &ka);
        let acks = self.sent_to(s.addr);
        assert_eq!(acks.len(), 1);
        assert_eq!(s.open(&acks[0]).0, ty::KEEPALIVE_ACK);
        self.clock.ms += 1100; // keep HELLO rate limits out of the way
        w
    }

    /// FRAMEs a repeater received: (src8, frame).
    fn frames_for(&mut self, s: &mut Sim) -> Vec<([u8; 8], Vec<u8>)> {
        self.sent_to(s.addr)
            .iter()
            .map(|d| {
                let (t, body) = s.open(d);
                assert_eq!(t, ty::FRAME);
                let (src, f) = wire::parse_frame(&body).unwrap();
                (src, f.to_vec())
            })
            .collect()
    }
}

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A seed whose public key starts with `first` (for path-hash collisions).
fn seed_with_first_byte(first: u8, not: &[[u8; 32]]) -> [u8; 32] {
    for i in 0u32.. {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(&i.to_le_bytes());
        s[31] = 0xEE;
        let k = SigningKey::from_bytes(&s);
        if k.verifying_key().as_bytes()[0] == first && !not.contains(&s) {
            return s;
        }
    }
    unreachable!()
}

/// A relayed flood GRP_TXT on Public: path as given (first hop first).
fn flood(text: &str, path: &[u8]) -> Vec<u8> {
    let mut f = Channel::public().build_txt("ON4XYZ", text, T0);
    f[1] = path.len() as u8;
    for (i, b) in path.iter().enumerate() {
        f.insert(2 + i, *b);
    }
    f
}

/// A direct frame (encrypted DM type) with the given path.
fn direct(path: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut f = vec![(0x02 << 2) | 0x02, path.len() as u8];
    f.extend_from_slice(path);
    f.extend_from_slice(payload);
    f
}

const BOTH: u8 = ROLE_OBSERVE | ROLE_BRIDGE;

#[test]
fn handshake_session_and_keepalive() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut w = World::new(vec![a.allowed(ROLE_OBSERVE)]);
    let welcome = w.connect(&mut a);
    assert_eq!(welcome.roles, ROLE_OBSERVE, "bridge not allowed, so not granted");
    assert_eq!((welcome.keepalive_s, welcome.status_s, welcome.neighbours_s), (25, 60, 300));
    let ops = w.ops();
    assert!(ops.iter().any(|o| matches!(o, Op::Up { pk, roles, .. } if *pk == a.public() && *roles == ROLE_OBSERVE)));
    assert_eq!(w.hub.connected(), 1);

    // NAT roaming: a new source port keeps the session, replies follow it.
    a.addr = "192.0.2.77:40000".parse().unwrap();
    let ka = a.seal(ty::KEEPALIVE, &[]);
    w.feed(a.addr, &ka);
    assert_eq!(w.sent_to(a.addr).len(), 1);

    // Replay of an accepted datagram and a bad MAC are dropped silently.
    w.feed(a.addr, &ka);
    let mut forged = a.seal(ty::KEEPALIVE, &[]);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    w.feed(a.addr, &forged);
    assert!(w.sent_to(a.addr).is_empty());
    assert_eq!(w.hub.stats().replay, 1);
    assert_eq!(w.hub.stats().bad_mac, 1);
}

#[test]
fn hello_rejections() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut stranger = Sim::new(seed(9), "ON9BAD", 1009, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH)]);

    let now = w.now();
    let h = stranger.make_hello(now);
    w.feed(stranger.addr, &h);
    assert!(w.sent_to(stranger.addr).is_empty(), "not on the allowlist");

    // Clock 5 minutes off.
    let mut skewed = w.now();
    skewed.unix += 300;
    let h = a.make_hello(skewed);
    w.feed(a.addr, &h);
    assert!(w.sent_to(a.addr).is_empty(), "outside the ±120 s window");

    // Tampered signature.
    w.clock.ms += 1100;
    a.hello_ts = 0;
    let now = w.now();
    let mut h = a.make_hello(now);
    h[8] ^= 1;
    w.feed(a.addr, &h);
    assert!(w.sent_to(a.addr).is_empty());

    // A good one, then the same HELLO again (ts not increasing).
    w.clock.ms += 1100;
    let now = w.now();
    let h = a.make_hello(now);
    w.feed(a.addr, &h);
    assert_eq!(w.sent_to(a.addr).len(), 1);
    w.clock.ms += 1100;
    w.feed(a.addr, &h);
    assert!(w.sent_to(a.addr).is_empty(), "replayed HELLO");
}

#[test]
fn flood_bridging_hold_dedup_and_src() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut b = Sim::new(seed(2), "ON0BBB", 1002, BOTH);
    let mut c = Sim::new(seed(3), "ON0CCC", 1003, BOTH);
    let mut o = Sim::new(seed(4), "ON0OBS", 1004, ROLE_OBSERVE);
    let mut w = World::new(vec![a.allowed(BOTH), b.allowed(BOTH), c.allowed(BOTH), o.allowed(ROLE_OBSERVE)]);
    for s in [&mut a, &mut b, &mut c, &mut o] {
        w.connect(s);
    }

    // A relayed a flood heard via y; it ends with A's own hash.
    let f = flood("hello island", &[0x77, a.public()[0]]);
    let d = a.bridge(&f, false);
    w.feed(a.addr, &d);
    // C heard the same packet on RF during the hold.
    let d = c.observe(&flood("hello island", &[0x77]), -90, 0);
    w.feed(c.addr, &d);

    w.advance(900);
    assert!(w.frames_for(&mut b).is_empty(), "held for ~1 s first");
    w.advance(200);
    let got = w.frames_for(&mut b);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, a.public()[..8]);
    assert_eq!(got[0].1, f, "frame bytes are never modified");
    assert!(w.frames_for(&mut a).is_empty(), "never back to the offering repeater");
    assert!(w.frames_for(&mut c).is_empty(), "C reported it, so C has it");
    assert!(w.sent_to(o.addr).is_empty(), "observe-only repeaters get no frames");

    // B relays it on RF too and offers it: nothing new goes out.
    let mut fb = f.clone();
    fb[1] += 1;
    fb.insert(2 + 2, b.public()[0]);
    let d = b.bridge(&fb, false);
    w.feed(b.addr, &d);
    w.advance(1500);
    assert!(w.frames_for(&mut a).is_empty() && w.frames_for(&mut c).is_empty() && w.frames_for(&mut b).is_empty());
    assert_eq!(w.hub.stats().bridged, 1);
}

#[test]
fn own_replies_are_not_bridged_but_own_adverts_are() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut b = Sim::new(seed(2), "ON0BBB", 1002, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH), b.allowed(BOTH)]);
    w.connect(&mut a);
    w.connect(&mut b);

    let pong = Channel::hashtag("mesh").build_txt("ON0AAA", "pong rssi -95dBm snr 7.5dB", T0);
    let d = a.bridge(&pong, true);
    w.feed(a.addr, &d);
    let adv = build_advert(&a.key, T0, node_type::REPEATER, Some((51.0, 4.2)), "ON0AAA");
    let d = a.bridge(&adv, true);
    w.feed(a.addr, &d);
    w.advance(1200);
    let got = w.frames_for(&mut b);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, adv);
    assert_eq!(w.hub.stats().own_skipped, 1);
}

#[test]
fn direct_routing_path_tail_and_collisions() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let first = a.public()[0];
    // A2 shares A's first public-key byte: a 1-byte path-hash collision.
    let mut a2 = Sim::new(seed_with_first_byte(first, &[seed(1)]), "ON0AA2", 1005, BOTH);
    let mut b = Sim::new(seed(2), "ON0BBB", 1002, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH), a2.allowed(BOTH), b.allowed(BOTH)]);
    for s in [&mut a, &mut a2, &mut b] {
        w.connect(s);
    }
    assert_eq!(a2.public()[0], first);

    // Floods teach the hub: via A the route was [y1, y2], via A2 it was [w].
    let d = a.bridge(&flood("one", &[0x31, 0x32, first]), false);
    w.feed(a.addr, &d);
    let d = a2.bridge(&flood("two", &[0x55, first]), false);
    w.feed(a2.addr, &d);
    w.advance(1200);
    w.frames_for(&mut b);
    w.frames_for(&mut a);
    w.frames_for(&mut a2);

    // z (behind B) replies to x on the reversed path; B stripped itself.
    let reply = direct(&[first, 0x32, 0x31], &[1, 2, 3, 4, 5, 6]);
    let d = b.bridge(&reply, false);
    w.feed(b.addr, &d);
    w.advance(1200);
    assert_eq!(w.frames_for(&mut a).len(), 1, "A is where the route went");
    assert!(w.frames_for(&mut a2).is_empty(), "same first byte, different route");
    assert!(w.frames_for(&mut b).is_empty());

    // A reply on a tail neither repeater has relayed goes nowhere.
    let stray = direct(&[first, 0x99], &[9, 9, 9]);
    let d = b.bridge(&stray, false);
    w.feed(b.addr, &d);
    w.advance(1200);
    assert!(w.frames_for(&mut a).is_empty() && w.frames_for(&mut a2).is_empty());
    assert_eq!(w.hub.stats().direct_unrouted, 1);

    // Last hop: [A] with an empty tail matches a flood A heard directly.
    let d = a.bridge(&flood("three", &[first]), false);
    w.feed(a.addr, &d);
    w.advance(1200);
    w.frames_for(&mut b);
    w.frames_for(&mut a2);
    let d = b.bridge(&direct(&[first], &[7, 7, 7]), false);
    w.feed(b.addr, &d);
    w.advance(1200);
    assert_eq!(w.frames_for(&mut a).len(), 1);
    assert!(w.frames_for(&mut a2).is_empty());
}

#[test]
fn rate_limit_per_repeater() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut b = Sim::new(seed(2), "ON0BBB", 1002, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH), b.allowed(BOTH)]);
    w.connect(&mut a);
    w.connect(&mut b);
    for i in 0..20 {
        let d = a.bridge(&flood(&format!("msg {i}"), &[a.public()[0]]), false);
        w.feed(a.addr, &d);
    }
    w.advance(1100);
    // 25/min with a burst of 8; about half a token refilled during the hold.
    assert_eq!(w.frames_for(&mut b).len(), 8);
    assert_eq!(w.hub.stats().rate_limited, 12);
}

#[test]
fn timeout_reset_and_bye() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut b = Sim::new(seed(2), "ON0BBB", 1002, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH), b.allowed(BOTH)]);
    w.connect(&mut a);
    w.connect(&mut b);
    w.ops();

    // B keeps talking, A goes quiet: 3 x 25 s + 5 s later A is dropped.
    for _ in 0..9 {
        w.advance(10_000);
        let ka = b.seal(ty::KEEPALIVE, &[]);
        w.feed(b.addr, &ka);
    }
    let ops = w.ops();
    assert!(ops.iter().any(|o| matches!(o, Op::Down { pk, reason, .. } if *pk == a.public() && reason == "timeout")));
    assert!(!ops.iter().any(|o| matches!(o, Op::Down { pk, .. } if *pk == b.public())));

    // A's next datagram is under a session the hub forgot: signed RESET.
    let ka = a.seal(ty::KEEPALIVE, &[]);
    w.feed(a.addr, &ka);
    let r = w.sent_to(a.addr);
    assert_eq!(r.len(), 1);
    let (sid, seq, _) = wire::check_reset(&r[0], &hub_key().verifying_key().to_bytes()).unwrap();
    assert_eq!((sid, seq), (a.sid, a.seq));
    // Rate limited: one per source per 5 s.
    let ka = a.seal(ty::KEEPALIVE, &[]);
    w.feed(a.addr, &ka);
    assert!(w.sent_to(a.addr).is_empty());

    // B says bye.
    let d = b.seal(ty::BYE_UP, &[wire::bye::SHUTDOWN]);
    w.feed(b.addr, &d);
    assert_eq!(w.hub.connected(), 0);
}

#[test]
fn rehandshake_replaces_session_and_allowlist_revocation() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, BOTH);
    let mut w = World::new(vec![a.allowed(BOTH)]);
    w.connect(&mut a);
    let old_sid = a.sid;
    let old_up = a.k_up;

    // New handshake: the old session keeps working until the new one is confirmed.
    let now = w.now();
    let hello = a.make_hello(now);
    w.feed(a.addr, &hello);
    let welcome = w.sent_to(a.addr).remove(0);
    let ka_old = wire::seal(ty::KEEPALIVE, old_sid, a.seq + 1, &[], &old_up);
    w.feed(a.addr, &ka_old);
    assert_eq!(w.sent_to(a.addr).len(), 1, "old session still answers");
    a.accept_welcome(&welcome);
    let ka = a.seal(ty::KEEPALIVE, &[]);
    w.feed(a.addr, &ka);
    assert_eq!(a.open(&w.sent_to(a.addr)[0]).0, ty::KEEPALIVE_ACK);
    let ka_old = wire::seal(ty::KEEPALIVE, old_sid, 999, &[], &old_up);
    w.feed(a.addr, &ka_old);
    assert!(w.hub.stats().unknown_session >= 1, "old session is gone");
    w.sent_to(a.addr);

    // Revoking bridge: BYE "not allowed" under the live session.
    let now = w.now();
    w.hub.set_allowlist(Some(now), vec![a.allowed(ROLE_OBSERVE)]);
    w.out.extend(w.hub.drain());
    let byes = w.sent_to(a.addr);
    assert_eq!(byes.len(), 1);
    assert_eq!(a.open(&byes[0]), (ty::BYE_DOWN, vec![wire::bye::NOT_ALLOWED]));
    assert_eq!(w.hub.connected(), 0);
}

#[test]
fn observe_decodes_adverts_and_public_text_only() {
    let mut a = Sim::new(seed(1), "ON0AAA", 1001, ROLE_OBSERVE);
    let mut w = World::new(vec![a.allowed(ROLE_OBSERVE)]);
    w.connect(&mut a);
    w.ops();

    let node = SigningKey::from_bytes(&seed(42));
    let adv = build_advert(&node, T0, node_type::CHAT, Some((50.93, 4.21)), "ON4XYZ");
    let d = a.observe(&adv, -101, 0);
    w.feed(a.addr, &d);
    let txt = Channel::public().build_txt("ON4XYZ", "hello Merchtem", T0);
    let d = a.observe(&txt, -95, 0);
    w.feed(a.addr, &d);
    let dm = direct(&[0x12], &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    let d = a.observe(&dm, -99, 0);
    w.feed(a.addr, &d);

    let ops = w.ops();
    assert_eq!(ops.iter().filter(|o| matches!(o, Op::Frame { .. })).count(), 3);
    assert!(ops.iter().any(|o| matches!(o, Op::Node { pk, name: Some(n), lat: Some(_), .. } if *pk == node.verifying_key().to_bytes() && n == "ON4XYZ")));
    assert!(ops.iter().any(|o| matches!(o, Op::Message { text, sender: Some(s), channel, .. } if text == "hello Merchtem" && s == "ON4XYZ" && channel == "Public")));
    assert_eq!(ops.iter().filter(|o| matches!(o, Op::Message { .. } | Op::Node { .. })).count(), 2, "nothing decoded from the DM");

    // BRIDGE without the bridge role is refused.
    let d = a.bridge(&txt, false);
    w.feed(a.addr, &d);
    assert_eq!(w.hub.stats().role_denied, 1);
}
