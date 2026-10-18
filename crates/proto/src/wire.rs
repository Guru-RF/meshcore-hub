//! IP backbone wire format, version 1.
//!
//! The contract is meshcore-repeater `docs/backbone.md`; section names below
//! refer to it. Integers are little-endian. Handshake datagrams are Ed25519
//! signed, every later datagram carries a session id, a sequence number and a
//! truncated HMAC-SHA256.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const MAGIC: [u8; 2] = *b"MB";
pub const VERSION: u8 = 1;
/// Largest datagram either side sends.
pub const MAX_DGRAM: usize = 1200;
/// Session header: magic(2) version(1) type(1) session_id(4) seq(4).
pub const HDR: usize = 12;
pub const MAC_LEN: usize = 16;
/// HELLO bytes before the name.
pub const HELLO_FIXED: usize = 75;
pub const WELCOME_LEN: usize = 148;
pub const RESET_LEN: usize = 80;
pub const NAME_MAX: usize = 32;
pub const SIG_LEN: usize = 64;
/// A LoRa frame is 1..=255 bytes.
pub const FRAME_MAX: usize = 255;
/// Handshake and RESET timestamps must be within this many seconds.
pub const TS_WINDOW_S: u32 = 120;

/// Datagram types ("Datagram header and types").
pub mod ty {
    pub const HELLO: u8 = 0x01;
    pub const WELCOME: u8 = 0x02;
    pub const RESET: u8 = 0x03;
    pub const KEEPALIVE: u8 = 0x10;
    pub const OBSERVE: u8 = 0x11;
    pub const BRIDGE: u8 = 0x12;
    pub const STATUS: u8 = 0x13;
    pub const NEIGHBOURS: u8 = 0x14;
    pub const BYE_UP: u8 = 0x1F;
    pub const KEEPALIVE_ACK: u8 = 0x20;
    pub const FRAME: u8 = 0x21;
    pub const POLICY: u8 = 0x22;
    pub const BYE_DOWN: u8 = 0x2F;

    /// Types 0x10..=0x1F flow repeater -> hub under `k_up`.
    pub fn is_up(t: u8) -> bool {
        (0x10..=0x1F).contains(&t)
    }
    /// Types 0x20..=0x2F flow hub -> repeater under `k_down`.
    pub fn is_down(t: u8) -> bool {
        (0x20..=0x2F).contains(&t)
    }
}

pub const ROLE_OBSERVE: u8 = 0x01;
pub const ROLE_BRIDGE: u8 = 0x02;
pub const ROLES_ALL: u8 = ROLE_OBSERVE | ROLE_BRIDGE;

/// OBSERVE flag: the frame came from the hub, not from RF.
pub const OBS_FROM_BACKBONE: u8 = 0x01;
/// BRIDGE flag: the repeater originated the frame itself.
pub const BRIDGE_OWN: u8 = 0x01;

/// OBSERVE `disposition` values.
pub mod disp {
    pub const FORWARDED: u8 = 0;
    pub const DUPLICATE: u8 = 1;
    pub const POLICY: u8 = 2;
    pub const LOCAL: u8 = 3;
    pub const LIMITED: u8 = 4;

    pub fn name(d: u8) -> &'static str {
        match d {
            FORWARDED => "forwarded",
            DUPLICATE => "duplicate",
            POLICY => "policy",
            LOCAL => "local",
            LIMITED => "limited",
            _ => "unknown",
        }
    }
}

/// BYE reasons.
pub mod bye {
    pub const SHUTDOWN: u8 = 0;
    pub const REKEY: u8 = 1;
    pub const DISABLED: u8 = 2;
    pub const NOT_ALLOWED: u8 = 3;

    pub fn name(r: u8) -> &'static str {
        match r {
            SHUTDOWN => "shutting down",
            REKEY => "new handshake",
            DISABLED => "backbone disabled",
            NOT_ALLOWED => "not allowed",
            _ => "unknown",
        }
    }
}

const CTX_HELLO: &[u8] = b"MCBB1 HELLO";
const CTX_WELCOME: &[u8] = b"MCBB1 WELCOME";
const CTX_RESET: &[u8] = b"MCBB1 RESET";
const CTX_UP: &[u8] = b"MCBB1 up";
const CTX_DOWN: &[u8] = b"MCBB1 down";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Short,
    Magic,
    Version,
    Type,
    Length,
    Name,
    Key,
    Signature,
    HelloHash,
    Roles,
    SessionId,
    Mac,
    LowOrder,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn header(t: u8) -> [u8; 4] {
    [MAGIC[0], MAGIC[1], VERSION, t]
}

/// Check magic and version and return the type. Unknown types are the
/// caller's business.
pub fn datagram_type(d: &[u8]) -> Result<u8, Error> {
    if d.len() < 4 {
        return Err(Error::Short);
    }
    if d[0..2] != MAGIC {
        return Err(Error::Magic);
    }
    if d[2] != VERSION {
        return Err(Error::Version);
    }
    Ok(d[3])
}

fn sign(key: &SigningKey, ctx: &[u8], bytes: &[u8]) -> [u8; SIG_LEN] {
    let mut msg = Vec::with_capacity(ctx.len() + bytes.len());
    msg.extend_from_slice(ctx);
    msg.extend_from_slice(bytes);
    key.sign(&msg).to_bytes()
}

fn verify(public: &[u8; 32], ctx: &[u8], bytes: &[u8], sig: &[u8]) -> Result<(), Error> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| Error::Key)?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::Signature)?;
    let mut msg = Vec::with_capacity(ctx.len() + bytes.len());
    msg.extend_from_slice(ctx);
    msg.extend_from_slice(bytes);
    vk.verify_strict(&msg, &sig).map_err(|_| Error::Signature)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------- HELLO --

/// A parsed HELLO. Its signature is checked separately by [`verify_hello`],
/// so the hub can consult its allowlist before paying for the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub roles: u8,
    pub ts: u32,
    pub node_pub: [u8; 32],
    pub eph_pub: [u8; 32],
    /// The repeater's node name, informational only.
    pub name: String,
}

pub fn build_hello(id: &SigningKey, roles: u8, ts: u32, eph_pub: &[u8; 32], name: &str) -> Vec<u8> {
    let mut name = name.as_bytes();
    if name.len() > NAME_MAX {
        name = &name[..NAME_MAX];
    }
    let mut d = Vec::with_capacity(HELLO_FIXED + name.len() + SIG_LEN);
    d.extend_from_slice(&header(ty::HELLO));
    d.push(roles);
    d.push(0);
    d.extend_from_slice(&ts.to_le_bytes());
    d.extend_from_slice(id.verifying_key().as_bytes());
    d.extend_from_slice(eph_pub);
    d.push(name.len() as u8);
    d.extend_from_slice(name);
    let sig = sign(id, CTX_HELLO, &d);
    d.extend_from_slice(&sig);
    d
}

pub fn parse_hello(d: &[u8]) -> Result<Hello, Error> {
    if datagram_type(d)? != ty::HELLO {
        return Err(Error::Type);
    }
    if d.len() < HELLO_FIXED + SIG_LEN {
        return Err(Error::Short);
    }
    let n = d[74] as usize;
    if n > NAME_MAX {
        return Err(Error::Name);
    }
    if d.len() != HELLO_FIXED + n + SIG_LEN {
        return Err(Error::Length);
    }
    Ok(Hello {
        roles: d[4],
        ts: rd_u32(d, 6),
        node_pub: d[10..42].try_into().unwrap(),
        eph_pub: d[42..74].try_into().unwrap(),
        name: String::from_utf8_lossy(&d[75..75 + n]).into_owned(),
    })
}

/// Check the HELLO signature against the key it carries.
pub fn verify_hello(d: &[u8], h: &Hello) -> Result<(), Error> {
    let body = d.len() - SIG_LEN;
    verify(&h.node_pub, CTX_HELLO, &d[..body], &d[body..])
}

// -------------------------------------------------------------- WELCOME --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Welcome {
    pub roles: u8,
    pub ts: u32,
    pub session_id: u32,
    pub eph_pub: [u8; 32],
    pub keepalive_s: u16,
    pub status_s: u16,
    pub neighbours_s: u16,
}

pub fn build_welcome(hub: &SigningKey, w: &Welcome, hello_hash: &[u8; 32]) -> [u8; WELCOME_LEN] {
    let mut d = [0u8; WELCOME_LEN];
    d[0..4].copy_from_slice(&header(ty::WELCOME));
    d[4] = w.roles;
    d[5] = 0;
    d[6..10].copy_from_slice(&w.ts.to_le_bytes());
    d[10..14].copy_from_slice(&w.session_id.to_le_bytes());
    d[14..46].copy_from_slice(&w.eph_pub);
    d[46..78].copy_from_slice(hello_hash);
    d[78..80].copy_from_slice(&w.keepalive_s.to_le_bytes());
    d[80..82].copy_from_slice(&w.status_s.to_le_bytes());
    d[82..84].copy_from_slice(&w.neighbours_s.to_le_bytes());
    let sig = sign(hub, CTX_WELCOME, &d[..84]);
    d[84..].copy_from_slice(&sig);
    d
}

/// The repeater's checks on a WELCOME (used by tests and the simulator).
pub fn check_welcome(d: &[u8], hub_pub: &[u8; 32], hello_hash: &[u8; 32], roles_asked: u8) -> Result<Welcome, Error> {
    if datagram_type(d)? != ty::WELCOME {
        return Err(Error::Type);
    }
    if d.len() != WELCOME_LEN {
        return Err(Error::Length);
    }
    if d[46..78] != hello_hash[..] {
        return Err(Error::HelloHash);
    }
    verify(hub_pub, CTX_WELCOME, &d[..84], &d[84..])?;
    let w = Welcome {
        roles: d[4],
        ts: rd_u32(d, 6),
        session_id: rd_u32(d, 10),
        eph_pub: d[14..46].try_into().unwrap(),
        keepalive_s: rd_u16(d, 78),
        status_s: rd_u16(d, 80),
        neighbours_s: rd_u16(d, 82),
    };
    if w.session_id == 0 {
        return Err(Error::SessionId);
    }
    if w.roles & !roles_asked != 0 {
        return Err(Error::Roles);
    }
    Ok(w)
}

// ---------------------------------------------------------------- RESET --

pub fn build_reset(hub: &SigningKey, session_id: u32, seq: u32, ts: u32) -> [u8; RESET_LEN] {
    let mut d = [0u8; RESET_LEN];
    d[0..4].copy_from_slice(&header(ty::RESET));
    d[4..8].copy_from_slice(&session_id.to_le_bytes());
    d[8..12].copy_from_slice(&seq.to_le_bytes());
    d[12..16].copy_from_slice(&ts.to_le_bytes());
    let sig = sign(hub, CTX_RESET, &d[..16]);
    d[16..].copy_from_slice(&sig);
    d
}

/// Check a RESET's signature; returns (session_id, seq, ts).
pub fn check_reset(d: &[u8], hub_pub: &[u8; 32]) -> Result<(u32, u32, u32), Error> {
    if datagram_type(d)? != ty::RESET {
        return Err(Error::Type);
    }
    if d.len() != RESET_LEN {
        return Err(Error::Length);
    }
    verify(hub_pub, CTX_RESET, &d[..16], &d[16..])?;
    Ok((rd_u32(d, 4), rd_u32(d, 8), rd_u32(d, 12)))
}

// --------------------------------------------------------- session keys --

/// `k_up` and `k_down` from the X25519 shared secret and the two complete
/// handshake datagrams. `None` if the shared secret is all zero.
pub fn derive_keys(shared: &[u8; 32], hello: &[u8], welcome: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if shared.iter().all(|&b| b == 0) {
        return None;
    }
    let th = sha256(&[hello, welcome]);
    let k = |ctx: &[u8]| -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(shared).expect("any key length");
        m.update(ctx);
        m.update(&th);
        m.finalize().into_bytes().into()
    };
    Some((k(CTX_UP), k(CTX_DOWN)))
}

/// X25519 public key for a secret scalar.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    *x25519_dalek::PublicKey::from(&s).as_bytes()
}

/// X25519 shared secret.
pub fn x25519(secret: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    *s.diffie_hellman(&x25519_dalek::PublicKey::from(*peer_pub)).as_bytes()
}

// ----------------------------------------------------- session datagrams --

/// Session header + body + truncated MAC.
pub fn seal(t: u8, session_id: u32, seq: u32, body: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(HDR + body.len() + MAC_LEN);
    d.extend_from_slice(&header(t));
    d.extend_from_slice(&session_id.to_le_bytes());
    d.extend_from_slice(&seq.to_le_bytes());
    d.extend_from_slice(body);
    let mut m = HmacSha256::new_from_slice(key).expect("any key length");
    m.update(&d);
    let mac = m.finalize().into_bytes();
    d.extend_from_slice(&mac[..MAC_LEN]);
    d
}

/// The unauthenticated session header: (type, session_id, seq). Used to find
/// the session (and its key) before [`open`].
pub fn peek(d: &[u8]) -> Result<(u8, u32, u32), Error> {
    let t = datagram_type(d)?;
    if d.len() < HDR + MAC_LEN {
        return Err(Error::Short);
    }
    Ok((t, rd_u32(d, 4), rd_u32(d, 8)))
}

/// Verify a session datagram's MAC in constant time and return its body.
/// No replay check: see [`Replay`].
pub fn open<'a>(d: &'a [u8], key: &[u8; 32]) -> Result<&'a [u8], Error> {
    peek(d)?;
    let end = d.len() - MAC_LEN;
    let mut m = HmacSha256::new_from_slice(key).expect("any key length");
    m.update(&d[..end]);
    let mac = m.finalize().into_bytes();
    if !bool::from(mac[..MAC_LEN].ct_eq(&d[end..])) {
        return Err(Error::Mac);
    }
    Ok(&d[HDR..end])
}

/// 64-wide sliding replay window, the same as the repeater's `bb_replay_check`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Replay {
    top: u32,
    bits: u64,
}

impl Replay {
    /// Accept `seq` once. Returns false for 0, a repeat, or one older than the window.
    pub fn check(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.top {
            let shift = seq - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = seq;
            return true;
        }
        let back = self.top - seq;
        if back >= 64 || self.bits & (1u64 << back) != 0 {
            return false;
        }
        self.bits |= 1u64 << back;
        true
    }
}

// ---------------------------------------------------------------- bodies --

/// OBSERVE body: one frame heard, and what the repeater did with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observe<'a> {
    pub flags: u8,
    pub disposition: u8,
    pub rssi: i16,
    /// SNR in quarter dB.
    pub snr_q: i8,
    pub pkt_hash: [u8; 8],
    pub frame: &'a [u8],
}

impl Observe<'_> {
    pub fn from_backbone(&self) -> bool {
        self.flags & OBS_FROM_BACKBONE != 0
    }
    pub fn snr(&self) -> f32 {
        self.snr_q as f32 / 4.0
    }
}

pub fn parse_observe(b: &[u8]) -> Result<Observe<'_>, Error> {
    if b.len() < 14 {
        return Err(Error::Short);
    }
    let n = b[5] as usize;
    if n == 0 || b.len() < 14 + n {
        return Err(Error::Length);
    }
    Ok(Observe {
        flags: b[0],
        disposition: b[1],
        rssi: i16::from_le_bytes([b[2], b[3]]),
        snr_q: b[4] as i8,
        pkt_hash: b[6..14].try_into().unwrap(),
        frame: &b[14..14 + n],
    })
}

pub fn build_observe(o: &Observe<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(14 + o.frame.len());
    b.push(o.flags);
    b.push(o.disposition);
    b.extend_from_slice(&o.rssi.to_le_bytes());
    b.push(o.snr_q as u8);
    b.push(o.frame.len() as u8);
    b.extend_from_slice(&o.pkt_hash);
    b.extend_from_slice(o.frame);
    b
}

/// BRIDGE body: a frame the repeater just queued for RF, offered to the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bridge<'a> {
    pub flags: u8,
    pub pkt_hash: [u8; 8],
    pub frame: &'a [u8],
}

impl Bridge<'_> {
    pub fn own(&self) -> bool {
        self.flags & BRIDGE_OWN != 0
    }
}

pub fn parse_bridge(b: &[u8]) -> Result<Bridge<'_>, Error> {
    if b.len() < 10 {
        return Err(Error::Short);
    }
    let n = b[1] as usize;
    if n == 0 || b.len() < 10 + n {
        return Err(Error::Length);
    }
    Ok(Bridge { flags: b[0], pkt_hash: b[2..10].try_into().unwrap(), frame: &b[10..10 + n] })
}

pub fn build_bridge(br: &Bridge<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + br.frame.len());
    b.push(br.flags);
    b.push(br.frame.len() as u8);
    b.extend_from_slice(&br.pkt_hash);
    b.extend_from_slice(br.frame);
    b
}

/// FRAME body (hub -> repeater): `src` is the first 8 bytes of the offering
/// repeater's public key.
pub fn build_frame(src: &[u8; 8], frame: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + frame.len());
    b.push(0);
    b.push(frame.len() as u8);
    b.extend_from_slice(src);
    b.extend_from_slice(frame);
    b
}

/// Parse a FRAME body: (src, frame).
pub fn parse_frame(b: &[u8]) -> Result<([u8; 8], &[u8]), Error> {
    if b.len() < 10 {
        return Err(Error::Short);
    }
    let n = b[1] as usize;
    if n == 0 || b.len() < 10 + n {
        return Err(Error::Length);
    }
    Ok((b[2..10].try_into().unwrap(), &b[10..10 + n]))
}

/// POLICY ("Rooms and blocks"): entry kinds and limits.
pub mod policy {
    pub const ROOM: u8 = 1;
    pub const BLOCK_NAME: u8 = 2;
    pub const BLOCK_KEY: u8 = 3;
    /// Bytes of entries in one page: a full datagram less header, MAC and
    /// the 6-byte page header.
    pub const PAGE_ENTRIES: usize = super::MAX_DGRAM - 12 - 16 - 6;
    pub const MAX_PAGES: usize = 16;
    pub const MAX_ROOMS: usize = 32;
    pub const MAX_BLOCKS: usize = 256;
}

/// One entry of a POLICY set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyEntry {
    /// A room, its name exactly as hashed: `#` and 1-30 more bytes.
    Room(String),
    /// A blocked node name, 1-31 bytes: group-message senders and advert names.
    BlockName(String),
    /// A blocked Ed25519 public key: adverts.
    BlockKey([u8; 32]),
}

impl PolicyEntry {
    fn kind(&self) -> u8 {
        match self {
            PolicyEntry::Room(_) => policy::ROOM,
            PolicyEntry::BlockName(_) => policy::BLOCK_NAME,
            PolicyEntry::BlockKey(_) => policy::BLOCK_KEY,
        }
    }

    fn value(&self) -> &[u8] {
        match self {
            PolicyEntry::Room(s) | PolicyEntry::BlockName(s) => s.as_bytes(),
            PolicyEntry::BlockKey(k) => k,
        }
    }

    /// `kind`, `len`, value: the entry as it goes on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let v = self.value();
        let mut b = vec![self.kind(), v.len() as u8];
        b.extend_from_slice(v);
        b
    }

    /// Fits the wire format.
    pub fn valid(&self) -> bool {
        match self {
            PolicyEntry::Room(s) => s.starts_with('#') && (2..=31).contains(&s.len()),
            PolicyEntry::BlockName(s) => (1..=31).contains(&s.len()),
            PolicyEntry::BlockKey(_) => true,
        }
    }
}

/// POLICY bodies for one complete set, page by page; `None` when the set
/// needs more than 16 pages. Entries must be `valid()`.
pub fn build_policy(version: u32, entries: &[PolicyEntry]) -> Option<Vec<Vec<u8>>> {
    let mut pages: Vec<Vec<u8>> = vec![vec![]];
    for e in entries {
        let enc = e.encode();
        if pages.last().is_some_and(|p| p.len() + enc.len() > policy::PAGE_ENTRIES) {
            pages.push(vec![]);
        }
        pages.last_mut()?.extend_from_slice(&enc);
    }
    if pages.len() > policy::MAX_PAGES {
        return None;
    }
    let n = pages.len() as u8;
    Some(
        pages
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let mut b = version.to_le_bytes().to_vec();
                b.extend_from_slice(&[i as u8 + 1, n]);
                b.extend_from_slice(&p);
                b
            })
            .collect(),
    )
}

/// Parse a POLICY body: (version, page, pages, entries). Unknown kinds, and
/// entries whose length is wrong for their kind, are skipped.
pub fn parse_policy(b: &[u8]) -> Result<(u32, u8, u8, Vec<PolicyEntry>), Error> {
    if b.len() < 6 {
        return Err(Error::Short);
    }
    let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let (page, pages) = (b[4], b[5]);
    if version == 0 || pages == 0 || pages as usize > policy::MAX_PAGES || page == 0 || page > pages {
        return Err(Error::Length);
    }
    let mut out = Vec::new();
    let mut i = 6;
    while i < b.len() {
        if i + 2 > b.len() || i + 2 + b[i + 1] as usize > b.len() {
            return Err(Error::Length);
        }
        let (kind, v) = (b[i], &b[i + 2..i + 2 + b[i + 1] as usize]);
        i += 2 + v.len();
        let e = match kind {
            policy::ROOM => std::str::from_utf8(v).ok().map(|s| PolicyEntry::Room(s.into())),
            policy::BLOCK_NAME => std::str::from_utf8(v).ok().map(|s| PolicyEntry::BlockName(s.into())),
            policy::BLOCK_KEY => v.try_into().ok().map(PolicyEntry::BlockKey),
            _ => None,
        };
        if let Some(e) = e.filter(PolicyEntry::valid) {
            out.push(e);
        }
    }
    Ok((version, page, pages, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq32(start: u8) -> [u8; 32] {
        std::array::from_fn(|i| start + i as u8)
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    // docs/backbone.md, "Test vectors".
    const HELLO_HEX: &str = "
        4d420101030000c0cf6a03a107bff3ce10be1d70dd18e74bc09967e4d6309ba5
        0d5f1ddc8664125531b879a631eede1bf9c98f12032cdeadd0e7a079398fc786
        b88cc846ec89af85a51a064f4e3052464772325767d90b5585b5c869ce17adc0
        e8f74e92f152d3477ff99a441b2db0efd18ccd7110639f44ea3c211d4c9c1783
        bae163f4d80503c556271a1ce798c1020f";
    const WELCOME_HEX: &str = "
        4d420102030001c0cf6a4d3c2b1a675dd574ed7789310b3d2e7681f3790b466c
        773b1521fecf36577958371ea52f6c96f061289bab91bf5fd637e4a1220deafb
        e2efb728e115f6f749965b9c4e7e19003c002c01b611bef646242ce91a5de9ae
        16c95aeefb334cf94e8dab058e8c35062fad386758ee6d8ef90d3006e2199afd
        eb1316dd522ae4ac8948d0b6f6cf6c4c507b8001";

    struct Vectors {
        rep: SigningKey,
        hub: SigningKey,
        rep_eph: [u8; 32],
        hub_eph: [u8; 32],
    }

    fn vectors() -> Vectors {
        Vectors {
            rep: SigningKey::from_bytes(&seq32(0x00)),
            hub: SigningKey::from_bytes(&seq32(0x20)),
            rep_eph: seq32(0x40),
            hub_eph: seq32(0x60),
        }
    }

    #[test]
    fn vector_keys() {
        let v = vectors();
        assert_eq!(hex::encode(v.rep.verifying_key().as_bytes()), "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
        assert_eq!(hex::encode(v.hub.verifying_key().as_bytes()), "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7");
        assert_eq!(hex::encode(x25519_public(&v.rep_eph)), "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a");
        assert_eq!(hex::encode(x25519_public(&v.hub_eph)), "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f");
    }

    #[test]
    fn vector_hello() {
        let v = vectors();
        let d = build_hello(&v.rep, 3, 1792000000, &x25519_public(&v.rep_eph), "ON0RFG");
        assert_eq!(d, h(HELLO_HEX));
        assert_eq!(d.len(), 145);
        assert_eq!(hex::encode(sha256(&[&d])), "6c96f061289bab91bf5fd637e4a1220deafbe2efb728e115f6f749965b9c4e7e");

        let p = parse_hello(&d).unwrap();
        assert_eq!(p.roles, 3);
        assert_eq!(p.ts, 1792000000);
        assert_eq!(p.name, "ON0RFG");
        verify_hello(&d, &p).unwrap();

        let mut bad = d.clone();
        bad[20] ^= 1;
        let pb = parse_hello(&bad).unwrap();
        assert_eq!(verify_hello(&bad, &pb), Err(Error::Signature));
        assert_eq!(parse_hello(&d[..144]), Err(Error::Length));
    }

    #[test]
    fn vector_welcome_and_keys() {
        let v = vectors();
        let hello = h(HELLO_HEX);
        let hello_hash = sha256(&[&hello]);
        let w = Welcome {
            roles: 3,
            ts: 1792000001,
            session_id: 0x1a2b3c4d,
            eph_pub: x25519_public(&v.hub_eph),
            keepalive_s: 25,
            status_s: 60,
            neighbours_s: 300,
        };
        let d = build_welcome(&v.hub, &w, &hello_hash);
        assert_eq!(d.to_vec(), h(WELCOME_HEX));
        let hub_pub = *v.hub.verifying_key().as_bytes();
        assert_eq!(check_welcome(&d, &hub_pub, &hello_hash, 3).unwrap(), w);
        assert_eq!(check_welcome(&d, &hub_pub, &hello_hash, 1), Err(Error::Roles));

        let shared_h = x25519(&v.hub_eph, &x25519_public(&v.rep_eph));
        let shared_r = x25519(&v.rep_eph, &x25519_public(&v.hub_eph));
        assert_eq!(shared_h, shared_r);
        assert_eq!(hex::encode(shared_h), "d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e");
        let (k_up, k_down) = derive_keys(&shared_h, &hello, &d).unwrap();
        assert_eq!(hex::encode(k_up), "141922284ac65dafe1f28d9af212229728a9a949d3d6301bd83ae2cb73455ce5");
        assert_eq!(hex::encode(k_down), "be484977837de2e5315ff41d3bf7b7cd3d4b7bb1af1dde564c29849822df7fae");
        assert!(derive_keys(&[0; 32], &hello, &d).is_none());

        let ka = seal(ty::KEEPALIVE, 0x1a2b3c4d, 1, &[], &k_up);
        assert_eq!(ka, h("4d4201104d3c2b1a0100000095909f12cd7628661a2ba746b8a8e276"));
        let ack = seal(ty::KEEPALIVE_ACK, 0x1a2b3c4d, 1, &[], &k_down);
        assert_eq!(ack, h("4d4201204d3c2b1a0100000008b340d0bfeb875470dd700794c28f87"));

        // POLICY, hub -> repeater, seq 2: room "#pra", block name "Spammer",
        // block key = the repeater's public key.
        let entries = [
            PolicyEntry::Room("#pra".into()),
            PolicyEntry::BlockName("Spammer".into()),
            PolicyEntry::BlockKey(v.rep.verifying_key().to_bytes()),
        ];
        let pages = build_policy(1792000200, &entries).unwrap();
        assert_eq!(pages.len(), 1);
        let pol = seal(ty::POLICY, 0x1a2b3c4d, 2, &pages[0], &k_down);
        assert_eq!(
            pol,
            h("4d4201224d3c2b1a02000000c8c0cf6a010101042370726102075370616d6d65
               72032003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc866412
               5531b8dfa5bd382036fa2862cbb243ebf7e7a5")
        );
        assert_eq!(parse_policy(open(&pol, &k_down).unwrap()).unwrap(), (1792000200, 1, 1, entries.to_vec()));
        assert_eq!(peek(&ka).unwrap(), (ty::KEEPALIVE, 0x1a2b3c4d, 1));
        assert_eq!(open(&ka, &k_up).unwrap(), &[] as &[u8]);
        assert_eq!(open(&ka, &k_down), Err(Error::Mac));

        let frame = h("1500b001020304");
        let obs = Observe {
            flags: 0,
            disposition: disp::FORWARDED,
            rssi: -107,
            snr_q: 21,
            pkt_hash: crate::meshcore::Packet::parse(&frame).unwrap().pkt_hash(),
            frame: &frame,
        };
        let d = seal(ty::OBSERVE, 0x1a2b3c4d, 2, &build_observe(&obs), &k_up);
        assert_eq!(
            d,
            h("4d4201114d3c2b1a02000000000095ff150795bb58de03d4fb371500b001020304789982ea2e4f120a35a9e324ab0c46b7")
        );
        assert_eq!(parse_observe(open(&d, &k_up).unwrap()).unwrap(), obs);
    }

    #[test]
    fn vector_reset() {
        let v = vectors();
        let d = build_reset(&v.hub, 0x1a2b3c4d, 7, 1792000100);
        assert_eq!(
            d.to_vec(),
            h("4d4201034d3c2b1a0700000064c0cf6ad0b442eaf3ddd0afa74708d9026a7eae
               4305e0026173c660ec68a875ccfa60912ed4a62aaa9b5cd3240240bfdd930a0f
               f8cb58c032415be8666c6764abc8040a")
        );
        assert_eq!(check_reset(&d, v.hub.verifying_key().as_bytes()).unwrap(), (0x1a2b3c4d, 7, 1792000100));
    }

    #[test]
    fn replay_window() {
        let mut w = Replay::default();
        assert!(!w.check(0));
        assert!(w.check(1));
        assert!(!w.check(1));
        assert!(w.check(3));
        assert!(w.check(2));
        assert!(!w.check(2));
        assert!(w.check(100));
        assert!(w.check(37));
        assert!(!w.check(36), "64 below the top is outside the window");
        assert!(w.check(500));
        assert!(!w.check(100));
    }

    #[test]
    fn bodies_roundtrip() {
        let f = [0x11u8, 0, 1, 2, 3];
        let br = Bridge { flags: BRIDGE_OWN, pkt_hash: [9; 8], frame: &f };
        assert_eq!(parse_bridge(&build_bridge(&br)).unwrap(), br);
        let fr = build_frame(&[7; 8], &f);
        assert_eq!(parse_frame(&fr).unwrap(), ([7; 8], &f[..]));
        assert_eq!(parse_bridge(&[0, 0, 1, 2, 3, 4, 5, 6, 7, 8]), Err(Error::Length));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn pages_split_between_entries_and_cap_at_sixteen() {
        let mut entries: Vec<PolicyEntry> = (0..policy::MAX_ROOMS).map(|i| PolicyEntry::Room(format!("#room{i:02}-{}", "x".repeat(20)))).collect();
        entries.extend((0..policy::MAX_BLOCKS).map(|i| PolicyEntry::BlockKey([i as u8; 32])));
        let pages = build_policy(7, &entries).unwrap();
        assert!(pages.len() > 1 && pages.len() <= policy::MAX_PAGES);
        let mut back = Vec::new();
        for (i, p) in pages.iter().enumerate() {
            assert!(p.len() - 6 <= policy::PAGE_ENTRIES);
            let (v, page, n, e) = parse_policy(p).unwrap();
            assert_eq!((v, page as usize, n as usize), (7, i + 1, pages.len()));
            back.extend(e);
        }
        assert_eq!(back, entries, "no entry split or lost");

        let empty = build_policy(9, &[]).unwrap();
        assert_eq!(empty, vec![vec![9, 0, 0, 0, 1, 1]], "an empty set is one page without entries");

        let too_many: Vec<PolicyEntry> = (0..600).map(|i| PolicyEntry::BlockKey([i as u8; 32])).collect();
        assert!(build_policy(1, &too_many).is_none());
    }

    #[test]
    fn parse_skips_unknown_and_wrong_lengths_but_rejects_overruns() {
        let mut b = vec![1, 0, 0, 0, 1, 1];
        b.extend_from_slice(&[9, 2, 0xAA, 0xBB]); // unknown kind
        b.extend_from_slice(&[3, 2, 0xAA, 0xBB]); // key of the wrong length
        b.extend_from_slice(&[1, 3, b'p', b'r', b'a']); // room without '#'
        b.extend_from_slice(&[2, 3, b'B', b'o', b'b']);
        assert_eq!(parse_policy(&b).unwrap().3, vec![PolicyEntry::BlockName("Bob".into())]);
        b.extend_from_slice(&[2, 9, b'x']);
        assert_eq!(parse_policy(&b), Err(Error::Length));
    }
}
