//! MeshCore over-the-air frames, matching meshcore-repeater `src/packet.c`,
//! `src/advert.c` and the public-channel codec in `src/mesh.c`.
//!
//! Wire layout:
//! ```text
//! [0]     header           0bVVPPPPRR (version, payload type, route type)
//! [1..4]  transport codes  2 x u16, only for TRANSPORT_FLOOD / TRANSPORT_DIRECT
//! [next]  path_len         bits 0-5 hop count, bits 6-7 hash size - 1
//! [next]  path             hops x hash size bytes (<= 64)
//! [next]  payload          the rest (<= 184 bytes)
//! ```

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const MAX_FRAME: usize = 255;
pub const MAX_PATH: usize = 64;
pub const MAX_PAYLOAD: usize = 184;

pub mod route {
    pub const TRANSPORT_FLOOD: u8 = 0;
    pub const FLOOD: u8 = 1;
    pub const DIRECT: u8 = 2;
    pub const TRANSPORT_DIRECT: u8 = 3;
}

pub mod ptype {
    pub const REQ: u8 = 0x00;
    pub const RESPONSE: u8 = 0x01;
    pub const TXT_MSG: u8 = 0x02;
    pub const ACK: u8 = 0x03;
    pub const ADVERT: u8 = 0x04;
    pub const GRP_TXT: u8 = 0x05;
    pub const GRP_DATA: u8 = 0x06;
    pub const ANON_REQ: u8 = 0x07;
    pub const PATH: u8 = 0x08;
    pub const TRACE: u8 = 0x09;
    pub const MULTIPART: u8 = 0x0A;
    pub const CONTROL: u8 = 0x0B;
    pub const RAW_CUSTOM: u8 = 0x0F;

    pub fn name(t: u8) -> &'static str {
        match t {
            REQ => "REQ",
            RESPONSE => "RESPONSE",
            TXT_MSG => "TXT_MSG",
            ACK => "ACK",
            ADVERT => "ADVERT",
            GRP_TXT => "GRP_TXT",
            GRP_DATA => "GRP_DATA",
            ANON_REQ => "ANON_REQ",
            PATH => "PATH",
            TRACE => "TRACE",
            MULTIPART => "MULTIPART",
            CONTROL => "CONTROL",
            RAW_CUSTOM => "RAW_CUSTOM",
            _ => "UNKNOWN",
        }
    }
}

/// Advert node types.
pub mod node_type {
    pub const CHAT: u8 = 1;
    pub const REPEATER: u8 = 2;
    pub const ROOM: u8 = 3;
    pub const SENSOR: u8 = 4;
}

/// A parsed frame borrowing the raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub raw: &'a [u8],
    pub header: u8,
    pub transport: Option<[u16; 2]>,
    /// The encoded path_len byte.
    pub path_len: u8,
    pub path: &'a [u8],
    pub payload: &'a [u8],
}

/// `pkt_valid_path_len`: hash size 4 is reserved, and the path is <= 64 bytes.
pub fn valid_path_len(path_len: u8) -> bool {
    let count = (path_len & 0x3F) as usize;
    let size = ((path_len >> 6) + 1) as usize;
    size != 4 && count * size <= MAX_PATH
}

impl<'a> Packet<'a> {
    /// Same acceptance rules as the repeater's `pkt_parse`.
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 2 || raw.len() > MAX_FRAME {
            return None;
        }
        let header = raw[0];
        let mut i = 1;
        let rt = header & 0x03;
        let transport = if rt == route::TRANSPORT_FLOOD || rt == route::TRANSPORT_DIRECT {
            if i + 4 > raw.len() {
                return None;
            }
            let t = [u16::from_le_bytes([raw[1], raw[2]]), u16::from_le_bytes([raw[3], raw[4]])];
            i += 4;
            Some(t)
        } else {
            None
        };
        if i >= raw.len() {
            return None;
        }
        let path_len = raw[i];
        i += 1;
        if !valid_path_len(path_len) {
            return None;
        }
        let pbl = (path_len & 0x3F) as usize * ((path_len >> 6) + 1) as usize;
        if i + pbl > raw.len() {
            return None;
        }
        let path = &raw[i..i + pbl];
        let payload = &raw[i + pbl..];
        if payload.len() > MAX_PAYLOAD {
            return None;
        }
        Some(Packet { raw, header, transport, path_len, path, payload })
    }

    pub fn route(&self) -> u8 {
        self.header & 0x03
    }
    pub fn ptype(&self) -> u8 {
        (self.header >> 2) & 0x0F
    }
    pub fn version(&self) -> u8 {
        (self.header >> 6) & 0x03
    }
    pub fn is_flood(&self) -> bool {
        self.route() & 0x02 == 0
    }
    pub fn is_direct(&self) -> bool {
        !self.is_flood()
    }
    /// Bytes per path hash (1..=3).
    pub fn hash_size(&self) -> usize {
        ((self.path_len >> 6) + 1) as usize
    }
    /// Hop count: number of hashes in the path.
    pub fn hops(&self) -> usize {
        (self.path_len & 0x3F) as usize
    }
    /// The path split into its hashes, first hop first.
    pub fn path_hashes(&self) -> std::slice::Chunks<'a, u8> {
        self.path.chunks(self.hash_size())
    }

    /// MeshCore's dedup hash: SHA256(payload_type [|| path_len as u16 LE for
    /// TRACE] || payload), first 8 bytes. The path is not hashed, so the same
    /// packet has the same hash at every hop.
    pub fn pkt_hash(&self) -> [u8; 8] {
        let t = self.ptype();
        let mut h = Sha256::new();
        h.update([t]);
        if t == ptype::TRACE {
            h.update((self.path_len as u16).to_le_bytes());
        }
        h.update(self.payload);
        let d = h.finalize();
        d[..8].try_into().unwrap()
    }
}

// --------------------------------------------------------------- adverts --

const ADV_LATLON: u8 = 0x10;
const ADV_FEAT1: u8 = 0x20;
const ADV_FEAT2: u8 = 0x40;
const ADV_NAME: u8 = 0x80;
const ADV_DATA_OFF: usize = 100;
const ADV_DATA_MAX: usize = 32;

/// A decoded ADVERT payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Advert {
    pub public_key: [u8; 32],
    pub timestamp: u32,
    /// Ed25519 over pub || timestamp || app_data checked out.
    pub verified: bool,
    pub node_type: u8,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub name: Option<String>,
}

impl Advert {
    /// pub(32) ts(4) sig(64) app_data: flags, then lat/lon (i32 x1e6),
    /// feat1, feat2, name, each only when its flag is set.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < ADV_DATA_OFF {
            return None;
        }
        let public_key: [u8; 32] = payload[0..32].try_into().unwrap();
        let timestamp = u32::from_le_bytes(payload[32..36].try_into().unwrap());
        let sig = &payload[36..100];
        let app = &payload[ADV_DATA_OFF..];

        // The repeater verifies over at most 32 bytes of app_data; do the same.
        let signed_app = &app[..app.len().min(ADV_DATA_MAX)];
        let mut msg = Vec::with_capacity(36 + signed_app.len());
        msg.extend_from_slice(&public_key);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg.extend_from_slice(signed_app);
        let verified = match (VerifyingKey::from_bytes(&public_key), Signature::from_slice(sig)) {
            (Ok(vk), Ok(s)) => vk.verify_strict(&msg, &s).is_ok(),
            _ => false,
        };

        let mut adv = Advert { public_key, timestamp, verified, node_type: 0, lat: None, lon: None, name: None };
        let Some(&flags) = app.first() else {
            return Some(adv);
        };
        adv.node_type = flags & 0x0F;
        let mut i = 1;
        if flags & ADV_LATLON != 0 {
            if app.len() < i + 8 {
                return Some(adv);
            }
            let lat = i32::from_le_bytes(app[i..i + 4].try_into().unwrap()) as f64 / 1e6;
            let lon = i32::from_le_bytes(app[i + 4..i + 8].try_into().unwrap()) as f64 / 1e6;
            // 0,0 is what an unset position looks like on many nodes.
            if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) && !(lat == 0.0 && lon == 0.0) {
                adv.lat = Some(lat);
                adv.lon = Some(lon);
            }
            i += 8;
        }
        if flags & ADV_FEAT1 != 0 {
            i += 2;
        }
        if flags & ADV_FEAT2 != 0 {
            i += 2;
        }
        if flags & ADV_NAME != 0 && i < app.len() {
            let raw = &app[i..];
            let raw = raw.split(|&b| b == 0).next().unwrap_or_default();
            let name = String::from_utf8_lossy(raw).trim().to_string();
            if !name.is_empty() {
                adv.name = Some(name);
            }
        }
        Some(adv)
    }
}

/// Build a signed ADVERT frame (FLOOD, empty path). For tests and the simulator.
pub fn build_advert(
    key: &ed25519_dalek::SigningKey,
    ts: u32,
    node_type: u8,
    pos: Option<(f64, f64)>,
    name: &str,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut app = vec![node_type & 0x0F];
    if let Some((lat, lon)) = pos {
        app[0] |= ADV_LATLON;
        app.extend_from_slice(&((lat * 1e6).round() as i32).to_le_bytes());
        app.extend_from_slice(&((lon * 1e6).round() as i32).to_le_bytes());
    }
    if !name.is_empty() {
        app[0] |= ADV_NAME;
        let room = ADV_DATA_MAX - app.len();
        app.extend_from_slice(&name.as_bytes()[..name.len().min(room)]);
    }
    let pubk = key.verifying_key().to_bytes();
    let mut msg = pubk.to_vec();
    msg.extend_from_slice(&ts.to_le_bytes());
    msg.extend_from_slice(&app);
    let sig = key.sign(&msg).to_bytes();
    let mut f = vec![(ptype::ADVERT << 2) | route::FLOOD, 0];
    f.extend_from_slice(&pubk);
    f.extend_from_slice(&ts.to_le_bytes());
    f.extend_from_slice(&sig);
    f.extend_from_slice(&app);
    f
}

// ------------------------------------------------------ public channels --

type HmacSha256 = Hmac<Sha256>;

/// A group channel whose key is public: a published PSK or a `#hashtag`
/// channel (key = SHA256("#name")[..16]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub name: String,
    /// Key bytes, zero-padded to 32 like the repeater's `mc_pub_channel_t`.
    secret: [u8; 32],
    /// One-byte channel hash: SHA256(key bytes)[0].
    pub hash: u8,
}

/// Decrypted GRP_TXT plaintext: [timestamp:4][txt_type:1]["sender: text"].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupText {
    pub timestamp: u32,
    pub txt_type: u8,
    pub sender: Option<String>,
    pub text: String,
}

impl Channel {
    fn from_key(name: &str, key: &[u8]) -> Option<Self> {
        if key.len() != 16 && key.len() != 32 {
            return None;
        }
        let mut secret = [0u8; 32];
        secret[..key.len()].copy_from_slice(key);
        let hash = Sha256::digest(key)[0];
        Some(Channel { name: name.to_string(), secret, hash })
    }

    /// A published key, 16 or 32 bytes, as hex or base64.
    pub fn from_psk(name: &str, psk: &str) -> Option<Self> {
        let psk = psk.trim();
        let key = if psk.len().is_multiple_of(2) && psk.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(psk).ok()?
        } else {
            base64::engine::general_purpose::STANDARD.decode(psk).ok()?
        };
        Self::from_key(name, &key)
    }

    /// A hashtag channel; `name` with or without the leading '#'.
    pub fn hashtag(name: &str) -> Self {
        let tag = format!("#{}", name.trim().trim_start_matches('#'));
        let d = Sha256::digest(tag.as_bytes());
        Self::from_key(&tag, &d[..16]).expect("16-byte key")
    }

    /// The default MeshCore "Public" channel.
    pub fn public() -> Self {
        Self::from_psk("Public", "izOH6cXN6mrJ5e26oRXNcg==").expect("valid key")
    }

    fn aes(&self) -> Aes128 {
        Aes128::new(GenericArray::from_slice(&self.secret[..16]))
    }

    fn mac(&self, ct: &[u8]) -> [u8; 2] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.secret).expect("any key length");
        m.update(ct);
        let d = m.finalize().into_bytes();
        [d[0], d[1]]
    }

    /// GRP_TXT / GRP_DATA payload [channel_hash:1][mac:2][ciphertext] belongs
    /// to this channel: the hash matches and HMAC(key, ciphertext)[..2] checks out.
    pub fn matches(&self, payload: &[u8]) -> bool {
        payload.len() >= 19 && payload[0] == self.hash && self.mac(&payload[3..]) == payload[1..3]
    }

    /// Decrypt a GRP_TXT payload that [`matches`](Self::matches) this channel.
    pub fn decrypt(&self, payload: &[u8]) -> Option<GroupText> {
        if !self.matches(payload) {
            return None;
        }
        let ct = &payload[3..];
        if !ct.len().is_multiple_of(16) {
            return None;
        }
        let aes = self.aes();
        let mut plain = ct.to_vec();
        for block in plain.chunks_mut(16) {
            aes.decrypt_block(GenericArray::from_mut_slice(block));
        }
        if plain.len() < 5 {
            return None;
        }
        let timestamp = u32::from_le_bytes(plain[0..4].try_into().unwrap());
        let txt_type = plain[4];
        let body = plain[5..].split(|&b| b == 0).next().unwrap_or_default();
        let body = String::from_utf8_lossy(body).into_owned();
        let (sender, text) = match body.split_once(": ") {
            Some((s, t)) => (Some(s.to_string()), t.to_string()),
            None => (None, body),
        };
        Some(GroupText { timestamp, txt_type, sender, text })
    }

    /// Build a FLOOD GRP_TXT carrying "sender: text" (`channel_build_txt`).
    pub fn build_txt(&self, sender: &str, text: &str, ts: u32) -> Vec<u8> {
        let mut plain = ts.to_le_bytes().to_vec();
        plain.push(0);
        plain.extend_from_slice(format!("{sender}: {text}").as_bytes());
        let padded = plain.len().div_ceil(16).max(1) * 16;
        plain.resize(padded, 0);
        let aes = self.aes();
        for block in plain.chunks_mut(16) {
            aes.encrypt_block(GenericArray::from_mut_slice(block));
        }
        let mac = self.mac(&plain);
        let mut f = vec![(ptype::GRP_TXT << 2) | route::FLOOD, 0, self.hash, mac[0], mac[1]];
        f.extend_from_slice(&plain);
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_hash() {
        // From the backbone test vectors: a GRP_TXT flood with an empty path.
        let f = hex::decode("1500b001020304").unwrap();
        let p = Packet::parse(&f).unwrap();
        assert_eq!(p.route(), route::FLOOD);
        assert_eq!(p.ptype(), ptype::GRP_TXT);
        assert_eq!(p.hops(), 0);
        assert_eq!(p.payload, &[0xb0, 1, 2, 3, 4]);
        assert_eq!(hex::encode(p.pkt_hash()), "95bb58de03d4fb37");

        // The path does not change the hash.
        let f2 = hex::decode("1502aabbb001020304").unwrap();
        let p2 = Packet::parse(&f2).unwrap();
        assert_eq!(p2.hops(), 2);
        assert_eq!(p2.path_hashes().collect::<Vec<_>>(), vec![&[0xaa][..], &[0xbb][..]]);
        assert_eq!(p2.pkt_hash(), p.pkt_hash());

        // Transport route: 4 code bytes before path_len.
        let f3 = hex::decode("1434120000016600").unwrap();
        let p3 = Packet::parse(&f3).unwrap();
        assert_eq!(p3.transport, Some([0x1234, 0]));
        assert_eq!(p3.path, &[0x66]);

        assert!(Packet::parse(&[0x15]).is_none());
        assert!(Packet::parse(&[0x15, 0x05, 1, 2]).is_none(), "path longer than the frame");
        assert!(Packet::parse(&[0x15, 0xC1, 1, 2, 3, 4]).is_none(), "hash size 4 is reserved");
    }

    #[test]
    fn advert_roundtrip() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let f = build_advert(&key, 1792000000, node_type::REPEATER, Some((51.0, 4.2)), "ON0RFG");
        let p = Packet::parse(&f).unwrap();
        assert_eq!(p.ptype(), ptype::ADVERT);
        let a = Advert::decode(p.payload).unwrap();
        assert!(a.verified);
        assert_eq!(a.node_type, node_type::REPEATER);
        assert_eq!(a.name.as_deref(), Some("ON0RFG"));
        assert!((a.lat.unwrap() - 51.0).abs() < 1e-6 && (a.lon.unwrap() - 4.2).abs() < 1e-6);

        let mut bad = f.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!Advert::decode(Packet::parse(&bad).unwrap().payload).unwrap().verified);
    }

    #[test]
    fn channels() {
        let public = Channel::public();
        let mesh = Channel::hashtag("mesh");
        assert_eq!(mesh.name, "#mesh");
        assert_eq!(Channel::hashtag("#mesh"), mesh);

        let f = public.build_txt("ON0RFG", "hello Belgium", 1792000000);
        let p = Packet::parse(&f).unwrap();
        assert!(public.matches(p.payload));
        assert!(!mesh.matches(p.payload));
        let t = public.decrypt(p.payload).unwrap();
        assert_eq!(t.sender.as_deref(), Some("ON0RFG"));
        assert_eq!(t.text, "hello Belgium");
        assert_eq!(t.timestamp, 1792000000);
        assert!(mesh.decrypt(p.payload).is_none());
    }

    /// Frames built by meshcore-repeater's own C codec (channel_build_txt with
    /// its aes128 / hmac_sha256), so both sides agree on keys, hash and MAC.
    #[test]
    fn channels_match_repeater_c() {
        let public = Channel::public();
        let mesh = Channel::hashtag("mesh");
        assert_eq!(public.hash, 0x11);
        assert_eq!(mesh.hash, 0xb0);

        let f = hex::decode("150011ab86d9a10fb10a1f7f3b738b6e1db46ead5ce9a2b1c713daa81c533d608910d40409").unwrap();
        let t = public.decrypt(Packet::parse(&f).unwrap().payload).unwrap();
        assert_eq!((t.sender.as_deref(), t.text.as_str(), t.timestamp), (Some("ON0RFG"), "hello from C", 1792000000));
        assert_eq!(public.build_txt("ON0RFG", "hello from C", 1792000000), f);

        let f = hex::decode("1500b060891ca194ca7902cb151344a32ef19463802258d5a278bf4854a3402e91122e94e3").unwrap();
        let t = mesh.decrypt(Packet::parse(&f).unwrap().payload).unwrap();
        assert_eq!((t.sender.as_deref(), t.text.as_str()), (Some("ON6URE"), "ping"));
    }
}
