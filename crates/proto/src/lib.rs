//! Shared code for the meshcore-hub backbone daemon and portal.
//!
//! - [`wire`]: the IP backbone protocol, version 1, exactly as specified in
//!   meshcore-repeater `docs/backbone.md` (the contract with the repeaters).
//! - [`meshcore`]: MeshCore over-the-air frames: parsing, the dedup hash,
//!   adverts and public group-channel text.

pub mod meshcore;
pub mod wire;

/// Lower-case hex of `b`.
pub fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Decode exactly `N` bytes of hex (surrounding whitespace ignored).
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = hex::decode(s.trim()).ok()?;
    v.try_into().ok()
}
