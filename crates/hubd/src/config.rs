//! `hub.toml`: listen address, keys, timing, bridging policy, the repeater
//! allowlist and the public channels the portal may decode.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use meshcore_proto::meshcore::Channel;
use meshcore_proto::wire::{ROLE_BRIDGE, ROLE_OBSERVE};
use serde::Deserialize;

use crate::core::{Allowed, Kind, Params, Pub};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// UDP address the backbone listens on.
    #[serde(default = "d_listen")]
    pub listen: String,
    /// The hub's Ed25519 identity, written by `meshcore-hubd genkey`.
    /// `$CREDENTIALS_DIRECTORY/hub.key` (systemd `LoadCredential=`) wins.
    #[serde(default = "d_key")]
    pub hub_key: PathBuf,
    #[serde(default = "d_db")]
    pub database: PathBuf,
    /// Unix socket the portal reads live events from.
    #[serde(default = "d_sock")]
    pub events_socket: PathBuf,
    /// The kind guessed before a node's first STATUS (`Kind::of`): a bare
    /// callsign starting with one of these is a repeater, anything else a hotspot.
    #[serde(default = "d_prefixes")]
    pub repeater_prefixes: Vec<String>,
    #[serde(default)]
    pub timing: Timing,
    #[serde(default)]
    pub bridge: Bridge,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default, rename = "repeater")]
    pub repeaters: Vec<RepeaterCfg>,
    #[serde(default, rename = "channel")]
    pub channels: Vec<ChannelCfg>,
}

/// Intervals the hub hands out in WELCOME.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timing {
    pub keepalive_s: u16,
    pub status_s: u16,
    pub neighbours_s: u16,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { keepalive_s: 25, status_s: 60, neighbours_s: 300 }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Bridge {
    /// Wait this long after the first BRIDGE of a packet for other reports.
    pub hold_ms: u64,
    /// FRAMEs per minute per repeater; keep it below the repeaters' own
    /// `backbone_rate` (30).
    pub rate_per_min: u32,
    /// Also bridge a repeater's own replies (pong, help, time, probe, #mbox).
    /// Its own adverts are always bridged.
    pub own_replies: bool,
    /// How long a packet hash is remembered for dedup.
    pub dedup_s: u64,
    /// How long flood paths are remembered for routing direct frames.
    pub path_memory_h: u64,
}

impl Default for Bridge {
    fn default() -> Self {
        Bridge { hold_ms: 1000, rate_per_min: 25, own_replies: false, dedup_s: 600, path_memory_h: 24 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    pub frames_days: u32,
    pub messages_days: u32,
    pub history_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention { frames_days: 14, messages_days: 180, history_days: 90 }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeaterCfg {
    pub callsign: String,
    /// The `pub=` line of the repeater's `repeater.key`.
    #[serde(rename = "pub")]
    pub public_key: String,
    #[serde(default = "d_roles")]
    pub roles: Vec<String>,
}

/// A public channel to decode for the portal: `psk` (hex or base64) with a
/// `name`, or a `hashtag` channel.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCfg {
    pub name: Option<String>,
    pub psk: Option<String>,
    pub hashtag: Option<String>,
}

fn d_listen() -> String {
    "0.0.0.0:4405".into()
}
fn d_key() -> PathBuf {
    "/etc/meshcore-hub/hub.key".into()
}
fn d_db() -> PathBuf {
    "/var/lib/meshcore-hub/hub.db".into()
}
fn d_sock() -> PathBuf {
    "/run/meshcore-hub/events.sock".into()
}
fn d_prefixes() -> Vec<String> {
    vec!["ON0".into()]
}
fn d_roles() -> Vec<String> {
    vec!["observe".into()]
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.allowlist()?;
        cfg.decode_channels()?;
        Ok(cfg)
    }

    pub fn params(&self) -> Params {
        Params {
            keepalive_s: self.timing.keepalive_s,
            status_s: self.timing.status_s,
            neighbours_s: self.timing.neighbours_s,
            hold_ms: self.bridge.hold_ms,
            rate_per_min: self.bridge.rate_per_min.max(1),
            own_replies: self.bridge.own_replies,
            dedup_ms: self.bridge.dedup_s.max(60) * 1000,
            path_memory_ms: self.bridge.path_memory_h.max(1) * 3600 * 1000,
        }
    }

    pub fn allowlist(&self) -> Result<Vec<(Pub, Allowed)>> {
        let mut seen: HashMap<Pub, &str> = HashMap::new();
        let mut out = Vec::new();
        for r in &self.repeaters {
            let Some(pk) = meshcore_proto::unhex::<32>(&r.public_key) else {
                bail!("repeater {}: pub must be 64 hex characters", r.callsign);
            };
            if let Some(prev) = seen.insert(pk, &r.callsign) {
                bail!("repeaters {prev} and {} have the same public key", r.callsign);
            }
            let mut roles = 0;
            for role in &r.roles {
                roles |= match role.as_str() {
                    "observe" => ROLE_OBSERVE,
                    "bridge" => ROLE_BRIDGE,
                    other => bail!("repeater {}: unknown role {other:?} (observe, bridge)", r.callsign),
                };
            }
            let kind = Kind::of(&r.callsign, &self.repeater_prefixes);
            out.push((pk, Allowed { callsign: r.callsign.clone(), roles, kind }));
        }
        Ok(out)
    }

    /// Configured channels; MeshCore "Public" and `#mesh` when none are set.
    pub fn decode_channels(&self) -> Result<Vec<Channel>> {
        if self.channels.is_empty() {
            return Ok(vec![Channel::public(), Channel::hashtag("mesh")]);
        }
        self.channels
            .iter()
            .map(|c| match (&c.psk, &c.hashtag) {
                (Some(psk), None) => {
                    let name = c.name.as_deref().unwrap_or("channel");
                    Channel::from_psk(name, psk).with_context(|| format!("channel {name}: psk must be a 16 or 32 byte key"))
                }
                (None, Some(tag)) => Ok(Channel::hashtag(tag)),
                _ => bail!("each [[channel]] needs exactly one of psk or hashtag"),
            })
            .collect()
    }

    /// The key file to use: systemd's credential first, then `hub_key`.
    pub fn key_path(&self) -> PathBuf {
        if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
            let p = Path::new(&dir).join("hub.key");
            if p.exists() {
                return p;
            }
        }
        self.hub_key.clone()
    }
}

/// Key file: `seed=<64 hex>` and `pub=<64 hex>` lines; `#` comments.
pub fn load_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut seed = None;
    let mut public = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("seed=") {
            seed = meshcore_proto::unhex::<32>(v);
        } else if let Some(v) = line.strip_prefix("pub=") {
            public = meshcore_proto::unhex::<32>(v);
        }
    }
    let Some(seed) = seed else { bail!("{}: no valid seed= line", path.display()) };
    let key = SigningKey::from_bytes(&seed);
    if let Some(p) = public
        && p != key.verifying_key().to_bytes()
    {
        bail!("{}: pub= does not match seed=", path.display());
    }
    Ok(key)
}

pub fn write_key(path: &Path, key: &SigningKey) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let text = format!(
        "# meshcore-hub backbone identity (Ed25519). Keep it private.\n\
         # Repeaters pin the pub= value as backbone_hub_key.\n\
         seed={}\npub={}\n",
        hex::encode(key.to_bytes()),
        hex::encode(key.verifying_key().as_bytes())
    );
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite an existing key)", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_callsign() {
        let cfg: Config = toml::from_str(
            r#"
            [[repeater]]
            callsign = "ON0RFG"
            pub = "9ebd58ba0191164815aecbcf39537b8108c0b4a737e82357311b2bb3282cb940"
            [[repeater]]
            callsign = "OR7F-4"
            pub = "3cc11df930c56540e54ab7ee4f30bcbf52ae8c4bad195c280681e8c392ac1e9a"
            [[repeater]]
            callsign = "on0abc"
            pub = "0000000000000000000000000000000000000000000000000000000000000001"
            [[repeater]]
            callsign = "ON4ABC"
            pub = "0000000000000000000000000000000000000000000000000000000000000002"
            "#,
        )
        .unwrap();
        let kinds: Vec<_> = cfg.allowlist().unwrap().into_iter().map(|(_, a)| (a.callsign, a.kind)).collect();
        assert_eq!(
            kinds,
            [
                ("ON0RFG".to_string(), Kind::Repeater),
                ("OR7F-4".to_string(), Kind::Hotspot),
                ("on0abc".to_string(), Kind::Repeater),
                ("ON4ABC".to_string(), Kind::Hotspot),
            ]
        );
        assert_eq!(Kind::of("ON0RFG-1", &["ON0".into()]), Kind::Hotspot, "only a hotspot carries an SSID");
        assert_eq!(Kind::of("PI1XYZ", &["ON0".into(), "PI".into()]), Kind::Repeater);
        assert_eq!(Kind::of("ON0RFG", &[]), Kind::Hotspot);
    }
}
