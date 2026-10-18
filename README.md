# meshcore-hub

The central **IP fallback backbone** and **public portal** for the ham
MeshCore network built on [meshcore-repeater](https://github.com/Guru-RF/meshcore-repeater),
running at **[be.mesh73.net](https://be.mesh73.net)**.

- **Backbone (`meshcore-hubd`)**: repeaters open an authenticated UDP session
  to the hub. It joins RF islands and blind spots by carrying frames between
  repeaters, but only where they are needed. If the hub is unreachable, every
  repeater carries on exactly as it would without it.
- **Portal (`meshcore-portal`)**: a live map and monitor. It shows backbone
  repeaters (green) and hotspots (violet), the nodes they hear, RF links
  coloured by SNR, duty cycle, traffic, public-channel messages, and how to
  join.

The wire protocol is specified in meshcore-repeater
[`docs/backbone.md`](https://github.com/Guru-RF/meshcore-repeater/blob/main/docs/backbone.md).
That document is the contract; this repo implements the hub side of it.

```
 repeater ─┐  UDP 4405, Ed25519 handshake,              ┌──────────── VM be.mesh73.net ────────────┐
 repeater ─┼─ per-session HMAC keys (NAT friendly) ───▶ │ meshcore-hubd ──▶ SQLite (WAL)           │
 repeater ─┘                                            │      │ events.sock     ▲ read-only       │
                                                        │      ▼                 │                 │
 browsers ──── HTTPS / WSS ──── Caddy :443 ───────────▶ │ meshcore-portal :8080 ─┘                 │
                                                        └──────────────────────────────────────────┘
```

## Layout

| Path | What |
|---|---|
| `crates/proto` | Backbone wire format (handshake, sessions, bodies) and MeshCore frame decoding (packet hash, adverts, public channels). Tests check every test vector in `docs/backbone.md`, plus frames built by the repeater's own C code. |
| `crates/hubd` | The hub. `core.rs` is a pure state machine (handshake, sessions, bridging, path-tail routing, rate limits), `store.rs` the SQLite writer, `main.rs` the I/O shell. `tests/hub.rs` drives the core with simulated repeaters on a fake clock. |
| `crates/hubd/examples/simrep.rs` | A simulated repeater over real UDP, for trying a hub locally. |
| `crates/portal` | The portal: JSON API, live WebSocket, and the page from `web/` compiled in. |
| `web/` | The single-page map (Leaflet + OpenStreetMap, no build step). |
| `deploy/` | Production config, systemd units, Caddyfile, and the build / install / deploy scripts. `gcp-key.sh` backs up and restores the hub key in Secret Manager. |
| `docs/gcp.md` | Running a hub on Google Cloud from scratch, including key backup, restore and rotation. |

## How bridging works

The hub follows the "Hub rules" in `docs/backbone.md`:

- **Candidates:** only frames a repeater is about to transmit (BRIDGE) are
  bridged. Frames a repeater only observed never are.
- **Hold:** after the first BRIDGE, the hub waits ~1 s for other repeaters to
  report the same packet. Repeaters that already heard it on RF are skipped.
- **Floods** go to every other connected bridge repeater that hasn't reported
  the packet.
- **Own replies:** a repeater's own replies (pong, help, time, probe, `#mbox`)
  stay in their island. Its own adverts are bridged.
- **Direct frames** are routed by path only, never flooded. The *path-tail
  rule* only sends to a repeater that recently relayed a flood along the same
  reversed path, so 1-byte path-hash collisions cannot misroute.
- **Limits:** frames are never modified, each hash goes to a repeater at most
  once, and each repeater gets at most 25 frames a minute (the repeater itself
  caps at 30).

## Privacy

- **No IP addresses** are stored or published.
- **Frames** are kept as metadata only: type, route, hops, RSSI/SNR, and what
  the repeater did with them.
- **Message text** is decoded only for channels whose keys are published and
  configured in `hub.toml` (by default *Public* and `#mesh`). Private messages
  are never decoded.
- **Positions** come only from signed adverts the nodes broadcast themselves.
- **Retention:** frame metadata is kept 14 days, messages 180 days, history 90
  days (`[retention]` in `hub.toml`).

## Develop

```sh
cargo test                     # proto vectors, hub state machine, store
cargo clippy --all-targets
```

To run the whole thing locally with two simulated repeaters:

```sh
cargo build --examples
mkdir -p /tmp/mch && cd /tmp/mch
HUB=$(~/path/to/meshcore-hub/target/debug/meshcore-hubd genkey hub.key)
P1=$(cargo run -q --example simrep -- pub ON0SIM1)   # run in the repo
P2=$(cargo run -q --example simrep -- pub ON0SIM2)
cat > hub.toml <<EOF
listen = "127.0.0.1:44050"
hub_key = "hub.key"
database = "hub.db"
events_socket = "events.sock"
[[repeater]]
callsign = "ON0SIM1"
pub = "$P1"
roles = ["observe", "bridge"]
[[repeater]]
callsign = "ON0SIM2"
pub = "$P2"
roles = ["observe", "bridge"]
EOF
meshcore-hubd -c hub.toml &
meshcore-portal --listen 127.0.0.1:18080 --db hub.db --events events.sock &
simrep 127.0.0.1:44050 $HUB ON0SIM1 50.9593 4.2310 &     # Merchtem
simrep 127.0.0.1:44050 $HUB ON0SIM2 51.0543 3.7174 &     # Gent
# open http://127.0.0.1:18080
```

## Deploy

Production is the `meshcore-hub` VM: project `customer-uba`, zone
`europe-west1-b`, e2-small, Debian 13. It has the static IP 34.62.184.236,
which `be.mesh73.net` points to. The firewall rule `meshcore-backbone` allows
UDP 4405; the VM's `http-server` and `https-server` tags allow 80 and 443.

```sh
deploy/deploy.sh               # build in a Debian 13 container, copy over IAP, install
SKIP_BUILD=1 deploy/deploy.sh  # reinstall what is in dist/
RESTART=1 deploy/deploy.sh     # also restart services whose files did not change
```

A deploy restarts only what changed. A new `meshcore-hubd` binary or unit
restarts the hub, and repeaters reconnect on their own. A portal-only update
leaves repeater sessions untouched.

`deploy/install.sh` is idempotent. It:

- creates the `meshcore-hub` and `meshcore-portal` users;
- installs the binaries, units, `hub.toml` and the Caddyfile;
- generates the hub key on first install only;
- restarts the services and prints the hub public key.

### Operations

| Task | How |
|---|---|
| Add a repeater or hotspot | Add a `[[repeater]]` (callsign, `pub=` from its `repeater.key`, roles) to `deploy/hub.toml`, then run `deploy/deploy.sh`. A change to `hub.toml` alone reloads the allowlist without dropping sessions. The callsign decides the kind: `repeater_prefixes` (`ON0`) are repeaters, other calls hotspots. |
| Remove a repeater or role | Same. The hub sends it BYE "not allowed". |
| Hub public key | `sudo meshcore-hubd pubkey`. It is also on the portal's Join tab. |
| Logs | `journalctl -u meshcore-hubd -u meshcore-portal -f` |
| Unknown repeaters knocking | The hub logs `HELLO from … key … is not on the allowlist`, with the key to add. |

**Files on the VM:**

| Path | Contents |
|---|---|
| `/etc/meshcore-hub/hub.key` | Private key, root only. The service gets it through `LoadCredential=`. |
| `/etc/meshcore-hub/hub.toml` | Config and allowlist. |
| `/var/lib/meshcore-hub/hub.db` | The database. |
| `/run/meshcore-hub/events.sock` | Live events for the portal. |

**The hub key is backed up** in Secret Manager as `meshcore-hub-key`,
pinned to europe-west1. `deploy/gcp-key.sh verify` checks that it still
matches the VM. If the VM is rebuilt, run `deploy/gcp-key.sh restore`
*before* the first deploy, or the hub gets a new identity and every repeater
needs a new `backbone_hub_key`.

To set up a hub on Google Cloud from scratch (VM, IP, firewall, DNS, key
backup, restore and rotation), see [docs/gcp.md](docs/gcp.md).

## Licence

MIT, see [LICENSE](LICENSE).
