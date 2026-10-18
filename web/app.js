// MeshCore Backbone portal. Plain JS, no build step.
// Everything that comes from the mesh (names, message text) is untrusted:
// it only ever reaches the page through esc() or textContent.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const TYPE = { 1: "companion", 2: "repeater", 3: "room", 4: "sensor" };
const ROUTE = { 0: "flood", 1: "flood", 2: "direct", 3: "direct" };
const PTYPE = ["REQ", "RESPONSE", "TXT_MSG", "ACK", "ADVERT", "GRP_TXT", "GRP_DATA", "ANON_REQ", "PATH", "TRACE", "MULTIPART", "CONTROL", "", "", "", "RAW_CUSTOM"];
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
// Why the hub did not bridge an offered frame (offers.outcome).
const SKIP = {
  own_reply: "own reply, stays in its island",
  heard: "every other island already heard it",
  no_route: "no backbone node on its path",
  no_peer: "no other island connected",
  rate_limited: "rate limit reached",
};

const state = {
  overview: null,
  repeaters: new Map(), // pub -> repeater
  nodes: new Map(),     // pub -> node
  links: [],
  messages: new Map(),  // hash -> message
  detail: null,         // pub of the open repeater
  offers: null,         // outcome -> count, 24 h
};

// ------------------------------------------------------------- helpers --

const now = () => Math.floor(Date.now() / 1000);

function ago(ts) {
  if (!ts) return "never";
  const d = Math.max(0, now() - ts);
  if (d < 60) return `${d} s ago`;
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}

function dur(s) {
  if (s == null) return "–";
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} m`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}

const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmt = (n, d = 0) => (n == null || Number.isNaN(n) ? "–" : Number(n).toFixed(d));
const snrClass = (snr) => (snr >= 5 ? "snr-good" : snr >= -5 ? "snr-mid" : "snr-bad");
const snrColor = (snr) => css(snr >= 5 ? "--on" : snr >= -5 ? "--warn" : "--bad");
// Backbone nodes: repeaters (club calls) green, hotspots (personal calls) violet.
const isHotspot = (r) => r.kind === "hotspot";
const kindColor = (r) => css(isHotspot(r) ? "--hs" : "--on");

async function api(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

function debounce(fn, ms) {
  let t;
  return () => { clearTimeout(t); t = setTimeout(fn, ms); };
}

function store(key, val) {
  try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch { return null; }
}

// ----------------------------------------------------------------- map --

const map = L.map("map", { zoomControl: true, worldCopyJump: true }).setView([50.64, 4.67], 8);
L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 18,
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
}).addTo(map);
const linkLayer = L.layerGroup().addTo(map);
const nodeLayer = L.layerGroup().addTo(map);
const ipLayer = L.layerGroup().addTo(map);
const repLayer = L.layerGroup().addTo(map);
const flashLayer = L.layerGroup().addTo(map);
const repMarkers = new Map();
let fitted = false;
let fitPts = null;
let userMoved = false;
map.on("dragstart", () => { userMoved = true; });

function fit() {
  if (!fitPts) return;
  // No animation: Leaflet drops a new view while a zoom animation runs.
  if (fitPts.length === 1) map.setView(fitPts[0], 10, { animate: false });
  // Extra room on the right for the callsign labels, and at the bottom for the legend.
  else map.fitBounds(fitPts, { paddingTopLeft: [40, 40], paddingBottomRight: [110, 70], maxZoom: 11, animate: false });
}

// The map's box changes when the page settles (scrollbars, phone toolbars):
// re-measure, and re-fit until the viewer moves the map themselves.
new ResizeObserver(() => {
  map.invalidateSize({ pan: false });
  if (!userMoved) fit();
}).observe(document.getElementById("map"));

// The hub itself ([map] in hub.toml): where it runs, if configured.
function hubPos() {
  const h = state.overview?.hub || {};
  const lat = parseFloat(h.hub_lat), lon = parseFloat(h.hub_lon);
  return Number.isFinite(lat) && Number.isFinite(lon) ? [lat, lon] : null;
}
const hubName = () => state.overview?.hub?.hub_name || "IP-HUB";

function posOf(pub) {
  const r = state.repeaters.get(pub);
  if (r && r.lat != null) return [r.lat, r.lon];
  const n = state.nodes.get(pub);
  if (n && n.lat != null) return [n.lat, n.lon];
  return null;
}

function drawMap() {
  linkLayer.clearLayers();
  nodeLayer.clearLayers();
  ipLayer.clearLayers();
  repLayer.clearLayers();
  repMarkers.clear();

  for (const l of state.links) {
    const a = posOf(l.repeater), b = posOf(l.node);
    if (!a || !b) continue;
    const age = now() - (l.last_heard || 0);
    L.polyline([a, b], {
      color: snrColor(l.snr), weight: 2.5, opacity: age < 6 * 3600 ? 0.85 : age < 86400 ? 0.5 : 0.25,
    })
      .bindTooltip(`${esc(nameOf(l.repeater))} ↔ ${esc(nameOf(l.node))}<br>${fmt(l.rssi)} dBm · SNR ${fmt(l.snr, 1)} dB · ${ago(l.last_heard)}`)
      .addTo(linkLayer);
  }

  for (const n of state.nodes.values()) {
    if (n.lat == null || state.repeaters.has(n.pub)) continue;
    const t = n.type || 0;
    L.circleMarker([n.lat, n.lon], {
      radius: t === 2 ? 6 : 4.5, weight: 1, color: css("--panel"), fillColor: css(`--t${t}`) || css("--off"), fillOpacity: 0.9,
    })
      .bindPopup(`<b>${esc(n.name || "unnamed")}</b><br>${TYPE[t] || "node"} · heard ${ago(n.last_seen)}<br><span class="mono">${esc(n.pub.slice(0, 16))}…</span>`)
      .addTo(nodeLayer);
  }

  const pts = [];
  const hub = hubPos();
  if (hub) {
    pts.push(hub);
    const online = [...state.repeaters.values()].filter((r) => r.online).length;
    L.marker(hub, { icon: L.divIcon({ className: "hubmark", html: "IP", iconSize: [24, 24] }), keyboard: false })
      .bindTooltip(esc(hubName()), { permanent: true, direction: "right", offset: [12, 0], className: "cs" })
      .bindPopup(`<b>${esc(hubName())}</b><br>IP backbone hub · ${online} connected<br>UDP ${esc(String(state.overview?.hub?.backbone_listen || "").split(":").pop())} · ${esc(location.hostname)}`)
      .addTo(ipLayer);
  }
  for (const r of state.repeaters.values()) {
    if (r.lat == null) continue;
    pts.push([r.lat, r.lon]);
    // Its session to the hub, as a dashed IP line.
    if (hub && r.online) {
      L.polyline([[r.lat, r.lon], hub], { color: css("--ip"), weight: 2, dashArray: "5 7", opacity: 0.85, interactive: true })
        .bindTooltip(`${esc(r.callsign)} ↔ ${esc(hubName())} over IP · up ${dur(now() - r.session_since)}`, { sticky: true })
        .addTo(ipLayer);
    }
    // Offline: grey, with a ring in the kind's colour.
    const m = L.circleMarker([r.lat, r.lon], {
      radius: 9, weight: 3, color: r.online ? css("--panel") : kindColor(r), fillColor: r.online ? kindColor(r) : css("--off"), fillOpacity: 1,
    })
      .bindTooltip(esc(r.callsign), { permanent: true, direction: "right", offset: [10, 0], className: "cs" })
      .on("click", () => openDetail(r.pub))
      .addTo(repLayer);
    repMarkers.set(r.pub, m);
  }
  if (!fitted && pts.length) {
    fitted = true;
    fitPts = pts;
    fit();
  }
}

function nameOf(pub) {
  return state.repeaters.get(pub)?.callsign || state.nodes.get(pub)?.name || pub.slice(0, 8);
}

function repByCall(cs) {
  for (const r of state.repeaters.values()) if (r.callsign === cs) return r;
  return null;
}

function pulse(cs) {
  const r = repByCall(cs);
  const m = r && repMarkers.get(r.pub);
  if (!m) return;
  m.setRadius(13);
  setTimeout(() => m.setRadius(9), 350);
}

function flashBridge(from, to) {
  const a = repByCall(from), b = repByCall(to);
  const pa = a && posOf(a.pub), pb = b && posOf(b.pub);
  if (!pa || !pb) return;
  // Bridged frames travel through the hub.
  const hub = hubPos();
  const line = L.polyline(hub ? [pa, hub, pb] : [pa, pb], { color: css("--bridge"), weight: 3, dashArray: "6 8", opacity: 0.95 }).addTo(flashLayer);
  setTimeout(() => flashLayer.removeLayer(line), 2500);
}

// --------------------------------------------------------- side panels --

function renderStats() {
  const o = state.overview;
  if (!o) return;
  const online = [...state.repeaters.values()].filter((r) => r.online).length;
  $("#st-rep").textContent = `${online}/${state.repeaters.size}`;
  $("#st-nodes").textContent = o.nodes_24h;
  $("#st-msgs").textContent = o.messages_24h;
  $("#st-bridged").textContent = o.bridged_24h;

  const port = String(o.hub?.backbone_listen || ":4405").split(":").pop();
  $("#join-conf").textContent =
    `backbone          = true\n` +
    `backbone_host     = ${location.hostname}\n` +
    `backbone_port     = ${port}\n` +
    `backbone_hub_key  = ${o.hub?.hub_pub || "(hub key not published yet)"}\n` +
    `backbone_observe  = true\n` +
    `backbone_bridge   = true`;
}

function renderRepeaters() {
  const el = $("#repeaters");
  const list = [...state.repeaters.values()].sort((a, b) => (b.online - a.online) || (isHotspot(a) - isHotspot(b)) || a.callsign.localeCompare(b.callsign));
  if (!list.length) {
    el.innerHTML = `<p class="empty">Nothing on the backbone yet.</p>`;
    return;
  }
  el.innerHTML = list.map((r) => {
    const s = r.status || {};
    const rt = r.rates_1h || {};
    const roles = r.online ? [r.roles & 1 && "observe", r.roles & 2 && "bridge"].filter(Boolean) : [];
    return `<button class="card" data-pub="${esc(r.pub)}">
      <div class="row"><i class="state ${r.online ? "on" : ""} ${isHotspot(r) ? "hs" : ""}"></i><span class="cs">${esc(r.callsign)}</span>
        ${isHotspot(r) ? `<span class="badge hs">hotspot</span>` : ""}
        ${roles.map((x) => `<span class="badge">${x}</span>`).join("")}
        ${r.online ? "" : `<span class="badge off">offline</span>`}
        <span class="when">${r.online ? `up ${dur(now() - r.session_since)}` : `seen ${ago(r.last_seen)}`}</span></div>
      <div class="kv">
        <div><b>${rt.duty_tx != null ? fmt(rt.duty_tx * 100, 1) + "%" : "–"}</b><span>TX duty, 1 h</span></div>
        <div><b>${fmt(rt.rx_per_h)}</b><span>heard / h</span></div>
        <div><b>${r.heard_direct ?? "–"}</b><span>direct links</span></div>
        <div><b>${fmt(rt.crc_per_h)}</b><span>CRC err / h</span></div>
      </div>
      <div class="row"><span class="when" style="margin-left:0">${s.fw ? "fw " + esc(s.fw) + " · " : ""}uptime ${dur(r.uptime)}</span></div>
    </button>`;
  }).join("");
}

async function openDetail(pub) {
  state.detail = pub;
  selectTab("repeaters");
  const box = $("#detail");
  $("#repeaters").hidden = true;
  box.hidden = false;
  box.innerHTML = `<p class="empty">Loading…</p>`;
  let r;
  try { r = await api(`/api/repeater/${pub}`); } catch { box.innerHTML = `<p class="empty">Could not load this node.</p>`; return; }
  if (state.detail !== pub) return;
  try { history.replaceState(null, "", `#r/${encodeURIComponent(r.callsign)}`); } catch {}

  const h = r.history || [];
  const duty = [], rx = [];
  for (let i = 1; i < h.length; i++) {
    const dt = h[i].ts - h[i - 1].ts;
    if (dt <= 0 || h[i].uptime < h[i - 1].uptime) continue;
    duty.push([h[i].ts, ((h[i].airtime_tx - h[i - 1].airtime_tx) / (dt * 1000)) * 100]);
    rx.push([h[i].ts, ((h[i].rx_total - h[i - 1].rx_total) * 3600) / dt]);
  }
  const st = r.status || {};
  const radio = st.radio || {};
  box.innerHTML = `
    <button class="back" type="button">← Backbone</button>
    <div class="row" style="display:flex;align-items:center;gap:8px"><i class="state ${r.online ? "on" : ""} ${isHotspot(r) ? "hs" : ""}"></i><h2>${esc(r.callsign)}</h2>
      <span class="badge ${isHotspot(r) ? "hs" : ""}">${isHotspot(r) ? "hotspot" : "repeater"}</span>
      <span class="badge ${r.online ? "" : "off"}">${r.online ? "online" : "offline"}</span></div>
    <p class="mono">${esc(r.pub)}</p>
    <div class="kv">
      <div><b>${dur(r.uptime)}</b><span>uptime</span></div>
      <div><b>${r.online ? dur(now() - r.session_since) : ago(r.last_seen)}</b><span>${r.online ? "on backbone" : "last seen"}</span></div>
      <div><b>${esc(st.fw || "–")}</b><span>firmware</span></div>
      <div><b>${radio.freq ? fmt(radio.freq, 3) : "–"}</b><span>MHz</span></div>
    </div>
    ${r.online ? "" : `<p class="note">Offline: ${esc(r.down_reason || "never connected")}</p>`}
    <h3>TX duty cycle, 24 h (%)</h3>${chart(duty)}
    <h3>Packets heard per hour, 24 h</h3>${chart(rx)}
    <h3>Heard by ${esc(r.callsign)} (7 days)</h3>
    ${heardTable(r.heard || [])}
    <h3>Backbone sessions</h3>
    <ol class="feed">${(r.sessions_log || []).map((l) => `<li class="sess"><span class="t">${clock(l.ts)}</span><span class="r">${esc(l.event)}</span><span class="d">${esc(l.detail || "")} · ${ago(l.ts)}</span></li>`).join("") || `<li><span></span><span></span><span class="d">none yet</span></li>`}</ol>`;
  $(".back", box).onclick = closeDetail;
  if (r.lat != null) {
    userMoved = true;
    map.setView([r.lat, r.lon], Math.max(map.getZoom(), 10));
  }
}

function closeDetail() {
  state.detail = null;
  $("#detail").hidden = true;
  $("#repeaters").hidden = false;
  try { history.replaceState(null, "", location.pathname); } catch {}
}

function heardTable(rows) {
  if (!rows.length) return `<p class="note">Nothing reported yet.</p>`;
  return `<table class="heard"><thead><tr><th>Node</th><th>Type</th><th class="n">Hops</th><th class="n">RSSI</th><th class="n">SNR</th><th class="n">Heard</th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td>${esc(x.name || x.pub.slice(0, 10))}</td><td>${TYPE[x.type] || "–"}</td><td class="n">${x.hops}</td>
      <td class="n">${fmt(x.rssi)}</td><td class="n ${x.hops === 0 ? snrClass(x.snr) : ""}">${fmt(x.snr, 1)}</td><td class="n">${ago(x.last_heard)}</td></tr>`).join("")}
  </tbody></table>`;
}

function chart(series) {
  if (series.length < 2) return `<p class="note">Not enough reports yet.</p>`;
  const W = 300, H = 70;
  const t0 = series[0][0], t1 = series[series.length - 1][0];
  const max = Math.max(...series.map((p) => p[1]), 1e-9);
  const x = (t) => ((t - t0) / Math.max(1, t1 - t0)) * W;
  const y = (v) => H - 4 - (v / max) * (H - 16);
  const line = series.map((p, i) => `${i ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join("");
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <path class="area" d="${line}L${W},${H}L0,${H}Z"/><path class="stroke" d="${line}"/>
    <text x="2" y="10">max ${fmt(max, max < 10 ? 1 : 0)}</text></svg>`;
}

function spark(id, values) {
  const el = $(id);
  const W = 240, H = 40, max = Math.max(...values, 1);
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * W).toFixed(1)},${(H - 2 - (v / max) * (H - 6)).toFixed(1)}`);
  el.innerHTML = `<path d="M0,${H}L${pts.join("L")}L${W},${H}Z"/>`;
}

// ---------------------------------------------------------------- feed --

const feedEl = $("#feed");

function feed(cls, t, who, html) {
  const li = document.createElement("li");
  li.className = `${cls} new`;
  li.innerHTML = `<span class="t">${clock(t || now())}</span><span class="r">${esc(who)}</span><span class="d">${html}</span>`;
  feedEl.prepend(li);
  while (feedEl.children.length > 200) feedEl.lastChild.remove();
}

function skipped(o) {
  feed("skipped", o.ts, o.from || "?", `<b>not bridged</b> · ${esc(o.type || "?")} ${esc(o.route || "")} · ${esc(SKIP[o.outcome] || o.outcome)}${o.detail ? ` (${esc(o.detail)})` : ""}`);
}

function renderOffers(counts) {
  const el = $("#offers");
  const n = Object.values(counts || {}).reduce((a, b) => a + b, 0);
  if (!n) { el.textContent = "Nothing offered for bridging in the last 24 h."; return; }
  const parts = [`${counts.bridged || 0} bridged`];
  for (const [k, label] of Object.entries({ own_reply: "own replies", heard: "already heard everywhere", no_route: "no route", no_peer: "no other island", rate_limited: "rate-limited" })) {
    if (counts[k]) parts.push(`${counts[k]} ${label}`);
  }
  el.textContent = `Offered for bridging, 24 h: ${n} · ${parts.join(" · ")}`;
}

function renderMessages() {
  const el = $("#messages");
  const list = [...state.messages.values()].sort((a, b) => b.first_heard - a.first_heard).slice(0, 300);
  if (!list.length) {
    el.innerHTML = `<p class="empty">No public messages yet.</p>`;
    return;
  }
  el.innerHTML = list.map((m) => `<li class="${m.fresh ? "new" : ""}">
    <div class="head"><span class="from">${esc(m.sender || "?")}</span><span class="chan">${esc(m.channel)}</span><span class="time">${clock(m.first_heard)}</span></div>
    <div class="text">${esc(m.text)}</div>
    <div class="via">${(m.heard || []).map((h) => `<span>${esc(h.rep || "?")} ${fmt(h.rssi)} dBm · ${fmt(h.snr, 1)} dB${h.hops ? ` · ${h.hops} hop${h.hops > 1 ? "s" : ""}` : ""}</span>`).join("")}</div>
  </li>`).join("");
  for (const m of list) m.fresh = false;
}

// ---------------------------------------------------------------- data --

async function loadAll() {
  const [o, reps, nodes, links] = await Promise.all([api("/api/overview"), api("/api/repeaters"), api("/api/nodes"), api("/api/links")]);
  state.overview = o;
  state.repeaters = new Map(reps.map((r) => [r.pub, r]));
  state.nodes = new Map(nodes.map((n) => [n.pub, n]));
  state.links = links;
  renderStats();
  renderRepeaters();
  drawMap();
}

async function loadActivity() {
  const a = await api("/api/activity");
  spark("#spark-heard", a.heard);
  spark("#spark-bridged", a.bridged);
  state.offers = a.offers_24h || {};
  renderOffers(state.offers);
  if (!feedEl.children.length) {
    const items = [
      ...(a.recent_skipped || []).map((o) => ({ ts: o.ts, f: () => skipped({ ...o, from: o.src, type: PTYPE[o.ptype], route: ROUTE[o.route] }) })),
      ...a.recent_bridged.map((b) => ({ ts: b.ts, f: () => feed("bridged", b.ts, b.src || "?", `<b>bridged</b> to ${esc(b.dst || "?")} · ${PTYPE[b.ptype] || "?"} ${ROUTE[b.route]}`) })),
      ...a.recent_sessions.map((s) => ({ ts: s.ts, f: () => feed("sess", s.ts, s.rep || "?", `<b>${esc(s.event)}</b> ${esc(s.detail || "")}`) })),
    ].sort((x, y) => x.ts - y.ts);
    for (const i of items) i.f();
    for (const li of feedEl.children) li.classList.remove("new");
  }
}

async function loadMessages() {
  const list = await api("/api/messages?limit=200");
  for (const m of list) state.messages.set(m.hash, m);
  renderMessages();
}

const refresh = debounce(() => loadAll().catch(() => {}), 1500);

// ---------------------------------------------------------------- live --

function onEvent(ev) {
  switch (ev.t) {
    case "frame":
      pulse(ev.rep);
      if (ev.bb) break;
      feed("", ev.ts, ev.rep, `<b>${esc(ev.type)}</b> ${esc(ev.route)} · ${ev.hops} hop${ev.hops === 1 ? "" : "s"} · ${fmt(ev.rssi)} dBm · ${fmt(ev.snr, 1)} dB · ${esc(ev.disp)}`);
      break;
    case "msg": {
      const m = state.messages.get(ev.hash) || { hash: ev.hash, channel: ev.channel, sender: ev.sender, text: ev.text, sent_ts: ev.sent, first_heard: ev.ts, heard: [] };
      m.heard = (m.heard || []).filter((h) => h.rep !== ev.rep).concat([{ rep: ev.rep, rssi: ev.rssi, snr: ev.snr, hops: ev.hops }]);
      m.fresh = true;
      state.messages.set(ev.hash, m);
      renderMessages();
      if (state.overview && m.heard.length === 1) { state.overview.messages_24h++; renderStats(); }
      break;
    }
    case "node": {
      const n = state.nodes.get(ev.pub) || { pub: ev.pub, adverts: 0 };
      Object.assign(n, { name: ev.name ?? n.name, type: ev.type, lat: ev.lat, lon: ev.lon, last_seen: ev.ts });
      state.nodes.set(ev.pub, n);
      refresh();
      break;
    }
    case "up":
    case "down": {
      const r = state.repeaters.get(ev.pub);
      if (r) { r.online = ev.t === "up" ? 1 : 0; if (r.online) r.session_since = ev.ts; else r.down_reason = ev.reason; }
      feed("sess", ev.ts, ev.rep, `<b>${ev.t === "up" ? "connected" : "disconnected"}</b> ${esc(ev.t === "up" ? (ev.roles || []).join(" + ") : ev.reason)}`);
      renderRepeaters(); renderStats(); drawMap(); refresh();
      break;
    }
    case "offer":
      if (state.offers) { state.offers[ev.outcome] = (state.offers[ev.outcome] || 0) + 1; renderOffers(state.offers); }
      if (ev.outcome !== "bridged") skipped(ev);
      break;
    case "bridged":
      flashBridge(ev.from, ev.to);
      feed("bridged", ev.ts, ev.from, `<b>bridged</b> to ${esc(ev.to)} · ${esc(ev.type)} ${esc(ev.route)}`);
      if (state.overview) { state.overview.bridged_24h++; renderStats(); }
      break;
    case "status":
    case "neighbours":
      refresh();
      break;
  }
}

const liveEl = $("#live");
let backoff = 1000;

function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/live`);
  ws.onopen = () => { backoff = 1000; liveEl.classList.add("ok"); $("span", liveEl).textContent = "live"; };
  ws.onmessage = (e) => { try { onEvent(JSON.parse(e.data)); } catch {} };
  ws.onclose = () => {
    liveEl.classList.remove("ok");
    $("span", liveEl).textContent = "reconnecting";
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30000);
  };
}

// ---------------------------------------------------------------- tabs --

function selectTab(name) {
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  for (const p of document.querySelectorAll(".panel")) p.hidden = p.id !== `tab-${name}`;
  store("tab", name);
  if (name === "messages") renderMessages();
}

for (const b of document.querySelectorAll(".tabs button")) b.onclick = () => selectTab(b.dataset.tab);
$("#repeaters").addEventListener("click", (e) => {
  const c = e.target.closest(".card");
  if (c) openDetail(c.dataset.pub);
});
$("#join-copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("#join-conf").textContent); $("#join-copy").textContent = "Copied"; } catch { $("#join-copy").textContent = "Select and copy"; }
  setTimeout(() => ($("#join-copy").textContent = "Copy"), 1800);
};

// --------------------------------------------------------------- start --

(async () => {
  const tab = store("tab");
  if (tab && document.getElementById(`tab-${tab}`)) selectTab(tab);
  try { await loadAll(); } catch (e) { $("#repeaters").innerHTML = `<p class="empty">The hub database is not reachable right now.</p>`; }
  loadActivity().catch(() => {});
  loadMessages().catch(() => {});
  const m = location.hash.match(/^#r\/(.+)$/);
  if (m) { const r = repByCall(decodeURIComponent(m[1])); if (r) openDetail(r.pub); }
  connect();
  setInterval(() => loadAll().catch(() => {}), 60000);
  setInterval(() => loadActivity().catch(() => {}), 300000);
  setInterval(() => { renderRepeaters(); }, 30000);
})();
