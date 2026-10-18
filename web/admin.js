// Backbone admin: rooms and blocked users. Plain JS, no build step.
// Names and text from the mesh are untrusted: they only reach the page
// through esc() or textContent.
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const now = () => Math.floor(Date.now() / 1000);
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "–");

function ago(ts) {
  if (!ts) return "never";
  const d = Math.max(0, now() - ts);
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}

function flash(msg, bad = false) {
  const el = $("#flash");
  el.textContent = msg;
  el.classList.toggle("bad", bad);
  el.hidden = false;
  clearTimeout(flash.t);
  flash.t = setTimeout(() => (el.hidden = true), bad ? 8000 : 4000);
}

async function call(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    credentials: "same-origin",
  });
  let data = {};
  try { data = await r.json(); } catch {}
  if (!r.ok) {
    const e = new Error(data.error || `${r.status} ${r.statusText}`);
    e.status = r.status;
    throw e;
  }
  return data;
}

// ------------------------------------------------------------- passkeys --

const b64u = {
  dec(s) {
    const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
    return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
  },
  enc(buf) {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

// WebIDL rejects null for optional members: drop them.
function clean(v) {
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === "object" && !(v instanceof ArrayBuffer)) {
    const o = {};
    for (const [k, x] of Object.entries(v)) if (x !== null && x !== undefined) o[k] = clean(x);
    return o;
  }
  return v;
}

async function createPasskey(options) {
  const pk = clean(options.publicKey);
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) }));
  const c = await navigator.credentials.create({ publicKey: pk });
  return {
    id: c.id,
    rawId: b64u.enc(c.rawId),
    type: c.type,
    response: {
      attestationObject: b64u.enc(c.response.attestationObject),
      clientDataJSON: b64u.enc(c.response.clientDataJSON),
      transports: c.response.getTransports ? c.response.getTransports() : undefined,
    },
    extensions: c.getClientExtensionResults(),
  };
}

async function usePasskey(options) {
  const pk = clean(options.publicKey);
  pk.challenge = b64u.dec(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) }));
  const c = await navigator.credentials.get({ publicKey: pk });
  return {
    id: c.id,
    rawId: b64u.enc(c.rawId),
    type: c.type,
    response: {
      authenticatorData: b64u.enc(c.response.authenticatorData),
      clientDataJSON: b64u.enc(c.response.clientDataJSON),
      signature: b64u.enc(c.response.signature),
      userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : undefined,
    },
    extensions: c.getClientExtensionResults(),
  };
}

function passkeyError(e) {
  if (e && e.name === "NotAllowedError") return "The passkey request was cancelled or timed out.";
  if (e && e.name === "InvalidStateError") return "This device already has a passkey for this account.";
  return e && e.message ? e.message : String(e);
}

// ---------------------------------------------------------------- views --

function show(view) {
  for (const id of ["invite", "signin", "dash"]) $(`#${id}`).hidden = id !== view;
}

let inviteToken = null;

async function start() {
  if (!window.PublicKeyCredential) {
    flash("This browser has no passkey support (WebAuthn). Use a current browser.", true);
  }
  const m = location.hash.match(/^#invite=([A-Za-z0-9_-]+)$/);
  if (m) {
    inviteToken = m[1];
    try {
      const i = await call("POST", "/api/admin/invite", { token: inviteToken });
      $("#invite-text").textContent = i.existing
        ? `This invite adds a passkey on this device to the admin account ${i.email}.`
        : `You've been invited as a room admin with ${i.email}.`;
      show("invite");
    } catch (e) {
      flash(e.message, true);
      history.replaceState(null, "", location.pathname);
      inviteToken = null;
      await load();
    }
    return;
  }
  await load();
}

$("#invite-go").onclick = async () => {
  try {
    const s = await call("POST", "/api/admin/register/start", { token: inviteToken });
    const credential = await createPasskey(s.options);
    await call("POST", "/api/admin/register/finish", { ceremony: s.ceremony, credential });
    history.replaceState(null, "", location.pathname);
    inviteToken = null;
    flash("Passkey created. You're signed in.");
    await load();
  } catch (e) {
    flash(passkeyError(e), true);
  }
};

$("#signin-go").onclick = async () => {
  try {
    const s = await call("POST", "/api/admin/login/start");
    const credential = await usePasskey(s.options);
    await call("POST", "/api/admin/login/finish", { ceremony: s.ceremony, credential });
    await load();
  } catch (e) {
    flash(passkeyError(e), true);
  }
};

$("#signout").onclick = async () => {
  try { await call("POST", "/api/admin/logout"); } catch {}
  $("#who").hidden = true;
  show("signin");
};

let state = null;

async function load() {
  try {
    state = await call("GET", "/api/admin/state");
  } catch (e) {
    if (e.status === 401) {
      $("#who").hidden = true;
      show("signin");
      return;
    }
    flash(e.message, true);
    return;
  }
  $("#who-email").textContent = state.me.email;
  $("#who").hidden = false;
  render();
  show("dash");
}

function empty(text) {
  return `<li class="empty">${esc(text)}</li>`;
}

function render() {
  const s = state;
  $("#rooms").innerHTML =
    s.rooms.map((r) => `<li><span class="main">${esc(r.name)}</span><span class="meta">added by ${esc(r.created_by)} · ${ago(r.created_ts)}</span>
      <button type="button" class="link danger" data-room="${esc(r.name.slice(1))}">Remove</button></li>`).join("") ||
    empty("No central rooms yet: nodes serve only their own.");

  const t = now();
  $("#blocks").innerHTML =
    s.blocks.map((b) => {
      const expired = b.expires_ts && b.expires_ts <= t;
      const until = b.expires_ts ? (expired ? `expired ${ago(b.expires_ts)}` : `until ${when(b.expires_ts)}`) : "until removed";
      return `<li class="${expired ? "off" : ""}"><span class="main">${b.kind === "key" ? `<code>${esc(b.value.slice(0, 16))}…</code>` : esc(b.value)}</span>
        <span class="badge">${b.kind}</span>
        <span class="meta">${esc(until)} · by ${esc(b.created_by)}${b.reason ? ` · ${esc(b.reason)}` : ""}</span>
        <button type="button" class="link danger" data-block="${b.id}">${expired ? "Delete" : "Unblock"}</button></li>`;
    }).join("") || empty("Nobody is blocked.");

  $("#senders").innerHTML =
    s.senders.map((x) => `<li><span class="main">${esc(x.sender)}</span><span class="meta">${x.n} message${x.n === 1 ? "" : "s"} · ${esc(x.channels)} · ${ago(x.last)}</span>
      ${x.blocked ? `<span class="badge off">blocked</span>` : `<button type="button" class="link" data-sender="${esc(x.sender)}">Block…</button>`}</li>`).join("") ||
    empty("No messages on the decoded channels this week.");

  const v = s.policy_version;
  $("#nodes").innerHTML =
    s.nodes.map((n) => {
      let sync;
      if (!n.policy) sync = `<span class="badge off">doesn't take central rooms and blocks</span>`;
      else if (n.policy.version === v) sync = `<span class="badge">up to date</span>`;
      else sync = `<span class="badge warn">${n.online ? "updating" : "behind"}</span>`;
      const p = n.policy ? ` · ${n.policy.rooms ?? 0} rooms, ${n.policy.blocks ?? 0} blocks${n.policy.skipped ? `, ${n.policy.skipped} skipped` : ""}` : "";
      return `<li><span class="main">${esc(n.callsign)}</span><span class="meta">${esc(n.kind)} · ${n.online ? "online" : "offline"}${esc(p)}</span>${sync}</li>`;
    }).join("") || empty("No nodes on the allowlist.");

  $("#admins").innerHTML = s.admins.map((a) => `<li><span class="main">${esc(a.email)}${a.id === s.me.id ? " (you)" : ""}</span>
      <span class="meta">${a.passkeys} passkey${a.passkeys === 1 ? "" : "s"} · last sign-in ${ago(a.last_login)} · invited by ${esc(a.invited_by)}</span>
      ${s.admins.length > 1 ? `<button type="button" class="link danger" data-admin="${a.id}">Remove</button>` : ""}</li>`).join("");

  $("#invites").innerHTML = s.invites.map((i) => `<li><span class="main">${esc(i.email)}</span><span class="meta">invited by ${esc(i.invited_by)} · open until ${when(i.expires_ts)}</span>
      <button type="button" class="link danger" data-invite="${i.id}">Withdraw</button></li>`).join("");

  $("#audit").innerHTML = s.audit.map((l) => `<li><span class="t">${esc(when(l.ts))}</span><span class="r">${esc(l.admin)}</span><span class="d"><b>${esc(l.action)}</b> ${esc(l.detail || "")}</span></li>`).join("") ||
    `<li><span></span><span></span><span class="d">Nothing yet.</span></li>`;
}

// -------------------------------------------------------------- actions --

async function act(fn, done) {
  try {
    await fn();
    if (done) flash(done);
    await load();
  } catch (e) {
    if (e.status === 401) { show("signin"); flash("Your session ended: sign in again.", true); return; }
    flash(e.message, true);
  }
}

$("#room-form").onsubmit = (e) => {
  e.preventDefault();
  const name = $("#room-name").value;
  act(async () => { await call("POST", "/api/admin/rooms", { name }); $("#room-name").value = ""; }, "Room added. The nodes get it within seconds.");
};

$("#block-form").onsubmit = (e) => {
  e.preventDefault();
  const body = { kind: $("#block-kind").value, value: $("#block-value").value, reason: $("#block-reason").value, days: Number($("#block-days").value) };
  act(async () => {
    await call("POST", "/api/admin/blocks", body);
    $("#block-value").value = "";
    $("#block-reason").value = "";
  }, "Blocked. The nodes get it within seconds.");
};

$("#invite-form").onsubmit = (e) => {
  e.preventDefault();
  const email = $("#invite-email").value;
  act(async () => {
    const r = await call("POST", "/api/admin/invites", { email });
    $("#invite-to").textContent = r.email;
    $("#invite-url").textContent = r.link;
    $("#invite-link").hidden = false;
    $("#invite-email").value = "";
  });
};

$("#invite-copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("#invite-url").textContent); $("#invite-copy").textContent = "Copied"; } catch { $("#invite-copy").textContent = "Select and copy"; }
  setTimeout(() => ($("#invite-copy").textContent = "Copy"), 1800);
};

document.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-room],button[data-block],button[data-sender],button[data-admin],button[data-invite]");
  if (!b) return;
  const d = b.dataset;
  if (d.room && confirm(`Remove room #${d.room}? Nodes stop serving it unless it's also in their own config.`)) {
    act(() => call("DELETE", `/api/admin/rooms/${encodeURIComponent(d.room)}`), "Room removed.");
  } else if (d.block) {
    act(() => call("DELETE", `/api/admin/blocks/${d.block}`), "Block removed.");
  } else if (d.sender) {
    $("#block-kind").value = "name";
    $("#block-value").value = d.sender;
    $("#block-reason").focus();
    $("#block-form").scrollIntoView({ behavior: "smooth", block: "center" });
  } else if (d.admin) {
    const a = state.admins.find((x) => String(x.id) === d.admin);
    if (a && confirm(`Remove admin ${a.email}? Their passkeys stop working at once.`)) {
      act(async () => { const r = await call("DELETE", `/api/admin/admins/${d.admin}`); if (r.self) location.reload(); }, "Admin removed.");
    }
  } else if (d.invite) {
    act(() => call("DELETE", `/api/admin/invites/${d.invite}`), "Invite withdrawn.");
  }
});

start();
