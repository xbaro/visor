// App de consulta de despeses. La clau de l'usuari només es guarda embolcallada amb un secret que
// dóna l'autenticador del mòbil (passkey amb extensió PRF) després de la biometria; mai en clar. Si el dispositiu
// no ho suporta, l'app no desa la clau (fail closed).
import { VERSION, parseKeyPayload, importKey, parseEnvelope, openEnvelope, sealUpload, applyBundle, decodeBody } from "./efam.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const eur = (s) => Number(s).toLocaleString("ca-ES", { style: "currency", currency: "EUR" });
const LOCK_MS = 2 * 60 * 1000;
let session = null, lockTimer = null; // {keyId, key: CryptoKey (no extraïble), state}

// ---------- emmagatzematge local (IndexedDB) ----------
const idb = () => new Promise((res, rej) => { const r = indexedDB.open("efam", 1); r.onupgradeneeded = () => r.result.createObjectStore("kv"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const kvGet = async (k) => { const d = await idb(); return new Promise((res) => { const q = d.transaction("kv").objectStore("kv").get(k); q.onsuccess = () => res(q.result); }); };
const kvSet = async (k, v) => { const d = await idb(); return new Promise((res) => { const t = d.transaction("kv", "readwrite"); t.objectStore("kv").put(v, k); t.oncomplete = res; }); };
const kvDel = async (k) => { const d = await idb(); return new Promise((res) => { const t = d.transaction("kv", "readwrite"); t.objectStore("kv").delete(k); t.oncomplete = res; }); };

// ---------- desbloqueig biomètric (WebAuthn + PRF) ----------
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
async function prfSecret(credId, salt) {
  const a = await navigator.credentials.get({ publicKey: { challenge: rand(32), allowCredentials: credId ? [{ id: credId, type: "public-key" }] : [], userVerification: "required", extensions: { prf: { eval: { first: salt } } } } });
  const out = a.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error("Aquest dispositiu no permet protegir la clau amb la biometria");
  return { secret: new Uint8Array(out), credId: new Uint8Array(a.rawId) };
}
const aesFrom = (raw, usages) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);

async function enroll(payloadText) {
  const { keyId, raw } = parseKeyPayload(payloadText);
  const salt = rand(32);
  const cred = await navigator.credentials.create({ publicKey: { rp: { name: "Visor" }, user: { id: rand(16), name: "usuari", displayName: "Usuari" }, challenge: rand(32), pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" }, extensions: { prf: { enabled: true } } } });
  if (!cred.getClientExtensionResults().prf?.enabled) throw new Error("Aquest dispositiu no permet protegir la clau amb la biometria");
  const { secret } = await prfSecret(new Uint8Array(cred.rawId), salt);   // demana la biometria
  const iv = rand(12);
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesFrom(secret, ["encrypt"]), raw);
  await kvSet("meta", { keyId, credId: new Uint8Array(cred.rawId), salt, iv, wrapped: new Uint8Array(wrapped) });
  raw.fill(0);
}

async function unlock() {
  const meta = await kvGet("meta");
  if (!meta) throw new Error("Falta configurar la clau");
  const { secret } = await prfSecret(meta.credId, meta.salt);
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: meta.iv }, await aesFrom(secret, ["decrypt"]), meta.wrapped));
  const key = await importKey(raw); raw.fill(0);
  const st = await kvGet("state");
  let state = null;
  if (st) state = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: st.iv }, key, st.ct)));
  session = { keyId: meta.keyId, key, state };
  arm();
}
async function saveState() {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, session.key, new TextEncoder().encode(JSON.stringify(session.state)));
  await kvSet("state", { iv, ct: new Uint8Array(ct) });
}
function arm() { clearTimeout(lockTimer); lockTimer = setTimeout(lock, LOCK_MS); }
function lock() { session = null; clearTimeout(lockTimer); render(); }
document.addEventListener("visibilitychange", () => { if (document.hidden) lock(); });
document.addEventListener("pointerdown", () => session && arm());


// ---------- canvis fets a l'app (ADR-0017): es veuen al moment i s'envien a l'ordinador com una pujada xifrada ----------
const flat = (t) => { const out = []; const walk = (v, p) => { if (Array.isArray(v)) v.forEach((x) => out.push(`${p} / ${x}`)); else Object.entries(v || {}).forEach(([k, c]) => { out.push(`${p} / ${k}`); walk(c, `${p} / ${k}`); }); }; Object.entries(t || {}).forEach(([k, v]) => { out.push(k); walk(v, k); }); return out; };
const newId = () => "c-" + [...rand(8)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function addChange(c) {
  if (!session.state) throw new Error("Carrega primer un paquet de dades");
  (session.state.changes ||= []).push({ id: newId(), ...c }); await saveState(); renderChg();
}
function withChanges(r, ch) {
  let o = r;
  for (const c of ch) {
    if (c.tx_id !== r.id) continue;
    if (c.op === "recat_tx") o = { ...o, category: c.category, subcategory: c.subcategory || "", changed: true, parts: o.lines.length ? o.parts : [{ category: c.category, subcategory: c.subcategory || "", amount: o.amount }] };
    else if (c.op === "recat_line") {
      const lines = o.lines.map((l) => (l.description === c.description && l.amount === c.amount ? { ...l, category: c.category, classified: true, changed: true } : l));
      const m = new Map();
      lines.forEach((l) => { const [h, ...rest] = l.classified && l.category ? l.category.split(" / ") : [o.category, o.subcategory]; const k = `${h}\u0000${rest.join(" / ")}`; m.set(k, (m.get(k) || 0) + Number(l.amount)); });
      const parts = [...m.entries()].map(([k, v]) => { const [category, subcategory] = k.split("\u0000"); return { category, subcategory, amount: v.toFixed(2) }; });
      const diff = Number(o.amount) - parts.reduce((s, p) => s + Number(p.amount), 0);
      if (parts.length) parts[0].amount = (Number(parts[0].amount) + diff).toFixed(2);
      o = { ...o, lines, parts, changed: true };
    }
  }
  return o;
}
function budgetView() {
  const B = session.state.budget, ch = (session.state.changes || []).filter((c) => c.op === "budget_set");
  if (!ch.length) return B;
  let g = B.config.global != null ? Number(B.config.global) : null; const cats = { ...(B.config.categories || {}) };
  ch.forEach((c) => { if ("global" in c) g = c.global; Object.entries(c.categories || {}).forEach(([k, v]) => (v == null ? delete cats[k] : (cats[k] = v))); });
  const months = {};
  Object.entries(B.months).forEach(([m, x]) => {
    const sp = Number(x.variable.spent);
    months[m] = { ...x, variable: { ...x.variable, budget: g != null ? g.toFixed(2) : null, left: g != null ? (g - sp).toFixed(2) : null, pct: g ? ((sp / g) * 100).toFixed(2) : null,
      cats: x.variable.cats.map((c) => ({ ...c, budget: cats[c.category] != null ? Number(cats[c.category]).toFixed(2) : null })) } };
  });
  return { ...B, config: { global: g, categories: cats }, months };
}
function pathPicker(current, remLabel, onSave) {
  const box = el("div", "ed"), sel = el("select"), rem = el("input"), lab = el("label");
  sel.append(...flat(session.state.category_tree).map((p) => new Option(p, p)));
  if (current && ![...sel.options].some((o) => o.value === current)) sel.prepend(new Option(current, current));
  sel.value = current || sel.options[0]?.value;
  rem.type = "checkbox"; rem.style.width = "auto"; lab.append(el("span", "", remLabel), rem);
  const row = el("div", "row"), ok = el("button", "", "Desa el canvi"), no = el("button", "ghost", "Cancel·la");
  ok.onclick = run(async () => onSave(sel.value, rem.checked)); no.onclick = () => box.remove();
  row.append(ok, no); box.append(sel, lab, row); return box;
}
function renderChg() {
  const box = $("chg"), ch = session?.state?.changes || [];
  box.hidden = !ch.length || !session; if (box.hidden) return;
  const pend = ch.filter((c) => !c.sent).length;
  box.replaceChildren(el("div", "", `✎ ${ch.length} canvi${ch.length > 1 ? "s" : ""} ${pend ? `(${pend} per enviar)` : "enviat(s), esperant el paquet següent"}`));
  if (pend) {
    const row = el("div", "row"), send = el("button", "", "Envia els canvis"), drop = el("button", "ghost", "Descarta");
    send.onclick = run(sendChanges); drop.onclick = run(async () => { session.state.changes = ch.filter((c) => c.sent); await saveState(); render(); });
    row.append(send, drop); box.append(row);
  }
}
async function sendChanges() {
  const todo = session.state.changes.filter((c) => !c.sent); if (!todo.length) return;
  const body = { format: "efam-changes1", base_seq: session.state.seq ?? null, changes: todo.map(({ sent, path, ...c }) => c) };
  const file = new File([JSON.stringify(body)], "canvis.json", { type: "application/vnd.efam.changes+json" });
  const blob = await sealUpload(file, session.keyId, session.key);
  const f = new File([blob], `canvis-${Date.now()}.efam`, { type: "application/octet-stream" });
  if (navigator.canShare?.({ files: [f] })) await navigator.share({ files: [f], title: "Canvis" });
  else { const a = el("a", "", "Baixa el fitxer de canvis"); a.href = URL.createObjectURL(blob); a.download = f.name; $("chg").append(a); }
  todo.forEach((c) => (c.sent = true)); await saveState(); msg("Canvis xifrats. Comparteix el fitxer cap al grup."); renderChg();
}
function editBudget(host, v, B) {
  host.querySelector(".ed")?.remove();
  const box = el("div", "ed"), inputs = new Map(), mk = (label, val) => { const l = el("label"), i = el("input"); i.type = "number"; i.min = "0"; i.step = "1"; i.inputMode = "decimal"; i.value = val != null && val !== "" ? Number(val) : ""; l.append(el("span", "", label), i); box.append(l); inputs.set(label, i); return i; };
  const g = mk("Total mensual", v.budget);
  const names = [...new Set([...v.cats.map((c) => c.category), ...Object.keys(B.config.categories || {})])];
  names.forEach((c) => mk(c, (B.config.categories || {})[c] ?? v.cats.find((x) => x.category === c)?.budget));
  const row = el("div", "row"), ok = el("button", "", "Desa el pressupost"), no = el("button", "ghost", "Cancel·la");
  ok.onclick = run(async () => {
    const patch = { op: "budget_set" }, cur = (B.config.categories || {});
    const gv = g.value === "" ? null : Number(g.value); if (gv !== (B.config.global != null ? Number(B.config.global) : null)) patch.global = gv;
    const cats = {}; names.forEach((c) => { const x = inputs.get(c).value === "" ? null : Number(inputs.get(c).value); if (x !== (cur[c] != null ? Number(cur[c]) : null)) cats[c] = x; });
    if (Object.keys(cats).length) patch.categories = cats;
    if (patch.global === undefined && !patch.categories) return box.remove();
    await addChange(patch); renderHome();
  });
  no.onclick = () => box.remove(); row.append(ok, no); box.append(row); host.append(box);
}

// ---------- vistes ----------
const views = ["setup", "locked", "home", "summary", "group", "list", "detail", "upload"];
let tab = "home", stack = [];
const show = (v) => { views.forEach((x) => $(x).hidden = x !== v); renderChg(); $("foot").hidden = !session; $("nav").hidden = !session; $("nav").querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b.dataset.tab === tab); if (b.dataset.tab === "home") b.hidden = !session?.state?.budget; }); };
function msg(t, err) { const m = $("msg"); m.textContent = t || ""; m.className = err ? "err" : "ok"; }
// Paquets antics (sense `parts`/`pending`): es tracten com una sola partida a la seva categoria.
const norm = (r) => (r.parts ? r : { ...r, pending: !!r.pending, parts: [{ category: r.category, subcategory: r.subcategory, amount: r.amount }] });
const allItems = () => { const ch = session.state?.changes || []; return Object.values(session.state?.items || {}).map((r) => withChanges(norm(r), ch)); };
const catName = (c) => c || "Sense classificar";
const pathName = (r) => [catName(r.category), r.subcategory].filter(Boolean).join(" › ");

async function render() {
  msg("");
  $("ver").textContent = `v${VERSION}`;
  if (!(await kvGet("meta"))) { $("nav").hidden = true; return show("setup"); }
  if (!session) { $("nav").hidden = true; return show("locked"); }
  stack = [];
  openTab(tab);
}
function openTab(t) { if (t === "home" && !session.state?.budget) t = "summary"; tab = t; stack = []; if (t === "home") renderHome(); else if (t === "summary") renderSummary(); else if (t === "list") renderList(); else show("upload"); }


// ---------- Inici visual: pressupost, despeses fixes, categories, creixement i resultat dels mesos ----------
const NS = "http://www.w3.org/2000/svg";
const svg = (t, a = {}, ...k) => { const e = document.createElementNS(NS, t); Object.entries(a).forEach(([x, y]) => e.setAttribute(x, y)); e.append(...k); return e; };
const N = (s) => Number(s);
const COL = ["var(--c1)", "var(--c2)", "var(--c3)"];
let homeMonth = "";
function trackBar(parts, scale, budget) {
  const t = el("div", "trk");
  parts.forEach((v, i) => { const s = el("span"); s.style.width = `${Math.max(0, (v / scale) * 100)}%`; s.style.background = COL[i]; t.append(s); });
  if (budget != null) { const m = el("div", "mk"); m.style.left = `${Math.min(100, (budget / scale) * 100)}%`; t.append(m); }
  return t;
}
function renderHome() {
  show("home");
  const B = budgetView(), months = Object.keys(B.months).sort();
  if (!months.includes(homeMonth)) homeMonth = months[months.length - 1] || "";
  const sel = $("hmonth"); sel.replaceChildren(...[...months].reverse().map((m) => new Option(monthLabel(m), m))); sel.value = homeMonth;
  const body = $("hbody"); body.replaceChildren();
  const m = B.months[homeMonth]; if (!m) return body.append(el("p", "muted", "Sense dades."));
  const v = m.variable, f = m.fixed, spent = N(v.spent), bud = v.budget != null ? N(v.budget) : null;
  // 1. Despesa variable: anell (carregat / targeta pendent de liquidar / tiquets que esperen moviment)
  const c1 = el("div", "card"); c1.append(el("h3", "", "Despesa variable"));
  const r = el("div", "ring"), den = Math.max(bud ?? spent, spent, 1), C = 2 * Math.PI * 52;
  const ring = svg("svg", { width: 130, height: 130, viewBox: "0 0 130 130", role: "img", "aria-label": "Despesa variable" }, svg("circle", { cx: 65, cy: 65, r: 52, fill: "none", stroke: "var(--line)", "stroke-width": 16 }));
  let off = 0;
  [N(v.loaded), N(v.card), N(v.tickets)].forEach((x, i) => { const len = Math.max(0, (x / den) * C); if (len > 0) ring.append(svg("circle", { cx: 65, cy: 65, r: 52, fill: "none", stroke: COL[i], "stroke-width": 16, "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -off, transform: "rotate(-90 65 65)" })); off += len; });
  const tx = el("div"); const over = bud != null && spent > bud;
  tx.append(el("div", "t" + (over ? " over" : ""), bud != null ? `${v.pct ? Math.round(N(v.pct)) : 0} %` : eur(spent)));
  tx.append(el("div", "muted", bud != null ? `${eur(spent)} de ${eur(bud)}` : "Sense pressupost global"));
  if (bud != null) tx.append(el("div", over ? "over" : "good", over ? `Passat per ${eur(spent - bud)}` : `Queden ${eur(bud - spent)}`));
  r.append(ring, tx); c1.append(r);
  const leg = el("div", "leg");
  [["Al compte", v.loaded], ["Targeta pendent", v.card], ["Tiquets pendents", v.tickets]].forEach(([n, x], i) => { const s = el("span"); const d = el("i"); d.style.background = COL[i]; s.append(d, `${n} ${eur(x)}`); leg.append(s); });
  c1.append(leg);
  const eb = el("button", "ghost mini", "Edita el pressupost"); eb.onclick = () => editBudget(c1, v, B); c1.append(eb);
  if (!m.complete) c1.append(el("p", "muted", "Mes encara no complet: les dades no arriben a final de mes."));
  body.append(c1);
  // 2. Despeses fixes
  if (f.items.length) {
    const c2 = el("div", "card"); c2.append(el("h3", "", "Despeses fixes"));
    c2.append(el("div", "t", `${f.pct != null ? Math.round(N(f.pct)) : 0} % carregat`), el("div", "muted", `${eur(f.loaded)} de ${eur(f.expected)}`));
    const t = trackBar([N(f.loaded)], Math.max(N(f.expected), 1)); t.style.margin = "8px 0"; c2.append(t);
    f.items.forEach((i) => { const row = el("div", "fx" + (i.done ? " done" : "")); row.append(el("span", "", `${i.done ? "✓" : "⏳"} ${i.sub || i.category}`), el("span", "a", i.done ? eur(i.loaded) : `~${eur(i.expected)}`)); c2.append(row); });
    body.append(c2);
  }
  // 3. Categories variables
  const rows = v.cats.filter((c) => N(c.spent) > 0 || c.budget != null).slice(0, 10);
  if (rows.length) {
    const c3 = el("div", "card"); c3.append(el("h3", "", "Per categoria"));
    const scale = Math.max(...rows.map((c) => Math.max(N(c.spent), c.budget != null ? N(c.budget) : 0)), 1);
    rows.forEach((c) => {
      const b = c.budget != null ? N(c.budget) : null, ov = b != null && N(c.spent) > b, w = el("div", "cr");
      const h = el("div", "h"); h.append(el("b", "", catName(c.category)), el("span", ov ? "over" : "", b != null ? `${eur(c.spent)} / ${eur(b)}` : eur(c.spent)));
      h.onclick = () => { sumMonth = homeMonth; stack.push(renderHome); renderGroup(c.category); };
      w.append(h, trackBar([N(c.loaded), N(c.card), N(c.tickets)], scale, b)); c3.append(w);
    });
    body.append(c3);
  }
  // 4. Creixement de les partides respecte dels mesos anteriors
  if (m.growth.length) {
    const c4 = el("div", "card"); c4.append(el("h3", "", "Evolució de les partides"), el("div", "muted", "Respecte la mitjana dels 3 mesos anteriors"));
    m.growth.forEach((g) => { const up = N(g.delta) > 0, row = el("div", "gr"); row.append(el("span", "", `${g.sub || g.category}`), el("span", up ? "over" : "good", `${up ? "▲ +" : "▼ "}${Math.round(N(g.pct))} %  ·  ${eur(g.value)}`)); c4.append(row); });
    body.append(c4);
  }
  // 5. Resultat de cada mes respecte el pressupost
  const c5 = el("div", "card"); c5.append(el("h3", "", "Mesos: final respecte el pressupost"));
  const hist = el("div", "hist"), hmax = Math.max(...months.map((k) => Math.max(N(B.months[k].variable.spent), bud ?? 0)), 1);
  months.forEach((k) => {
    const x = B.months[k].variable, sp = N(x.spent), col = el("div", "col" + (k === homeMonth ? " sel" : "")), b = el("div", "b");
    b.style.height = `${(sp / hmax) * 90}px`; if (bud != null) { const mk = el("div", "bm"); mk.style.bottom = `${(bud / hmax) * 90 - (sp / hmax) * 90}px`; mk.style.position = "absolute"; b.append(mk); b.style.overflow = "visible"; }
    const d = bud != null ? sp - bud : null;
    col.append(el("span", d != null && d > 0 ? "over" : "good", d == null ? "" : `${d > 0 ? "+" : ""}${Math.round(d)}`), b, el("span", "", MON3[Number(k.slice(5)) - 1]));
    col.onclick = () => { homeMonth = k; renderHome(); }; hist.append(col);
  });
  c5.append(hist); if (bud != null) c5.append(el("p", "muted", "Línia = pressupost. Sobre cada mes: quant s'ha passat (+) o t'ha sobrat (−) del pressupost."));
  body.append(c5);
}
$("hmonth").onchange = (e) => { homeMonth = e.target.value; renderHome(); };

// Resum: tria un mes i veu els totals per grup (categoria); coherent amb l'informe PDF (les compres de targeta sense liquidar no compten).
let sumMonth = "";
function renderSummary() {
  show("summary");
  const items = allItems();
  const months = [...new Set(items.map((r) => r.date.slice(0, 7)))].sort().reverse();
  const sel = $("smonth");
  if (!months.includes(sumMonth)) sumMonth = months[0] || "";
  sel.replaceChildren(...months.map((m) => new Option(monthLabel(m), m)));
  sel.value = sumMonth;
  const inMonth = items.filter((r) => r.date.startsWith(sumMonth));
  const groups = new Map();
  inMonth.filter((r) => !r.pending).forEach((r) => r.parts.forEach((p) => groups.set(p.category, (groups.get(p.category) || 0) + Number(p.amount))));
  const total = [...groups.values()].reduce((a, b) => a + b, 0);
  const pend = inMonth.filter((r) => r.pending).reduce((s, r) => s + Number(r.amount), 0);
  $("stotal").textContent = eur(total);
  $("spend").textContent = pend ? `Pendent de liquidar (no suma): ${eur(pend)}` : "";
  const ul = $("groups"); ul.replaceChildren();
  const top = Math.max(...groups.values(), 1);
  [...groups.entries()].filter(([, v]) => Math.abs(v) >= 0.005).sort((a, b) => b[1] - a[1]).forEach(([c, v]) => {
    const li = el("li", "g"); li.tabIndex = 0;
    const bar = el("span", "bar"); bar.style.width = `${Math.max(2, (Math.max(v, 0) / top) * 100)}%`;
    li.append(el("span", "n", catName(c)), el("span", "a", eur(v)), el("span", "p", total > 0 ? `${((v / total) * 100).toFixed(0)} %` : ""), bar);
    li.onclick = () => { stack.push(renderSummary); renderGroup(c); };
    ul.append(li);
  });
  if (!groups.size) ul.append(el("li", "muted", "Sense despeses aquest mes."));
}
const MON3 = ['gen','feb','mar','abr','mai','jun','jul','ago','set','oct','nov','des'];
const monthLabel = (m) => new Date(`${m}-01T00:00:00`).toLocaleDateString("ca-ES", { month: "long", year: "numeric" });

// Grup: subgrups amb subtotal i les partides; cada compra amb tiquet obre la compra sencera classificada.
function renderGroup(cat) {
  show("group");
  $("gtitle").textContent = catName(cat);
  const subs = new Map();
  allItems().filter((r) => !r.pending && r.date.startsWith(sumMonth)).forEach((r) => r.parts.forEach((p) => {
    if (p.category !== cat) return;
    const k = p.subcategory || "(sense subcategoria)";
    if (!subs.has(k)) subs.set(k, []);
    subs.get(k).push({ r, v: Number(p.amount) });
  }));
  const body = $("gbody"); body.replaceChildren();
  $("gsum").textContent = `${monthLabel(sumMonth)} · ${eur([...subs.values()].flat().reduce((s, x) => s + x.v, 0))}`;
  [...subs.entries()].sort((a, b) => b[1].reduce((s, x) => s + x.v, 0) - a[1].reduce((s, x) => s + x.v, 0)).forEach(([k, rows]) => {
    const h = el("div", "sub"); h.append(el("span", "", k), el("span", "a", eur(rows.reduce((s, x) => s + x.v, 0))));
    const ul = el("ul"); body.append(h, ul);
    rows.sort((a, b) => b.r.date.localeCompare(a.r.date)).forEach(({ r, v }) => {
      const li = el("li"); li.tabIndex = 0;
      li.append(el("span", "d", r.date.slice(5).split("-").reverse().join("/")), el("span", "n", r.merchant || r.description), el("span", "a", eur(v)));
      const extra = [];
      if (r.lines.length) extra.push("🧾 compra amb tiquet");
      if (Math.abs(Number(r.amount) - v) > 0.005) extra.push(`part de ${eur(r.amount)}`);
      if (extra.length) li.append(el("span", "c", extra.join(" · ")));
      li.onclick = () => { stack.push(() => renderGroup(cat)); renderDetail(r); };
      ul.append(li);
    });
  });
}

// Detall pla (opció): totes les despeses amb cerca i filtres.
function renderList() {
  show("list");
  const items = allItems();
  const months = [...new Set(items.map((r) => r.date.slice(0, 7)))].sort().reverse();
  const mSel = $("month"), cSel = $("cat");
  const keepM = mSel.value, keepC = cSel.value;
  mSel.replaceChildren(new Option("Tots els mesos", ""), ...months.map((m) => new Option(m, m)));
  cSel.replaceChildren(new Option("Totes les categories", ""), ...[...new Set(items.map((r) => catName(r.category)))].sort().map((c) => new Option(c, c)));
  mSel.value = keepM; cSel.value = keepC;
  const q = $("q").value.trim().toLowerCase();
  const rows = items.filter((r) => (!mSel.value || r.date.startsWith(mSel.value)) && (!cSel.value || catName(r.category) === cSel.value)
    && (!q || `${r.description} ${r.merchant} ${r.category} ${r.subcategory}`.toLowerCase().includes(q))).sort((a, b) => b.date.localeCompare(a.date));
  $("total").textContent = `${rows.length} despeses · ${eur(rows.reduce((s, r) => s + Number(r.amount), 0))}`;
  const ul = $("rows"); ul.replaceChildren();
  rows.slice(0, 300).forEach((r) => {
    const li = el("li"); li.tabIndex = 0;
    li.append(el("span", "d", r.date.slice(5).split("-").reverse().join("/")), el("span", "n", r.merchant || r.description), el("span", "a", eur(r.amount)), el("span", "c", pathName(r)));
    if (r.lines.length) li.append(el("span", "t", `🧾 ${r.lines.length}`));
    li.onclick = () => { stack.push(renderList); renderDetail(r); };
    ul.append(li);
  });
  $("seqinfo").textContent = session.state ? `Paquet ${session.state.seq}` : "Cap paquet carregat";
}

// Compra: comerç, data, import i, si hi ha tiquet, la compra sencera amb la categoria de cada línia.
function renderDetail(r) {
  show("detail");
  const d = $("detailbody"); d.replaceChildren();
  const kv = (k, v) => { if (v) { const row = el("div", "kv"); row.append(el("span", "k", k), el("span", "v", v)); d.append(row); } };
  d.append(el("h2", "", r.merchant || r.description));
  kv("Data de compra", new Date(`${r.date}T00:00:00`).toLocaleDateString("ca-ES", { day: "numeric", month: "long", year: "numeric" }));
  kv("Import", eur(r.amount)); kv("Descripció del banc", r.description); kv("Origen", r.origin);
  if (r.pending) kv("Estat", "Targeta pendent de liquidar (no suma als totals)");
  if (r.lines.length) {
    d.append(el("h3", "", "Repartiment per categoria"));
    r.parts.forEach((p) => { const row = el("div", "line"); row.append(el("span", "", [catName(p.category), p.subcategory].filter(Boolean).join(" › ")), el("span", "a", eur(p.amount))); d.append(row); });
    d.append(el("h3", "", "Compra sencera"));
    r.lines.forEach((l) => {
      const row = el("div", "line"); const left = el("span", "");
      left.append(el("span", "", `${l.quantity && l.quantity !== "1" ? l.quantity + " × " : ""}${l.description}`), el("span", l.classified ? "tag" : "tag no", l.classified ? l.category : "no classificat"));
      const eb = el("button", "ghost mini", "✎"); eb.setAttribute("aria-label", "Canvia la categoria"); if (l.changed) left.append(el("span", "tag ch", "canvi pendent"));
      eb.onclick = () => { row.parentElement.querySelector(".ed")?.remove(); row.after(pathPicker(l.category, "Recorda-ho per a aquest producte", async (path, remember) => { await addChange({ op: "recat_line", tx_id: r.id, description: l.description, amount: l.amount, category: path, remember }); renderDetail(withChanges(norm(session.state.items[r.id]), session.state.changes)); })); };
      row.append(left, el("span", "a", eur(l.amount)), eb); d.append(row);
    });
    r.discounts.forEach((x) => { const row = el("div", "line"); row.append(el("span", "", `Descompte ${x.type}${x.description ? " · " + x.description : ""}`), el("span", "a", eur(x.amount))); d.append(row); });
  } else {
    kv("Categoria", pathName(r) + (r.changed ? " (canvi pendent)" : ""));
    d.append(el("p", "muted", "Sense tiquet: la categoria és la del comerç."));
    if (!r.id.startsWith("resid-")) {
      const eb = el("button", "ghost", "Canvia la categoria");
      eb.onclick = () => { d.querySelector(".ed")?.remove(); d.append(pathPicker([r.category, r.subcategory].filter(Boolean).join(" / "), "Recorda-ho per a aquest comerç", async (path, remember) => { const [category, ...rest] = path.split(" / "); await addChange({ op: "recat_tx", tx_id: r.id, category, subcategory: rest.join(" / "), remember }); renderDetail(withChanges(norm(session.state.items[r.id]), session.state.changes)); })); };
      d.append(eb);
    }
  }
}

// ---------- accions ----------
async function importPackage(bytes) {
  const env = parseEnvelope(bytes);
  if (!env) throw new Error("No és un paquet de l'app");
  const { plain } = await openEnvelope(env, "bundle", session.keyId, session.key);
  const keep = (session.state?.changes || []).filter((c) => !c.sent);          // els enviats ja són al paquet nou; els no enviats es conserven
  session.state = applyBundle(session.state, decodeBody(plain));
  session.state.changes = keep;
  await saveState();
  msg(`Paquet ${session.state.seq} carregat: ${Object.keys(session.state.items).length} despeses.`);
  openTab(tab);
}
async function doUpload(file) {
  if (!file) return;
  const blob = await sealUpload(file, session.keyId, session.key);
  const f = new File([blob], `${(file.name || "foto").replace(/\.[^.]+$/, "")}.efam`, { type: "application/octet-stream" });
  if (navigator.canShare?.({ files: [f] })) await navigator.share({ files: [f], title: "Fitxer xifrat" });
  else { const a = el("a", "", "Baixa el fitxer xifrat"); a.href = URL.createObjectURL(blob); a.download = f.name; $("uploadres").replaceChildren(a); }
  msg("Fitxer xifrat. Comparteix-lo.");
}

const run = (fn) => async (...a) => { try { await fn(...a); } catch (e) { if (e.name !== "NotAllowedError") msg(e.message, true); } };
$("savekey").onclick = run(async () => { await enroll($("keytext").value); $("keytext").value = ""; msg("Clau protegida amb la biometria."); await unlock(); render(); });
$("scan").onclick = run(async () => {
  if (!("BarcodeDetector" in window)) throw new Error("Aquest navegador no escaneja QR: escriu el text de la clau");
  const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  const v = $("video"); v.srcObject = s; v.hidden = false; await v.play();
  const det = new BarcodeDetector({ formats: ["qr_code"] });
  for (let i = 0; i < 300; i++) { const c = await det.detect(v); if (c[0]) { $("keytext").value = c[0].rawValue; break; } await new Promise((r) => setTimeout(r, 200)); }
  s.getTracks().forEach((t) => t.stop()); v.hidden = true;
});
async function takePending() {
  if (!window.__pending) return;
  const p = window.__pending; window.__pending = null;
  await importPackage(p);
}
$("unlock").onclick = run(async () => { await unlock(); await takePending(); render(); });
$("lock").onclick = lock;
$("filepkg").onchange = run(async (e) => { const f = e.target.files[0]; if (f) await importPackage(new Uint8Array(await f.arrayBuffer())); e.target.value = ""; });
["q", "month", "cat"].forEach((id) => $(id).addEventListener("input", () => session && renderList()));
const back = () => (stack.length ? stack.pop()() : openTab(tab));
$("back").onclick = back; $("gback").onclick = back; $("upback").onclick = () => openTab("home");
$("smonth").onchange = (e) => { sumMonth = e.target.value; renderSummary(); };
$("nav").querySelectorAll("button").forEach((b) => (b.onclick = () => session && openTab(b.dataset.tab)));
$("toupload").onclick = () => openTab("upload");
$("pickfile").onchange = run(async (e) => { await doUpload(e.target.files[0]); e.target.value = ""; });
$("takephoto").onchange = run(async (e) => { await doUpload(e.target.files[0]); e.target.value = ""; });
$("forget").onclick = run(async () => { if (confirm("S'esborraran la clau i les dades d'aquest dispositiu. Continuar?")) { await kvDel("meta"); await kvDel("state"); session = null; render(); } });

if ("serviceWorker" in navigator) {
  const had = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener("controllerchange", () => { if (had && !session) location.reload(); });   // versió nova: es recarrega sola si està bloquejada
  navigator.serviceWorker.register("sw.js").catch(() => {});
}   // sense SW l'app funciona igual (només perd el mode offline del codi)
(async () => {
  await render();
  if (new URLSearchParams(location.search).get("shared")) {
    const r = await (await caches.open("efam-inbox")).match("pending");
    if (r) { msg("Paquet rebut: desbloqueja per obrir-lo."); window.__pending = new Uint8Array(await r.arrayBuffer()); await (await caches.open("efam-inbox")).delete("pending"); }
  }
})();
