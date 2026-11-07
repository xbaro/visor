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

// ---------- vistes ----------
const views = ["setup", "locked", "summary", "group", "list", "detail", "upload"];
let tab = "summary", stack = [];
const show = (v) => { views.forEach((x) => $(x).hidden = x !== v); $("nav").hidden = !session; $("nav").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab)); };
function msg(t, err) { const m = $("msg"); m.textContent = t || ""; m.className = err ? "err" : "ok"; }
// Paquets antics (sense `parts`/`pending`): es tracten com una sola partida a la seva categoria.
const norm = (r) => (r.parts ? r : { ...r, pending: !!r.pending, parts: [{ category: r.category, subcategory: r.subcategory, amount: r.amount }] });
const allItems = () => Object.values(session.state?.items || {}).map(norm);
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
function openTab(t) { tab = t; stack = []; if (t === "summary") renderSummary(); else if (t === "list") renderList(); else show("upload"); }

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
      row.append(left, el("span", "a", eur(l.amount))); d.append(row);
    });
    r.discounts.forEach((x) => { const row = el("div", "line"); row.append(el("span", "", `Descompte ${x.type}${x.description ? " · " + x.description : ""}`), el("span", "a", eur(x.amount))); d.append(row); });
  } else {
    kv("Categoria", pathName(r));
    d.append(el("p", "muted", "Sense tiquet: la categoria és la del comerç."));
  }
}

// ---------- accions ----------
async function importPackage(bytes) {
  const env = parseEnvelope(bytes);
  if (!env) throw new Error("No és un paquet de l'app");
  const { plain } = await openEnvelope(env, "bundle", session.keyId, session.key);
  session.state = applyBundle(session.state, decodeBody(plain));
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
$("back").onclick = back; $("gback").onclick = back; $("upback").onclick = () => openTab("summary");
$("smonth").onchange = (e) => { sumMonth = e.target.value; renderSummary(); };
$("nav").querySelectorAll("button").forEach((b) => (b.onclick = () => session && openTab(b.dataset.tab)));
$("toupload").onclick = () => openTab("upload");
$("pickfile").onchange = run(async (e) => { await doUpload(e.target.files[0]); e.target.value = ""; });
$("takephoto").onchange = run(async (e) => { await doUpload(e.target.files[0]); e.target.value = ""; });
$("forget").onclick = run(async () => { if (confirm("S'esborraran la clau i les dades d'aquest dispositiu. Continuar?")) { await kvDel("meta"); await kvDel("state"); session = null; render(); } });

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});   // sense SW l'app funciona igual (només perd el mode offline del codi)
(async () => {
  await render();
  if (new URLSearchParams(location.search).get("shared")) {
    const r = await (await caches.open("efam-inbox")).match("pending");
    if (r) { msg("Paquet rebut: desbloqueja per obrir-lo."); window.__pending = new Uint8Array(await r.arrayBuffer()); await (await caches.open("efam-inbox")).delete("pending"); }
  }
})();
