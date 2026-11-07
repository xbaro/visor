// App de consulta de despeses. La clau de l'usuari només es guarda embolcallada amb un secret que
// dóna l'autenticador del mòbil (passkey amb extensió PRF) després de la biometria; mai en clar. Si el dispositiu
// no ho suporta, l'app no desa la clau (fail closed).
import { parseKeyPayload, importKey, parseEnvelope, openEnvelope, sealUpload, applyBundle, decodeBody } from "./efam.js";

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
const views = ["setup", "locked", "list", "detail", "upload"];
const show = (v) => views.forEach((x) => $(x).hidden = x !== v);
function msg(t, err) { const m = $("msg"); m.textContent = t || ""; m.className = err ? "err" : "ok"; }

async function render() {
  msg("");
  if (!(await kvGet("meta"))) return show("setup");
  if (!session) return show("locked");
  renderList();
}

function renderList() {
  show("list");
  const items = Object.values(session.state?.items || {});
  const months = [...new Set(items.map((r) => r.date.slice(0, 7)))].sort().reverse();
  const mSel = $("month"), cSel = $("cat");
  const keepM = mSel.value, keepC = cSel.value;
  mSel.replaceChildren(new Option("Tots els mesos", ""), ...months.map((m) => new Option(m, m)));
  cSel.replaceChildren(new Option("Totes les categories", ""), ...[...new Set(items.map((r) => r.category || "Sense classificar"))].sort().map((c) => new Option(c, c)));
  mSel.value = keepM; cSel.value = keepC;
  const q = $("q").value.trim().toLowerCase();
  const rows = items.filter((r) => (!mSel.value || r.date.startsWith(mSel.value)) && (!cSel.value || (r.category || "Sense classificar") === cSel.value)
    && (!q || `${r.description} ${r.merchant} ${r.category} ${r.subcategory}`.toLowerCase().includes(q))).sort((a, b) => b.date.localeCompare(a.date));
  $("total").textContent = `${rows.length} despeses · ${eur(rows.reduce((s, r) => s + Number(r.amount), 0))}`;
  const ul = $("rows"); ul.replaceChildren();
  rows.slice(0, 300).forEach((r) => {
    const li = el("li"); li.tabIndex = 0;
    li.append(el("span", "d", r.date.slice(5).split("-").reverse().join("/")), el("span", "n", r.merchant || r.description), el("span", "a", eur(r.amount)),
      el("span", "c", [r.category || "Sense classificar", r.subcategory].filter(Boolean).join(" › ")));
    if (r.lines.length) li.append(el("span", "t", `🧾 ${r.lines.length}`));
    li.onclick = () => renderDetail(r);
    ul.append(li);
  });
  $("seqinfo").textContent = session.state ? `Paquet ${session.state.seq}` : "Cap paquet carregat";
}

function renderDetail(r) {
  show("detail");
  const d = $("detailbody"); d.replaceChildren();
  const kv = (k, v) => { if (v) { const row = el("div", "kv"); row.append(el("span", "k", k), el("span", "v", v)); d.append(row); } };
  d.append(el("h2", "", r.merchant || r.description));
  kv("Data", r.date); kv("Import", eur(r.amount)); kv("Descripció", r.description);
  kv("Categoria", [r.category || "Sense classificar", r.subcategory].filter(Boolean).join(" › ")); kv("Origen", r.origin);
  if (r.lines.length) {
    d.append(el("h3", "", "Detall del tiquet"));
    r.lines.forEach((l) => { const row = el("div", "line"); row.append(el("span", "", `${l.quantity && l.quantity !== "1" ? l.quantity + " × " : ""}${l.description}`), el("span", "a", eur(l.amount))); d.append(row); });
    r.discounts.forEach((x) => { const row = el("div", "line"); row.append(el("span", "", `Descompte ${x.type}${x.description ? " · " + x.description : ""}`), el("span", "a", eur(x.amount))); d.append(row); });
  } else d.append(el("p", "muted", "Sense tiquet: la categoria és la del comerç."));
}

// ---------- accions ----------
async function importPackage(bytes) {
  const env = parseEnvelope(bytes);
  if (!env) throw new Error("No és un paquet de l'app");
  const { plain } = await openEnvelope(env, "bundle", session.keyId, session.key);
  session.state = applyBundle(session.state, decodeBody(plain));
  await saveState();
  msg(`Paquet ${session.state.seq} carregat: ${Object.keys(session.state.items).length} despeses.`);
  renderList();
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
$("back").onclick = () => renderList();
$("toupload").onclick = () => show("upload");
$("upback").onclick = () => renderList();
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
