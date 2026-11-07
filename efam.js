// Lògica pura de l'app: sobres AES-256-GCM (format efam1). Sense DOM: es pot provar amb Node.
export const VERSION = "1.1.0";
const enc = new TextEncoder(), dec = new TextDecoder();
export const b64 = (buf) => { let s = ""; new Uint8Array(buf).forEach((c) => (s += String.fromCharCode(c))); return btoa(s); };
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const unb64url = (s) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
const aad = (kind, keyId, seq) => enc.encode(`efam1|${kind}|${keyId}|${seq}`);

/** «efam1:key:<key_id>:<clau base64url>» (el que mostra el QR) -> {keyId, raw: Uint8Array(32)} */
export function parseKeyPayload(text) {
  const m = /^efam1:key:(k-[0-9a-f]+):([A-Za-z0-9_-]+)$/.exec(text.trim());
  if (!m) throw new Error("Clau no vàlida");
  const raw = unb64url(m[2]);
  if (raw.length !== 32) throw new Error("La clau ha de ser de 256 bits");
  return { keyId: m[1], raw };
}
export const importKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

export function parseEnvelope(bytes) {
  try { const e = JSON.parse(dec.decode(bytes)); return e && e.format === "efam1" ? e : null; } catch { return null; }
}

/** Desxifra un sobre `kind` amb la clau de l'usuari; falla si el key_id no és el nostre o s'ha alterat. */
export async function openEnvelope(env, kind, keyId, key) {
  if (env.kind !== kind) throw new Error("Tipus de paquet inesperat");
  if (env.key_id !== keyId) throw new Error("Aquest paquet és d'un altre usuari");
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(env.nonce), additionalData: aad(kind, env.key_id, env.seq) }, key, unb64(env.ct));
    return { seq: env.seq, plain: new Uint8Array(pt) };
  } catch { throw new Error("No s'ha pogut obrir (alterat o clau que no correspon)"); }
}

/** Xifra un fitxer per pujar-lo: sobre `upload` amb nom, tipus i dades (qui el rep valida el remitent). */
export async function sealUpload(file, keyId, key) {
  const data = new Uint8Array(await file.arrayBuffer());
  const inner = enc.encode(JSON.stringify({ name: file.name || "foto.jpg", mime: file.type || "", data: b64(data) }));
  const seq = Math.floor(Date.now() / 1000), nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad("upload", keyId, seq) }, key, inner);
  return new Blob([JSON.stringify({ format: "efam1", kind: "upload", key_id: keyId, seq, nonce: b64(nonce), ct: b64(ct) })], { type: "application/octet-stream" });
}

/** Aplica un paquet de dades a l'estat local {seq, items:{id: despesa}}. `full` (reset) substitueix; `delta` exigeix base_seq coincident. */
export function applyBundle(state, body) {
  if (body.kind === "full" || body.reset) return { seq: body.seq, items: Object.fromEntries(body.upsert.map((r) => [r.id, r])) };
  if (!state || body.base_seq !== state.seq) throw new Error("Falta un paquet anterior: cal un paquet complet");
  const items = { ...state.items };
  body.upsert.forEach((r) => (items[r.id] = r));
  body.delete.forEach((id) => delete items[id]);
  return { seq: body.seq, items };
}
export const decodeBody = (plain) => JSON.parse(dec.decode(plain));
