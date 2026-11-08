// Service worker: tot offline (només codi, mai dades) i rep el paquet compartit (Web Share Target).
const CACHE = "efam-v1.3.2", FILES = ["./", "index.html", "app.js", "efam.js", "manifest.webmanifest", "icon.svg", "icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png"];
self.addEventListener("install", (e) => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES))); });
self.addEventListener("activate", (e) => e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE && k !== "efam-inbox").map((k) => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method === "POST" && u.pathname.endsWith("/share")) {
    e.respondWith((async () => {
      const f = (await e.request.formData()).get("pkg");
      const c = await caches.open("efam-inbox");
      if (f) await c.put("pending", new Response(f));
      return Response.redirect("./?shared=1", 303);
    })());
    return;
  }
  // Primer la xarxa (així les versions noves arriben sempre que hi hagi connexió); sense connexió, la còpia local.
  e.respondWith(fetch(e.request).then((resp) => { if (resp.ok && e.request.method === "GET") { const copy = resp.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); } return resp; }).catch(() => caches.match(e.request)));
});
