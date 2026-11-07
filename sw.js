// Service worker: tot offline (només codi, mai dades) i rep el paquet compartit (Web Share Target).
const CACHE = "efam-v1", FILES = ["./", "index.html", "app.js", "efam.js", "manifest.webmanifest", "icon.svg"];
self.addEventListener("install", (e) => e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES))));
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
  e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
});
