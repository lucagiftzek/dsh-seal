export {};
// sw.js in passthrough mode: retires an installed sealing worker. It has no
// fetch handler, so every request goes to the network unchanged.
declare const self: any;
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e: any) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith("dsh-seal-")) await caches.delete(k);
    await self.registration.unregister();
  })());
});
