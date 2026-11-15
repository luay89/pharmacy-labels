// Bump the version whenever a cached file changes: files other than the page are served cache-first.
const CACHE_NAME = 'product-labels-v11';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './web-icon-192.svg',
  './web-icon-512.svg',
  './device-key.js',
  './license-client.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key.startsWith('product-labels-') && key !== CACHE_NAME)
        .map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const requestUrl = new URL(event.request.url);
  if (requestUrl.pathname.includes('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }
  // The page itself goes network-first so a new release shows on the next load; the cache is the offline fallback.
  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).then((resp) => {
      if (resp.ok) {
        const cloned = resp.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put('./index.html', cloned));
      }
      return resp;
    }).catch(() => caches.match('./index.html')));
    return;
  }
  // Only navigations fall back to the cached page. A script, icon or manifest that is neither cached nor
  // reachable fails as a network error: answering it with index.html would run HTML as JavaScript.
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((resp) => {
      if (resp.ok) {
        const cloned = resp.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cloned));
      }
      return resp;
    }).catch(() => Response.error()))
  );
});
