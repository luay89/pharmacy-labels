const CACHE_NAME = 'product-labels-v2';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './web-icon-192.svg',
  './web-icon-512.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key.startsWith('product-labels-') && key !== CACHE_NAME)
        .map((key) => caches.delete(key)))
    )
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const requestUrl = new URL(event.request.url);
  if (requestUrl.pathname.includes('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((resp) => {
      if (resp.ok) {
        const cloned = resp.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, cloned));
      }
      return resp;
    }).catch(() => caches.match('./index.html')))
  );
});
