/* Sabro Vision - Service Worker for Smart TV & Mobile PWA */
const CACHE_NAME = 'sabro-vision-v1';
const STATIC_ASSETS = [
  '/',
  '/static/manifest.json',
  '/static/icons/icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Network-only for live streaming feeds, API calls, and Admin routes
  if (
    url.pathname.startsWith('/live/') ||
    url.pathname.startsWith('/stream/') ||
    url.pathname.startsWith('/proxy') ||
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/admin') ||
    url.pathname.startsWith('/player_api.php') ||
    url.pathname.startsWith('/get.php') ||
    event.request.method !== 'GET'
  ) {
    return;
  }

  // Stale-While-Revalidate for static assets and shell
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      const fetchPromise = fetch(event.request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        })
        .catch(() => cachedResponse);

      return cachedResponse || fetchPromise;
    })
  );
});
