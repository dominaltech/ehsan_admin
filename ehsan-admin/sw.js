// ─────────────────────────────────────────────────────────
//  Ehsan Admin — Service Worker  (sw.js)
//  • Offline cache for the admin shell
//  • Handles push notifications from the Netlify edge function
// ─────────────────────────────────────────────────────────
const CACHE = 'ehsan-admin-v1';
const SHELL = ['/ehan_admin.html', '/manifest.json'];

// Install — pre-cache the app shell
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

// Activate — remove old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first, fall back to cache (skip Supabase API calls)
self.addEventListener('fetch', e => {
  if (e.request.url.includes('supabase.co') || e.request.url.includes('googleapis.com')) return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});

// ── Push received from Netlify edge function ──
self.addEventListener('push', e => {
  let data = { title: 'Ehsan Admin', body: 'You have a new notification.' };
  try { if (e.data) data = e.data.json(); } catch { data.body = e.data?.text() || data.body; }

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body:               data.body,
      icon:               '/icon-192.png',
      badge:              '/icon-192.png',
      tag:                'ehsan-order',
      data:               { url: data.url || '/ehan_admin.html' },
      vibrate:            [200, 100, 200, 100, 200],
      requireInteraction: true,          // stays on screen until tapped
      renotify:           true
    })
  );
});

// ── Tap notification → open / focus admin panel ──
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const target = e.notification.data?.url || '/ehan_admin.html';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('ehan_admin') && 'focus' in c) return c.focus();
      }
      return clients.openWindow(target);
    })
  );
});
