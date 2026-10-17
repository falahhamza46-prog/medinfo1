const CACHE = 'medinfo-v2';
const FILES = 'medinfo-files'; // نفس اسم الذاكرة الذي تستخدمه الصفحة
const FONTS = 'medinfo-fonts-v1';
const SHELL = ['/', '/icon.svg', '/icon-192.png', '/icon-512.png', '/manifest.json'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((k) => Promise.all(k.filter((x) => ![CACHE, FILES, FONTS].includes(x)).map((x) => caches.delete(x))))
      .then(() => self.clients.claim())
  );
});

const timeout = (ms) => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms));

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);

  // الخطوط: من الذاكرة أولاً وتتحدث في الخلفية
  if (u.hostname === 'fonts.googleapis.com' || u.hostname === 'fonts.gstatic.com') {
    e.respondWith(caches.open(FONTS).then(async (c) => {
      const hit = await c.match(req);
      const net = fetch(req).then((r) => { c.put(req, r.clone()).catch(() => {}); return r; }).catch(() => hit);
      return hit || net;
    }));
    return;
  }
  if (u.origin !== location.origin) return;

  // ملفات المواد والصور: النسخة المحفوظة على الجهاز أولاً
  if (u.pathname.startsWith('/api/files/')) {
    e.respondWith((async () => {
      const c = await caches.open(FILES);
      const hit = await c.match(req, { ignoreSearch: true });
      if (hit) return hit;
      const r = await fetch(req);
      // الصور (صور الواجبات وصور المواد) تُحفظ تلقائياً، أما بقية الملفات فبطلب المستخدم فقط
      if (r.ok && (r.headers.get('content-type') || '').startsWith('image/')) {
        c.put(u.origin + u.pathname, r.clone()).catch(() => {});
      }
      return r;
    })());
    return;
  }
  if (u.pathname.startsWith('/api/')) return;

  // الصفحة نفسها: الشبكة أولاً بمهلة قصيرة، ثم النسخة المخزنة
  e.respondWith(
    Promise.race([fetch(req), timeout(6000)])
      .then((r) => {
        const copy = r.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        return r;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }).then((m) => m || caches.match('/')))
  );
});

self.addEventListener('push', (e) => {
  let d = { title: 'تحديث جديد', body: '', tab: '', course: '' };
  try { d = Object.assign(d, e.data.json()); } catch (_) {}
  e.waitUntil((async () => {
    const list = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    list.forEach((c) => c.postMessage({ type: 'push' }));
    // الصفحة مفتوحة وظاهرة: الصفحة نفسها تعرض الإشعار وتشغّل المنبه
    if (list.some((c) => c.visibilityState === 'visible')) return;
    try { if (self.navigator.setAppBadge) await self.navigator.setAppBadge(1); } catch (_) {}
    await self.registration.showNotification(d.title, {
      body: d.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      dir: 'rtl',
      lang: 'ar',
      vibrate: [250, 120, 250, 120, 400],
      tag: 'medinfo-update',
      renotify: true,
      requireInteraction: false,
      data: { tab: d.tab, course: d.course },
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const d = e.notification.data || {};
  e.waitUntil((async () => {
    try { if (self.navigator.clearAppBadge) await self.navigator.clearAppBadge(); } catch (_) {}
    const list = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if ('focus' in c) { c.postMessage({ type: 'goto', tab: d.tab, course: d.course }); return c.focus(); }
    }
    return clients.openWindow('/?go=' + encodeURIComponent((d.course || '') + '.' + (d.tab || '')));
  })());
});
