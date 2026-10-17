// واجهة برمجية واحدة لكل الموقع. التخزين: Netlify Blobs (قاعدة بيانات مدمجة بلا إعداد).
import { getStore } from '@netlify/blobs';
import webpush from 'web-push';
import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

export const config = { path: '/api/*' };

const store = (n) => getStore({ name: n, consistency: 'strong' });
const json = (o, status = 200) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const fail = (m, s = 400) => json({ error: m }, s);
const b64u = (b) => Buffer.from(b).toString('base64url');

/* ---------- المفاتيح والمصادقة ---------- */
async function getSecret() {
  const m = store('meta');
  let s = await m.get('secret');
  if (!s) { s = randomBytes(32).toString('hex'); await m.set('secret', s); }
  return s;
}
async function getVapid() {
  const m = store('meta');
  let v = await m.get('vapid', { type: 'json' });
  if (!v) { v = webpush.generateVAPIDKeys(); await m.setJSON('vapid', v); }
  return v;
}
const hashPw = (pw, salt) => scryptSync(String(pw), salt, 32).toString('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };

async function checkPassword(pw) {
  const auth = await store('meta').get('auth', { type: 'json' });
  if (!auth) {
    const def = process.env.ADMIN_PASSWORD || '1234';
    return { ok: same(String(pw), def), isDefault: true };
  }
  return { ok: same(hashPw(pw, auth.salt), auth.hash), isDefault: false };
}
async function makeToken() {
  const exp = Date.now() + 12 * 3600 * 1000;
  const body = b64u(JSON.stringify({ exp }));
  const sig = createHmac('sha256', await getSecret()).update(body).digest('base64url');
  return { token: body + '.' + sig, exp };
}
async function isAdmin(req) {
  const h = req.headers.get('authorization') || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [body, sig] = t.split('.');
  if (!body || !sig) return false;
  const good = createHmac('sha256', await getSecret()).update(body).digest('base64url');
  if (!same(sig, good)) return false;
  try { return JSON.parse(Buffer.from(body, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}

/* ---------- الإشعارات ---------- */
async function sendPush(title, body, extra = {}) {
  if (!title) return;
  const v = await getVapid();
  webpush.setVapidDetails('mailto:' + (process.env.CONTACT_EMAIL || 'admin@example.com'), v.publicKey, v.privateKey);
  const P = store('push');
  const { blobs } = await P.list();
  const tab = ['schedule', 'subjects', 'hw', 'notices'].includes(extra.tab) ? extra.tab : '';
  const course = ['c1', 'c2'].includes(extra.course) ? extra.course : '';
  const payload = JSON.stringify({ title, body: body || '', tab, course });
  await Promise.allSettled(
    blobs.map(async (b) => {
      const sub = await P.get(b.key, { type: 'json' });
      if (!sub) return;
      try { await webpush.sendNotification(sub, payload, { TTL: 86400 }); }
      catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await P.delete(b.key); }
    })
  );
}

const bump = async () => { const v = String(Date.now()); await store('data').set('ver', v); return v; };
const fileIndex = async () => (await store('data').get('files', { type: 'json' })) || [];
const ID = /^[a-f0-9-]{36}$/;

/* ---------- المسارات ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const method = req.method;
  try {
    // قراءة عامة
    if (path === '/state' && method === 'GET') {
      const D = store('data');
      const vapid = (await getVapid()).publicKey;
      const ver = (await D.get('ver')) || '0';
      if (url.searchParams.get('ver') === ver) return json({ unchanged: true, vapid });
      const state = await D.get('state', { type: 'json' });
      return json({ state, files: await fileIndex(), ver, vapid });
    }

    if (path === '/login' && method === 'POST') {
      const { pw } = await req.json();
      const r = await checkPassword(pw || '');
      if (!r.ok) { await new Promise((res) => setTimeout(res, 700)); return fail('كلمة المرور غير صحيحة', 403); }
      return json({ ...(await makeToken()), defaultPw: r.isDefault });
    }

    if (path === '/push' && method === 'POST') {
      const sub = await req.json();
      if (!sub || !sub.endpoint || !sub.keys) return fail('اشتراك غير صالح');
      const key = createHash('sha256').update(sub.endpoint).digest('hex');
      await store('push').setJSON(key, sub);
      return json({ ok: true });
    }
    if (path === '/push' && method === 'DELETE') {
      const { endpoint } = await req.json();
      if (endpoint) await store('push').delete(createHash('sha256').update(endpoint).digest('hex'));
      return json({ ok: true });
    }

    if (path.startsWith('/files/') && method === 'GET') {
      const id = path.slice(7);
      if (!ID.test(id)) return fail('غير موجود', 404);
      const r = await store('files').getWithMetadata(id, { type: 'arrayBuffer' });
      if (!r) return fail('غير موجود', 404);
      const name = (r.metadata && r.metadata.name) || 'file';
      const mime = (r.metadata && r.metadata.mime) || 'application/octet-stream';
      const inlineOk = /^image\/(png|jpe?g|gif|webp)$/.test(mime) || mime === 'application/pdf';
      const dl = url.searchParams.get('dl') === '1' || !inlineOk;
      return new Response(r.data, {
        headers: {
          'content-type': inlineOk ? mime : 'application/octet-stream',
          'content-disposition': (dl ? 'attachment' : 'inline') + "; filename*=UTF-8''" + encodeURIComponent(name),
          'cache-control': 'public, max-age=3600',
          'x-content-type-options': 'nosniff',
        },
      });
    }

    // كل ما بعد هذا يحتاج أدمن
    if (!(await isAdmin(req))) return fail('يلزم تسجيل الدخول كأدمن', 401);

    if (path === '/state' && method === 'PUT') {
      const { state, notify } = await req.json();
      if (!state || typeof state !== 'object') return fail('بيانات غير صالحة');
      delete state.pw;
      const raw = JSON.stringify(state);
      if (raw.length > 1_500_000) return fail('حجم البيانات كبير جداً');
      await store('data').set('state', raw);
      const ver = await bump();
      if (notify && notify.title) await sendPush(String(notify.title).slice(0, 80), String(notify.body || '').slice(0, 140), notify);
      return json({ ver });
    }

    if (path === '/password' && method === 'POST') {
      const { old, pw } = await req.json();
      if (!(await checkPassword(old || '')).ok) return fail('كلمة المرور الحالية غير صحيحة', 403);
      if (!pw || String(pw).length < 4) return fail('كلمة المرور قصيرة جداً');
      const salt = randomBytes(16).toString('hex');
      await store('meta').setJSON('auth', { salt, hash: hashPw(pw, salt) });
      return json({ ok: true });
    }

    if (path === '/files' && method === 'POST') {
      let meta;
      try { meta = JSON.parse(decodeURIComponent(req.headers.get('x-meta') || '')); } catch { return fail('بيانات الملف ناقصة'); }
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) return fail('الملف فارغ');
      if (buf.byteLength > 5.5 * 1024 * 1024) return fail('الحد الأقصى للملف 5 م.ب');
      const id = randomUUID();
      const name = String(meta.name || 'file').slice(0, 200);
      const mime = String(meta.mime || 'application/octet-stream').slice(0, 100);
      await store('files').set(id, buf, { metadata: { name, mime } });
      if (!meta.sub) return json({ id, url: '/api/files/' + id });
      const file = { id, name, mime, size: buf.byteLength, course: meta.course, sub: meta.sub, at: Date.now() };
      const idx = await fileIndex();
      idx.push(file);
      await store('data').setJSON('files', idx);
      const ver = await bump();
      await sendPush('ملف جديد', name, { tab: 'subjects', course: meta.course });
      return json({ file, ver });
    }

    if (path.startsWith('/files/') && method === 'DELETE') {
      const id = path.slice(7);
      if (!ID.test(id)) return fail('غير موجود', 404);
      await store('files').delete(id);
      await store('data').setJSON('files', (await fileIndex()).filter((f) => f.id !== id));
      return json({ ver: await bump() });
    }

    return fail('مسار غير معروف', 404);
  } catch (e) {
    console.error(e);
    return fail('خطأ في الخادم', 500);
  }
};
