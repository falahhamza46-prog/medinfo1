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
  const tab = ['schedule', 'subjects', 'hw', 'notices', 'photos'].includes(extra.tab) ? extra.tab : '';
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

/* ---------- الصور المشتركة ---------- */
const photoIndex = async () => (await store('data').get('photos', { type: 'json' })) || [];
const sha256 = (x) => createHash('sha256').update(String(x)).digest('hex');
const publicPhoto = ({ k, ...p }) => p; // لا نكشف هاش السر
const isJpeg = (u8) => u8.length > 4 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff;
const MAX_FULL = 1.6 * 1024 * 1024;
const MAX_THUMB = 160 * 1024;
const MAX_PER_STUDENT = 60;
const MAX_TOTAL = 800;
// تعديل الفهرس مع التحقق بعد الكتابة لتقليل ضياع التحديثات عند الرفع المتزامن
async function mutatePhotos(fn, verify) {
  for (let i = 0; i < 4; i++) {
    const idx = fn(await photoIndex());
    await store('data').setJSON('photos', idx);
    const after = await photoIndex();
    if (verify(after)) return after;
    await new Promise((r) => setTimeout(r, 120 + Math.random() * 280));
  }
  return photoIndex();
}

// الحالة العامة: بدون أسرار الطلبة (يُرسل فقط هل الاسم محجوز)
const pubState = (st) => st && Object.assign({}, st, { students: ((st && st.students) || []).map((x) => ({ id: x.id, name: x.name, claimed: !!x.claimed })) });

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
      return json({ state: pubState(state), files: await fileIndex(), photos: (await photoIndex()).map(publicPhoto), ver, vapid });
    }

    if (path === '/login' && method === 'POST') {
      const { pw } = await req.json();
      const r = await checkPassword(pw || '');
      if (!r.ok) { await new Promise((res) => setTimeout(res, 700)); return fail('كلمة المرور غير صحيحة', 403); }
      return json({ ...(await makeToken()), defaultPw: r.isDefault });
    }

    // اختيار الاسم: كل اسم يُحجز لشخص واحد فقط ويختفي من القائمة عند الباقين
    if (path === '/claim' && method === 'POST') {
      const { id } = await req.json();
      const D = store('data');
      const st = await D.get('state', { type: 'json' });
      const stu = ((st && st.students) || []).find((x) => x.id === String(id));
      if (!stu) return fail('الاسم غير موجود في القائمة', 404);
      if (stu.claimed) return fail('هذا الاسم اختاره شخص آخر. اختر اسماً آخر', 409);
      const ck = randomBytes(16).toString('hex');
      stu.claimed = true; stu.k = sha256(ck);
      await D.set('state', JSON.stringify(st));
      await new Promise((r) => setTimeout(r, 150));
      const chk = await D.get('state', { type: 'json' });
      const again = ((chk && chk.students) || []).find((x) => x.id === stu.id);
      if (!again || again.k !== stu.k) return fail('هذا الاسم اختاره شخص آخر. اختر اسماً آخر', 409);
      return json({ ck, ver: await bump() });
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

    if (path.startsWith('/photos/') && method === 'GET') {
      const id = path.slice(8);
      if (!ID.test(id)) return fail('غير موجود', 404);
      const key = url.searchParams.get('t') === '1' ? id + '.t' : id;
      const r = await store('photos').get(key, { type: 'arrayBuffer' });
      if (!r) return fail('غير موجود', 404);
      return new Response(r, {
        headers: {
          'content-type': 'image/jpeg',
          'content-disposition': 'inline; filename="photo-' + id.slice(0, 8) + '.jpg"',
          'cache-control': 'public, max-age=31536000, immutable',
          'x-content-type-options': 'nosniff',
        },
      });
    }

    if (path === '/photos' && method === 'POST') {
      let meta;
      try { meta = JSON.parse(decodeURIComponent(req.headers.get('x-meta') || '')); } catch { return fail('بيانات الصورة ناقصة'); }
      const sid = String(meta.sid || '');
      let name;
      if (sid === 'admin') {
        if (!(await isAdmin(req))) return fail('يلزم تسجيل الدخول كأدمن', 401);
        name = 'الأدمن';
      } else {
        const st = await store('data').get('state', { type: 'json' });
        const stu = ((st && st.students) || []).find((x) => x.id === sid);
        if (!stu || !stu.claimed || !same(sha256(req.headers.get('x-ck') || ''), String(stu.k || ''))) return fail('اسمك غير مفعّل. أعد اختيار اسمك', 403);
        name = String(stu.name).slice(0, 80);
      }
      const buf = new Uint8Array(await req.arrayBuffer());
      if (buf.length < 12 || buf.length > MAX_FULL + MAX_THUMB + 8) return fail('حجم الصورة غير مقبول');
      const tl = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
      if (tl < 100 || tl > MAX_THUMB || 4 + tl >= buf.length) return fail('بيانات الصورة غير صالحة');
      const thumb = buf.slice(4, 4 + tl);
      const full = buf.slice(4 + tl);
      if (full.length > MAX_FULL) return fail('الصورة كبيرة جداً');
      if (!isJpeg(thumb) || !isJpeg(full)) return fail('الصور المقبولة بصيغة JPEG فقط');
      const idx0 = await photoIndex();
      if (idx0.length >= MAX_TOTAL) return fail('امتلأ الألبوم. تواصل مع الأدمن');
      if (sid !== 'admin' && idx0.filter((p) => p.sid === sid).length >= MAX_PER_STUDENT) return fail('وصلت إلى الحد الأقصى من الصور (' + MAX_PER_STUDENT + ')');
      const id = randomUUID();
      const secret = randomBytes(16).toString('hex');
      await store('photos').set(id, full.buffer.slice(full.byteOffset, full.byteOffset + full.byteLength));
      await store('photos').set(id + '.t', thumb.buffer.slice(thumb.byteOffset, thumb.byteOffset + thumb.byteLength));
      const w = Math.max(0, Math.min(10000, Number(meta.w) || 0));
      const h = Math.max(0, Math.min(10000, Number(meta.h) || 0));
      const photo = { id, sid, name, cap: String(meta.cap || '').slice(0, 140), at: Date.now(), w, h, k: sha256(secret) };
      await mutatePhotos((a) => a.concat(photo), (a) => a.some((p) => p.id === id));
      const ver = await bump();
      if (sid === 'admin') await sendPush('صورة جديدة', 'شاركها ' + name, { tab: 'photos' });
      return json({ photo: publicPhoto(photo), secret, ver });
    }

    if (path.startsWith('/photos/') && method === 'DELETE') {
      const id = path.slice(8);
      if (!ID.test(id)) return fail('غير موجود', 404);
      const p = (await photoIndex()).find((x) => x.id === id);
      if (!p) return fail('غير موجود', 404);
      const secret = req.headers.get('x-secret') || '';
      const mine = secret && same(sha256(secret), p.k);
      if (!mine && !(await isAdmin(req))) return fail('لا تملك صلاحية حذف هذه الصورة', 403);
      await store('photos').delete(id);
      await store('photos').delete(id + '.t');
      await mutatePhotos((a) => a.filter((x) => x.id !== id), (a) => !a.some((x) => x.id === id));
      return json({ ver: await bump() });
    }

    // كل ما بعد هذا يحتاج أدمن
    if (!(await isAdmin(req))) return fail('يلزم تسجيل الدخول كأدمن', 401);

    if (path === '/state' && method === 'PUT') {
      const { state, notify } = await req.json();
      if (!state || typeof state !== 'object') return fail('بيانات غير صالحة');
      delete state.pw;
      // الحفاظ على حجز الأسماء: العميل لا يرى الأسرار فندمجها من المخزّن
      const old = await store('data').get('state', { type: 'json' });
      const om = new Map(((old && old.students) || []).map((x) => [x.id, x]));
      state.students = (Array.isArray(state.students) ? state.students : ((old && old.students) || [])).slice(0, 500).map((x) => {
        const o = om.get(x.id);
        return { id: String(x.id).slice(0, 40), name: String(x.name).slice(0, 80), ...(o && o.claimed ? { claimed: true, k: o.k } : {}) };
      });
      const raw = JSON.stringify(state);
      if (raw.length > 1_500_000) return fail('حجم البيانات كبير جداً');
      await store('data').set('state', raw);
      const ver = await bump();
      if (notify && notify.title) await sendPush(String(notify.title).slice(0, 80), String(notify.body || '').slice(0, 140), notify);
      return json({ ver });
    }

    if (path === '/unclaim' && method === 'POST') {
      const { id } = await req.json();
      const D = store('data');
      const st = await D.get('state', { type: 'json' });
      const stu = ((st && st.students) || []).find((x) => x.id === String(id));
      if (!stu) return fail('غير موجود', 404);
      delete stu.claimed; delete stu.k;
      await D.set('state', JSON.stringify(st));
      return json({ ver: await bump() });
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
