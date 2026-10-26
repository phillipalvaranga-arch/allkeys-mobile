/* Allkeys vault format (identical to the Windows app):
   "AKV1" | iterations int32 LE | salt(16) | IV(16) | AES-256-CBC ciphertext | HMAC-SHA256(32)
   master = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
   encKey = HMAC(master, "Allkeys v1 AES-256-CBC key"), macKey = HMAC(master, "Allkeys v1 HMAC-SHA256 key") */
(function (g) {
  'use strict';
  const S = g.crypto.subtle, te = new TextEncoder();
  const MAGIC = [0x41, 0x4B, 0x56, 0x31];
  const ITER = 200000;
  function rand(n) { const b = new Uint8Array(n); g.crypto.getRandomValues(b); return b; }
  function readHeader(d) {
    if (!d || d.length < 88) return null;
    for (let i = 0; i < 4; i++) if (d[i] !== MAGIC[i]) return null;
    if ((d.length - 72) % 16 !== 0) return null;
    const it = new DataView(d.buffer, d.byteOffset + 4, 4).getInt32(0, true);
    if (it < 10000 || it > 5000000) return null;
    return { iterations: it, salt: d.slice(8, 24) };
  }
  async function deriveKeys(password, salt, iterations) {
    const pw = te.encode(password);
    const base = await S.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    pw.fill(0);
    const master = new Uint8Array(await S.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256));
    const mk = await S.importKey('raw', master, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    master.fill(0);
    const encRaw = new Uint8Array(await S.sign('HMAC', mk, te.encode('Allkeys v1 AES-256-CBC key')));
    const macRaw = new Uint8Array(await S.sign('HMAC', mk, te.encode('Allkeys v1 HMAC-SHA256 key')));
    const enc = await S.importKey('raw', encRaw, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
    const mac = await S.importKey('raw', macRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    // fingerprint lets "change master password" check the current password without keeping it
    const fp = new Uint8Array(await S.digest('SHA-256', encRaw));
    encRaw.fill(0); macRaw.fill(0);
    return { enc, mac, salt: new Uint8Array(salt), iterations, fp };
  }
  async function protect(keys, plain) {
    const iv = rand(16);
    const ct = new Uint8Array(await S.encrypt({ name: 'AES-CBC', iv }, keys.enc, plain));
    const body = new Uint8Array(40 + ct.length);
    body.set(MAGIC, 0);
    new DataView(body.buffer).setInt32(4, keys.iterations, true);
    body.set(keys.salt, 8); body.set(iv, 24); body.set(ct, 40);
    const tag = new Uint8Array(await S.sign('HMAC', keys.mac, body));
    const out = new Uint8Array(body.length + 32); out.set(body); out.set(tag, body.length);
    return out;
  }
  async function unprotect(keys, d) {
    if (!readHeader(d)) return null;
    const n = d.length - 32;
    const ok = await S.verify('HMAC', keys.mac, d.slice(n), d.slice(0, n));
    if (!ok) return null;
    return new Uint8Array(await S.decrypt({ name: 'AES-CBC', iv: d.slice(24, 40) }, keys.enc, d.slice(40, n)));
  }
  async function open(d, password) {
    const h = readHeader(d);
    if (!h) return { ok: false, reason: 'Corrupt' };
    const keys = await deriveKeys(password, h.salt, h.iterations);
    const plain = await unprotect(keys, d);
    if (!plain) return { ok: false, reason: 'WrongPassword' };
    const doc = JSON.parse(new TextDecoder().decode(plain)); plain.fill(0);
    return { ok: true, keys, entries: normalize(doc) };
  }
  function normalize(doc) {
    let list = doc && doc.entries; if (list == null) list = []; if (!Array.isArray(list)) list = [list];
    return list.filter(Boolean).map(e => newEntry(e));
  }
  function stamp(d) { d = d || new Date(); const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; }
  function newEntry(e) {
    const s = v => (v == null ? '' : String(v)); const now = stamp();
    return { Id: s(e.Id) || g.crypto.randomUUID(), Site: s(e.Site), Username: s(e.Username), Password: s(e.Password),
      Url: s(e.Url), Notes: s(e.Notes), Created: s(e.Created) || now, Modified: s(e.Modified) || now };
  }
  async function seal(keys, entries) {
    const doc = { app: 'Allkeys', format: 1, entries: entries.map(e => ({ Id: e.Id, Site: e.Site, Username: e.Username,
      Password: e.Password, Url: e.Url, Notes: e.Notes, Created: e.Created, Modified: e.Modified })) };
    const plain = te.encode(JSON.stringify(doc));
    try { return await protect(keys, plain); } finally { plain.fill(0); }
  }
  function randIndex(max) { const lim = 4294967296 - (4294967296 % max), b = new Uint32Array(1);
    for (;;) { g.crypto.getRandomValues(b); if (b[0] < lim) return b[0] % max; } }
  function strongPassword(len, symbols) {
    len = Math.max(8, Math.min(64, len | 0 || 20));
    const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789']; if (symbols) sets.push('!@#$%^&*-_=+?');
    const all = sets.join('');
    for (;;) { let pw = ''; for (let i = 0; i < len; i++) pw += all[randIndex(all.length)];
      if (sets.every(s => [...s].some(c => pw.includes(c)))) return pw; }
  }
  function sameBytes(a, b) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i]; return x === 0; }
  g.AK = { ITER, rand, readHeader, deriveKeys, protect, unprotect, open, seal, newEntry, stamp, strongPassword, sameBytes };
})(typeof window !== 'undefined' ? window : globalThis);
