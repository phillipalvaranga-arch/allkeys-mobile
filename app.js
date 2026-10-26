(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const IDLE_MS = 5 * 60 * 1000, CLIP_MS = 30 * 1000;
  let keys = null, entries = null, current = null, editing = null, clip = null, clipTimer = null, idleTimer = null, pendingImport = null, busy = false;

  // ---------- IndexedDB (stores only the encrypted AKV1 bytes) ----------
  function db() { return new Promise((res, rej) => { const r = indexedDB.open('allkeys', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('vault'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
  async function idb(mode, fn) { const d = await db(); return new Promise((res, rej) => {
    const t = d.transaction('vault', mode), st = t.objectStore('vault'); const r = fn(st);
    t.oncomplete = () => res(r && r.result); t.onerror = () => rej(t.error); }); }
  const getVault = () => idb('readonly', s => s.get('dat')).then(v => v ? new Uint8Array(v) : null);
  async function putVault(bytes) {
    const old = await getVault();
    await idb('readwrite', s => { if (old) s.put(old, 'bak'); s.put(bytes, 'dat'); });
  }
  async function saveEntries(list, k) {
    k = k || keys;
    const data = await AK.seal(k, list);
    if (!(await AK.unprotect(k, data))) throw new Error('The new vault could not be verified, so nothing was changed.');
    await putVault(data);
    entries = list;
  }
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});

  // ---------- UI helpers ----------
  function toast(msg) { const t = $('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.h); toast.h = setTimeout(() => t.hidden = true, 3500); }
  function openSheet(id) { closeSheets(); $('overlay').hidden = false; $(id).hidden = false; }
  function closeSheets() { document.querySelectorAll('.sheet').forEach(s => s.hidden = true); $('overlay').hidden = true; }
  function confirmBox(text) { return new Promise(res => { $('cfText').textContent = text; const prev = [...document.querySelectorAll('.sheet')].find(s => !s.hidden);
    $('dConfirm').hidden = false; $('overlay').hidden = false;
    const done = v => { $('dConfirm').hidden = true; if (!prev) $('overlay').hidden = true; $('cfYes').onclick = $('cfNo').onclick = null; res(v); };
    $('cfYes').onclick = () => done(true); $('cfNo').onclick = () => done(false); }); }
  document.querySelectorAll('[data-show]').forEach(cb => cb.addEventListener('change', () =>
    cb.dataset.show.split(',').forEach(id => $(id).type = cb.checked ? 'text' : 'password')));
  document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeSheets));
  $('overlay').addEventListener('click', closeSheets);

  // ---------- clipboard (cleared after 30 s) ----------
  async function copySecret(text, what) {
    if (!text) { toast(`This entry has no ${what.toLowerCase()} to copy.`); return; }
    try { await navigator.clipboard.writeText(text); } catch { toast('Could not copy. Please try again.'); return; }
    clip = text; clearTimeout(clipTimer); clipTimer = setTimeout(clearClip, CLIP_MS);
    toast(`${what} copied. The clipboard will be cleared in 30 seconds.`);
  }
  async function clearClip() {
    clearTimeout(clipTimer); if (!clip) return;
    try { await navigator.clipboard.writeText(''); } catch {}
    clip = null;
  }

  // ---------- lock ----------
  function resetIdle() { clearTimeout(idleTimer); if (keys) idleTimer = setTimeout(lock, IDLE_MS); }
  ['pointerdown', 'keydown', 'input', 'scroll'].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true, capture: true }));
  function lock() {
    keys = null; entries = null; current = null; editing = null; pendingImport = null; clearTimeout(idleTimer);
    closeSheets(); $('list').textContent = ''; $('search').value = '';
    document.querySelectorAll('input[type=password],input[data-secret],#gOut,#ePass,#eNotes').forEach(i => i.value = '');
    showLock();
  }
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { clearClip(); if (keys) lock(); } });
  window.addEventListener('pagehide', () => { clearClip(); if (keys) lock(); });

  async function showLock() {
    $('vMain').hidden = true; $('vLock').hidden = false;
    const v = await getVault();
    $('lockUnlock').hidden = !v; $('lockCreate').hidden = !!v;
    ['uErr', 'cErr'].forEach(i => $(i).textContent = '');
    if (v) setTimeout(() => $('uPw').focus(), 50);
  }
  function showMain() { $('vLock').hidden = true; $('vMain').hidden = false; render(); resetIdle(); }

  $('uBtn').onclick = async () => {
    if (busy) return; const p = $('uPw').value;
    if (!p) { $('uErr').textContent = 'Please type your master password.'; return; }
    busy = true; $('uErr').textContent = 'Unlocking...';
    try { const r = await AK.open(await getVault(), p);
      if (!r.ok) { $('uErr').textContent = r.reason === 'Corrupt' ? 'Your vault looks damaged. Import your vault file from your PC.' : 'Wrong password. Please try again.'; $('uPw').value = ''; return; }
      keys = r.keys; entries = r.entries; $('uPw').value = ''; showMain();
    } catch (e) { $('uErr').textContent = 'Something went wrong: ' + e.message; } finally { busy = false; }
  };
  $('uPw').addEventListener('keydown', e => { if (e.key === 'Enter') $('uBtn').click(); });
  $('cBtn').onclick = async () => {
    if (busy) return; const a = $('cPw1').value, b = $('cPw2').value;
    if (a.length < 8) { $('cErr').textContent = 'Your master password must be at least 8 characters long.'; return; }
    if (a !== b) { $('cErr').textContent = 'The two passwords do not match. Please type them again.'; return; }
    busy = true; $('cErr').textContent = 'Creating your vault...';
    try { const k = await AK.deriveKeys(a, AK.rand(16), AK.ITER); await saveEntries([], k); keys = k; $('cPw1').value = $('cPw2').value = ''; showMain(); }
    catch (e) { $('cErr').textContent = 'Something went wrong: ' + e.message; } finally { busy = false; }
  };

  // ---------- list ----------
  function render() {
    const q = $('search').value.trim().toLowerCase(), ul = $('list'); ul.textContent = '';
    const sorted = [...entries].sort((a, b) => a.Site.toLowerCase().localeCompare(b.Site.toLowerCase()));
    let shown = 0;
    for (const e of sorted) {
      if (q && ![e.Site, e.Username, e.Url, e.Notes].some(v => v && v.toLowerCase().includes(q))) continue;
      const li = document.createElement('li'), s = document.createElement('div'), u = document.createElement('div');
      s.className = 's'; s.textContent = e.Site; u.className = 'u'; u.textContent = e.Username || e.Url || '';
      li.append(s, u); li.onclick = () => view(e.Id); ul.append(li); shown++;
    }
    $('count').textContent = q ? `Showing ${shown} of ${entries.length}` : `${entries.length} saved`;
    $('empty').hidden = entries.length > 0;
  }
  $('search').addEventListener('input', render);
  const find = id => entries.find(e => e.Id === id);

  function view(id) {
    current = find(id); if (!current) return; const e = current;
    $('vSite').textContent = e.Site; $('vUser').textContent = e.Username || '—';
    $('vPass').textContent = e.Password ? '••••••••••' : '—'; $('vReveal').textContent = 'Show';
    $('vUrl').textContent = e.Url || '—'; $('vOpen').hidden = !e.Url; $('vNotes').textContent = e.Notes || '';
    $('vDates').textContent = `Created ${e.Created} · Modified ${e.Modified}`;
    openSheet('dView');
  }
  $('vCopyU').onclick = () => current && copySecret(current.Username, 'Username');
  $('vCopyP').onclick = () => current && copySecret(current.Password, 'Password');
  $('vReveal').onclick = () => { if (!current) return; const hid = $('vReveal').textContent === 'Show';
    $('vPass').textContent = hid ? (current.Password || '—') : (current.Password ? '••••••••••' : '—'); $('vReveal').textContent = hid ? 'Hide' : 'Show'; };
  $('vOpen').onclick = () => { if (!current) return; let u = current.Url.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = 'https://' + u;
    if (!/^https?:\/\//i.test(u)) { toast('Only http and https websites can be opened.'); return; }
    window.open(u, '_blank', 'noopener,noreferrer'); };
  $('vEdit').onclick = () => current && edit(current);
  $('vDel').onclick = async () => { const e = current; if (!e) return;
    if (!(await confirmBox(`Delete the entry for '${e.Site}'?\n\nThis cannot be undone.`))) return;
    try { await saveEntries(entries.filter(x => x.Id !== e.Id)); closeSheets(); render(); toast(`Deleted '${e.Site}'.`); } catch (err) { toast('Could not save: ' + err.message); } };

  // ---------- add / edit ----------
  function edit(e) {
    editing = e || null;
    $('eTitle').textContent = e ? 'Edit Entry' : 'Add Entry';
    $('eSite').value = e ? e.Site : ''; $('eUser').value = e ? e.Username : ''; $('ePass').value = e ? e.Password : '';
    $('eUrl').value = e ? e.Url : ''; $('eNotes').value = e ? e.Notes : ''; $('eErr').textContent = '';
    $('ePass').type = 'password'; document.querySelector('[data-show=ePass]').checked = false;
    openSheet('dEdit'); setTimeout(() => $('eSite').focus(), 50);
  }
  $('bAdd').onclick = () => edit(null);
  $('eGen').onclick = async () => { if ($('ePass').value && !(await confirmBox('Replace the current password with a new generated one?'))) return;
    $('ePass').value = AK.strongPassword(+$('eLen').value, $('eSym').checked); };
  $('eSave').onclick = async () => {
    const site = $('eSite').value.trim(); if (!site) { $('eErr').textContent = 'Please enter the site or app name.'; return; }
    const f = { Site: site, Username: $('eUser').value.trim(), Password: $('ePass').value, Url: $('eUrl').value.trim(), Notes: $('eNotes').value };
    let list, saved;
    if (editing) { saved = AK.newEntry({ ...f, Id: editing.Id, Created: editing.Created, Modified: AK.stamp() }); list = entries.map(x => x.Id === editing.Id ? saved : x); }
    else { saved = AK.newEntry(f); list = [...entries, saved]; }
    try { await saveEntries(list); closeSheets(); $('search').value = ''; render(); toast(`${editing ? 'Updated' : 'Saved'} '${saved.Site}'.`); editing = null; }
    catch (err) { $('eErr').textContent = 'Your change could not be saved: ' + err.message; }
  };

  // ---------- menu ----------
  $('bMenu').onclick = () => openSheet('dMenu');
  $('bLock').onclick = lock;
  $('dMenu').addEventListener('click', ev => { const a = ev.target.dataset.act; if (!a) return;
    if (a === 'close') closeSheets(); else if (a === 'lock') lock(); else if (a === 'gen') { openSheet('dGen'); $('gGen').click(); }
    else if (a === 'master') { ['mCur', 'mNew1', 'mNew2'].forEach(i => $(i).value = ''); $('mErr').textContent = ''; openSheet('dMaster'); }
    else if (a === 'export') exportVault(); else if (a === 'import') $('fileIn').click(); });
  $('gGen').onclick = () => $('gOut').value = AK.strongPassword(+$('gLen').value, $('gSym').checked);
  $('gCopy').onclick = () => copySecret($('gOut').value, 'Password');

  $('mOk').onclick = async () => {
    if (busy) return; const cur = $('mCur').value, n1 = $('mNew1').value, n2 = $('mNew2').value;
    if (n1.length < 8) { $('mErr').textContent = 'The new password must be at least 8 characters long.'; return; }
    if (n1 !== n2) { $('mErr').textContent = 'The new passwords do not match.'; return; }
    busy = true; $('mErr').textContent = 'Checking...';
    try { const chk = await AK.deriveKeys(cur, keys.salt, keys.iterations);
      if (!AK.sameBytes(chk.fp, keys.fp)) { $('mErr').textContent = 'The current master password is wrong.'; $('mCur').value = ''; return; }
      const nk = await AK.deriveKeys(n1, AK.rand(16), AK.ITER); await saveEntries(entries, nk); keys = nk;
      closeSheets(); toast('Your master password has been changed.');
    } catch (e) { $('mErr').textContent = 'Something went wrong: ' + e.message; } finally { busy = false; }
  };

  // ---------- export / import (same vault.dat format as the PC app) ----------
  async function exportVault() {
    const data = await getVault(); if (!data) return;
    const blob = new Blob([data], { type: 'application/octet-stream' }), name = 'Allkeys-vault-' + AK.stamp().slice(0, 10) + '.dat';
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.append(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
    closeSheets(); toast(`Saved ${name} to your Downloads. It is encrypted with your master password.`);
  }
  $('cImport').onclick = () => $('fileIn').click();
  $('fileIn').onchange = async () => {
    const f = $('fileIn').files[0]; $('fileIn').value = ''; if (!f) return;
    if (f.size > 50 * 1024 * 1024) { toast('That file is too big to be an Allkeys vault.'); return; }
    const d = new Uint8Array(await f.arrayBuffer());
    if (!AK.readHeader(d)) { toast('That file is not an Allkeys vault file.'); return; }
    pendingImport = d; $('iPw').value = ''; $('iErr').textContent = '';
    $('iInfo').textContent = keys
      ? `"${f.name}": entries from this file will be merged into your phone vault (new ones added, newer edits win). Your phone master password stays the same.`
      : `"${f.name}": this becomes your phone vault. Unlock it with the master password you use on your PC.`;
    openSheet('dImport'); setTimeout(() => $('iPw').focus(), 50);
  };
  $('iOk').onclick = async () => {
    if (busy || !pendingImport) return; busy = true; $('iErr').textContent = 'Checking...';
    try { const r = await AK.open(pendingImport, $('iPw').value);
      if (!r.ok) { $('iErr').textContent = 'Wrong password for that file. Please try again.'; return; }
      if (!keys) { await putVault(pendingImport); keys = r.keys; entries = r.entries; pendingImport = null; closeSheets(); showMain(); toast(`Imported ${entries.length} passwords.`); return; }
      const map = new Map(entries.map(e => [e.Id, e])); let added = 0, updated = 0;
      for (const e of r.entries) { const m = map.get(e.Id);
        if (!m) { map.set(e.Id, e); added++; } else if (e.Modified > m.Modified) { map.set(e.Id, e); updated++; } }
      await saveEntries([...map.values()]); pendingImport = null; closeSheets(); render();
      toast(`Import done: ${added} added, ${updated} updated.`);
    } catch (e) { $('iErr').textContent = 'Something went wrong: ' + e.message; } finally { busy = false; $('iPw').value = ''; }
  };

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  showLock();
})();
