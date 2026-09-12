/**
 * Full-Screen Unified Vault Dashboard (Inside Extension)
 * Shares the exact same chrome.storage.local & chrome.storage.session with the popup and content script.
 */

import {
  deriveMasterKey,
  generateSalt,
  encryptPayload,
  decryptPayload,
  CANARY_SECRET,
  exportRawKey,
  importRawKey,
  generateSecurePassword
} from './crypto.js';

import {
  getStoredMeta,
  setStoredMeta,
  getStoredItems,
  saveStoredItem,
  deleteStoredItem,
  clearAllStoredData,
  getSessionKey,
  setSessionKey,
  clearSessionKey
} from './storage.js';

let masterKey = null;
let items = [];
let searchQuery = '';

function showToast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

async function init() {
  const meta = await getStoredMeta();
  if (!meta || !meta.salt || !meta.canary) {
    renderSetup();
    return;
  }

  const sessionKeyBase64 = await getSessionKey();
  if (sessionKeyBase64) {
    try {
      masterKey = await importRawKey(sessionKeyBase64);
      await loadItems();
      renderDashboard();
      return;
    } catch (err) {
      console.error(err);
    }
  }

  renderUnlock(meta);
}

async function loadItems() {
  const encrypted = await getStoredItems();
  const decrypted = [];
  for (const item of encrypted) {
    try {
      const secret = await decryptPayload(
        { ciphertext: item.ciphertext, iv: item.iv },
        masterKey
      );
      decrypted.push({
        id: item.id,
        category: item.category || 'logins',
        updatedAt: item.updatedAt,
        ...secret
      });
    } catch (e) {
      console.error(e);
    }
  }
  items = decrypted;
}

function renderSetup() {
  const app = document.getElementById('full-vault-app');
  app.innerHTML = `
    <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;">
      <div class="card" style="max-width:400px;width:100%;text-align:center;padding:2rem;">
        <div style="font-size:32px;margin-bottom:0.5rem;">🛡️</div>
        <h2 style="font-size:1.4rem;">Setup Unified Vault</h2>
        <p style="font-size:12px;color:var(--text-secondary);margin-bottom:1rem;">
          Any password saved here is immediately available for 1-click auto-fill on GitHub, NeoCollab, and Examly!
        </p>
        <form id="v-setup-form" style="display:flex;flex-direction:column;gap:0.75rem;text-align:left;">
          <input type="password" id="v-p1" class="form-input" placeholder="Master Password (min 8 chars)" required />
          <input type="password" id="v-p2" class="form-input" placeholder="Confirm Master Password" required />
          <button type="submit" class="btn btn-primary" style="margin-top:0.5rem;">Create Vault</button>
        </form>
      </div>
    </div>
  `;

  document.getElementById('v-setup-form').onsubmit = async (e) => {
    e.preventDefault();
    const p1 = document.getElementById('v-p1').value;
    const p2 = document.getElementById('v-p2').value;
    if (p1.length < 8 || p1 !== p2) {
      showToast('Passwords must match and be at least 8 characters.');
      return;
    }

    const salt = generateSalt(16);
    const key = await deriveMasterKey(p1, salt);
    const canary = await encryptPayload({ canary: CANARY_SECRET }, key);
    const meta = { salt, canary, createdAt: new Date().toISOString() };

    await setStoredMeta(meta);
    const keyBase64 = await exportRawKey(key);
    await setSessionKey(keyBase64);

    masterKey = key;
    items = [];
    showToast('Vault created!');
    renderDashboard();
  };
}

function renderUnlock(meta) {
  const app = document.getElementById('full-vault-app');
  app.innerHTML = `
    <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;">
      <div class="card" style="max-width:380px;width:100%;text-align:center;padding:2rem;">
        <div style="font-size:32px;margin-bottom:0.5rem;">🔒</div>
        <h2 style="font-size:1.4rem;">Vault Locked</h2>
        <p style="font-size:12px;color:var(--text-secondary);margin-bottom:1rem;">
          Unlock once per browser session. Stays unlocked until you close your browser.
        </p>
        <form id="v-unlock-form" style="display:flex;flex-direction:column;gap:0.75rem;">
          <input type="password" id="v-pass" class="form-input" placeholder="Enter Master Password" required autofocus />
          <button type="submit" class="btn btn-primary">Unlock Vault</button>
        </form>
      </div>
    </div>
  `;

  document.getElementById('v-unlock-form').onsubmit = async (e) => {
    e.preventDefault();
    const p = document.getElementById('v-pass').value;
    try {
      const key = await deriveMasterKey(p, meta.salt);
      const test = await decryptPayload(meta.canary, key);
      if (!test || test.canary !== CANARY_SECRET) throw new Error('Bad key');

      const keyBase64 = await exportRawKey(key);
      await setSessionKey(keyBase64);

      masterKey = key;
      await loadItems();
      renderDashboard();
      showToast('Vault unlocked for this session');
    } catch (err) {
      showToast('Incorrect master password');
    }
  };
}

function renderDashboard() {
  const app = document.getElementById('full-vault-app');
  const filtered = items.filter(i => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (i.title || '').toLowerCase().includes(q) ||
           (i.username || '').toLowerCase().includes(q) ||
           (i.url || '').toLowerCase().includes(q);
  });

  app.innerHTML = `
    <header class="navbar">
      <div class="nav-brand">
        <span>🛡️</span>
        <span>Offline Vault — Unified Dashboard</span>
      </div>
      <div style="display:flex;gap:0.5rem;align-items:center;">
        <button class="btn btn-secondary" id="d-btn-import">📂 Import Localhost Backup</button>
        <button class="btn btn-primary" id="d-btn-add">＋ Add New Account</button>
        <button class="btn btn-danger" id="d-btn-lock">🔒 Lock</button>
      </div>
    </header>

    <div class="layout">
      <aside class="sidebar">
        <div>
          <span style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;">Vault Sync</span>
          <p style="font-size:12px;color:var(--text-secondary);margin-top:0.35rem;">
            Directly connected to the Chrome extension. Any changes here are instantly available for auto-fill on all websites!
          </p>
        </div>
        <div style="margin-top:auto;background:var(--bg-input);padding:0.75rem;border-radius:var(--radius);font-size:11px;color:var(--primary);">
          ● 100% Local & Encrypted
        </div>
      </aside>

      <main class="main-content">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <h2 style="font-size:1.3rem;">All Credentials (${filtered.length})</h2>
            <p style="font-size:12px;color:var(--text-muted);">AES-256-GCM encrypted in your browser extension storage.</p>
          </div>
          <input type="text" id="d-search" class="form-input" style="max-width:280px;margin-top:0;" placeholder="Search passwords..." value="${searchQuery}" />
        </div>

        <div class="items-grid">
          ${filtered.length === 0 ? `
            <div style="grid-column:1/-1;padding:3rem;text-align:center;color:var(--text-muted);border:1px dashed var(--border-color);border-radius:var(--radius);">
              No credentials found. Click <strong>＋ Add New Account</strong> or import your localhost backup!
            </div>
          ` : `
            ${filtered.map(item => `
              <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                  <strong style="font-size:1.05rem;">${escapeHtml(item.title)}</strong>
                  <div style="display:flex;gap:4px;">
                    <button class="btn btn-secondary" style="padding:2px 8px;font-size:11px;" data-copy="${escapeHtml(item.password)}">📋 Copy</button>
                    <button class="btn btn-danger" style="padding:2px 8px;font-size:11px;" data-del="${item.id}">🗑️</button>
                  </div>
                </div>
                ${item.username ? `
                  <div class="card-row">
                    <span style="color:var(--text-muted);">Username</span>
                    <span style="font-family:monospace;">${escapeHtml(item.username)}</span>
                  </div>
                ` : ''}
                <div class="card-row">
                  <span style="color:var(--text-muted);">Password</span>
                  <span style="font-family:monospace;letter-spacing:2px;">••••••••••••</span>
                </div>
                ${item.url ? `
                  <div style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;">
                    Website: <strong>${escapeHtml(item.url)}</strong>
                  </div>
                ` : ''}
              </div>
            `).join('')}
          `}
        </div>
      </main>
    </div>

    <div id="modal-container"></div>
  `;

  document.getElementById('d-search').oninput = (e) => {
    searchQuery = e.target.value;
    renderDashboard();
  };

  document.getElementById('d-btn-lock').onclick = async () => {
    await clearSessionKey();
    masterKey = null;
    init();
    showToast('Vault locked');
  };

  document.getElementById('d-btn-add').onclick = openAddModal;
  document.getElementById('d-btn-import').onclick = openImportModal;

  document.querySelectorAll('[data-copy]').forEach(b => {
    b.onclick = () => {
      navigator.clipboard.writeText(b.getAttribute('data-copy'));
      showToast('Password copied to clipboard!');
    };
  });

  document.querySelectorAll('[data-del]').forEach(b => {
    b.onclick = async () => {
      const id = b.getAttribute('data-del');
      if (confirm('Delete this login?')) {
        await deleteStoredItem(id);
        items = items.filter(i => i.id !== id);
        renderDashboard();
        showToast('Deleted');
      }
    };
  });
}

function openAddModal() {
  const slot = document.getElementById('modal-container');
  slot.innerHTML = `
    <div class="modal-overlay" id="add-modal-overlay">
      <div class="modal-box" onclick="event.stopPropagation()">
        <h3 style="font-size:1.1rem;">Add New Login</h3>
        <form id="d-add-form" style="display:flex;flex-direction:column;gap:0.75rem;">
          <div>
            <label style="font-size:11px;color:var(--text-muted);">TITLE (e.g. NeoCollab, GitHub, Examly) *</label>
            <input type="text" id="m-title" class="form-input" placeholder="NeoCollab" required />
          </div>
          <div>
            <label style="font-size:11px;color:var(--text-muted);">USERNAME / EMAIL</label>
            <input type="text" id="m-user" class="form-input" placeholder="user@gmail.com" />
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <label style="font-size:11px;color:var(--text-muted);">PASSWORD</label>
              <button type="button" id="m-gen" style="background:none;border:none;color:var(--primary);cursor:pointer;font-size:11px;">✨ Generate</button>
            </div>
            <input type="password" id="m-pass" class="form-input" placeholder="Password" required />
          </div>
          <div>
            <label style="font-size:11px;color:var(--text-muted);">WEBSITE DOMAIN (e.g. neocollab.com or examly.io)</label>
            <input type="text" id="m-url" class="form-input" placeholder="neocollab.com" />
          </div>
          <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.5rem;">
            <button type="button" class="btn btn-secondary" id="m-cancel">Cancel</button>
            <button type="submit" class="btn btn-primary">Save to Vault</button>
          </div>
        </form>
      </div>
    </div>
  `;

  document.getElementById('m-cancel').onclick = () => { slot.innerHTML = ''; };
  document.getElementById('add-modal-overlay').onclick = () => { slot.innerHTML = ''; };
  document.getElementById('m-gen').onclick = () => {
    const pwd = generateSecurePassword({ length: 20 });
    const p = document.getElementById('m-pass');
    p.type = 'text';
    p.value = pwd;
    showToast('Strong password generated');
  };

  document.getElementById('d-add-form').onsubmit = async (e) => {
    e.preventDefault();
    const title = document.getElementById('m-title').value.trim();
    const username = document.getElementById('m-user').value.trim();
    const password = document.getElementById('m-pass').value;
    const url = document.getElementById('m-url').value.trim();

    const secret = { title, username, password, url };
    const encrypted = await encryptPayload(secret, masterKey);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

    const record = {
      id,
      category: 'logins',
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      updatedAt: new Date().toISOString()
    };

    await saveStoredItem(record);
    items.unshift({ id, ...secret });
    slot.innerHTML = '';
    renderDashboard();
    showToast('Saved! Immediately ready for auto-fill on ' + (url || title));
  };
}

function openImportModal() {
  const slot = document.getElementById('modal-container');
  slot.innerHTML = `
    <div class="modal-overlay" id="import-modal-overlay">
      <div class="modal-box" onclick="event.stopPropagation()">
        <h3 style="font-size:1.2rem;">📂 Import Localhost Backup</h3>
        <p style="font-size:12px;color:var(--text-secondary);">
          Select the <code>.json</code> backup file you exported from the localhost web app.
        </p>
        <form id="import-form" style="display:flex;flex-direction:column;gap:0.85rem;">
          <div style="border:1px dashed var(--border-color);padding:1rem;border-radius:var(--radius);text-align:center;background:var(--bg-input);">
            <label style="display:block;cursor:pointer;font-size:12px;color:var(--primary);font-weight:600;">
              📁 Click to Choose Backup File (.json)
              <input type="file" id="import-file" accept=".json" style="display:none;" required />
            </label>
            <div id="file-selected-status" style="font-size:11px;color:var(--text-muted);margin-top:4px;">
              No file selected yet
            </div>
          </div>

          <div id="pass-section">
            <label style="font-size:11px;color:var(--text-muted);display:block;margin-bottom:2px;">MASTER PASSWORD (USED TO EXPORT BACKUP)</label>
            <input type="password" id="import-pass" class="form-input" placeholder="Enter master password" required />
          </div>

          <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.5rem;">
            <button type="button" class="btn btn-secondary" id="import-cancel">Cancel</button>
            <button type="submit" class="btn btn-primary" id="btn-do-import">⚡ Decrypt & Import</button>
          </div>
        </form>
      </div>
    </div>
  `;

  const fileInput = document.getElementById('import-file');
  const fileStatus = document.getElementById('file-selected-status');
  const passInput = document.getElementById('import-pass');
  const importBtn = document.getElementById('btn-do-import');

  fileInput.onchange = () => {
    if (fileInput.files && fileInput.files[0]) {
      fileStatus.style.color = '#10b981';
      fileStatus.textContent = `✓ Selected: ${fileInput.files[0].name}`;
      passInput.focus();
    }
  };

  document.getElementById('import-cancel').onclick = () => { slot.innerHTML = ''; };
  document.getElementById('import-modal-overlay').onclick = () => { slot.innerHTML = ''; };

  document.getElementById('import-form').onsubmit = async (e) => {
    e.preventDefault();
    const file = fileInput.files[0];
    const pass = passInput.value;
    if (!file) {
      showToast('Please select a .json file first');
      return;
    }

    importBtn.textContent = 'Decrypting...';
    importBtn.disabled = true;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const backup = JSON.parse(evt.target.result);
        if (!backup.salt || !backup.canary || !Array.isArray(backup.items)) {
          throw new Error('Unrecognized backup format. Please select the .json file exported from Offline Vault.');
        }

        const backupKey = await deriveMasterKey(pass, backup.salt);
        const test = await decryptPayload(backup.canary, backupKey);
        if (!test || test.canary !== CANARY_SECRET) {
          throw new Error('Incorrect master password for this backup file.');
        }

        let count = 0;
        for (const bItem of backup.items) {
          try {
            const secret = await decryptPayload({ ciphertext: bItem.ciphertext, iv: bItem.iv }, backupKey);
            const reEncrypted = await encryptPayload(secret, masterKey);
            const id = bItem.id || Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
            await saveStoredItem({
              id,
              category: bItem.category || 'logins',
              ciphertext: reEncrypted.ciphertext,
              iv: reEncrypted.iv,
              updatedAt: new Date().toISOString()
            });
            count++;
          } catch (err) {
            console.error('Failed to decrypt record', err);
          }
        }

        slot.innerHTML = '';
        await loadItems();
        renderDashboard();
        showToast(`🎉 Success! Imported ${count} credentials into your extension!`);
      } catch (err) {
        importBtn.textContent = '⚡ Decrypt & Import';
        importBtn.disabled = false;
        showToast('Import error: ' + err.message);
      }
    };
    reader.readAsText(file);
  };
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

init();
