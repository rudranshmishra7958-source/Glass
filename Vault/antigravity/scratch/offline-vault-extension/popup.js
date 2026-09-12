/**
 * Offline Vault - Popup Script
 * Manages unlock, item CRUD, active tab autofill, and full dashboard integration.
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
  getSessionKey,
  setSessionKey,
  clearSessionKey
} from './storage.js';

let masterKey = null;
let currentTab = null;
let items = [];
let searchQuery = '';

function showToast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2000);
}

function isDomainMatch(savedUrlOrTitle, pageUrl) {
  if (!savedUrlOrTitle || !pageUrl) return false;
  const cleanSaved = savedUrlOrTitle.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '').trim();
  const cleanPage = pageUrl.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '').trim();

  if (cleanPage.includes(cleanSaved) || cleanSaved.includes(cleanPage)) return true;

  const pageParts = cleanPage.split('.');
  const savedParts = cleanSaved.split('.');
  if (pageParts.length >= 2 && savedParts.length >= 2) {
    if (pageParts.slice(-2).join('.') === savedParts.slice(-2).join('.')) return true;
  }

  const brandKeywords = cleanSaved.replace(/[^a-z0-9]/g, ' ').split(/\s+/).filter(w => w.length > 3);
  for (const kw of brandKeywords) {
    if (cleanPage.includes(kw)) return true;
  }
  return false;
}

function extractDisplayDomain(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    return parsed.hostname.replace(/^www\./, '').toLowerCase();
  } catch (e) {
    return url.toLowerCase();
  }
}

async function init() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0] || null;

  const meta = await getStoredMeta();
  if (!meta || !meta.salt || !meta.canary) {
    renderSetup();
    return;
  }

  // Check in-memory browser session key
  const sessionKeyBase64 = await getSessionKey();
  if (sessionKeyBase64) {
    try {
      masterKey = await importRawKey(sessionKeyBase64);
      await loadDecryptedItems();
      renderDashboard();
      return;
    } catch (err) {
      console.warn('Session key import failed:', err);
    }
  }

  // Otherwise prompt for master password
  renderUnlock(meta);
}

async function loadDecryptedItems() {
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
      console.error('Decryption failed for item', item.id, e);
    }
  }

  items = decrypted;
}

// 1. SETUP SCREEN
function renderSetup() {
  const app = document.getElementById('popup-app');
  app.innerHTML = `
    <div class="auth-wrapper" id="setup-box">
      <div style="font-size:28px;">🛡️</div>
      <h2 style="font-size:16px;font-weight:700;">Create Offline Vault</h2>
      <p style="font-size:11px;color:var(--text-secondary);">
        Set a master password. Stays unlocked until you close your browser. Zero cloud.
      </p>
      <form id="setup-form" style="display:flex;flex-direction:column;gap:0.75rem;text-align:left;">
        <div>
          <label style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:2px;">MASTER PASSWORD</label>
          <input type="password" id="setup-pass" class="auth-input" placeholder="Min 8 characters" required />
        </div>
        <div>
          <label style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:2px;">CONFIRM PASSWORD</label>
          <input type="password" id="setup-confirm" class="auth-input" placeholder="Repeat password" required />
        </div>
        <button type="submit" class="btn btn-primary" style="padding:0.6rem;">Create Secure Vault</button>
      </form>
    </div>
  `;

  document.getElementById('setup-form').onsubmit = async (e) => {
    e.preventDefault();
    const p1 = document.getElementById('setup-pass').value;
    const p2 = document.getElementById('setup-confirm').value;

    if (p1.length < 8) {
      showToast('Password must be at least 8 characters');
      return;
    }
    if (p1 !== p2) {
      showToast('Passwords do not match');
      return;
    }

    const salt = generateSalt(16);
    const key = await deriveMasterKey(p1, salt);
    const canary = await encryptPayload({ canary: CANARY_SECRET }, key);

    const meta = { salt, canary, createdAt: new Date().toISOString() };
    await setStoredMeta(meta);

    // Save session key in memory for this browser session
    const keyBase64 = await exportRawKey(key);
    await setSessionKey(keyBase64);

    masterKey = key;
    items = [];
    showToast('Vault created & unlocked!');
    renderDashboard();
  };
}

// 2. UNLOCK SCREEN
function renderUnlock(meta) {
  const app = document.getElementById('popup-app');
  app.innerHTML = `
    <div class="auth-wrapper" id="unlock-box">
      <div style="font-size:28px;">🔒</div>
      <h2 style="font-size:16px;font-weight:700;">Vault Locked</h2>
      <p style="font-size:11px;color:var(--text-secondary);">
        Enter master password to unlock for this browser session.
      </p>
      <form id="unlock-form" style="display:flex;flex-direction:column;gap:0.75rem;">
        <input type="password" id="unlock-pass" class="auth-input" placeholder="Master Password" required autofocus />
        <button type="submit" class="btn btn-primary" style="padding:0.6rem;">Unlock</button>
      </form>
    </div>
  `;

  document.getElementById('unlock-form').onsubmit = async (e) => {
    e.preventDefault();
    const p = document.getElementById('unlock-pass').value;

    try {
      const key = await deriveMasterKey(p, meta.salt);
      const test = await decryptPayload(meta.canary, key);

      if (!test || test.canary !== CANARY_SECRET) throw new Error('Bad key');

      // Save session key in memory (persists until browser closes)
      const keyBase64 = await exportRawKey(key);
      await setSessionKey(keyBase64);

      masterKey = key;
      await loadDecryptedItems();
      renderDashboard();
      showToast('Vault unlocked for this session');
    } catch (err) {
      const box = document.getElementById('unlock-box');
      box.classList.add('shake');
      setTimeout(() => box.classList.remove('shake'), 400);
      showToast('Incorrect master password');
    }
  };
}

// 3. MAIN DASHBOARD
function renderDashboard() {
  const app = document.getElementById('popup-app');
  const activeUrl = currentTab ? currentTab.url : '';
  const displayDomain = currentTab ? extractDisplayDomain(currentTab.url) : '';

  // Filter items matching current tab
  const tabMatches = items.filter((item) => {
    return isDomainMatch(item.url, activeUrl) || isDomainMatch(item.title, activeUrl);
  });

  const filteredItems = items.filter((item) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (item.title || '').toLowerCase().includes(q) ||
      (item.username || '').toLowerCase().includes(q) ||
      (item.url || '').toLowerCase().includes(q)
    );
  });

  app.innerHTML = `
    <header class="popup-header">
      <div class="brand-wrap">
        <span>🛡️</span>
        <span>Offline Vault</span>
      </div>
      <div style="display:flex;align-items:center;gap:4px;">
        <button class="btn-icon" id="p-btn-open-dashboard" title="Open Full Screen Dashboard">🖥️</button>
        <button class="btn btn-secondary" id="p-btn-gen" title="Password Generator">✨</button>
        <button class="btn btn-primary" id="p-btn-add">＋ Add</button>
        <button class="btn-icon" id="p-btn-lock" title="Lock Vault Now" style="color:var(--danger)">🔒</button>
      </div>
    </header>

    ${displayDomain && tabMatches.length > 0 ? `
      <div class="tab-match-banner">
        <div>
          <strong>${tabMatches.length} login(s)</strong> for <code>${displayDomain}</code>
        </div>
        <button class="btn btn-primary" id="btn-fill-active-tab" style="font-size:10px;padding:2px 8px;">
          ⚡ Fill on Tab
        </button>
      </div>
    ` : ''}

    <div class="search-bar">
      <input type="text" class="search-input" id="p-search" placeholder="Search passwords..." value="${searchQuery}" />
    </div>

    <div class="items-list" id="p-list">
      ${filteredItems.length === 0 ? `
        <div style="text-align:center;padding:2rem 1rem;color:var(--text-muted);font-size:12px;">
          ${searchQuery ? 'No matching passwords found.' : 'No passwords saved yet.<br/>Click <strong>＋ Add</strong> to save your first account!'}
        </div>
      ` : `
        ${filteredItems.map(item => `
          <div class="mini-card">
            <div class="mini-card-header">
              <span class="mini-card-title">${escapeHtml(item.title || 'Untitled')}</span>
              <div style="display:flex;gap:4px;">
                <button class="btn-icon" data-copy-pass="${escapeHtml(item.password || '')}" title="Copy password">📋 Pass</button>
                <button class="btn-icon" data-del="${item.id}" title="Delete" style="color:var(--danger)">🗑️</button>
              </div>
            </div>
            ${item.username ? `
              <div class="mini-card-field">
                <span style="color:var(--text-muted);">User</span>
                <span class="mini-val">${escapeHtml(item.username)}</span>
                <button class="btn-icon" data-copy-user="${escapeHtml(item.username)}" title="Copy username">📋</button>
              </div>
            ` : ''}
            ${item.url ? `
              <div style="font-size:10px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                ${escapeHtml(item.url)}
              </div>
            ` : ''}
          </div>
        `).join('')}
      `}
    </div>

    <div id="modal-slot"></div>
  `;

  // Search input
  document.getElementById('p-search').oninput = (e) => {
    searchQuery = e.target.value;
    renderDashboard();
  };

  // Open full dashboard in a new tab
  document.getElementById('p-btn-open-dashboard').onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('vault.html') });
  };

  // Lock action
  document.getElementById('p-btn-lock').onclick = async () => {
    await clearSessionKey();
    masterKey = null;
    init();
    showToast('Vault locked');
  };

  // Generator trigger
  document.getElementById('p-btn-gen').onclick = openGenerator;

  // Add Item trigger
  document.getElementById('p-btn-add').onclick = () => openAddForm(displayDomain);

  // Fill on active tab
  if (document.getElementById('btn-fill-active-tab') && tabMatches.length > 0) {
    document.getElementById('btn-fill-active-tab').onclick = () => {
      fillOnActiveTab(tabMatches[0]);
    };
  }

  // Copy and Delete handlers
  document.querySelectorAll('[data-copy-pass]').forEach(btn => {
    btn.onclick = () => {
      navigator.clipboard.writeText(btn.getAttribute('data-copy-pass'));
      showToast('Password copied!');
    };
  });

  document.querySelectorAll('[data-copy-user]').forEach(btn => {
    btn.onclick = () => {
      navigator.clipboard.writeText(btn.getAttribute('data-copy-user'));
      showToast('Username copied!');
    };
  });

  document.querySelectorAll('[data-del]').forEach(btn => {
    btn.onclick = async () => {
      const id = btn.getAttribute('data-del');
      if (confirm('Delete this item?')) {
        await deleteStoredItem(id);
        items = items.filter(i => i.id !== id);
        renderDashboard();
        showToast('Item deleted');
      }
    };
  });
}

// Fill directly on current tab via DOM injection
async function fillOnActiveTab(cred) {
  if (!currentTab || !currentTab.id) return;

  await chrome.scripting.executeScript({
    target: { tabId: currentTab.id },
    func: (username, password) => {
      const passInput = document.querySelector('input[type="password"]');
      const userInput = document.querySelector('input[type="text"]:not([readonly]), input[type="email"], input[autocomplete="username"], input[name="login"], input[id="login_field"]');

      if (userInput && username) {
        userInput.focus();
        userInput.value = username;
        userInput.dispatchEvent(new Event('input', { bubbles: true }));
        userInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
      if (passInput && password) {
        passInput.focus();
        passInput.value = password;
        passInput.dispatchEvent(new Event('input', { bubbles: true }));
        passInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
    },
    args: [cred.username, cred.password]
  });

  showToast('Filled on page!');
  setTimeout(() => window.close(), 600);
}

// 4. ADD ITEM FORM
function openAddForm(suggestedDomain) {
  const slot = document.getElementById('modal-slot');
  slot.innerHTML = `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.85);display:flex;flex-direction:column;padding:1rem;z-index:30;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
        <strong style="font-size:13px;">Save New Login</strong>
        <button class="btn-icon" id="m-close">✕</button>
      </div>
      <form id="add-item-form" style="display:flex;flex-direction:column;gap:0.5rem;flex:1;">
        <div>
          <label style="font-size:10px;color:var(--text-muted)">TITLE *</label>
          <input type="text" id="add-title" class="search-input" placeholder="e.g. NeoCollab or Examly" value="${suggestedDomain || ''}" required />
        </div>
        <div>
          <label style="font-size:10px;color:var(--text-muted)">USERNAME / EMAIL</label>
          <input type="text" id="add-user" class="search-input" placeholder="user@gmail.com" />
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;">
            <label style="font-size:10px;color:var(--text-muted)">PASSWORD</label>
            <button type="button" id="add-gen" style="background:none;border:none;color:var(--primary);cursor:pointer;font-size:10px;">✨ Generate</button>
          </div>
          <input type="password" id="add-pass" class="search-input" placeholder="Password" required />
        </div>
        <div>
          <label style="font-size:10px;color:var(--text-muted)">WEBSITE URL / DOMAIN</label>
          <input type="text" id="add-url" class="search-input" placeholder="examly.io or neocollab.com" value="${suggestedDomain || ''}" />
        </div>
        <div style="margin-top:auto;display:flex;gap:0.5rem;">
          <button type="button" class="btn btn-secondary" style="flex:1;" id="add-cancel">Cancel</button>
          <button type="submit" class="btn btn-primary" style="flex:1;">Save Encrypted</button>
        </div>
      </form>
    </div>
  `;

  document.getElementById('m-close').onclick = () => { slot.innerHTML = ''; };
  document.getElementById('add-cancel').onclick = () => { slot.innerHTML = ''; };

  document.getElementById('add-gen').onclick = () => {
    const p = generateSecurePassword({ length: 20 });
    const input = document.getElementById('add-pass');
    input.type = 'text';
    input.value = p;
    showToast('Strong password generated');
  };

  document.getElementById('add-item-form').onsubmit = async (e) => {
    e.preventDefault();
    const title = document.getElementById('add-title').value.trim();
    const username = document.getElementById('add-user').value.trim();
    const password = document.getElementById('add-pass').value;
    const url = document.getElementById('add-url').value.trim();

    const secret = { title, username, password, url };
    const encrypted = await encryptPayload(secret, masterKey);

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const item = {
      id,
      category: 'logins',
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      updatedAt: new Date().toISOString()
    };

    await saveStoredItem(item);
    items.unshift({ id, ...secret });
    slot.innerHTML = '';
    renderDashboard();
    showToast('Login encrypted & saved permanently!');
  };
}

// 5. GENERATOR MODAL
function openGenerator() {
  const slot = document.getElementById('modal-slot');
  slot.innerHTML = `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.85);display:flex;flex-direction:column;padding:1rem;z-index:30;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
        <strong style="font-size:13px;">Password Generator</strong>
        <button class="btn-icon" id="g-close">✕</button>
      </div>
      <div style="background:var(--bg-input);padding:0.75rem;border-radius:var(--radius);font-family:monospace;font-size:13px;word-break:break-all;" id="g-res"></div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;font-size:11px;">
        <span>Length</span>
        <span id="g-len-val" style="color:var(--primary);font-weight:700;">20</span>
      </div>
      <input type="range" id="g-len" min="8" max="64" value="20" style="width:100%;accent-color:var(--primary);margin-top:0.25rem;" />
      <div style="margin-top:auto;display:flex;gap:0.5rem;">
        <button class="btn btn-secondary" style="flex:1;" id="g-regen">🔄 Regenerate</button>
        <button class="btn btn-primary" style="flex:1;" id="g-copy">📋 Copy</button>
      </div>
    </div>
  `;

  const res = document.getElementById('g-res');
  const slider = document.getElementById('g-len');
  const lenVal = document.getElementById('g-len-val');

  const doGen = () => {
    const p = generateSecurePassword({ length: parseInt(slider.value, 10) });
    res.textContent = p;
    lenVal.textContent = slider.value;
  };

  slider.oninput = doGen;
  document.getElementById('g-regen').onclick = doGen;
  document.getElementById('g-close').onclick = () => { slot.innerHTML = ''; };
  document.getElementById('g-copy').onclick = () => {
    navigator.clipboard.writeText(res.textContent);
    showToast('Copied to clipboard!');
  };

  doGen();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

init();
