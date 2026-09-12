/**
 * Offline Vault - In-Page Content Script
 * Automatically injects auto-fill and quick-copy badges into login forms.
 * Broad input detection for NeoCollab, Examly, GitHub, and all modern login flows.
 */

const SHIELD_SVG = `
<svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
</svg>`;

let activeDropdown = null;

// Close dropdown on outside click
document.addEventListener('click', (e) => {
  if (activeDropdown && !activeDropdown.contains(e.target) && !e.target.closest('.__offline_vault_badge')) {
    activeDropdown.remove();
    activeDropdown = null;
  }
});

// Position the badge on the right edge inside the input
function attachBadgeToInput(input) {
  if (input.__offline_vault_attached) return;
  input.__offline_vault_attached = true;

  const badge = document.createElement('div');
  badge.className = '__offline_vault_badge';
  badge.innerHTML = SHIELD_SVG;
  badge.title = 'Offline Vault: Autofill or Copy';

  function updatePosition() {
    if (!input.isConnected) {
      badge.remove();
      return;
    }
    const rect = input.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    badge.style.top = `${window.scrollY + rect.top + (rect.height - 22) / 2}px`;
    badge.style.left = `${window.scrollX + rect.right - 28}px`;
  }

  updatePosition();
  document.body.appendChild(badge);

  window.addEventListener('resize', updatePosition);
  window.addEventListener('scroll', updatePosition, true);

  badge.addEventListener('click', (e) => {
    e.stopPropagation();
    e.preventDefault();
    openAutofillDropdown(input, badge);
  });
}

function openAutofillDropdown(input, badge) {
  if (activeDropdown) {
    activeDropdown.remove();
    activeDropdown = null;
  }

  const dropdown = document.createElement('div');
  dropdown.className = '__offline_vault_dropdown';

  const badgeRect = badge.getBoundingClientRect();
  dropdown.style.top = `${window.scrollY + badgeRect.bottom + 6}px`;
  dropdown.style.left = `${Math.max(10, window.scrollX + badgeRect.right - 260)}px`;

  dropdown.innerHTML = `
    <div class="__offline_vault_header">
      <span>🛡️ Offline Vault</span>
      <span style="font-size:10px;color:#94a3b8;">100% Offline</span>
    </div>
    <div class="__offline_vault_notice">Checking vault...</div>
  `;

  document.body.appendChild(dropdown);
  activeDropdown = dropdown;

  // Ask background worker for credentials matching this URL
  chrome.runtime.sendMessage(
    { type: 'GET_MATCHING_CREDENTIALS', url: window.location.href },
    (response) => {
      if (!dropdown.isConnected) return;

      if (!response || !response.isUnlocked) {
        dropdown.innerHTML = `
          <div class="__offline_vault_header">
            <span>🛡️ Offline Vault</span>
          </div>
          <div class="__offline_vault_notice">
            🔒 <strong>Vault is locked</strong><br/>
            Click the extension icon in your browser toolbar to unlock once for this session.
          </div>
        `;
        return;
      }

      const creds = response.credentials || [];
      if (creds.length === 0) {
        dropdown.innerHTML = `
          <div class="__offline_vault_header">
            <span>🛡️ Offline Vault</span>
          </div>
          <div class="__offline_vault_notice">
            No credentials saved for this site.<br/>
            Click the toolbar extension icon to save this account.
          </div>
        `;
        return;
      }

      dropdown.innerHTML = `
        <div class="__offline_vault_header">
          <span>🛡️ Matching Logins</span>
          <span style="font-size:10px;color:#94a3b8;">${creds.length} found</span>
        </div>
        <div>
          ${creds.map((cred, idx) => `
            <div class="__offline_vault_item">
              <div class="__offline_vault_user" title="${cred.username || cred.title}">
                ${cred.username || cred.title || 'Login Entry'}
              </div>
              <div class="__offline_vault_actions">
                <button class="__offline_vault_btn __offline_vault_btn_fill" data-fill-idx="${idx}">
                  ⚡ Auto-Fill
                </button>
                <button class="__offline_vault_btn __offline_vault_btn_copy" data-copy-idx="${idx}">
                  📋 Copy
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      `;

      // Wire Auto-Fill action
      dropdown.querySelectorAll('[data-fill-idx]').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const idx = parseInt(btn.getAttribute('data-fill-idx'), 10);
          const cred = creds[idx];
          fillCredentialsIntoForm(input, cred);
          dropdown.remove();
          activeDropdown = null;
        });
      });

      // Wire Copy action
      dropdown.querySelectorAll('[data-copy-idx]').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const idx = parseInt(btn.getAttribute('data-copy-idx'), 10);
          const cred = creds[idx];
          navigator.clipboard.writeText(cred.password);
          btn.textContent = '✓ Copied!';
          setTimeout(() => {
            if (dropdown.isConnected) dropdown.remove();
          }, 800);
        });
      });
    }
  );
}

// Find matching form elements and fill them safely
function fillCredentialsIntoForm(targetInput, cred) {
  const form = targetInput.closest('form') || document.body;

  // Find password field
  const passInput = form.querySelector('input[type="password"]') || (targetInput.type === 'password' ? targetInput : null);

  // Find username / email field
  const userInput = form.querySelector(
    'input[type="email"], input[type="text"]:not([readonly]), input[autocomplete*="user"], input[name*="user"], input[name*="login"], input[name*="email"], input[id*="user"], input[id*="login"], input[id*="email"]'
  ) || (targetInput.type !== 'password' ? targetInput : null);

  if (userInput && cred.username) {
    userInput.focus();
    userInput.value = cred.username;
    userInput.dispatchEvent(new Event('input', { bubbles: true }));
    userInput.dispatchEvent(new Event('change', { bubbles: true }));
  }

  if (passInput && cred.password) {
    passInput.focus();
    passInput.value = cred.password;
    passInput.dispatchEvent(new Event('input', { bubbles: true }));
    passInput.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

// Scan DOM for login inputs with broad selector support
function scanForInputs() {
  const inputs = document.querySelectorAll(
    'input[type="password"], input[type="email"], input[autocomplete*="user"], input[autocomplete*="email"], input[name*="user"], input[name*="login"], input[name*="email"], input[id*="user"], input[id*="login"], input[id*="email"], input[placeholder*="email" i], input[placeholder*="user" i]'
  );

  inputs.forEach((input) => {
    if (input.type === 'search' || input.type === 'hidden' || input.disabled || input.readOnly) return;
    const rect = input.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      attachBadgeToInput(input);
    }
  });
}

// Initial scan
scanForInputs();

// Re-scan when forms are dynamically mounted (e.g. Examly multi-step sign in, NeoCollab, GitHub)
const observer = new MutationObserver(() => {
  scanForInputs();
});
observer.observe(document.body, { childList: true, subtree: true });
