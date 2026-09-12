# Offline Password Manager - Browser Extension Implementation Plan

Transform the offline password manager into a native **Chrome/Edge Browser Extension (Manifest V3)** with in-page credential auto-fill and quick-copy overlays on websites like GitHub, Google, and more.

## User Review Required

> [!IMPORTANT]
> **Zero-Network Policy Maintained**:
> The extension will continue to enforce `connect-src 'none'` in its extension Content Security Policy. No network calls, telemetry, or external API connections will be allowed. All AES-256 encryption and storage remain 100% local inside the browser extension sandbox (`chrome.storage.local`).

> [!NOTE]
> **Easy Loading in Chrome / Edge**:
> Chrome and Edge allow loading local extensions with one click via `chrome://extensions` > "Developer mode" > **"Load unpacked"**. No Web Store approval or purchase is necessary.

---

## Architecture & Workflows

```mermaid
graph TD
    subgraph Browser Extension Sandbox
        Popup[Toolbar Popup UI] --> Crypto[Web Crypto API AES-GCM]
        Crypto --> Storage[(chrome.storage.local)]
        Background[background.js Service Worker] --> Storage
    end

    subgraph Web Page (e.g. GitHub)
        ContentScript[content.js Injected Script]
        Inputs[Login & Password Inputs]
        OverlayUI[Floating Shield / Autofill Dropdown]
    end

    Inputs -->|Focus/Click| ContentScript
    ContentScript -->|chrome.runtime.sendMessage| Background
    Background -->|Get matching domain creds| ContentScript
    ContentScript -->|Render popup badge| OverlayUI
    OverlayUI -->|Click 'Auto-Fill' or 'Copy'| Inputs
```

---

## Proposed Changes

We will build the extension in a dedicated directory:
`C:\Users\vijay\.gemini\antigravity\scratch\offline-vault-extension`

### 1. Extension Manifest & Core Configuration

#### [NEW] `manifest.json`
- Manifest V3 compliant.
- Permissions: `["storage", "activeTab", "scripting"]`.
- Host permissions: `["<all_urls>"]` (needed to detect login inputs on sites like `github.com`).
- Strict zero-network Content Security Policy (`connect-src 'none';`).
- Declares popup, background service worker, and content scripts.

---

### 2. Cryptographic & Storage Layer

#### [NEW] `crypto.js`
- PBKDF2 (100,000 iterations, SHA-256) + AES-GCM 256-bit encryption using native Web Crypto API.
- Canary verification token for zero-knowledge master password authentication.

#### [NEW] `storage.js`
- Wrapper around `chrome.storage.local` for storing encrypted vault items, salt, canary, and settings.

---

### 3. Background Service Worker & Message Hub

#### [NEW] `background.js`
- Coordinates communication between web page content scripts and the vault.
- Maintains in-memory session unlock state and inactivity timer.
- Domain matcher: extracts current tab hostname (e.g., `github.com`) and matches against saved URLs in the vault.

---

### 4. In-Page Auto-Fill & Overlay (`github.com`, etc.)

#### [NEW] `content.js`
- Monitors input elements on web pages for username (`type="text"`, `type="email"`, `name="login"`, `id="login_field"`) and password (`type="password"`).
- Injects a subtle, non-intrusive shield icon on the right side of the input field.
- When clicked:
  - If vault is locked: shows a mini-card: *"Vault is locked. Click extension icon to unlock."*
  - If vault is unlocked: displays matching saved account(s) for that domain with:
    - **"Auto-Fill" button**: Automatically fills username & password and dispatches standard DOM events (`input`, `change`) so the site accepts the credentials.
    - **"Copy" button**: Copies password to clipboard without filling.

#### [NEW] `content.css`
- Scoped styling for the floating badge and dropdown to prevent conflicts with host website CSS.

---

### 5. Extension Popup UI

#### [NEW] `popup.html` & `popup.js`
- Clean, compact dark-mode popup that opens when clicking the extension icon in the Chrome/Edge toolbar.
- Shows master password setup or unlock screen.
- When unlocked:
  - Automatically highlights credentials matching the **current active tab**.
  - One-click "Fill this page" button.
  - Full vault management: search, copy, add new item, password generator, health audit, settings, and instant Lock button.

#### [NEW] `icons/`
- Extension icons (16x16, 48x48, 128x128) generated as clean SVG/PNG assets.

---

## Verification Plan

### Manual Verification Steps
1. **Load Unpacked Extension**:
   - Open Chrome or Edge -> `chrome://extensions` or `edge://extensions`.
   - Enable "Developer mode" -> Click **"Load unpacked"** -> Select `C:\Users\vijay\.gemini\antigravity\scratch\offline-vault-extension`.
2. **Master Password Setup**:
   - Click the extension icon in the toolbar.
   - Set master password and create vault.
   - Add a credential with URL `github.com` (username `vijay@gmail.com`, password).
3. **In-Page Auto-Fill Test on GitHub**:
   - Navigate to `https://github.com/login`.
   - Observe the shield icon inside the login/password fields.
   - Click the icon or overlay -> Click **"Auto-Fill"**.
   - Verify username and password are automatically populated into GitHub's form inputs.
4. **Network Verification**:
   - Inspect extension service worker DevTools -> Verify 0 network requests are dispatched.
