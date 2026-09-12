# Offline Password Manager & Browser Extension - Walkthrough

A complete offline, zero-network password manager suite with client-side AES-256-GCM encryption, IndexedDB/local extension storage, and **in-page auto-fill on websites like GitHub**.

---

## 1. Web Application & Browser Extension Overview

The project provides two complementary solutions:

1. **Standalone Web App** (`offline-password-manager`):
   - Modular React + Vite codebase and single-file `offline-vault.html`.
   - Complete credential management, password generator, health audits, and encrypted JSON export/import.
2. **Chrome / Edge Browser Extension** (`offline-vault-extension`):
   - **In-Page Auto-Fill**: Injects a floating shield (🛡️) inside login inputs on sites like `github.com`.
   - **One-Click Auto-Fill**: Automatically fills username and password and triggers DOM change events.
   - **Toolbar Popup**: Access vault from any tab, match active tab domains, and generate passwords.
   - **Zero Network Calls**: Enforced by strict CSP (`connect-src 'none'`).

---

## 2. Browser Extension File Structure

Location: `C:\Users\vijay\.gemini\antigravity\scratch\offline-vault-extension`

| File | Role |
| :--- | :--- |
| [manifest.json](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/manifest.json) | Manifest V3 specification with zero-network CSP |
| [background.js](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/background.js) | Service worker: in-memory key cache, auto-lock, and domain matcher |
| [content.js](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/content.js) | In-page script: detects login inputs on sites and displays auto-fill/copy badge |
| [content.css](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/content.css) | Scoped CSS for in-page badges and dropdowns |
| [popup.html](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/popup.html) | Extension toolbar popup UI |
| [popup.js](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/popup.js) | Toolbar popup logic: active tab matching, quick fill, CRUD, generator |
| [popup.css](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/popup.css) | Compact dark mode cybersecurity styling |
| [crypto.js](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/crypto.js) | Native Web Crypto API (PBKDF2 100k + AES-GCM 256-bit) |
| [storage.js](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/storage.js) | Local encrypted storage wrapper (`chrome.storage.local`) |
| [README.md](file:///C:/Users/vijay/.gemini/antigravity/scratch/offline-vault-extension/README.md) | Setup and usage documentation |

---

## 3. How to Load and Test the Extension (30 Seconds)

### Step 1: Load into Browser
1. In **Google Chrome**, open a new tab and go to: `chrome://extensions`  
   *(Or in **Microsoft Edge**, go to `edge://extensions`)*
2. In the top right, turn **"Developer mode"** to **ON**.
3. Click the **"Load unpacked"** button in the top left.
4. Select the folder:
   ```text
   C:\Users\vijay\.gemini\antigravity\scratch\offline-vault-extension
   ```

### Step 2: Set Master Password
1. Click the **Offline Vault (🛡️)** icon in your browser toolbar (pin it if needed).
2. Set your master password and confirm.

### Step 3: Add GitHub Login
1. In the extension popup, click **＋ Add**.
2. Enter:
   - **Title**: `GitHub`
   - **Username**: `vijay@gmail.com`
   - **Password**: your password
   - **Website URL**: `github.com`
3. Click **Save Encrypted**.

### Step 4: Test In-Page Auto-Fill
1. Go to **https://github.com/login**.
2. Notice the green **shield badge (🛡️)** inside the login field!
3. Click the shield badge -> Click **⚡ Auto-Fill**.
4. Both username and password will be filled automatically!
