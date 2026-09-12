# Offline Vault - Chrome & Edge Browser Extension

A 100% offline, zero-network password manager extension with in-page auto-fill and quick-copy on websites like GitHub, Google, and more.

---

## How to Install in Chrome / Edge (30 Seconds)

### Step 1: Open Extensions Page
- **In Google Chrome**: Open a new tab and go to `chrome://extensions`
- **In Microsoft Edge**: Open a new tab and go to `edge://extensions`

### Step 2: Turn on Developer Mode
- In the top right (or bottom left in Edge), toggle **"Developer mode"** to **ON**.

### Step 3: Load the Extension
1. Click the **"Load unpacked"** button in the top left.
2. Select this folder:
   ```text
   C:\Users\vijay\.gemini\antigravity\scratch\offline-vault-extension
   ```
3. Click **Select Folder**.

The **Offline Vault** extension icon (🛡️) will appear in your browser toolbar!

---

## How to Use Auto-Fill on GitHub

1. Click the **Offline Vault (🛡️)** icon in your browser toolbar.
2. Set your Master Password on first launch.
3. Click **＋ Add** to save your GitHub account:
   - Title: `GitHub`
   - Username: `your-email@gmail.com`
   - Password: `your-password`
   - Website URL: `github.com`
   - Click **Save Encrypted**.
4. Now go to **https://github.com/login**:
   - You will see a green shield icon (🛡️) right inside GitHub's login/password box!
   - Click it and choose **⚡ Auto-Fill** or **📋 Copy**!
   - Alternatively, click the extension icon in your toolbar and press **"⚡ Fill on Tab"**.

---

## Security & Privacy Architecture
- **Zero Network Calls**: Enforced by strict CSP (`connect-src 'none'`).
- **AES-GCM 256-bit**: All credentials stored in `chrome.storage.local` are encrypted with your master password key derived via PBKDF2 (100,000 iterations).
- **Volatile Master Key**: The encryption key is kept only in temporary service worker memory and is flushed when locked or inactive.
