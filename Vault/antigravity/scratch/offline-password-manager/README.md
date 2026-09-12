# Offline Password Manager

A secure, 100% offline password manager web application built with React, the browser's native **Web Crypto API**, and **IndexedDB**.

---

## Key Features

- **100% Offline & Zero Network Calls**: Strict Content Security Policy (`connect-src 'none'`). All dependencies, icons, and styles are bundled locally. No servers, no tracking, no analytics.
- **Client-Side Cryptography**:
  - **Key Derivation**: PBKDF2 with SHA-256 and 100,000 iterations using a cryptographically random 16-byte salt (`crypto.getRandomValues`).
  - **Encryption**: Authenticated AES-GCM 256-bit with unique 12-byte initialization vectors (IV) for every credential record.
  - **Zero-Knowledge Auth**: Master password validity is verified against a canary token (`__OFFLINE_VAULT_CANARY_OK__`). No password hash is ever stored.
- **Persistent Local Storage**: Pure native IndexedDB wrapper (`OfflinePasswordManagerDB`) storing only encrypted ciphertexts and IVs.
- **Memory Protection**: Master encryption keys are stored exclusively in volatile JavaScript runtime memory and purged immediately upon locking or session inactivity.
- **Auto-Lock Timer**: Detects inactivity (mouse, keyboard, touch) and automatically locks the vault after a configurable timeout (default 15 minutes).
- **Security Health Audit**: Scans vault credentials for weak passwords (< 12 characters) and reused passwords across multiple accounts.
- **Built-in Password Generator**: Cryptographically secure random password generator with customizable length (8-64), character sets (uppercase, lowercase, numbers, symbols), and option to avoid ambiguous characters.
- **Encrypted Backup & Restore**: Export your vault as an encrypted `.json` file to safely back up across devices. Restore and merge backups using the backup's master password.

---

## Project Structure

```
offline-password-manager/
├── index.html                     # Vite entry HTML with strict zero-network CSP
├── offline-vault.html             # Completely self-contained single-file offline edition
├── package.json                   # Vite & React dependencies
├── vite.config.js                 # Vite bundler configuration
├── README.md                      # Documentation & security architecture
└── src/
    ├── main.jsx                   # React application mount
    ├── App.jsx                    # Root vault application & modal management
    ├── index.css                  # Self-contained dark-mode cybersecurity design system
    ├── services/
    │   ├── crypto.js              # PBKDF2 & AES-GCM Web Crypto API implementation
    │   ├── db.js                  # Native IndexedDB wrapper (meta & vault_items stores)
    │   └── generator.js           # Secure random generator & password entropy evaluator
    ├── context/
    │   └── VaultContext.jsx       # Global vault state, encryption, auto-lock & sync
    └── components/
        ├── Icons.jsx              # Pure SVG icon components (zero external icon fonts/CDNs)
        ├── UnlockScreen.jsx       # Vault setup & master password unlock interface
        ├── Navbar.jsx             # Top bar with live search, lock, and quick actions
        ├── Sidebar.jsx            # Category navigation (Logins, Cards, Notes, Favorites)
        ├── ItemList.jsx           # Filtered credential grid / list
        ├── ItemCard.jsx           # Credential card with one-click copy and visibility toggles
        ├── ItemModal.jsx          # Add / edit credential modal with inline generator
        ├── PasswordGeneratorModal.jsx # Standalone password generation tool
        ├── SettingsModal.jsx      # Auto-lock configuration, password change, backup/restore
        ├── SecurityAuditModal.jsx # Weak and duplicate password detector
        └── Toast.jsx              # Transient notification system
```

---

## How to Run

### Option 1: Double-Click Standalone Edition (No Node/npm required)
Open `offline-vault.html` in any modern web browser (Edge, Chrome, Firefox, Brave). It runs immediately with 100% offline capabilities and zero installation steps.

### Option 2: Vite React Development Server
If you have Node.js installed:
```bash
# 1. Install dependencies
npm install

# 2. Start the local development server
npm run dev
```
Then visit `http://localhost:3000` in your browser.

---

## Security Guarantees
1. **Zero External Data Flow**: No credentials, metadata, or telemetry are ever sent over a network.
2. **Encrypted at Rest**: All sensitive fields (passwords, usernames, URLs, notes, card numbers) are stored as AES-GCM ciphertexts inside IndexedDB.
3. **Volatile Key Lifespan**: Once locked, the master key is destroyed in RAM. A page refresh or tab close immediately locks the vault.
