# SafeBox Download Guard

SafeBox is a local browser-download protection extension for Chromium/Chrome.

## What it does

1. Watches browser downloads.
2. Uses the browser's own `danger` signal as the earliest available extension-level block signal.
3. Scans completed files locally with ClamAV, YARA, SHA-256, file-type analysis and simple heuristics.
4. High-risk completed files are moved to a SafeBox quarantine folder by the native host.
5. The extension presents **Delete File** and **Download Anyway** actions.
6. Manual files can also be selected and scanned.

## Important browser limitation

A normal extension cannot inspect the full arbitrary download body with ClamAV before the browser receives it. Therefore:

- Chrome/Chromium danger signals can be cancelled as early as the Downloads API exposes them.
- SafeBox's own ClamAV/YARA verdict happens after completion, then the native host quarantines the file immediately.
- `Download Anyway` is an explicit user override that releases the quarantined file.

This is intentionally represented honestly in the UI and report.

## Install

1. Load `extension/` unpacked at `chrome://extensions`.
2. Copy the extension ID.
3. From this project directory run:

```bash
./native-host/install_host.sh YOUR_EXTENSION_ID
```

4. Reload the extension.

For Flatpak Chromium, the installer also writes a Flatpak-scoped manifest when the app exists. If the Flatpak sandbox prevents launching the host, use a native Chrome/Chromium installation for the cleanest demo.

## Scanner requirements

Fedora:

```bash
sudo dnf install -y clamav clamav-freshclam file
sudo freshclam
```

Python:

```bash
source ~/Projects/safebox/backend/venv/bin/activate
pip install yara-python
```

The host prefers that existing SafeBox virtual environment when available.

## Testing

- A normal text file should be LOW.
- A source file containing suspicious network/process indicators should receive YARA evidence.
- The EICAR test file should trigger ClamAV and a CRITICAL verdict.

Do not use live malware on your normal workstation. Use EICAR/AMTSO or an isolated research VM if you need a controlled demonstration.
