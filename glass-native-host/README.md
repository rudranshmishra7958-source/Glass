# Glass native scanner

Local ClamAV + YARA host for the Glass Chrome extension. The browser cannot run these engines itself; Chrome talks to this process over native messaging (`com.glass.scanner`).

## Windows requirements

- Python 3 on PATH (`python`)
- ClamAV so `clamscan` is on PATH, then `freshclam`
- `pip install yara-python`

## Register the host

1. Load Glass unpacked at `chrome://extensions`.
2. Copy the extension ID.
3. From this folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_host_windows.ps1 -ExtensionId YOUR_EXTENSION_ID
```

4. Confirm `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.glass.scanner` in Registry Editor.
5. Reload Glass.

## CLI tests (Stage 1)

Framed native-messaging round-trip (PowerShell):

```powershell
python -c "import json,struct,sys; p=json.dumps({'action':'scan','download':{'id':1,'filename':r'C:\Windows\win.ini','danger':'safe'}}).encode(); sys.stdout.buffer.write(struct.pack('<I',len(p))+p)" | python -u host.py
```

Direct scanner:

```powershell
python scanner\scanner.py C:\Windows\win.ini
```

EICAR (standard AV test file, not live malware) should return `assessment.risk` of `CRITICAL` when ClamAV is installed.
