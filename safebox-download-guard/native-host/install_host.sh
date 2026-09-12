#!/usr/bin/env bash
set -euo pipefail
EXT_ID="${1:-}"
if [[ -z "$EXT_ID" ]]; then echo "Usage: $0 EXTENSION_ID"; exit 1; fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_PATH="$SCRIPT_DIR/host.py"
TEMPLATE="$SCRIPT_DIR/host_manifest.template.json"
chmod +x "$HOST_PATH"
install_one(){
  local dir="$1"
  mkdir -p "$dir"
  sed -e "s|__HOST_PATH__|$HOST_PATH|g" -e "s|EXTENSION_ID|$EXT_ID|g" "$TEMPLATE" > "$dir/com.safebox.browser.json"
  echo "Installed $dir/com.safebox.browser.json"
}
install_one "$HOME/.config/chromium/NativeMessagingHosts"
install_one "$HOME/.config/google-chrome/NativeMessagingHosts"
if [[ -d "$HOME/.var/app/org.chromium.Chromium" ]]; then
  install_one "$HOME/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts"
  echo "Flatpak Chromium manifest installed. If Flatpak still cannot launch the host, use native Chrome/Chromium for the demo or grant the Flatpak access to the SafeBox directory."
fi
echo "Extension origin allowed: chrome-extension://$EXT_ID/"
