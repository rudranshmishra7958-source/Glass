(function () {
  const STYLE_ID = "glass-cosmetic";

  function apply(enabled) {
    const existing = document.getElementById(STYLE_ID);
    if (!enabled) {
      existing?.remove();
      return;
    }
    const selectors = self.COSMETIC_SELECTORS || [];
    if (!selectors.length) {
      return;
    }
    const css = selectors.join(",\n") + " { display: none !important; }";
    if (existing) {
      existing.textContent = css;
      return;
    }
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = css;
    (document.documentElement || document.head || document.body)?.prepend(style);
  }

  async function load() {
    try {
      const stored = await chrome.storage.local.get("settings");
      apply(stored.settings?.cosmeticFiltering !== false);
    } catch {
      apply(true);
    }
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.settings) {
      return;
    }
    apply(changes.settings.newValue?.cosmeticFiltering !== false);
  });

  load();
})();
