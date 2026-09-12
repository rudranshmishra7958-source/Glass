(function () {
  function scanForms() {
    if (location.protocol !== "https:") {
      return [];
    }
    const warnings = [];
    for (const form of document.querySelectorAll("form")) {
      const action = form.getAttribute("action");
      if (!action) {
        continue;
      }
      try {
        const target = new URL(action, location.href);
        if (target.protocol === "http:") {
          warnings.push({
            action: target.href,
            method: (form.getAttribute("method") || "get").toUpperCase()
          });
        }
      } catch {
        // ignore malformed actions
      }
    }
    return warnings;
  }

  function reportForms() {
    const warnings = scanForms();
    if (!warnings.length) {
      return;
    }
    chrome.runtime.sendMessage({
      type: "INSECURE_FORMS",
      warnings
    });
  }

  function iframeHost(src) {
    try {
      return new URL(src, location.href).hostname.replace(/^www\./, "");
    } catch {
      return "";
    }
  }

  function replaceEmbed(iframe, host) {
    if (!iframe || iframe.dataset.glassEmbed === "1") {
      return;
    }
    iframe.dataset.glassEmbed = "1";
    const box = document.createElement("div");
    box.className = "glass-embed-placeholder";
    box.style.cssText =
      "display:flex;flex-direction:column;gap:8px;align-items:flex-start;justify-content:center;min-height:120px;padding:16px;border:1px dashed #8a5a12;background:#f4e6cc;color:#1c2530;font:13px/1.4 Segoe UI,system-ui,sans-serif;";
    const text = document.createElement("p");
    text.textContent = "Blocked embedded content";
    text.style.margin = "0";
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Load anyway";
    button.style.cssText =
      "border:0;border-radius:8px;padding:8px 12px;background:#5b7c99;color:#fff;cursor:pointer;font:inherit;";
    button.addEventListener("click", async () => {
      const site = location.hostname.replace(/^www\./, "");
      await chrome.runtime.sendMessage({
        type: "ADD_TRACKER_EXCEPTION",
        site,
        tracker: host
      });
      const src = iframe.getAttribute("src") || iframe.dataset.glassSrc || "";
      iframe.dataset.glassEmbed = "0";
      box.replaceWith(iframe);
      if (src) {
        iframe.src = src;
      }
    });
    box.append(text, button);
    iframe.dataset.glassSrc = iframe.getAttribute("src") || "";
    iframe.replaceWith(box);
    box.append(iframe);
    iframe.style.display = "none";
  }

  function scanEmbeds() {
    if (typeof isEmbedHost !== "function") {
      return;
    }
    for (const iframe of document.querySelectorAll("iframe[src]")) {
      if (iframe.dataset.glassEmbed === "1" || iframe.dataset.glassBlocked !== "1") {
        continue;
      }
      const host = iframeHost(iframe.getAttribute("src"));
      if (host && isEmbedHost(host)) {
        replaceEmbed(iframe, host);
      }
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type !== "EMBED_BLOCKED" || !message.url) {
      return;
    }
    const host = iframeHost(message.url) || message.host;
    for (const iframe of document.querySelectorAll("iframe[src]")) {
      const src = iframe.getAttribute("src") || "";
      if (src && (src === message.url || iframeHost(src) === host)) {
        iframe.dataset.glassBlocked = "1";
        replaceEmbed(iframe, host);
      }
    }
  });

  reportForms();
  setTimeout(scanEmbeds, 1500);
  const observer = new MutationObserver(() => {
    reportForms();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
