(function () {
  if (location.protocol !== "https:") {
    return;
  }

  function scanForms() {
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

  function report() {
    const warnings = scanForms();
    if (!warnings.length) {
      return;
    }
    chrome.runtime.sendMessage({
      type: "INSECURE_FORMS",
      warnings
    });
  }

  report();
  const observer = new MutationObserver(report);
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
