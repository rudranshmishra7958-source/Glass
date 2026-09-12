const CATEGORIES = [
  { id: "advertising", label: "Advertising" },
  { id: "analytics", label: "Analytics" },
  { id: "social", label: "Social" },
  { id: "other", label: "Other" }
];

const ICONS = {
  advertising:
    '<svg class="cat-icon cat-advertising" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M2.2 6.2 13 2.4c.6-.2 1.2.4 1 1L10.3 14c-.2.6-1 .7-1.4.2L7.2 12l-2.4 2.4c-.3.3-.8.3-1.1 0l-.7-.7c-.3-.3-.3-.8 0-1.1L5.4 10 3 8.3c-.6-.4-.5-1.2.2-1.4Z"/></svg>',
  analytics:
    '<svg class="cat-icon cat-analytics" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M2 13h12v1.5H2V13Zm1.5-1H5V7H3.5v5Zm3.5 0h1.5V4H8.5v8Zm3.5 0H13.5V2h-1.5v10Z"/></svg>',
  social:
    '<svg class="cat-icon cat-social" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M6 6.5a2 2 0 1 1-4 0 2 2 0 0 1 4 0Zm8 0a2 2 0 1 1-4 0 2 2 0 0 1 4 0ZM8 8.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4ZM2.4 13.5c0-1.6 1.4-2.7 3.1-2.7.4 0 .8 0 1.1.1A3.4 3.4 0 0 0 8 12.2c.3.6.4 1.2.4 1.3H2.4Zm8.1-2.7c1.7 0 3.1 1.1 3.1 2.7H9.6c0-.1.1-.7.4-1.3.4-.4.9-.7 1.5-.9.4-.1.7-.1 1-.5Z"/></svg>',
  other:
    '<svg class="cat-icon cat-other" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 1.4 14.6 8 8 14.6 1.4 8 8 1.4Zm0 3.3L4.7 8 8 11.3 11.3 8 8 4.7Z"/></svg>'
};

const domainEl = document.getElementById("domain");
const statusEl = document.getElementById("status");
const badgeEl = document.getElementById("badge");
const badgeCountEl = document.getElementById("badge-count");
const badgeLabelEl = document.getElementById("badge-label");
const badgeSplitEl = document.getElementById("badge-split");
const categoriesEl = document.getElementById("categories");
const listEl = document.getElementById("tracker-list");
const toggleEl = document.getElementById("block-toggle");
const categoryTogglesEl = document.getElementById("category-toggles");
const faviconEl = document.getElementById("favicon");
const lifetimeEl = document.getElementById("lifetime");
const trustToggleEl = document.getElementById("trust-toggle");
const securityWrapEl = document.getElementById("security-wrap");
const securityWarningsEl = document.getElementById("security-warnings");
const dashboardBtn = document.getElementById("open-dashboard");
const pauseBannerEl = document.getElementById("pause-banner");
const pauseHintEl = document.getElementById("pause-hint");
const pauseControlsEl = document.getElementById("pause-controls");
const resumeBtn = document.getElementById("resume-protection");
const blockNowBtn = document.getElementById("block-now");
const scanPanelEl = document.getElementById("scan-panel");
let currentTabId = null;
let reloadWatcher = null;

let currentHost = null;

function shortHash(hash) {
  const value = String(hash || "");
  if (!value) {
    return "";
  }
  if (value.length <= 20) {
    return value;
  }
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function latestScanFrom(scans, history) {
  if (Array.isArray(history) && history[0]) {
    return history[0];
  }
  return (
    Object.values(scans || {}).sort((a, b) => (b.ts || 0) - (a.ts || 0))[0] || null
  );
}

function renderDownloadScan(scan) {
  if (!scanPanelEl) {
    return;
  }
  if (!scan) {
    scanPanelEl.innerHTML = `<p class="empty">No downloads scanned yet.</p>`;
    return;
  }
  if (scan.status === "scanning") {
    scanPanelEl.innerHTML = `<p class="scan-pulse">Scanning ${escapeHtml(scan.filename || "download")}…</p>`;
    return;
  }
  if (scan.status === "error") {
    scanPanelEl.innerHTML = `<p class="scan-reason">${escapeHtml(scan.error || "Scan failed.")}</p>`;
    return;
  }
  const risk = scan.risk || scan.report?.assessment?.risk || "UNKNOWN";
  const reason = scan.report?.assessment?.reason || scan.error || "";
  const hash = shortHash(scan.report?.file?.sha256);
  const evidence = (scan.report?.assessment?.evidence || [])
    .slice(0, 3)
    .map((item) => `<p class="scan-reason">${escapeHtml(item.message || "")}</p>`)
    .join("");
  const actions =
    scan.action === "deleted"
      ? `<p class="scan-reason">File removed from Downloads.</p>`
      : `<div class="scan-actions">
          <button type="button" class="scan-delete" data-scan-action="delete" data-download-id="${Number(scan.downloadId)}">Delete file</button>
          <button type="button" data-scan-action="show" data-download-id="${Number(scan.downloadId)}">Download anyway</button>
        </div>`;
  scanPanelEl.innerHTML = `
    <p class="scan-risk" data-risk="${escapeHtml(risk)}">${escapeHtml(risk)}</p>
    <p class="scan-name">${escapeHtml(scan.filename || "download")}</p>
    <p class="scan-reason">${escapeHtml(reason)}</p>
    ${hash ? `<p class="scan-hash">${escapeHtml(hash)}</p>` : ""}
    ${evidence}
    ${actions}
  `;
}

async function loadDownloadScan() {
  const data = await chrome.runtime.sendMessage({ type: "GET_DOWNLOAD_SCANS" });
  renderDownloadScan(data?.latest || latestScanFrom(data?.scans, data?.history));
}

function severity(total) {
  if (total <= 3) return "green";
  if (total <= 10) return "amber";
  return "red";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function renderCategories(data) {
  const blockingOn = Boolean(data.blockingEnabled);
  categoriesEl.innerHTML = CATEGORIES.map((category) => {
    const active = data.activeCounts?.[category.id] ?? 0;
    const blocked = data.blockedCounts?.[category.id] ?? 0;
    const detected = data.counts?.[category.id] ?? active + blocked;
    let countLabel = String(detected);
    if (blockingOn && blocked > 0) {
      countLabel = `${active} live · ${blocked} blk`;
    }
    return `
      <div class="category glass-panel">
        <div class="category-left">
          ${ICONS[category.id]}
          <span>${category.label}</span>
        </div>
        <span class="category-count">${countLabel}</span>
      </div>
    `;
  }).join("");
}

function renderList(data, isHttp) {
  const detected = data.detectedCount ?? data.total ?? 0;
  if (isHttp && detected === 0) {
    listEl.innerHTML = `
      <div class="clean-state">
        <p class="clean-title">This site looks clean.</p>
        <p class="empty">No known trackers loaded on this page.</p>
      </div>
    `;
    return;
  }

  const exceptions = data.trackerExceptions || [];
  const canAllow = Boolean(data.blockingEnabled) && !data.whitelisted && !data.paused;
  const groups = CATEGORIES.map((category) => {
    const active = data.trackers?.[category.id] || [];
    const blocked = data.blockedTrackers?.[category.id] || [];
    if (!active.length && !blocked.length) {
      return "";
    }
    const row = (domain, extraClass) => {
      const excepted = isTrackerExceptedLocal(exceptions, currentHost, domain);
      const action = excepted
        ? `<button type="button" class="allow-btn is-on" data-tracker="${escapeHtml(domain)}" data-remove="1">allowed here</button>`
        : canAllow
          ? `<button type="button" class="allow-btn" data-tracker="${escapeHtml(domain)}">Allow here</button>`
          : "";
      const chip = extraClass.includes("is-blocked") && !excepted
        ? `<span class="chip">blocked</span>`
        : "";
      return `<div class="tracker-item ${excepted ? "is-allowed" : extraClass}"><span>${escapeHtml(domain)}</span><span class="tracker-actions">${chip}${action}</span></div>`;
    };
    const blockedRows = blocked.map((domain) => row(domain, "is-blocked")).join("");
    const activeRows = active.map((domain) => row(domain, "")).join("");
    return `<p class="group-label">${category.label}</p>${blockedRows}${activeRows}`;
  }).join("");

  listEl.innerHTML = groups || `<p class="empty">No known trackers on this page yet.</p>`;
  listEl.querySelectorAll(".allow-btn").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      if (!currentHost) {
        return;
      }
      await chrome.runtime.sendMessage({
        type: button.dataset.remove ? "REMOVE_TRACKER_EXCEPTION" : "ADD_TRACKER_EXCEPTION",
        site: currentHost,
        tracker: button.dataset.tracker
      });
      await load();
    });
  });
}

function isTrackerExceptedLocal(exceptions, site, tracker) {
  const page = String(site || "");
  const host = String(tracker || "");
  return (exceptions || []).some((entry) => {
    const entrySite = entry.site || "";
    const entryTracker = entry.tracker || "";
    const siteMatch = page === entrySite || page.endsWith("." + entrySite) || entrySite.endsWith("." + page);
    const trackerMatch =
      host === entryTracker || host.endsWith("." + entryTracker) || entryTracker.endsWith("." + host);
    return siteMatch && trackerMatch;
  });
}

function renderCategoryToggles(data) {
  const enabled = Boolean(data.blockingEnabled);
  categoryTogglesEl.hidden = !enabled;
  if (!enabled) {
    return;
  }
  const prefs = data.categoryBlocking || {};
  categoryTogglesEl.innerHTML = CATEGORIES.map((category) => {
    const checked = prefs[category.id] ? "checked" : "";
    return `
      <label class="mini-toggle glass-panel">
        <span>${ICONS[category.id]}${category.label}</span>
        <input type="checkbox" data-category="${category.id}" ${checked} />
        <span class="switch mini" aria-hidden="true"></span>
      </label>
    `;
  }).join("");

  categoryTogglesEl.querySelectorAll("input[data-category]").forEach((input) => {
    input.addEventListener("change", async () => {
      if (!currentHost) {
        return;
      }
      await chrome.runtime.sendMessage({
        type: "SET_CATEGORY_BLOCKING",
        host: currentHost,
        category: input.dataset.category,
        enabled: input.checked
      });
      await load();
    });
  });
}

function renderFavicon(url) {
  if (url) {
    faviconEl.src = url;
    faviconEl.hidden = false;
  } else {
    faviconEl.removeAttribute("src");
    faviconEl.hidden = true;
  }
}

function renderSecurityWarnings(data) {
  const forms = data.insecureForms || [];
  if (!forms.length) {
    securityWrapEl.hidden = true;
    securityWarningsEl.innerHTML = "";
    return;
  }
  securityWrapEl.hidden = false;
  const rows = forms
    .map(
      (item) =>
        `<div class="security-item"><strong>Insecure form</strong><span>${escapeHtml(item.method)} → ${escapeHtml(item.action)}</span></div>`
    )
    .join("");
  securityWarningsEl.innerHTML = rows;
}

function renderTrustToggle(data, isHttp) {
  const canTrust = Boolean(currentHost) && isHttp;
  trustToggleEl.disabled = !canTrust;
  trustToggleEl.checked = Boolean(data.whitelisted);
  toggleEl.disabled = !canTrust || Boolean(data.whitelisted);
  if (data.whitelisted) {
    toggleEl.checked = false;
    categoryTogglesEl.hidden = true;
  }
}

function renderLifetime(count) {
  if (!count) {
    lifetimeEl.hidden = true;
    lifetimeEl.textContent = "";
    return;
  }
  const formatted = Number(count).toLocaleString();
  lifetimeEl.hidden = false;
  lifetimeEl.textContent = `Glass has blocked ${formatted} trackers since install.`;
}

function pauseLabel(until) {
  if (until === "startup") {
    return "Blocking is off until the browser restarts.";
  }
  if (typeof until === "number") {
    const mins = Math.max(1, Math.round((until - Date.now()) / 60000));
    return `Blocking is off for about ${mins} more minute${mins === 1 ? "" : "s"}.`;
  }
  return "Blocking is off until you resume.";
}

function renderPause(data) {
  const paused = Boolean(data.paused);
  pauseBannerEl.hidden = !paused;
  pauseControlsEl.hidden = paused;
  if (paused) {
    pauseHintEl.textContent = pauseLabel(data.pauseUntil);
    statusEl.textContent = "Protection paused";
    toggleEl.disabled = true;
    trustToggleEl.disabled = true;
    categoryTogglesEl.hidden = true;
    blockNowBtn.disabled = true;
  }
}

function watchReloadComplete(tabId, onDone) {
  if (reloadWatcher) {
    chrome.tabs.onUpdated.removeListener(reloadWatcher);
    reloadWatcher = null;
  }
  reloadWatcher = (id, info) => {
    if (id === tabId && info.status === "complete") {
      chrome.tabs.onUpdated.removeListener(reloadWatcher);
      reloadWatcher = null;
      onDone();
    }
  };
  chrome.tabs.onUpdated.addListener(reloadWatcher);
}

function render(data, hostFallback, isHttp) {
  const host = data.domain || hostFallback;
  currentHost = host;
  domainEl.textContent = host || "unavailable";
  renderFavicon(data.favIconUrl);

  const detected = data.detectedCount ?? data.total ?? 0;
  const blocked = data.blockedCount ?? 0;
  const active = data.activeCount ?? detected;
  badgeEl.dataset.severity = severity(detected);
  badgeCountEl.textContent = String(detected);

  if (data.blockingEnabled && blocked > 0) {
    badgeLabelEl.textContent = detected === 1 ? "tracker detected" : "trackers detected";
    badgeSplitEl.hidden = false;
    badgeSplitEl.textContent = `${blocked} blocked · ${active} still active`;
  } else {
    badgeLabelEl.textContent = detected === 1 ? "tracker" : "trackers";
    badgeSplitEl.hidden = true;
    badgeSplitEl.textContent = "";
  }

  renderCategories(data);
  renderList(data, isHttp);
  renderCategoryToggles(data);
  renderLifetime(data.lifetimeBlocked || 0);
  renderSecurityWarnings(data);
  renderTrustToggle(data, isHttp);
  renderPause(data);

  const canToggle = Boolean(host) && isHttp && !data.whitelisted && !data.paused;
  toggleEl.disabled = !canToggle;
  toggleEl.checked = Boolean(data.blockingEnabled);
  blockNowBtn.disabled = !canToggle;
  document.body.classList.remove("is-loading");
  document.body.classList.add("is-ready");
}

async function load() {
  loadDownloadScan().catch((error) => console.error(error));
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const pause = await chrome.runtime.sendMessage({ type: "GET_PAUSE" });
  if (!tab) {
    currentTabId = null;
    statusEl.textContent = "No active tab";
    render({ total: 0, counts: {}, trackers: {}, ...(pause || {}) }, null, false);
    return;
  }
  currentTabId = tab.id;

  const isHttp = Boolean(tab.url && /^https?:/i.test(tab.url));
  if (!isHttp) {
    statusEl.textContent = "Open a website to inspect it";
    let host = null;
    try {
      host = new URL(tab.url).hostname.replace(/^www\./, "");
    } catch {
      host = null;
    }
    render(
      {
        total: 0,
        detectedCount: 0,
        counts: {},
        trackers: {},
        favIconUrl: tab.favIconUrl,
        paused: pause?.paused,
        pauseUntil: pause?.until
      },
      host,
      false
    );
    toggleEl.disabled = true;
    blockNowBtn.disabled = true;
    return;
  }

  statusEl.textContent = "Glass is running";
  const data = await chrome.runtime.sendMessage({
    type: "GET_TAB_DATA",
    tabId: tab.id
  });
  if (data && !data.favIconUrl) {
    data.favIconUrl = tab.favIconUrl || "";
  }
  render(
    data || {},
    new URL(tab.url).hostname.replace(/^www\./, ""),
    true
  );
}

toggleEl.addEventListener("change", async () => {
  if (!currentHost) {
    return;
  }
  await chrome.runtime.sendMessage({
    type: "SET_BLOCKING",
    host: currentHost,
    enabled: toggleEl.checked
  });
  await load();
});

trustToggleEl.addEventListener("change", async () => {
  if (!currentHost) {
    return;
  }
  await chrome.runtime.sendMessage({
    type: "SET_WHITELIST",
    host: currentHost,
    trusted: trustToggleEl.checked
  });
  await load();
});

dashboardBtn.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

async function setPause(until) {
  await chrome.runtime.sendMessage({ type: "SET_PAUSE", until });
  await load();
}

pauseControlsEl.querySelectorAll("[data-pause]").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = button.dataset.pause;
    const until = value === "startup" ? "startup" : Date.now() + Number(value);
    await setPause(until);
  });
});

resumeBtn.addEventListener("click", async () => {
  await setPause(null);
});

blockNowBtn.addEventListener("click", async () => {
  if (!currentTabId) {
    return;
  }
  blockNowBtn.disabled = true;
  const result = await chrome.runtime.sendMessage({
    type: "BLOCK_AND_RELOAD",
    tabId: currentTabId
  });
  if (!result?.ok) {
    statusEl.textContent = result?.reason || "Could not reload this tab";
    blockNowBtn.disabled = false;
    return;
  }
  statusEl.textContent = "Reloading to block loaded trackers…";
  watchReloadComplete(currentTabId, () => {
    load().catch((error) => console.error(error));
  });
});

load().catch((error) => {
  statusEl.textContent = "Could not read this tab";
  document.body.classList.remove("is-loading");
  console.error(error);
});

scanPanelEl?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-scan-action]");
  if (!button) {
    return;
  }
  const downloadId = Number(button.dataset.downloadId);
  const type = button.dataset.scanAction === "delete" ? "DELETE_SCANNED_FILE" : "SHOW_SCANNED_FILE";
  button.disabled = true;
  const result = await chrome.runtime.sendMessage({ type, downloadId });
  if (!result?.ok) {
    button.disabled = false;
    return;
  }
  await loadDownloadScan();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") {
    return;
  }
  if (changes.downloadScans || changes.downloadScanHistory) {
    loadDownloadScan().catch((error) => console.error(error));
  }
});
