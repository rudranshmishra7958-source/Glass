const CATEGORIES = [
  { id: "advertising", label: "Advertising" },
  { id: "analytics", label: "Analytics" },
  { id: "social", label: "Social" },
  { id: "other", label: "Other" }
];

let expandedTabId = null;
let liveTimer = null;
let dashboardCache = {};
const pendingReloads = new Set();
const historyFilters = {
  site: null,
  category: null,
  date: null
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts);
  }
}

function currentTabId() {
  const active = document.querySelector(".tab.is-active");
  return active?.dataset.tab || "overview";
}

function switchTab(id) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("is-active", tab.dataset.tab === id);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("is-active", panel.id === "panel-" + id);
  });
  syncLivePolling();
}

function dateKey(offsetDays) {
  const date = new Date();
  date.setDate(date.getDate() - offsetDays);
  return date.toISOString().slice(0, 10);
}

function dayTotals(history) {
  const days = [];
  for (let i = 6; i >= 0; i -= 1) {
    const key = dateKey(i);
    const labelDate = new Date();
    labelDate.setDate(labelDate.getDate() - i);
    let blocked = 0;
    for (const site of Object.values(history[key] || {})) {
      blocked += Number(site.blocked) || 0;
    }
    days.push({
      key,
      blocked,
      label: labelDate.toLocaleDateString(undefined, { weekday: "short" })
    });
  }
  return days;
}

function renderChart(history) {
  const days = dayTotals(history || {});
  const max = Math.max(1, ...days.map((day) => day.blocked));
  const width = 560;
  const height = 148;
  const barWidth = 56;
  const gap = 20;
  const chartLeft = 28;
  const chartBottom = 124;
  const bars = days
    .map((day, index) => {
      const barHeight = Math.round((day.blocked / max) * 100);
      const x = chartLeft + index * (barWidth + gap);
      const y = chartBottom - barHeight;
      return `
        <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6" fill="url(#glassBar)"></rect>
        <text x="${x + barWidth / 2}" y="${y - 6}" text-anchor="middle" class="chart-value">${day.blocked}</text>
        <text x="${x + barWidth / 2}" y="144" text-anchor="middle" class="chart-label">${escapeHtml(day.label)}</text>
      `;
    })
    .join("");
  document.getElementById("overview-chart").innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Trackers blocked over the last 7 days">
      <defs>
        <linearGradient id="glassBar" x1="0" y1="1" x2="0" y2="0">
          <stop offset="0%" stop-color="#5b7c99"></stop>
          <stop offset="100%" stop-color="#7ea3c4"></stop>
        </linearGradient>
      </defs>
      ${bars}
    </svg>
  `;
}

function renderWatchers(
  watchers,
  {
    targetId = "watchers-list",
    limit = 6,
    emptyMessage = "Browse a few sites — companies appear after Glass records trackers.",
    rowClass = "watchers-row"
  } = {}
) {
  const list = document.getElementById(targetId);
  if (!list) {
    return;
  }
  const source = Array.isArray(watchers) ? watchers : [];
  const rows = limit == null ? source : source.slice(0, limit);
  if (!rows.length) {
    list.innerHTML = `<p class="hint">${emptyMessage}</p>`;
    return;
  }
  const maxCount = Math.max(...rows.map((row) => Number(row.count) || 0), 1);
  list.innerHTML = rows
    .map((row) => {
      const count = Number(row.count) || 0;
      const width = Math.max(0, Math.min(100, (count / maxCount) * 100));
      return `<div class="${rowClass}">
      <span class="watchers-name">${escapeHtml(row.company || "Unknown")}</span>
      <span class="watchers-bar"><span style="width: ${width}%"></span></span>
      <span class="watchers-count">${count.toLocaleString()}</span>
    </div>`;
    })
    .join("");
}

function renderWatchersFocus(data) {
  const view = document.getElementById("watchers-view");
  view?.classList.remove("is-revealed");
  renderWatchers(data?.watchers, {
    targetId: "watchers-focus-list",
    limit: null,
    rowClass: "watchers-row watchers-focus-row"
  });
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      view?.classList.add("is-revealed");
    });
  });
}

function renderOverview(data) {
  document.getElementById("stat-blocked").textContent = Number(
    data.lifetimeBlocked || 0
  ).toLocaleString();
  document.getElementById("stat-threats").textContent = Number(
    data.lifetimeThreatsBlocked || 0
  ).toLocaleString();
  document.getElementById("stat-score").textContent = `${data.protectionScore || 0}%`;
  renderChart(data.visitHistory);
  renderWatchers(data.watchers, { targetId: "watchers-list", limit: 6 });
}

function trackerGroupsHtml(tab) {
  const groups = CATEGORIES.map((category) => {
    const blockedItems = tab.blockedTrackers?.[category.id] || [];
    const activeItems = tab.trackers?.[category.id] || [];
    if (!blockedItems.length && !activeItems.length) {
      return "";
    }
    const blockedRows = blockedItems
      .map(
        (domain) =>
          `<div class="tracker-item"><span>${escapeHtml(domain)}</span><span class="chip">blocked</span></div>`
      )
      .join("");
    const activeRows = activeItems
      .map((domain) => `<div class="tracker-item"><span>${escapeHtml(domain)}</span></div>`)
      .join("");
    return `<p class="group-label">${category.label}</p>${blockedRows}${activeRows}`;
  }).join("");
  return groups || `<p class="hint">No known trackers on this page.</p>`;
}

function renderLive(payload) {
  const tabs = payload?.tabs || [];
  const summaryEl = document.getElementById("live-summary");
  const listEl = document.getElementById("live-list");
  if (!tabs.length) {
    summaryEl.textContent = "";
    listEl.innerHTML =
      `<p class="workspace-empty">No website tabs are open.</p><p class="hint">Open a site in another tab — this list updates every few seconds.</p>`;
    return;
  }
  summaryEl.textContent = `${tabs.length} open site${tabs.length === 1 ? "" : "s"}, sorted by tracker count.`;
  listEl.innerHTML = tabs
    .map((tab) => {
      const open = Number(expandedTabId) === Number(tab.tabId);
      const favicon = tab.favIconUrl
        ? `<img class="live-favicon" src="${escapeHtml(tab.favIconUrl)}" alt="" />`
        : `<span class="live-favicon"></span>`;
      return `
        <article class="live-row${open ? " is-open" : ""}" data-tab-id="${tab.tabId}">
          <div class="live-top">
            <button type="button" class="live-head" data-tab-id="${tab.tabId}">
              ${favicon}
              <span class="live-meta">
                <strong>${escapeHtml(tab.domain || "unknown")}</strong>
                <span class="live-counts">
                  <span class="live-count">${tab.detectedCount} detected</span>
                  <span class="live-count live-count--blocked">${tab.blockedCount} blocked</span>
                  <span class="live-count live-count--active">${tab.activeCount} active</span>
                </span>
              </span>
            </button>
            <div class="live-actions">
              <button type="button" class="live-action" data-refresh="${tab.tabId}">Refresh</button>
              <button type="button" class="live-action" data-block="${tab.tabId}">Block active now</button>
            </div>
          </div>
          ${open ? `<div class="live-detail">${trackerGroupsHtml(tab)}</div>` : ""}
        </article>
      `;
    })
    .join("");

  listEl.querySelectorAll(".live-head").forEach((button) => {
    button.addEventListener("click", () => {
      const id = Number(button.dataset.tabId);
      expandedTabId = expandedTabId === id ? null : id;
      renderLive(payload);
    });
  });

  listEl.querySelectorAll("[data-refresh]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      refreshLive().catch((error) => console.error(error));
    });
  });

  listEl.querySelectorAll("[data-block]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      const tabId = Number(button.dataset.block);
      button.disabled = true;
      const result = await chrome.runtime.sendMessage({
        type: "BLOCK_AND_RELOAD",
        tabId
      });
      if (!result?.ok) {
        button.disabled = false;
        return;
      }
      pendingReloads.add(tabId);
    });
  });
}

function renderDownloads(data) {
  const el = document.getElementById("downloads-list");
  const list = data.downloadScanHistory || [];
  if (!list.length) {
    el.innerHTML = `<p class="workspace-empty">Download a file with Glass loaded — scans appear here after they finish.</p>`;
    return;
  }
  el.innerHTML =
    `<div class="row header download-row"><span>File</span><span>Verdict</span><span>When</span><span></span></div>` +
    list
      .map((item) => {
        const risk = item.risk || item.report?.assessment?.risk || item.status || "UNKNOWN";
        const deleted = item.action === "deleted";
        const scanning = item.status === "scanning";
        const actions = scanning
          ? `<span class="hint">Scanning…</span>`
          : deleted
          ? `<span class="hint">Removed</span>`
          : `<span class="download-actions">
              <button type="button" class="remove" data-scan-action="delete" data-download-id="${Number(item.downloadId)}">Delete</button>
              <button type="button" class="watchers-see-all" data-scan-action="show" data-download-id="${Number(item.downloadId)}">Show</button>
            </span>`;
        return `<div class="row download-row">
          <span class="mono">${escapeHtml(item.filename || "download")}</span>
          <span class="scan-verdict" data-risk="${escapeHtml(risk)}">${escapeHtml(risk)}</span>
          <span>${escapeHtml(formatTime(item.ts))}</span>
          ${actions}
        </div>`;
      })
      .join("");
  el.querySelectorAll("[data-scan-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const type =
        button.dataset.scanAction === "delete" ? "DELETE_SCANNED_FILE" : "SHOW_SCANNED_FILE";
      const result = await chrome.runtime.sendMessage({
        type,
        downloadId: Number(button.dataset.downloadId)
      });
      if (result?.history) {
        dashboardCache.downloadScanHistory = result.history;
      }
      if (result?.ok) {
        renderDownloads(dashboardCache);
      }
    });
  });
}

function renderThreats(data) {
  const list = data.threatLog || [];
  const el = document.getElementById("threat-list");
  if (!list.length) {
    el.innerHTML = `<p class="workspace-empty">No phishing or malware redirects logged yet.</p>`;
    return;
  }
  el.innerHTML =
    `<div class="row header threat-row"><span>Domain</span><span>Encountered on</span><span>When</span></div>` +
    list
      .map(
        (item) =>
          `<div class="row threat-row"><span class="mono">${escapeHtml(item.domain)}</span><span class="mono">${escapeHtml(item.site || item.domain)}</span><span>${escapeHtml(formatTime(item.ts))}</span></div>`
      )
      .join("");
}

function historyRowMatches(host, day, stats) {
  if (historyFilters.site && host !== historyFilters.site) {
    return false;
  }
  if (historyFilters.date && day !== historyFilters.date) {
    return false;
  }
  if (historyFilters.category) {
    if (!stats.counts) {
      return false;
    }
    return Number(stats.counts[historyFilters.category]) > 0;
  }
  return true;
}

function renderHistory(data) {
  const history = data.visitHistory || {};
  const days = Object.keys(history).sort().reverse();
  const el = document.getElementById("history-list");
  const hasHistory = days.some((day) => Object.keys(history[day] || {}).length);
  if (!hasHistory) {
    el.innerHTML = `<p class="workspace-empty">Browse a few sites with Glass loaded, then reopen this tab.</p>`;
    return;
  }
  const rows = [
    `<div class="row header history-row"><span>Site</span><span>Detected / blocked</span><span>Day</span><span></span></div>`
  ];
  let matchCount = 0;
  for (const day of days) {
    const sites = Object.entries(history[day] || {}).sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0));
    for (const [host, stats] of sites) {
      if (!historyRowMatches(host, day, stats)) {
        continue;
      }
      matchCount += 1;
      rows.push(
        `<div class="row history-row">
          <span class="mono">${escapeHtml(host)}</span>
          <span>${stats.detected || 0} / ${stats.blocked || 0}</span>
          <span>${escapeHtml(day)}</span>
          <button type="button" class="remove row-delete" data-day="${escapeHtml(day)}" data-host="${escapeHtml(host)}" aria-label="Delete ${escapeHtml(host)} on ${escapeHtml(day)}">×</button>
        </div>`
      );
    }
  }
  if (!matchCount) {
    el.innerHTML = `<p class="workspace-empty">No visits match these filters.</p>`;
    return;
  }
  el.innerHTML = rows.join("");
  el.querySelectorAll(".row-delete").forEach((button) => {
    button.addEventListener("click", async () => {
      const result = await chrome.runtime.sendMessage({
        type: "DELETE_HISTORY_ENTRY",
        day: button.dataset.day,
        host: button.dataset.host
      });
      dashboardCache.visitHistory = result.visitHistory || {};
      fillHistoryFilterOptions(dashboardCache.visitHistory);
      renderHistory(dashboardCache);
      renderOverview(dashboardCache);
    });
  });
}

function renderWhitelist(list) {
  const whitelist = list || [];
  const listEl = document.getElementById("whitelist-list");
  if (!whitelist.length) {
    listEl.innerHTML = `<p class="hint">No trusted sites yet.</p>`;
    return;
  }
  listEl.innerHTML = whitelist
    .map(
      (host) =>
        `<div class="whitelist-row"><span class="mono">${escapeHtml(host)}</span><button type="button" class="remove" data-host="${escapeHtml(host)}" aria-label="Remove ${escapeHtml(host)}">×</button></div>`
    )
    .join("");
  listEl.querySelectorAll("button[data-host]").forEach((button) => {
    button.addEventListener("click", async () => {
      const result = await chrome.runtime.sendMessage({
        type: "REMOVE_WHITELIST_ENTRY",
        host: button.dataset.host
      });
      dashboardCache.whitelist = result.whitelist || [];
      renderWhitelist(dashboardCache.whitelist);
    });
  });
}

function renderSettings(data) {
  const prefs = data.settings?.defaultCategoryBlocking || {};
  const toggles = document.getElementById("default-toggles");
  toggles.innerHTML = CATEGORIES.map((category) => {
    const checked = prefs[category.id] ? "checked" : "";
    return `<label class="setting-row"><span>${category.label}</span><input type="checkbox" data-default-cat="${category.id}" ${checked} /></label>`;
  }).join("");

  toggles.querySelectorAll("input[data-default-cat]").forEach((input) => {
    input.addEventListener("change", async () => {
      const next = { ...prefs, [input.dataset.defaultCat]: input.checked };
      await chrome.runtime.sendMessage({
        type: "UPDATE_SETTINGS",
        settings: { defaultCategoryBlocking: next }
      });
      dashboardCache.settings = {
        ...(dashboardCache.settings || {}),
        defaultCategoryBlocking: next
      };
    });
  });

  renderWhitelist(data.whitelist);
  renderExceptions(data.trackerExceptions);

  const cosmetic = document.getElementById("cosmetic-toggle");
  cosmetic.checked = data.settings?.cosmeticFiltering !== false;
  cosmetic.onchange = async () => {
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      settings: { cosmeticFiltering: cosmetic.checked }
    });
  };
}

function renderExceptions(list) {
  const el = document.getElementById("exception-list");
  const exceptions = list || [];
  if (!exceptions.length) {
    el.innerHTML = `<p class="hint">No per-tracker allows yet. Use “Allow here” in the popup.</p>`;
    return;
  }
  el.innerHTML = exceptions
    .map(
      (item) =>
        `<div class="whitelist-row"><span class="mono">${escapeHtml(item.tracker)} on ${escapeHtml(item.site)}</span><button type="button" class="remove" data-site="${escapeHtml(item.site)}" data-tracker="${escapeHtml(item.tracker)}">×</button></div>`
    )
    .join("");
  el.querySelectorAll("button[data-tracker]").forEach((button) => {
    button.addEventListener("click", async () => {
      const result = await chrome.runtime.sendMessage({
        type: "REMOVE_TRACKER_EXCEPTION",
        site: button.dataset.site,
        tracker: button.dataset.tracker
      });
      dashboardCache.trackerExceptions = result.trackerExceptions || [];
      renderExceptions(dashboardCache.trackerExceptions);
    });
  });
}

async function refreshLive() {
  const data = await chrome.runtime.sendMessage({ type: "GET_LIVE_TABS" });
  renderLive(data || { tabs: [] });
}

function syncLivePolling() {
  const liveVisible =
    document.body.classList.contains("tool-active") &&
    currentTabId() === "live" &&
    document.visibilityState === "visible";
  if (liveVisible && !liveTimer) {
    refreshLive().catch((error) => console.error(error));
    liveTimer = setInterval(() => {
      refreshLive().catch((error) => console.error(error));
    }, 3000);
  }
  if (!liveVisible && liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
}

const FILTER_TITLES = {
  site: "Site",
  category: "Category",
  date: "Date"
};

function closeHistoryFilters() {
  document.querySelectorAll(".filter-menu.is-open").forEach((menu) => {
    menu.classList.remove("is-open");
  });
  document.querySelectorAll(".filter-chip[aria-expanded='true']").forEach((chip) => {
    chip.setAttribute("aria-expanded", "false");
  });
}

function setFilterChipLabel(key, value, label) {
  const chip = document.querySelector(`.filter-chip[data-filter="${key}"]`);
  if (!chip) {
    return;
  }
  const title = FILTER_TITLES[key];
  const text = value ? `${title}: ${label}` : `${title}: any`;
  chip.querySelector(".filter-chip-label").textContent = text;
  chip.classList.toggle("has-value", Boolean(value));
  const clear = chip.querySelector(".filter-clear");
  if (clear) {
    clear.hidden = !value;
  }
}

function applyHistoryFilter(key, value, label) {
  historyFilters[key] = value || null;
  setFilterChipLabel(key, value, label);
  renderHistory(dashboardCache);
}

function resetHistoryFilters() {
  historyFilters.site = null;
  historyFilters.category = null;
  historyFilters.date = null;
  setFilterChipLabel("site", "", "");
  setFilterChipLabel("category", "", "");
  setFilterChipLabel("date", "", "");
}

function fillHistoryFilterOptions(history) {
  const sites = new Set();
  const days = Object.keys(history || {}).sort().reverse();
  for (const day of days) {
    for (const host of Object.keys(history[day] || {})) {
      sites.add(host);
    }
  }
  const siteMenu = document.getElementById("filter-menu-site");
  siteMenu.innerHTML =
    `<button type="button" class="filter-option" data-value="">any</button>` +
    Array.from(sites)
      .sort()
      .map(
        (host) =>
          `<button type="button" class="filter-option" data-value="${escapeHtml(host)}">${escapeHtml(host)}</button>`
      )
      .join("");
  const dateMenu = document.getElementById("filter-menu-date");
  dateMenu.innerHTML =
    `<button type="button" class="filter-option" data-value="">any</button>` +
    days
      .map(
        (day) =>
          `<button type="button" class="filter-option" data-value="${escapeHtml(day)}">${escapeHtml(day)}</button>`
      )
      .join("");
}

async function load() {
  const data = await chrome.runtime.sendMessage({ type: "GET_DASHBOARD_DATA" });
  dashboardCache = data || {};
  renderOverview(dashboardCache);
  renderThreats(dashboardCache);
  renderHistory(dashboardCache);
  renderDownloads(dashboardCache);
  fillHistoryFilterOptions(dashboardCache.visitHistory);
  renderSettings(dashboardCache);
  if (document.body.classList.contains("watchers-active")) {
    renderWatchersFocus(dashboardCache);
  }
  if (currentTabId() === "live") {
    await refreshLive();
  }
}

document.getElementById("history-filters").addEventListener("click", (event) => {
  const clear = event.target.closest(".filter-clear");
  if (clear) {
    event.stopPropagation();
    applyHistoryFilter(clear.dataset.clear, "", "");
    closeHistoryFilters();
    return;
  }
  const option = event.target.closest(".filter-option");
  if (option) {
    event.stopPropagation();
    const wrap = option.closest(".filter-chip-wrap");
    const chip = wrap.querySelector(".filter-chip");
    const value = option.dataset.value || "";
    applyHistoryFilter(chip.dataset.filter, value, option.textContent.trim());
    closeHistoryFilters();
    return;
  }
  const chip = event.target.closest(".filter-chip");
  if (!chip) {
    return;
  }
  event.stopPropagation();
  const menu = chip.parentElement.querySelector(".filter-menu");
  const willOpen = !menu.classList.contains("is-open");
  closeHistoryFilters();
  if (willOpen) {
    menu.classList.add("is-open");
    chip.setAttribute("aria-expanded", "true");
  }
});

document.addEventListener("click", (event) => {
  if (!event.target.closest("#history-filters")) {
    closeHistoryFilters();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeHistoryFilters();
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

document.addEventListener("visibilitychange", syncLivePolling);

document.getElementById("regen-rules").addEventListener("click", async () => {
  const status = document.getElementById("regen-status");
  const result = await chrome.runtime.sendMessage({ type: "REGENERATE_RULES" });
  status.textContent = result?.message || "Done.";
});

document.getElementById("trust-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("trust-input");
  const errorEl = document.getElementById("trust-error");
  const result = await chrome.runtime.sendMessage({
    type: "ADD_WHITELIST_ENTRY",
    host: input.value
  });
  if (!result?.ok) {
    errorEl.hidden = false;
    errorEl.textContent = result?.error || "Could not add that domain.";
    return;
  }
  errorEl.hidden = true;
  input.value = "";
  dashboardCache.whitelist = result.whitelist || [];
  renderWhitelist(dashboardCache.whitelist);
});

document.getElementById("clear-history").addEventListener("click", async () => {
  if (!confirm("Clear the last 7 days of visit history? This cannot be undone.")) {
    return;
  }
  await chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
  dashboardCache.visitHistory = {};
  dashboardCache.protectionScore = 0;
  resetHistoryFilters();
  fillHistoryFilterOptions(dashboardCache.visitHistory);
  renderHistory(dashboardCache);
  renderOverview(dashboardCache);
  if (document.body.classList.contains("watchers-active")) {
    renderWatchersFocus(dashboardCache);
  }
});

document.getElementById("export-data").addEventListener("click", async () => {
  const data = await chrome.runtime.sendMessage({ type: "GET_DASHBOARD_DATA" });
  const payload = {
    exportedAt: new Date().toISOString(),
    history: data?.visitHistory || {},
    threatLog: data?.threatLog || [],
    whitelist: data?.whitelist || []
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().slice(0, 10);
  await chrome.downloads.download({
    url,
    filename: `glass-export-${stamp}.json`,
    saveAs: true
  });
});

function initLandingReveal() {
  const features = document.querySelectorAll(".landing-feature");
  if (!features.length) {
    return;
  }
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    features.forEach((feature) => feature.classList.add("is-visible"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) {
          continue;
        }
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    },
    { threshold: 0.15, rootMargin: "0px 0px -40px 0px" }
  );
  features.forEach((feature) => observer.observe(feature));
}

function showDashboard(tab) {
  document.body.classList.remove("landing-active", "watchers-active");
  document.body.classList.add("tool-active");
  document.getElementById("landing-view").setAttribute("aria-hidden", "true");
  document.getElementById("watchers-view").setAttribute("aria-hidden", "true");
  document.getElementById("watchers-view").classList.remove("is-revealed");
  document.getElementById("dashboard-tool").removeAttribute("aria-hidden");
  if (tab) {
    switchTab(tab);
  }
  window.GlassLattice?.stop();
  syncLivePolling();
}

function showLanding() {
  document.body.classList.remove("tool-active", "watchers-active");
  document.body.classList.add("landing-active");
  document.getElementById("landing-view").removeAttribute("aria-hidden");
  document.getElementById("dashboard-tool").setAttribute("aria-hidden", "true");
  document.getElementById("watchers-view").setAttribute("aria-hidden", "true");
  document.getElementById("watchers-view").classList.remove("is-revealed");
  window.GlassLattice?.start();
  syncLivePolling();
}

async function showWatchers() {
  document.body.classList.remove("landing-active", "tool-active");
  document.body.classList.add("watchers-active");
  document.getElementById("landing-view").setAttribute("aria-hidden", "true");
  document.getElementById("dashboard-tool").setAttribute("aria-hidden", "true");
  document.getElementById("watchers-view").removeAttribute("aria-hidden");
  window.GlassLattice?.stop();
  syncLivePolling();
  if (!Array.isArray(dashboardCache.watchers)) {
    try {
      await load();
    } catch (error) {
      console.error(error);
    }
  }
  renderWatchersFocus(dashboardCache);
}

function initCubeSpinners() {
  const spinners = document.querySelectorAll(".cube-spinner");
  if (!spinners.length || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }
  spinners.forEach((el) => el.classList.add("is-js-driven"));
  const started = performance.now();
  const spin = (now) => {
    const angle = ((now - started) / 14000) * 360;
    const transform = `rotateX(-20deg) rotateY(${angle}deg)`;
    spinners.forEach((el) => {
      el.style.transform = transform;
    });
    requestAnimationFrame(spin);
  };
  requestAnimationFrame(spin);
}

document.getElementById("landing-enter").addEventListener("click", () => showDashboard());
document.getElementById("brand-home").addEventListener("click", showLanding);
document.getElementById("landing-watchers-portal").addEventListener("click", () => {
  showWatchers().catch((error) => console.error(error));
});
document.getElementById("overview-watchers-all").addEventListener("click", () => {
  showWatchers().catch((error) => console.error(error));
});
document.getElementById("watchers-back").addEventListener("click", showLanding);
document.getElementById("watchers-dashboard").addEventListener("click", () => showDashboard("overview"));
document.getElementById("landing-xray").addEventListener("click", () => {
  showWatchers().catch((error) => console.error(error));
});
document.getElementById("landing-xray").addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    showWatchers().catch((error) => console.error(error));
  }
});
initLandingReveal();
initCubeSpinners();

load().catch((error) => {
  console.error(error);
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "complete" && pendingReloads.has(tabId)) {
    pendingReloads.delete(tabId);
    refreshLive().catch((error) => console.error(error));
  }
});
