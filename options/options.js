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
  const height = 140;
  const barWidth = 56;
  const gap = 20;
  const chartLeft = 28;
  const chartBottom = 118;
  const bars = days
    .map((day, index) => {
      const barHeight = Math.round((day.blocked / max) * 90);
      const x = chartLeft + index * (barWidth + gap);
      const y = chartBottom - barHeight;
      return `
        <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6" fill="#5b7c99"></rect>
        <text x="${x + barWidth / 2}" y="${y - 6}" text-anchor="middle" class="chart-value">${day.blocked}</text>
        <text x="${x + barWidth / 2}" y="136" text-anchor="middle" class="chart-label">${escapeHtml(day.label)}</text>
      `;
    })
    .join("");
  document.getElementById("overview-chart").innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Trackers blocked over the last 7 days">
      ${bars}
    </svg>
  `;
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
    summaryEl.textContent = "No website tabs are open. Open a site in another tab — this list updates every few seconds.";
    listEl.innerHTML = "";
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
                <span class="hint">${tab.detectedCount} detected · ${tab.blockedCount} blocked · ${tab.activeCount} active</span>
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

function renderThreats(data) {
  const list = data.threatLog || [];
  const el = document.getElementById("threat-list");
  if (!list.length) {
    el.innerHTML = `<p class="hint">No phishing or malware redirects logged yet.</p>`;
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

function renderHistory(data) {
  const history = data.visitHistory || {};
  const days = Object.keys(history).sort().reverse();
  const el = document.getElementById("history-list");
  if (!days.length) {
    el.innerHTML = `<p class="hint">Browse a few sites with Glass loaded, then reopen this tab.</p>`;
    return;
  }
  const rows = [
    `<div class="row header history-row"><span>Site</span><span>Detected / blocked</span><span>Day</span><span></span></div>`
  ];
  for (const day of days) {
    const sites = Object.entries(history[day] || {}).sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0));
    for (const [host, stats] of sites) {
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
  el.innerHTML = rows.join("");
  el.querySelectorAll(".row-delete").forEach((button) => {
    button.addEventListener("click", async () => {
      const result = await chrome.runtime.sendMessage({
        type: "DELETE_HISTORY_ENTRY",
        day: button.dataset.day,
        host: button.dataset.host
      });
      dashboardCache.visitHistory = result.visitHistory || {};
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
  const liveVisible = currentTabId() === "live" && document.visibilityState === "visible";
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

async function load() {
  const data = await chrome.runtime.sendMessage({ type: "GET_DASHBOARD_DATA" });
  dashboardCache = data || {};
  renderOverview(dashboardCache);
  renderThreats(dashboardCache);
  renderHistory(dashboardCache);
  renderSettings(dashboardCache);
  if (currentTabId() === "live") {
    await refreshLive();
  }
}

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
  renderHistory(dashboardCache);
  renderOverview(dashboardCache);
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

load().catch((error) => {
  console.error(error);
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "complete" && pendingReloads.has(tabId)) {
    pendingReloads.delete(tabId);
    refreshLive().catch((error) => console.error(error));
  }
});
