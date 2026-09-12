const CATEGORIES = [
  { id: "advertising", label: "Advertising" },
  { id: "analytics", label: "Analytics" },
  { id: "social", label: "Social" },
  { id: "other", label: "Other" }
];

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

function switchTab(id) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("is-active", tab.dataset.tab === id);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("is-active", panel.id === "panel-" + id);
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
}

function renderLive(data) {
  const live = data.live;
  const domainEl = document.getElementById("live-domain");
  const summaryEl = document.getElementById("live-summary");
  const listEl = document.getElementById("live-list");
  if (!live || !live.domain) {
    domainEl.textContent = "Current tab";
    summaryEl.textContent = "Open a website, then return here to inspect live trackers.";
    listEl.innerHTML = "";
    return;
  }
  domainEl.textContent = live.domain;
  const detected = live.detectedCount || 0;
  const blocked = live.blockedCount || 0;
  const active = live.activeCount || 0;
  summaryEl.textContent = live.blockingEnabled
    ? `${detected} detected · ${blocked} blocked · ${active} still active`
    : `${detected} trackers detected`;

  const groups = CATEGORIES.map((category) => {
    const blockedItems = live.blockedTrackers?.[category.id] || [];
    const activeItems = live.trackers?.[category.id] || [];
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
  listEl.innerHTML = groups || `<p class="hint">No known trackers on this page.</p>`;
}

function renderThreats(data) {
  const list = data.threatLog || [];
  const el = document.getElementById("threat-list");
  if (!list.length) {
    el.innerHTML = `<p class="hint">No phishing or malware redirects logged yet.</p>`;
    return;
  }
  el.innerHTML =
    `<div class="row header"><span>Domain</span><span>When</span><span></span></div>` +
    list
      .map(
        (item) =>
          `<div class="row"><span class="mono">${escapeHtml(item.domain)}</span><span>${escapeHtml(formatTime(item.ts))}</span><span></span></div>`
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
  const rows = [];
  rows.push(
    `<div class="row header"><span>Site</span><span>Detected / blocked</span><span>Day</span></div>`
  );
  for (const day of days) {
    const sites = Object.entries(history[day] || {}).sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0));
    for (const [host, stats] of sites) {
      rows.push(
        `<div class="row"><span class="mono">${escapeHtml(host)}</span><span>${stats.detected || 0} / ${stats.blocked || 0}</span><span>${escapeHtml(day)}</span></div>`
      );
    }
  }
  el.innerHTML = rows.join("");
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
      await load();
    });
  });

  const whitelist = data.whitelist || [];
  const listEl = document.getElementById("whitelist-list");
  if (!whitelist.length) {
    listEl.innerHTML = `<p class="hint">No trusted sites yet. Use “Trust this site” in the popup.</p>`;
    return;
  }
  listEl.innerHTML = whitelist
    .map(
      (host) =>
        `<div class="whitelist-row"><span class="mono">${escapeHtml(host)}</span><button type="button" class="remove" data-host="${escapeHtml(host)}">Remove</button></div>`
    )
    .join("");
  listEl.querySelectorAll("button[data-host]").forEach((button) => {
    button.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({
        type: "REMOVE_WHITELIST_ENTRY",
        host: button.dataset.host
      });
      await load();
    });
  });
}

async function load() {
  const data = await chrome.runtime.sendMessage({ type: "GET_DASHBOARD_DATA" });
  renderOverview(data || {});
  renderLive(data || {});
  renderThreats(data || {});
  renderHistory(data || {});
  renderSettings(data || {});
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

document.getElementById("regen-rules").addEventListener("click", async () => {
  const status = document.getElementById("regen-status");
  const result = await chrome.runtime.sendMessage({ type: "REGENERATE_RULES" });
  status.textContent = result?.message || "Done.";
});

load().catch((error) => {
  console.error(error);
});
