const CATEGORIES = [
  { id: "advertising", label: "Advertising" },
  { id: "analytics", label: "Analytics" },
  { id: "social", label: "Social" },
  { id: "other", label: "Other" }
];

const domainEl = document.getElementById("domain");
const statusEl = document.getElementById("status");
const badgeEl = document.getElementById("badge");
const badgeCountEl = document.getElementById("badge-count");
const badgeLabelEl = document.getElementById("badge-label");
const categoriesEl = document.getElementById("categories");
const listEl = document.getElementById("tracker-list");
const toggleEl = document.getElementById("block-toggle");

let currentHost = null;

function severity(total) {
  if (total <= 3) return "green";
  if (total <= 10) return "amber";
  return "red";
}

function renderCategories(counts) {
  categoriesEl.innerHTML = CATEGORIES.map((category) => {
    const count = counts?.[category.id] ?? 0;
    return `
      <div class="category">
        <div class="category-left">
          <span class="dot dot-${category.id}"></span>
          <span>${category.label}</span>
        </div>
        <span class="category-count">${count}</span>
      </div>
    `;
  }).join("");
}

function renderList(trackers) {
  const groups = CATEGORIES.map((category) => {
    const items = trackers?.[category.id] || [];
    if (!items.length) {
      return "";
    }
    const rows = items
      .map((domain) => `<div class="tracker-item">${domain}</div>`)
      .join("");
    return `<p class="group-label">${category.label}</p>${rows}`;
  }).join("");

  listEl.innerHTML = groups || `<p class="empty">No known trackers on this page yet.</p>`;
}

function render(data, hostFallback) {
  const host = data.domain || hostFallback;
  currentHost = host;
  domainEl.textContent = host || "unavailable";

  const total = data.total || 0;
  badgeEl.dataset.severity = severity(total);
  badgeCountEl.textContent = String(total);
  badgeLabelEl.textContent = total === 1 ? "tracker" : "trackers";

  renderCategories(data.counts || {});
  renderList(data.trackers || {});

  const canToggle = Boolean(host);
  toggleEl.disabled = !canToggle;
  toggleEl.checked = Boolean(data.blockingEnabled);
}

async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    statusEl.textContent = "No active tab";
    render({ total: 0, counts: {}, trackers: {} }, null);
    return;
  }

  const isHttp = tab.url && /^https?:/i.test(tab.url);
  if (!isHttp) {
    statusEl.textContent = "Open a website to inspect it";
    let host = null;
    try {
      host = new URL(tab.url).hostname;
    } catch {
      host = null;
    }
    render({ total: 0, counts: {}, trackers: {} }, host);
    toggleEl.disabled = true;
    return;
  }

  statusEl.textContent = "Glass is running";
  const data = await chrome.runtime.sendMessage({
    type: "GET_TAB_DATA",
    tabId: tab.id
  });
  render(data || {}, new URL(tab.url).hostname.replace(/^www\./, ""));
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
});

load().catch((error) => {
  statusEl.textContent = "Could not read this tab";
  console.error(error);
});
