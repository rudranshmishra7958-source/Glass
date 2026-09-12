importScripts("tracker-list.js");

const RULESET_ID = "ruleset_1";
const tabState = new Map();

const CATEGORIES = ["advertising", "analytics", "social", "other"];

function emptyTrackers() {
  return {
    advertising: new Set(),
    analytics: new Set(),
    social: new Set(),
    other: new Set()
  };
}

function hostnameFromUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return normalizeHost(parsed.hostname);
  } catch {
    return null;
  }
}

function normalizeHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^www\./, "");
}

const MULTI_TLDS = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.jp",
  "ne.jp",
  "or.jp",
  "co.in",
  "com.br",
  "com.mx",
  "co.nz",
  "co.za",
  "com.sg",
  "co.kr",
  "com.tw",
  "com.hk"
]);

function rootDomain(host) {
  const parts = normalizeHost(host).split(".").filter(Boolean);
  if (parts.length <= 2) {
    return parts.join(".");
  }
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

function isFirstParty(pageHost, requestHost) {
  if (!pageHost || !requestHost) {
    return true;
  }
  if (pageHost === requestHost) {
    return true;
  }
  if (requestHost.endsWith("." + pageHost) || pageHost.endsWith("." + requestHost)) {
    return true;
  }
  return rootDomain(pageHost) === rootDomain(requestHost);
}

function ensureTab(tabId, pageUrl) {
  const pageDomain = pageUrl ? hostnameFromUrl(pageUrl) : null;
  const existing = tabState.get(tabId);
  if (existing) {
    if (pageDomain && existing.pageDomain !== pageDomain) {
      existing.pageDomain = pageDomain;
      existing.requests = new Set();
      existing.trackers = emptyTrackers();
    }
    return existing;
  }
  const state = {
    pageDomain,
    requests: new Set(),
    trackers: emptyTrackers()
  };
  tabState.set(tabId, state);
  return state;
}

function resetTab(tabId, pageUrl) {
  const pageDomain = pageUrl ? hostnameFromUrl(pageUrl) : null;
  tabState.set(tabId, {
    pageDomain,
    requests: new Set(),
    trackers: emptyTrackers()
  });
}

function categorizeDomain(host) {
  const normalized = normalizeHost(host);
  for (const category of CATEGORIES) {
    const domains = TRACKER_LIST[category] || [];
    for (const tracker of domains) {
      const t = normalizeHost(tracker);
      if (normalized === t || normalized.endsWith("." + t)) {
        return category;
      }
    }
  }
  return null;
}

function snapshot(tabId) {
  const state = tabState.get(tabId);
  const counts = { advertising: 0, analytics: 0, social: 0, other: 0 };
  const trackers = { advertising: [], analytics: [], social: [], other: [] };
  if (!state) {
    return {
      domain: null,
      counts,
      trackers,
      total: 0,
      thirdPartyCount: 0
    };
  }
  for (const category of CATEGORIES) {
    const list = Array.from(state.trackers[category]).sort();
    trackers[category] = list;
    counts[category] = list.length;
  }
  const total = CATEGORIES.reduce((sum, key) => sum + counts[key], 0);
  return {
    domain: state.pageDomain,
    counts,
    trackers,
    total,
    thirdPartyCount: state.requests.size
  };
}

async function getBlockedSites() {
  const stored = await chrome.storage.local.get("blockedSites");
  return stored.blockedSites || {};
}

async function setSiteBlocked(host, enabled) {
  const blockedSites = await getBlockedSites();
  if (enabled) {
    blockedSites[host] = true;
  } else {
    delete blockedSites[host];
  }
  await chrome.storage.local.set({ blockedSites });
}

async function applyBlockingForHost(host) {
  const blockedSites = await getBlockedSites();
  const enabled = Boolean(host && blockedSites[host]);
  if (enabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: [RULESET_ID]
    });
  } else {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: [RULESET_ID]
    });
  }
  return enabled;
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) {
      return;
    }

    if (details.type === "main_frame") {
      resetTab(details.tabId, details.url);
      console.log("[Glass] navigation", details.tabId, hostnameFromUrl(details.url));
      return;
    }

    const requestHost = hostnameFromUrl(details.url);
    if (!requestHost) {
      return;
    }

    const state = ensureTab(details.tabId);
    if (!state.pageDomain && details.initiator) {
      state.pageDomain = hostnameFromUrl(details.initiator);
    }
    if (!state.pageDomain && details.documentUrl) {
      state.pageDomain = hostnameFromUrl(details.documentUrl);
    }

    if (isFirstParty(state.pageDomain, requestHost)) {
      return;
    }

    const isNew = !state.requests.has(requestHost);
    state.requests.add(requestHost);
    if (isNew) {
      console.log("[Glass] third-party", details.tabId, requestHost);
    }

    const category = categorizeDomain(requestHost);
    if (category && !state.trackers[category].has(requestHost)) {
      state.trackers[category].add(requestHost);
      const snap = snapshot(details.tabId);
      console.log("[Glass] tracker", category, requestHost, snap.counts);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    resetTab(tabId, changeInfo.url);
  } else if (changeInfo.status === "loading" && tab.url) {
    const nextHost = hostnameFromUrl(tab.url);
    const current = tabState.get(tabId);
    if (nextHost && current && current.pageDomain && nextHost !== current.pageDomain) {
      resetTab(tabId, tab.url);
    } else if (!current) {
      ensureTab(tabId, tab.url);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    const host = hostnameFromUrl(tab.url || "");
    await applyBlockingForHost(host);
  } catch (error) {
    console.warn("[Glass] tab activate", error);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "GET_TAB_DATA") {
    (async () => {
      const tabId = message.tabId;
      let host = null;
      try {
        const tab = await chrome.tabs.get(tabId);
        host = hostnameFromUrl(tab.url || "");
        ensureTab(tabId, tab.url);
      } catch {
        host = tabState.get(tabId)?.pageDomain || null;
      }
      const blockedSites = await getBlockedSites();
      const data = snapshot(tabId);
      if (!data.domain) {
        data.domain = host;
      }
      data.blockingEnabled = Boolean(host && blockedSites[host]);
      sendResponse(data);
    })();
    return true;
  }

  if (message?.type === "SET_BLOCKING") {
    (async () => {
      const host = normalizeHost(message.host);
      const enabled = Boolean(message.enabled);
      await setSiteBlocked(host, enabled);
      await applyBlockingForHost(host);
      sendResponse({ ok: true, blockingEnabled: enabled, host });
    })();
    return true;
  }

  return false;
});

async function syncActiveTabBlocking() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      await applyBlockingForHost(hostnameFromUrl(tab.url || ""));
    }
  } catch (error) {
    console.warn("[Glass] sync blocking", error);
  }
}

chrome.runtime.onInstalled.addListener(syncActiveTabBlocking);
chrome.runtime.onStartup.addListener(syncActiveTabBlocking);
syncActiveTabBlocking();

console.log("[Glass] service worker ready");
