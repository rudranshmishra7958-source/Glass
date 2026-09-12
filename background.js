importScripts("rule-index.js", "tracker-list.js", "threat-list.js");

const tabState = new Map();
const SEVERITY_COLORS = {
  green: "#2f6f4e",
  amber: "#8a5a12",
  red: "#8b3a32"
};

const RISKY_DOWNLOAD =
  /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|zip|rar|mp3|mp4|avi)\.(exe|js|bat|scr|com|vbs|msi|cmd|ps1|jar|dll|apk)$/i;

function emptyTrackers() {
  return {
    advertising: new Set(),
    analytics: new Set(),
    social: new Set(),
    other: new Set()
  };
}

function emptyCounts() {
  return { advertising: 0, analytics: 0, social: 0, other: 0 };
}

function emptyLists() {
  return { advertising: [], analytics: [], social: [], other: [] };
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
  return normalizeTrackerHost(host);
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

function freshState(pageDomain) {
  return {
    pageDomain,
    requests: new Set(),
    trackers: emptyTrackers(),
    blockedHosts: emptyTrackers(),
    lifetimeCredited: new Set(),
    insecureForms: []
  };
}

function ensureTab(tabId, pageUrl) {
  const pageDomain = pageUrl ? hostnameFromUrl(pageUrl) : null;
  const existing = tabState.get(tabId);
  if (existing) {
    if (pageDomain && existing.pageDomain !== pageDomain) {
      tabState.set(tabId, freshState(pageDomain));
      return tabState.get(tabId);
    }
    return existing;
  }
  const state = freshState(pageDomain);
  tabState.set(tabId, state);
  return state;
}

function resetTab(tabId, pageUrl) {
  const pageDomain = pageUrl ? hostnameFromUrl(pageUrl) : null;
  tabState.set(tabId, freshState(pageDomain));
}

function categorizeDomain(host) {
  const normalized = normalizeHost(host);
  for (const entry of RULE_INDEX.entries) {
    if (normalized === entry.domain || normalized.endsWith("." + entry.domain)) {
      return entry.category;
    }
  }
  return null;
}

function allCategoryPrefs(enabled) {
  return {
    advertising: enabled,
    analytics: enabled,
    social: enabled,
    other: enabled
  };
}

function normalizeSitePrefs(value) {
  if (value === true) {
    return allCategoryPrefs(true);
  }
  if (!value || typeof value !== "object") {
    return allCategoryPrefs(false);
  }
  return {
    advertising: Boolean(value.advertising),
    analytics: Boolean(value.analytics),
    social: Boolean(value.social),
    other: Boolean(value.other)
  };
}

function isBlockingEnabled(prefs) {
  return CATEGORY_ORDER.some((category) => prefs[category]);
}

async function getBlockedSites() {
  const stored = await chrome.storage.local.get("blockedSites");
  return stored.blockedSites || {};
}

async function getWhitelist() {
  const stored = await chrome.storage.local.get("whitelist");
  return stored.whitelist || [];
}

async function isWhitelisted(host) {
  if (!host) {
    return false;
  }
  const list = await getWhitelist();
  const normalized = normalizeHost(host);
  return list.some((entry) => {
    const item = normalizeHost(entry);
    return normalized === item || normalized.endsWith("." + item) || item.endsWith("." + normalized);
  });
}

async function setWhitelisted(host, trusted) {
  const list = await getWhitelist();
  const normalized = normalizeHost(host);
  const next = list.filter((entry) => normalizeHost(entry) !== normalized);
  if (trusted) {
    next.push(normalized);
  }
  await chrome.storage.local.set({ whitelist: next });
  return trusted;
}

async function getSettings() {
  const stored = await chrome.storage.local.get("settings");
  const defaults = allCategoryPrefs(true);
  const saved = stored.settings?.defaultCategoryBlocking;
  return {
    defaultCategoryBlocking: saved ? normalizeSitePrefs(saved) : defaults
  };
}

async function setSettings(next) {
  const current = await getSettings();
  const merged = {
    defaultCategoryBlocking: next.defaultCategoryBlocking
      ? normalizeSitePrefs(next.defaultCategoryBlocking)
      : current.defaultCategoryBlocking
  };
  await chrome.storage.local.set({ settings: merged });
  return merged;
}

function dateKey(ts = Date.now()) {
  return new Date(ts).toISOString().slice(0, 10);
}

async function pruneHistory() {
  const stored = await chrome.storage.local.get(["visitHistory", "threatLog"]);
  const history = stored.visitHistory || {};
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 7);
  const cutoffKey = cutoff.toISOString().slice(0, 10);
  let changed = false;
  for (const day of Object.keys(history)) {
    if (day < cutoffKey) {
      delete history[day];
      changed = true;
    }
  }
  const threatLog = (stored.threatLog || []).slice(0, 200);
  if (changed) {
    await chrome.storage.local.set({ visitHistory: history, threatLog });
  } else if ((stored.threatLog || []).length > 200) {
    await chrome.storage.local.set({ threatLog });
  }
}

async function logVisit(url, data) {
  const host = hostnameFromUrl(url || "") || data.domain;
  if (!host) {
    return;
  }
  const day = dateKey();
  const stored = await chrome.storage.local.get("visitHistory");
  const history = stored.visitHistory || {};
  if (!history[day]) {
    history[day] = {};
  }
  history[day][host] = {
    detected: data.detectedCount || 0,
    blocked: data.blockedCount || 0,
    active: data.activeCount || 0,
    ts: Date.now()
  };
  await chrome.storage.local.set({ visitHistory: history });
}

async function logThreat(domain) {
  const host = normalizeHost(domain);
  if (!host || host === "unknown site") {
    return;
  }
  const stored = await chrome.storage.local.get(["threatLog", "lifetimeThreatsBlocked"]);
  const threatLog = stored.threatLog || [];
  const last = threatLog[0];
  if (last && last.domain === host && Date.now() - last.ts < 15000) {
    return;
  }
  threatLog.unshift({ domain: host, ts: Date.now() });
  await chrome.storage.local.set({
    threatLog: threatLog.slice(0, 200),
    lifetimeThreatsBlocked: (stored.lifetimeThreatsBlocked || 0) + 1
  });
}

function protectionScore(history) {
  let detected = 0;
  let blocked = 0;
  for (const day of Object.values(history || {})) {
    for (const site of Object.values(day || {})) {
      detected += Number(site.detected) || 0;
      blocked += Number(site.blocked) || 0;
    }
  }
  if (!detected) {
    return 0;
  }
  return Math.round((blocked / detected) * 100);
}

async function getSitePrefs(host) {
  if (await isWhitelisted(host)) {
    return allCategoryPrefs(false);
  }
  const blockedSites = await getBlockedSites();
  return normalizeSitePrefs(blockedSites[host]);
}

async function setSitePrefs(host, prefs) {
  if (await isWhitelisted(host)) {
    return allCategoryPrefs(false);
  }
  const blockedSites = await getBlockedSites();
  const normalized = normalizeSitePrefs(prefs);
  if (isBlockingEnabled(normalized)) {
    blockedSites[host] = normalized;
  } else {
    delete blockedSites[host];
  }
  await chrome.storage.local.set({ blockedSites });
  return normalized;
}

async function installThreatRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= THREAT_RULE_ID_BASE && rule.id < THREAT_RULE_ID_MAX)
    .map((rule) => rule.id);

  const addRules = THREAT_DOMAINS.map((domain, index) => {
    const warningUrl = new URL(chrome.runtime.getURL("warning.html"));
    warningUrl.searchParams.set("domain", domain);
    return {
      id: THREAT_RULE_ID_BASE + index,
      priority: 2,
      action: {
        type: "redirect",
        redirect: {
          url: warningUrl.href
        }
      },
      condition: {
        requestDomains: [domain],
        resourceTypes: ["main_frame", "sub_frame"]
      }
    };
  });

  if (removeRuleIds.length || addRules.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
  }
}

async function applyBlockingForHost(host) {
  const trackerRulesets = CATEGORY_ORDER.map((category) => RULESET_ID_BY_CATEGORY[category]);
  if (await isWhitelisted(host)) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: trackerRulesets
    });
    return allCategoryPrefs(false);
  }

  const prefs = host ? normalizeSitePrefs((await getBlockedSites())[host]) : allCategoryPrefs(false);
  const enableRulesetIds = [];
  const disableRulesetIds = [];
  for (const category of CATEGORY_ORDER) {
    const id = RULESET_ID_BY_CATEGORY[category];
    if (prefs[category]) {
      enableRulesetIds.push(id);
    } else {
      disableRulesetIds.push(id);
    }
  }
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds,
    disableRulesetIds
  });
  return prefs;
}

function hostMatchesBlocked(host, blockedSets) {
  for (const category of CATEGORY_ORDER) {
    for (const blocked of blockedSets[category]) {
      if (host === blocked || host.endsWith("." + blocked)) {
        return true;
      }
    }
  }
  return false;
}

function addBlockedHost(state, host) {
  const category = categorizeDomain(host);
  if (!category || !state) {
    return false;
  }
  if (state.blockedHosts[category].has(host)) {
    return false;
  }
  state.blockedHosts[category].add(host);
  return true;
}

async function getMatchedDomains(tabId) {
  const blocked = emptyTrackers();
  try {
    const result = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
    for (const info of result.rulesMatchedInfo || []) {
      const meta = RULE_INDEX.byId[info.rule.ruleId];
      if (!meta) {
        continue;
      }
      blocked[meta.category].add(meta.domain);
    }
  } catch (error) {
    console.warn("[Glass] getMatchedRules", error);
  }
  const state = tabState.get(tabId);
  if (state) {
    for (const category of CATEGORY_ORDER) {
      for (const domain of state.blockedHosts[category]) {
        blocked[category].add(domain);
      }
    }
  }
  return blocked;
}

async function creditLifetime(tabId, blockedSets) {
  const state = tabState.get(tabId);
  if (!state) {
    return;
  }
  let added = 0;
  for (const category of CATEGORY_ORDER) {
    for (const domain of blockedSets[category]) {
      if (!state.lifetimeCredited.has(domain)) {
        state.lifetimeCredited.add(domain);
        added += 1;
      }
    }
  }
  if (!added) {
    return;
  }
  const stored = await chrome.storage.local.get("lifetimeBlocked");
  await chrome.storage.local.set({
    lifetimeBlocked: (stored.lifetimeBlocked || 0) + added
  });
}

function severityFromCount(total) {
  if (total <= 3) {
    return "green";
  }
  if (total <= 10) {
    return "amber";
  }
  return "red";
}

async function setTabBadge(tabId, detectedCount, url) {
  try {
    const host = hostnameFromUrl(url || "");
    if (!host) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    if (detectedCount <= 0) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    const text = detectedCount > 99 ? "99+" : String(detectedCount);
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: SEVERITY_COLORS[severityFromCount(detectedCount)]
    });
    await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
  } catch (error) {
    console.warn("[Glass] badge", error);
  }
}

async function snapshot(tabId) {
  const state = tabState.get(tabId);
  const blockedSets = await getMatchedDomains(tabId);

  const activeLists = emptyLists();
  const blockedLists = emptyLists();
  const counts = emptyCounts();
  const blockedCounts = emptyCounts();
  const activeCounts = emptyCounts();
  const detected = new Set();

  if (state) {
    for (const category of CATEGORY_ORDER) {
      for (const domain of state.trackers[category]) {
        if (hostMatchesBlocked(domain, blockedSets)) {
          addBlockedHost(state, domain);
          continue;
        }
        activeLists[category].push(domain);
      }
    }
    for (const category of CATEGORY_ORDER) {
      for (const domain of state.blockedHosts[category]) {
        blockedSets[category].add(domain);
      }
    }
  }

  await creditLifetime(tabId, blockedSets);

  for (const category of CATEGORY_ORDER) {
    blockedLists[category] = Array.from(blockedSets[category]).sort();
    activeLists[category].sort();
    blockedCounts[category] = blockedLists[category].length;
    activeCounts[category] = activeLists[category].length;
    counts[category] = blockedCounts[category] + activeCounts[category];
    for (const domain of blockedLists[category]) {
      detected.add(domain);
    }
    for (const domain of activeLists[category]) {
      detected.add(domain);
    }
  }

  const blockedCount = CATEGORY_ORDER.reduce((sum, key) => sum + blockedCounts[key], 0);
  const activeCount = CATEGORY_ORDER.reduce((sum, key) => sum + activeCounts[key], 0);
  const stored = await chrome.storage.local.get("lifetimeBlocked");

  return {
    domain: state?.pageDomain || null,
    counts,
    trackers: activeLists,
    blockedTrackers: blockedLists,
    blockedCounts,
    activeCounts,
    blockedCount,
    activeCount,
    detectedCount: detected.size,
    total: detected.size,
    thirdPartyCount: state?.requests.size || 0,
    lifetimeBlocked: stored.lifetimeBlocked || 0,
    insecureForms: state?.insecureForms || []
  };
}

async function refreshTabUi(tabId, url) {
  const data = await snapshot(tabId);
  let pageUrl = url;
  if (!pageUrl) {
    try {
      const tab = await chrome.tabs.get(tabId);
      pageUrl = tab.url;
    } catch {
      pageUrl = "";
    }
  }
  await setTabBadge(tabId, data.detectedCount, pageUrl);
  return data;
}

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (details.tabId < 0 || details.type === "main_frame") {
      return;
    }
    if (details.error !== "net::ERR_BLOCKED_BY_CLIENT") {
      return;
    }
    const requestHost = hostnameFromUrl(details.url);
    if (!requestHost) {
      return;
    }
    const state = ensureTab(details.tabId);
    if (isFirstParty(state.pageDomain, requestHost)) {
      return;
    }
    if (addBlockedHost(state, requestHost)) {
      refreshTabUi(details.tabId);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) {
      return;
    }

    if (details.type === "main_frame") {
      resetTab(details.tabId, details.url);
      refreshTabUi(details.tabId, details.url);
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

    state.requests.add(requestHost);
    const category = categorizeDomain(requestHost);
    if (category && !state.trackers[category].has(requestHost)) {
      state.trackers[category].add(requestHost);
      refreshTabUi(details.tabId);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    resetTab(tabId, changeInfo.url);
    applyBlockingForHost(hostnameFromUrl(changeInfo.url));
    refreshTabUi(tabId, changeInfo.url);
  } else if (changeInfo.status === "loading" && tab.url) {
    const nextHost = hostnameFromUrl(tab.url);
    const current = tabState.get(tabId);
    if (nextHost && current && current.pageDomain && nextHost !== current.pageDomain) {
      resetTab(tabId, tab.url);
    } else if (!current) {
      ensureTab(tabId, tab.url);
    }
    refreshTabUi(tabId, tab.url);
  } else if (changeInfo.status === "complete") {
    refreshTabUi(tabId, tab.url).then((data) => logVisit(tab.url, data));
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
    await refreshTabUi(activeInfo.tabId, tab.url);
  } catch (error) {
    console.warn("[Glass] tab activate", error);
  }
});

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  const name = item.filename || item.url.split("/").pop().split("?")[0] || "";
  if (RISKY_DOWNLOAD.test(name)) {
    chrome.notifications.create(`glass-download-${item.id}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Glass: risky download",
      message: `Suspicious double extension: ${name}`
    });
  }
  suggest({ filename: item.filename });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_TAB_DATA") {
    (async () => {
      const tabId = message.tabId;
      let host = null;
      let favIconUrl = "";
      let tabUrl = "";
      try {
        const tab = await chrome.tabs.get(tabId);
        tabUrl = tab.url || "";
        host = hostnameFromUrl(tabUrl);
        favIconUrl = tab.favIconUrl || "";
        ensureTab(tabId, tabUrl);
      } catch {
        host = tabState.get(tabId)?.pageDomain || null;
      }
      const whitelisted = await isWhitelisted(host);
      const prefs = await getSitePrefs(host);
      const data = await refreshTabUi(tabId, tabUrl);
      if (!data.domain) {
        data.domain = host;
      }
      data.favIconUrl = favIconUrl;
      data.whitelisted = whitelisted;
      data.blockingEnabled = !whitelisted && isBlockingEnabled(prefs);
      data.categoryBlocking = prefs;
      sendResponse(data);
    })();
    return true;
  }

  if (message?.type === "SET_BLOCKING") {
    (async () => {
      const host = normalizeHost(message.host);
      const enabled = Boolean(message.enabled);
      const settings = await getSettings();
      const prefs = await setSitePrefs(
        host,
        enabled ? settings.defaultCategoryBlocking : allCategoryPrefs(false)
      );
      await applyBlockingForHost(host);
      sendResponse({
        ok: true,
        blockingEnabled: isBlockingEnabled(prefs),
        categoryBlocking: prefs,
        host
      });
    })();
    return true;
  }

  if (message?.type === "SET_CATEGORY_BLOCKING") {
    (async () => {
      const host = normalizeHost(message.host);
      const prefs = await getSitePrefs(host);
      if (CATEGORY_ORDER.includes(message.category)) {
        prefs[message.category] = Boolean(message.enabled);
      }
      const saved = await setSitePrefs(host, prefs);
      await applyBlockingForHost(host);
      sendResponse({
        ok: true,
        blockingEnabled: isBlockingEnabled(saved),
        categoryBlocking: saved,
        host
      });
    })();
    return true;
  }

  if (message?.type === "SET_WHITELIST") {
    (async () => {
      const host = normalizeHost(message.host);
      const trusted = Boolean(message.trusted);
      await setWhitelisted(host, trusted);
      await applyBlockingForHost(host);
      sendResponse({ ok: true, whitelisted: trusted, host });
    })();
    return true;
  }

  if (message?.type === "INSECURE_FORMS") {
    const tabId = sender.tab?.id;
    if (tabId == null) {
      return false;
    }
    const state = ensureTab(tabId);
    state.insecureForms = message.warnings || [];
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "LOG_THREAT_BLOCK") {
    (async () => {
      await logThreat(message.domain);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === "GET_DASHBOARD_DATA") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      let live = null;
      if (tab?.id != null) {
        const host = hostnameFromUrl(tab.url || "");
        const prefs = await getSitePrefs(host);
        live = await refreshTabUi(tab.id, tab.url);
        live.domain = live.domain || host;
        live.favIconUrl = tab.favIconUrl || "";
        live.whitelisted = await isWhitelisted(host);
        live.blockingEnabled = !live.whitelisted && isBlockingEnabled(prefs);
        live.categoryBlocking = prefs;
      }
      const stored = await chrome.storage.local.get([
        "lifetimeBlocked",
        "lifetimeThreatsBlocked",
        "visitHistory",
        "threatLog",
        "whitelist"
      ]);
      const settings = await getSettings();
      const visitHistory = stored.visitHistory || {};
      sendResponse({
        live,
        lifetimeBlocked: stored.lifetimeBlocked || 0,
        lifetimeThreatsBlocked: stored.lifetimeThreatsBlocked || 0,
        visitHistory,
        threatLog: stored.threatLog || [],
        whitelist: stored.whitelist || [],
        settings,
        protectionScore: protectionScore(visitHistory)
      });
    })();
    return true;
  }

  if (message?.type === "UPDATE_SETTINGS") {
    (async () => {
      const settings = await setSettings(message.settings || {});
      sendResponse({ ok: true, settings });
    })();
    return true;
  }

  if (message?.type === "REMOVE_WHITELIST_ENTRY") {
    (async () => {
      await setWhitelisted(message.host, false);
      sendResponse({ ok: true, whitelist: await getWhitelist() });
    })();
    return true;
  }

  if (message?.type === "REGENERATE_RULES") {
    (async () => {
      await installThreatRules();
      sendResponse({
        ok: true,
        message: "Threat rules reloaded. To refresh EasyPrivacy tracker rules, run `node generate-rules.js` then reload Glass."
      });
    })();
    return true;
  }

  return false;
});

async function syncActiveTabBlocking() {
  try {
    await pruneHistory();
    await installThreatRules();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      await applyBlockingForHost(hostnameFromUrl(tab.url || ""));
      await refreshTabUi(tab.id, tab.url);
    }
  } catch (error) {
    console.warn("[Glass] sync blocking", error);
  }
}

chrome.runtime.onInstalled.addListener(syncActiveTabBlocking);
chrome.runtime.onStartup.addListener(syncActiveTabBlocking);
syncActiveTabBlocking();

console.log("[Glass] service worker ready");
