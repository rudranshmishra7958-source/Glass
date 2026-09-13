importScripts(
  "rule-index.js",
  "tracker-list.js",
  "threat-list.js",
  "surrogate-list.js",
  "embed-domains.js",
  "company-map.js"
);

const tabCache = new Map();
const tabQueues = new Map();
const flushTimers = new Map();
const SEVERITY_COLORS = {
  green: "#2f6f4e",
  amber: "#8a5a12",
  red: "#8b3a32"
};

const RISKY_DOWNLOAD =
  /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|zip|rar|mp3|mp4|avi)\.(exe|js|bat|scr|com|vbs|msi|cmd|ps1|jar|dll|apk)$/i;

const NATIVE_HOST = "com.glass.scanner";
const SCAN_HISTORY_CAP = 50;
const DANGEROUS_DOWNLOAD_STATES = [
  "content",
  "url",
  "host",
  "file",
  "unwanted",
  "blockedTooLarge",
  "sensitiveContentBlock",
  "accountCompromise"
];

const PAUSE_ALARM = "glass-unpause";
const HISTORY_FLUSH_PREFIX = "history-flush-";
const HISTORY_FLUSH_MS = 5000;
const THREAT_HOST_SET = new Set(THREAT_DOMAINS);

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

function isHttpTabUrl(url) {
  return Boolean(url && /^https?:/i.test(url));
}

function pageUrlKey(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.origin + parsed.pathname + parsed.search;
  } catch {
    return String(url || "").split("#")[0];
  }
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

function tabStorageKey(tabId) {
  return `glassTab:${tabId}`;
}

function historyAlarmName(tabId) {
  return HISTORY_FLUSH_PREFIX + tabId;
}

function listsFromSets(sets) {
  return {
    advertising: Array.from(sets?.advertising || []),
    analytics: Array.from(sets?.analytics || []),
    social: Array.from(sets?.social || []),
    other: Array.from(sets?.other || [])
  };
}

function setsFromLists(lists) {
  const next = emptyTrackers();
  if (!lists) {
    return next;
  }
  for (const category of CATEGORY_ORDER) {
    next[category] = new Set(lists[category] || []);
  }
  return next;
}

function serializeTabState(state) {
  return {
    pageDomain: state.pageDomain || null,
    pageUrl: state.pageUrl || "",
    requests: Array.from(state.requests || []),
    trackers: listsFromSets(state.trackers),
    blockedHosts: listsFromSets(state.blockedHosts),
    insecureForms: state.insecureForms || [],
    lastActivityAt: state.lastActivityAt || Date.now(),
    navStartedAt: state.navStartedAt || state.lastActivityAt || Date.now(),
    dirty: Boolean(state.dirty)
  };
}

function deserializeTabState(raw) {
  return {
    pageDomain: raw.pageDomain || null,
    pageUrl: raw.pageUrl || "",
    requests: new Set(raw.requests || []),
    trackers: setsFromLists(raw.trackers),
    blockedHosts: setsFromLists(raw.blockedHosts),
    insecureForms: raw.insecureForms || [],
    lastActivityAt: raw.lastActivityAt || Date.now(),
    navStartedAt: raw.navStartedAt || raw.lastActivityAt || Date.now(),
    dirty: Boolean(raw.dirty)
  };
}

function freshState(pageDomain, pageUrl) {
  return {
    pageDomain: pageDomain || null,
    pageUrl: pageUrl || "",
    requests: new Set(),
    trackers: emptyTrackers(),
    blockedHosts: emptyTrackers(),
    insecureForms: [],
    lastActivityAt: Date.now(),
    navStartedAt: Date.now(),
    dirty: false
  };
}

function enqueueTab(tabId, task) {
  const previous = tabQueues.get(tabId) || Promise.resolve();
  const next = previous.then(task, task);
  tabQueues.set(
    tabId,
    next.catch((error) => {
      console.warn("[Glass] tab queue", error);
    })
  );
  return next;
}

async function getTabState(tabId) {
  if (tabCache.has(tabId)) {
    return tabCache.get(tabId);
  }
  const key = tabStorageKey(tabId);
  const stored = await chrome.storage.session.get(key);
  if (!stored[key]) {
    return null;
  }
  const state = deserializeTabState(stored[key]);
  tabCache.set(tabId, state);
  return state;
}

async function putTabState(tabId, state) {
  state.lastActivityAt = Date.now();
  tabCache.set(tabId, state);
  await chrome.storage.session.set({
    [tabStorageKey(tabId)]: serializeTabState(state)
  });
}

async function removeTabState(tabId) {
  tabCache.delete(tabId);
  if (flushTimers.has(tabId)) {
    clearTimeout(flushTimers.get(tabId));
    flushTimers.delete(tabId);
  }
  await chrome.storage.session.remove(tabStorageKey(tabId));
  await chrome.alarms.clear(historyAlarmName(tabId));
}

async function resetTab(tabId, pageUrl) {
  const state = freshState(hostnameFromUrl(pageUrl || ""), pageUrl || "");
  await putTabState(tabId, state);
  return state;
}

async function ensureTab(tabId, pageUrl) {
  const pageDomain = pageUrl ? hostnameFromUrl(pageUrl) : null;
  const existing = await getTabState(tabId);
  if (existing) {
    const urlChanged =
      pageUrl && existing.pageUrl && pageUrlKey(pageUrl) !== pageUrlKey(existing.pageUrl);
    const hostChanged = pageDomain && existing.pageDomain && existing.pageDomain !== pageDomain;
    if (urlChanged || hostChanged) {
      await flushHistoryForTab(tabId);
      return resetTab(tabId, pageUrl);
    }
    if (pageUrl && existing.pageUrl !== pageUrl) {
      existing.pageUrl = pageUrl;
    }
    if (pageDomain && !existing.pageDomain) {
      existing.pageDomain = pageDomain;
    }
    return existing;
  }
  return resetTab(tabId, pageUrl);
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

const EXCEPTION_RULE_ID_BASE = 800001;
const SITE_ALLOW_RULE_ID_BASE = 810001;
const SITE_ALLOW_RULE_ID_MAX = 820000;
const EXCEPTION_RESOURCE_TYPES = [
  "script",
  "xmlhttprequest",
  "image",
  "sub_frame",
  "ping",
  "media",
  "font",
  "stylesheet",
  "websocket",
  "other"
];

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

function prefsEqual(left, right) {
  return CATEGORY_ORDER.every((category) => Boolean(left?.[category]) === Boolean(right?.[category]));
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
    defaultCategoryBlocking: saved ? normalizeSitePrefs(saved) : defaults,
    cosmeticFiltering: stored.settings?.cosmeticFiltering !== false
  };
}

async function setSettings(next) {
  const current = await getSettings();
  const merged = {
    defaultCategoryBlocking: next.defaultCategoryBlocking
      ? normalizeSitePrefs(next.defaultCategoryBlocking)
      : current.defaultCategoryBlocking,
    cosmeticFiltering:
      typeof next.cosmeticFiltering === "boolean"
        ? next.cosmeticFiltering
        : current.cosmeticFiltering
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

function uniqueHostsFromSnapshot(data) {
  const hosts = new Set();
  for (const category of CATEGORY_ORDER) {
    for (const domain of data?.blockedTrackers?.[category] || []) {
      hosts.add(domain);
    }
    for (const domain of data?.trackers?.[category] || []) {
      hosts.add(domain);
    }
  }
  return Array.from(hosts).slice(0, 80);
}

function addHostsToTally(tally, hosts) {
  for (const host of hosts || []) {
    const company = companyFromHost(host);
    tally.set(company, (tally.get(company) || 0) + 1);
  }
}

function rankWatchers(visitHistory, sessionHosts) {
  const tally = new Map();
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 7);
  const cutoffKey = cutoff.toISOString().slice(0, 10);
  for (const day of Object.keys(visitHistory || {})) {
    if (day < cutoffKey) {
      continue;
    }
    for (const site of Object.values(visitHistory[day] || {})) {
      addHostsToTally(tally, site.hosts);
    }
  }
  addHostsToTally(tally, sessionHosts);
  return Array.from(tally.entries())
    .map(([company, count]) => ({ company, count }))
    .sort((a, b) => b.count - a.count || a.company.localeCompare(b.company));
}

async function sessionTrackerHosts() {
  const stored = await chrome.storage.session.get(null);
  const hosts = [];
  for (const [key, raw] of Object.entries(stored || {})) {
    if (!key.startsWith("glassTab:") || !raw) {
      continue;
    }
    for (const category of CATEGORY_ORDER) {
      hosts.push(...(raw.trackers?.[category] || []));
      hosts.push(...(raw.blockedHosts?.[category] || []));
    }
  }
  return hosts;
}

async function logVisit(url, data) {
  const host = hostnameFromUrl(url || "") || data.domain;
  if (!host) {
    return;
  }
  const day = dateKey();
  const stored = await chrome.storage.local.get(["visitHistory", "lifetimeBlocked"]);
  const history = stored.visitHistory || {};
  if (!history[day]) {
    history[day] = {};
  }
  const prev = history[day][host] || {};
  const prevBlocked = Number(prev.blocked) || 0;
  const nextBlocked = Number(data.blockedCount) || 0;
  const counts = data.counts || emptyCounts();
  const mergedHosts = Array.from(
    new Set([...(prev.hosts || []), ...uniqueHostsFromSnapshot(data)])
  ).slice(0, 80);
  history[day][host] = {
    detected: Number(data.detectedCount) || 0,
    blocked: nextBlocked,
    active: Number(data.activeCount) || 0,
    ts: Date.now(),
    counts: {
      advertising: Number(counts.advertising) || 0,
      analytics: Number(counts.analytics) || 0,
      social: Number(counts.social) || 0,
      other: Number(counts.other) || 0
    },
    hosts: mergedHosts
  };
  const lifetimeBlocked = Math.max(0, (stored.lifetimeBlocked || 0) - prevBlocked + nextBlocked);
  await chrome.storage.local.set({ visitHistory: history, lifetimeBlocked });
}

async function flushHistoryForTab(tabId) {
  const state = await getTabState(tabId);
  if (!state?.dirty) {
    return;
  }
  const data = await snapshot(tabId);
  await logVisit(state.pageUrl || "", data);
  const next = await getTabState(tabId);
  if (next) {
    next.dirty = false;
    await putTabState(tabId, next);
  }
}

async function scheduleHistoryFlush(tabId) {
  const state = await getTabState(tabId);
  if (!state?.dirty) {
    return;
  }
  const name = historyAlarmName(tabId);
  await chrome.alarms.clear(name);
  await chrome.alarms.create(name, { when: Date.now() + HISTORY_FLUSH_MS });
  if (flushTimers.has(tabId)) {
    clearTimeout(flushTimers.get(tabId));
  }
  flushTimers.set(
    tabId,
    setTimeout(() => {
      flushTimers.delete(tabId);
      enqueueTab(tabId, () => flushHistoryForTab(tabId));
    }, HISTORY_FLUSH_MS)
  );
}

async function flushStaleSessionTabs() {
  const all = await chrome.storage.session.get(null);
  const now = Date.now();
  for (const [key, raw] of Object.entries(all)) {
    if (!key.startsWith("glassTab:")) {
      continue;
    }
    const tabId = Number(key.slice("glassTab:".length));
    if (!Number.isFinite(tabId) || !raw?.dirty) {
      continue;
    }
    if (now - (raw.lastActivityAt || 0) >= HISTORY_FLUSH_MS) {
      enqueueTab(tabId, () => flushHistoryForTab(tabId));
    } else {
      enqueueTab(tabId, () => scheduleHistoryFlush(tabId));
    }
  }
}

function isThreatHost(host) {
  if (!host) {
    return false;
  }
  if (THREAT_HOST_SET.has(host)) {
    return true;
  }
  return THREAT_DOMAINS.some((domain) => host.endsWith("." + domain));
}

async function logThreat(domain, site) {
  if (await isPaused()) {
    return;
  }
  const host = normalizeHost(domain);
  if (!host || host === "unknown site") {
    return;
  }
  const encountered = normalizeHost(site) || host;
  const stored = await chrome.storage.local.get(["threatLog", "lifetimeThreatsBlocked"]);
  const threatLog = stored.threatLog || [];
  const last = threatLog[0];
  if (last && last.domain === host && Date.now() - last.ts < 15000) {
    return;
  }
  threatLog.unshift({ domain: host, site: encountered, ts: Date.now() });
  await chrome.storage.local.set({
    threatLog: threatLog.slice(0, 200),
    lifetimeThreatsBlocked: (stored.lifetimeThreatsBlocked || 0) + 1
  });
  try {
    await chrome.notifications.create(`glass-threat-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Glass blocked a dangerous site",
      message:
        encountered && encountered !== host
          ? `${host} was blocked on ${encountered}.`
          : `${host} was blocked.`
    });
  } catch (error) {
    console.warn("[Glass] threat notification", error);
  }
}

function maybeLogThreatRequest(details) {
  const warningBase = chrome.runtime.getURL("warning.html");
  let threatHost = null;
  const requestHost = hostnameFromUrl(details.url);
  if (requestHost && isThreatHost(requestHost)) {
    threatHost = requestHost;
  } else if (details.url && details.url.startsWith(warningBase)) {
    try {
      threatHost = new URL(details.url).searchParams.get("domain");
    } catch {
      threatHost = null;
    }
  }
  if (!threatHost) {
    return;
  }
  const site =
    hostnameFromUrl(details.initiator || "") ||
    hostnameFromUrl(details.documentUrl || "") ||
    (details.type === "main_frame" ? threatHost : null);
  logThreat(threatHost, site);
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

async function isPaused() {
  const stored = await chrome.storage.local.get("pauseState");
  const pauseState = stored.pauseState;
  if (!pauseState) {
    return false;
  }
  if (pauseState.until === "startup") {
    return true;
  }
  if (typeof pauseState.until === "number") {
    if (Date.now() >= pauseState.until) {
      await chrome.storage.local.remove("pauseState");
      return false;
    }
    return true;
  }
  return false;
}

async function getPauseState() {
  const paused = await isPaused();
  const stored = await chrome.storage.local.get("pauseState");
  return {
    paused,
    until: paused ? stored.pauseState?.until ?? null : null
  };
}

async function disableAllProtection() {
  const trackerRulesets = CATEGORY_ORDER.map((category) => RULESET_ID_BY_CATEGORY[category]);
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    disableRulesetIds: [...trackerRulesets, "ruleset_threats"]
  });
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter(
      (rule) =>
        (rule.id >= THREAT_RULE_ID_BASE && rule.id < THREAT_RULE_ID_MAX) ||
        (rule.id >= SURROGATE_RULE_ID_BASE && rule.id < SURROGATE_RULE_ID_MAX)
    )
    .map((rule) => rule.id);
  if (removeRuleIds.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules: []
    });
  }
  await syncTrackerExceptionRules();
  await syncSiteAllowRules();
  try {
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#8a5a12" });
    await chrome.action.setBadgeTextColor({ color: "#ffffff" });
  } catch (error) {
    console.warn("[Glass] paused badge", error);
  }
}

async function setPause(until) {
  if (!until) {
    await chrome.storage.local.remove("pauseState");
    await chrome.alarms.clear(PAUSE_ALARM);
    await installThreatRules();
    await syncActiveTabBlocking();
    return { paused: false, until: null };
  }
  await chrome.storage.local.set({ pauseState: { until } });
  if (typeof until === "number") {
    await chrome.alarms.create(PAUSE_ALARM, { when: until });
  } else {
    await chrome.alarms.clear(PAUSE_ALARM);
  }
  await disableAllProtection();
  return { paused: true, until };
}

function parseTypedHost(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) {
    return null;
  }
  try {
    const url = raw.includes("://") ? new URL(raw) : new URL("https://" + raw.replace(/^\/\//, ""));
    return normalizeHost(url.hostname);
  } catch {
    return normalizeHost(raw.replace(/^www\./, "").split("/")[0]);
  }
}

async function collectLiveTabs() {
  const tabs = await chrome.tabs.query({});
  const results = [];
  for (const tab of tabs) {
    if (tab.id == null || !isHttpTabUrl(tab.url)) {
      continue;
    }
    const host = hostnameFromUrl(tab.url);
    const data = await enqueueTab(tab.id, () => snapshot(tab.id));
    results.push({
      tabId: tab.id,
      title: tab.title || host || "",
      url: tab.url,
      domain: data.domain || host,
      favIconUrl: tab.favIconUrl || "",
      detectedCount: data.detectedCount || 0,
      blockedCount: data.blockedCount || 0,
      activeCount: data.activeCount || 0,
      trackers: data.trackers,
      blockedTrackers: data.blockedTrackers
    });
  }
  results.sort((a, b) => b.detectedCount - a.detectedCount || String(a.domain).localeCompare(String(b.domain)));
  return results;
}

async function applyBlockingForMatchingTabs(host) {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    const tabHost = hostnameFromUrl(tab.url || "");
    if (
      tabHost &&
      (tabHost === host || tabHost.endsWith("." + host) || host.endsWith("." + tabHost))
    ) {
      await applyBlockingForHost(tabHost);
    }
  }
}

async function clearVisitHistory() {
  await chrome.storage.local.set({ visitHistory: {} });
}

async function deleteHistoryEntry(day, host) {
  const stored = await chrome.storage.local.get("visitHistory");
  const history = stored.visitHistory || {};
  if (history[day]) {
    delete history[day][host];
    if (!Object.keys(history[day]).length) {
      delete history[day];
    }
  }
  await chrome.storage.local.set({ visitHistory: history });
  return history;
}

async function getTrackerExceptions() {
  const stored = await chrome.storage.local.get("trackerExceptions");
  return stored.trackerExceptions || [];
}

function exceptionKey(site, tracker) {
  return `${normalizeHost(site)}::${normalizeHost(tracker)}`;
}

function isTrackerExcepted(exceptions, site, tracker) {
  if (!site || !tracker) {
    return false;
  }
  const page = normalizeHost(site);
  const host = normalizeHost(tracker);
  return exceptions.some((entry) => {
    const entrySite = normalizeHost(entry.site);
    const entryTracker = normalizeHost(entry.tracker);
    const siteMatch =
      page === entrySite || page.endsWith("." + entrySite) || entrySite.endsWith("." + page);
    const trackerMatch =
      host === entryTracker || host.endsWith("." + entryTracker) || entryTracker.endsWith("." + host);
    return siteMatch && trackerMatch;
  });
}

async function addTrackerException(site, tracker) {
  const page = normalizeHost(site);
  const host = normalizeHost(tracker);
  if (!page || !host) {
    return getTrackerExceptions();
  }
  const list = await getTrackerExceptions();
  if (isTrackerExcepted(list, page, host)) {
    return list;
  }
  list.push({ site: page, tracker: host });
  await chrome.storage.local.set({ trackerExceptions: list });
  return list;
}

async function removeTrackerException(site, tracker) {
  const page = normalizeHost(site);
  const host = normalizeHost(tracker);
  const list = (await getTrackerExceptions()).filter(
    (entry) => exceptionKey(entry.site, entry.tracker) !== exceptionKey(page, host)
  );
  await chrome.storage.local.set({ trackerExceptions: list });
  return list;
}

async function collectSiteAllowHosts() {
  const hosts = new Set();
  for (const entry of await getWhitelist()) {
    const host = normalizeHost(entry);
    if (host) {
      hosts.add(host);
    }
  }
  const blockedSites = await getBlockedSites();
  for (const [host, prefs] of Object.entries(blockedSites)) {
    if (host && !isBlockingEnabled(normalizeSitePrefs(prefs))) {
      hosts.add(normalizeHost(host));
    }
  }
  return [...hosts];
}

async function syncSiteAllowRules() {
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= SITE_ALLOW_RULE_ID_BASE && rule.id < SITE_ALLOW_RULE_ID_MAX)
    .map((rule) => rule.id);
  if (await isPaused()) {
    if (removeRuleIds.length) {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds,
        addRules: []
      });
    }
    return;
  }
  const addRules = (await collectSiteAllowHosts()).slice(0, 200).map((host, index) => ({
    id: SITE_ALLOW_RULE_ID_BASE + index,
    priority: 100,
    action: { type: "allow" },
    condition: {
      initiatorDomains: [host],
      resourceTypes: EXCEPTION_RESOURCE_TYPES
    }
  }));
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds,
    addRules
  });
}

async function syncTrackerExceptionRules() {
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const removeRuleIds = existing
    .filter(
      (rule) => rule.id >= EXCEPTION_RULE_ID_BASE && rule.id < SITE_ALLOW_RULE_ID_BASE
    )
    .map((rule) => rule.id);
  if (await isPaused()) {
    if (removeRuleIds.length) {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds,
        addRules: []
      });
    }
    return;
  }
  const allowHosts = new Set(await collectSiteAllowHosts());
  const exceptions = (await getTrackerExceptions()).filter(
    (entry) => !allowHosts.has(normalizeHost(entry.site))
  );
  const addRules = exceptions.slice(0, 200).map((entry, index) => ({
    id: EXCEPTION_RULE_ID_BASE + index,
    priority: 4,
    action: { type: "allow" },
    condition: {
      requestDomains: [entry.tracker],
      initiatorDomains: [entry.site],
      resourceTypes: EXCEPTION_RESOURCE_TYPES
    }
  }));
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds,
    addRules
  });
}

async function installSurrogateRules(prefs) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= SURROGATE_RULE_ID_BASE && rule.id < SURROGATE_RULE_ID_MAX)
    .map((rule) => rule.id);
  const blockingOn = prefs && isBlockingEnabled(prefs) && !(await isPaused());
  const addRules = [];
  if (blockingOn) {
    for (const item of SURROGATES) {
      if (item.category && prefs[item.category] === false) {
        continue;
      }
      addRules.push({
        id: SURROGATE_RULE_ID_BASE + item.id,
        priority: 3,
        action: {
          type: "redirect",
          redirect: { extensionPath: item.path }
        },
        condition: {
          urlFilter: item.urlFilter,
          requestDomains: item.requestDomains,
          resourceTypes: ["script"]
        }
      });
    }
  }
  if (removeRuleIds.length || addRules.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
  }
}

async function getSitePrefs(host) {
  if (await isWhitelisted(host)) {
    return allCategoryPrefs(false);
  }
  const blockedSites = await getBlockedSites();
  if (!host || !Object.prototype.hasOwnProperty.call(blockedSites, host)) {
    const settings = await getSettings();
    return { ...settings.defaultCategoryBlocking };
  }
  return normalizeSitePrefs(blockedSites[host]);
}

async function setSitePrefs(host, prefs) {
  if (await isWhitelisted(host)) {
    return allCategoryPrefs(false);
  }
  const blockedSites = await getBlockedSites();
  const normalized = normalizeSitePrefs(prefs);
  const settings = await getSettings();
  if (prefsEqual(normalized, settings.defaultCategoryBlocking)) {
    delete blockedSites[host];
  } else {
    blockedSites[host] = normalized;
  }
  await chrome.storage.local.set({ blockedSites });
  return normalized;
}

async function enableRulesetsFromPrefs(prefs) {
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
  if (!disableRulesetIds.includes("ruleset_threats")) {
    enableRulesetIds.push("ruleset_threats");
  }
  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds,
    disableRulesetIds
  });
}

async function installThreatRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= THREAT_RULE_ID_BASE && rule.id < THREAT_RULE_ID_MAX)
    .map((rule) => rule.id);

  if (await isPaused()) {
    if (removeRuleIds.length) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules: []
      });
    }
    return;
  }

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
  if (await isPaused()) {
    await disableAllProtection();
    return allCategoryPrefs(false);
  }
  const settings = await getSettings();
  await enableRulesetsFromPrefs(settings.defaultCategoryBlocking);
  await installSurrogateRules(settings.defaultCategoryBlocking);
  await installThreatRules();
  await syncSiteAllowRules();
  await syncTrackerExceptionRules();
  return getSitePrefs(host);
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

function blockedSetsFromState(state) {
  const blocked = emptyTrackers();
  if (!state) {
    return blocked;
  }
  for (const category of CATEGORY_ORDER) {
    for (const domain of state.blockedHosts[category]) {
      blocked[category].add(domain);
    }
  }
  return blocked;
}

async function recordRuleMatch(tabId, host) {
  if (!tabId || tabId < 0 || !host) {
    return;
  }
  const state = await ensureTab(tabId);
  if (state.pageDomain && isFirstParty(state.pageDomain, host)) {
    return;
  }
  const exceptions = await getTrackerExceptions();
  if (isTrackerExcepted(exceptions, state.pageDomain, host)) {
    return;
  }
  if (!addBlockedHost(state, host)) {
    return;
  }
  state.dirty = true;
  await putTabState(tabId, state);
  await refreshTabUi(tabId);
  await scheduleHistoryFlush(tabId);
}

async function debugGetMatchedRules(tabId) {
  return chrome.declarativeNetRequest.getMatchedRules({ tabId });
}

async function getLifetimeBlocked() {
  const stored = await chrome.storage.local.get("lifetimeBlocked");
  return stored.lifetimeBlocked || 0;
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
    if (await isPaused()) {
      await chrome.action.setBadgeText({ tabId, text: "OFF" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#8a5a12" });
      await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
      return;
    }
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
  const state = await getTabState(tabId);
  const blockedSets = blockedSetsFromState(state);

  const activeLists = emptyLists();
  const blockedLists = emptyLists();
  const counts = emptyCounts();
  const blockedCounts = emptyCounts();
  const activeCounts = emptyCounts();
  const detected = new Set();
  let blockedChanged = false;

  if (state) {
    for (const category of CATEGORY_ORDER) {
      for (const domain of state.trackers[category]) {
        if (hostMatchesBlocked(domain, blockedSets)) {
          if (addBlockedHost(state, domain)) {
            blockedChanged = true;
          }
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
    if (blockedChanged) {
      state.dirty = true;
      await putTabState(tabId, state);
      await scheduleHistoryFlush(tabId);
    }
  }

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
  if ((await getTabState(tabId))?.dirty) {
    await scheduleHistoryFlush(tabId);
  }
  return data;
}

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request?.tabId;
    if (!tabId || tabId < 0) {
      return;
    }
    if (info.rule?.rulesetId === "ruleset_threats") {
      return;
    }
    const meta = RULE_INDEX.byId[info.rule?.ruleId];
    const host = meta?.domain || hostnameFromUrl(info.request?.url || "");
    enqueueTab(tabId, () => recordRuleMatch(tabId, host));
  });
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
    enqueueTab(details.tabId, async () => {
      const state = await ensureTab(details.tabId);
      if (isFirstParty(state.pageDomain, requestHost)) {
        return;
      }
      const exceptions = await getTrackerExceptions();
      if (isTrackerExcepted(exceptions, state.pageDomain, requestHost)) {
        return;
      }
      if (details.type === "sub_frame" && isEmbedHost(requestHost)) {
        chrome.tabs
          .sendMessage(details.tabId, {
            type: "EMBED_BLOCKED",
            url: details.url,
            host: requestHost
          })
          .catch(() => {});
      }
      if (addBlockedHost(state, requestHost)) {
        state.dirty = true;
        await putTabState(details.tabId, state);
        await refreshTabUi(details.tabId);
        await scheduleHistoryFlush(details.tabId);
      }
    });
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) {
      return;
    }

    if (details.type === "main_frame" || details.type === "sub_frame") {
      maybeLogThreatRequest(details);
    }

    enqueueTab(details.tabId, async () => {
      if (details.type === "main_frame") {
        await flushHistoryForTab(details.tabId);
        await resetTab(details.tabId, details.url);
        await refreshTabUi(details.tabId, details.url);
        return;
      }

      const requestHost = hostnameFromUrl(details.url);
      if (!requestHost) {
        return;
      }

      const state = await ensureTab(details.tabId);
      let changed = false;
      if (!state.pageDomain && details.initiator) {
        state.pageDomain = hostnameFromUrl(details.initiator);
        changed = true;
      }
      if (!state.pageDomain && details.documentUrl) {
        state.pageDomain = hostnameFromUrl(details.documentUrl);
        changed = true;
      }

      if (isFirstParty(state.pageDomain, requestHost)) {
        if (changed) {
          await putTabState(details.tabId, state);
        }
        return;
      }

      const requestCount = state.requests.size;
      state.requests.add(requestHost);
      if (state.requests.size !== requestCount) {
        changed = true;
      }
      const category = categorizeDomain(requestHost);
      let newTracker = false;
      if (category && !state.trackers[category].has(requestHost)) {
        state.trackers[category].add(requestHost);
        newTracker = true;
        changed = true;
        state.dirty = true;
      }
      if (changed) {
        await putTabState(details.tabId, state);
      }
      if (newTracker) {
        await refreshTabUi(details.tabId);
        await scheduleHistoryFlush(details.tabId);
      }
    });
  },
  { urls: ["<all_urls>"] }
);

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) {
    return;
  }
  if (details.error || !isHttpTabUrl(details.url)) {
    return;
  }
  enqueueTab(details.tabId, async () => {
    await flushHistoryForTab(details.tabId);
    await resetTab(details.tabId, details.url);
    await applyBlockingForHost(hostnameFromUrl(details.url));
    await refreshTabUi(details.tabId, details.url);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    enqueueTab(tabId, async () => {
      const current = await getTabState(tabId);
      const nextKey = pageUrlKey(changeInfo.url);
      const prevKey = pageUrlKey(current?.pageUrl || "");
      if (nextKey && prevKey && nextKey !== prevKey) {
        await flushHistoryForTab(tabId);
        await resetTab(tabId, changeInfo.url);
      } else {
        await ensureTab(tabId, changeInfo.url);
      }
      await applyBlockingForHost(hostnameFromUrl(changeInfo.url));
      await refreshTabUi(tabId, changeInfo.url);
    });
  } else if (changeInfo.status === "loading" && tab.url) {
    enqueueTab(tabId, async () => {
      const nextKey = pageUrlKey(tab.url);
      const current = await getTabState(tabId);
      const prevKey = pageUrlKey(current?.pageUrl || "");
      if (nextKey && prevKey && nextKey !== prevKey) {
        await flushHistoryForTab(tabId);
        await resetTab(tabId, tab.url);
      } else {
        await ensureTab(tabId, tab.url);
      }
      await refreshTabUi(tabId, tab.url);
    });
  } else if (changeInfo.status === "complete") {
    enqueueTab(tabId, async () => {
      await ensureTab(tabId, tab.url);
      await refreshTabUi(tabId, tab.url);
      await scheduleHistoryFlush(tabId);
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  enqueueTab(tabId, async () => {
    await flushHistoryForTab(tabId);
    await removeTabState(tabId);
  });
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

function downloadBasename(path) {
  const parts = String(path || "").split(/[/\\]/);
  return parts[parts.length - 1] || "download";
}

function connectNativeScan(request) {
  return new Promise((resolve, reject) => {
    let completed = false;
    let port;
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST);
    } catch (error) {
      reject(error);
      return;
    }

    function finish(callback, value) {
      if (completed) {
        return;
      }
      completed = true;
      try {
        port.disconnect();
      } catch {
        // already closed
      }
      callback(value);
    }

    port.onMessage.addListener((message) => {
      console.log("[Glass] native scan response", message);
      finish(resolve, message);
    });
    port.onDisconnect.addListener(() => {
      if (completed) {
        return;
      }
      const error = chrome.runtime.lastError;
      finish(
        reject,
        new Error(error?.message || "Glass native host disconnected.")
      );
    });
    try {
      port.postMessage(request);
    } catch (error) {
      finish(reject, error);
    }
  });
}

async function setScanRecord(downloadId, patch) {
  const key = String(downloadId);
  const stored = await chrome.storage.local.get(["downloadScans", "downloadScanHistory"]);
  const scans = stored.downloadScans || {};
  const next = {
    ...(scans[key] || {}),
    ...patch,
    downloadId: Number(downloadId),
    ts: patch.ts || Date.now()
  };
  scans[key] = next;
  let history = Array.isArray(stored.downloadScanHistory)
    ? stored.downloadScanHistory.filter((item) => String(item.downloadId) !== key)
    : [];
  history = [next, ...history].slice(0, SCAN_HISTORY_CAP);
  await chrome.storage.local.set({
    downloadScans: scans,
    downloadScanHistory: history
  });
  return next;
}

async function persistScanResult(download, report) {
  const risk = report?.assessment?.risk || "UNKNOWN";
  const record = await setScanRecord(download.id, {
    status: report?.status === "error" ? "error" : "completed",
    filename: downloadBasename(download.filename),
    path: download.filename || "",
    url: download.finalUrl || download.url || "",
    report,
    risk,
    error: report?.error || null
  });
  if (risk === "CRITICAL" || risk === "HIGH") {
    chrome.notifications.create(`glass-scan-${download.id}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `Glass: ${risk} download`,
      message: record.filename
    });
  }
  return record;
}

async function scanCompletedDownload(download) {
  if (!download?.filename) {
    return;
  }
  await setScanRecord(download.id, {
    status: "scanning",
    filename: downloadBasename(download.filename),
    path: download.filename || "",
    url: download.finalUrl || download.url || "",
    report: null,
    risk: null
  });
  try {
    const report = await connectNativeScan({
      action: "scan",
      download: {
        id: download.id,
        filename: download.filename,
        url: download.url || "",
        finalUrl: download.finalUrl || "",
        mime: download.mime || "",
        danger: download.danger || "safe"
      }
    });
    if (!report) {
      throw new Error("Native host returned no scan report.");
    }
    if (report.status === "error") {
      throw new Error(report.error || "Scanner returned an error.");
    }
    await persistScanResult(download, report);
  } catch (error) {
    console.warn("[Glass] download scan failed", error);
    await setScanRecord(download.id, {
      status: "error",
      filename: downloadBasename(download.filename),
      path: download.filename || "",
      url: download.finalUrl || download.url || "",
      report: null,
      risk: "UNKNOWN",
      error: error.message || String(error)
    });
  }
}

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

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.danger && DANGEROUS_DOWNLOAD_STATES.includes(delta.danger.current)) {
    try {
      const results = await chrome.downloads.search({ id: delta.id });
      if (results[0]) {
        await scanCompletedDownload(results[0]);
      }
    } catch (error) {
      console.warn("[Glass] danger-state scan failed", error);
    }
    return;
  }
  if (!delta.state || delta.state.current !== "complete") {
    return;
  }
  try {
    const results = await chrome.downloads.search({ id: delta.id });
    const download = results[0];
    if (!download) {
      return;
    }
    if (DANGEROUS_DOWNLOAD_STATES.includes(download.danger)) {
      return;
    }
    await scanCompletedDownload(download);
  } catch (error) {
    console.warn("[Glass] completed-download scan failed", error);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_TAB_DATA") {
    (async () => {
      const tabId = message.tabId;
      let host = null;
      let favIconUrl = "";
      let tabUrl = "";
      let data = {};
      try {
        const tab = await chrome.tabs.get(tabId);
        tabUrl = tab.url || "";
        host = hostnameFromUrl(tabUrl);
        favIconUrl = tab.favIconUrl || "";
        data = await enqueueTab(tabId, async () => {
          await ensureTab(tabId, tabUrl);
          return refreshTabUi(tabId, tabUrl);
        });
      } catch {
        host = (await getTabState(tabId))?.pageDomain || null;
        data = (await refreshTabUi(tabId, tabUrl)) || {};
      }
      const whitelisted = await isWhitelisted(host);
      const prefs = await getSitePrefs(host);
      if (!data.domain) {
        data.domain = host;
      }
      data.favIconUrl = favIconUrl;
      data.whitelisted = whitelisted;
      const pause = await getPauseState();
      data.paused = pause.paused;
      data.pauseUntil = pause.until;
      data.blockingEnabled = !whitelisted && !pause.paused && isBlockingEnabled(prefs);
      data.categoryBlocking = prefs;
      data.lifetimeBlocked = await getLifetimeBlocked();
      data.trackerExceptions = (await getTrackerExceptions()).filter((entry) =>
        isTrackerExcepted([entry], host, entry.tracker)
      );
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
      await applyBlockingForMatchingTabs(host);
      sendResponse({ ok: true, whitelisted: trusted, host });
    })();
    return true;
  }

  if (message?.type === "INSECURE_FORMS") {
    const tabId = sender.tab?.id;
    if (tabId == null) {
      return false;
    }
    enqueueTab(tabId, async () => {
      const state = await ensureTab(tabId, sender.tab?.url);
      state.insecureForms = message.warnings || [];
      await putTabState(tabId, state);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "LOG_THREAT_BLOCK") {
    (async () => {
      await logThreat(message.domain, message.site);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message?.type === "BLOCK_AND_RELOAD") {
    (async () => {
      const tabId = Number(message.tabId);
      if (!Number.isFinite(tabId)) {
        sendResponse({ ok: false, reason: "Missing tab." });
        return;
      }
      if (await isPaused()) {
        sendResponse({ ok: false, reason: "Protection is paused." });
        return;
      }
      let tab;
      try {
        tab = await chrome.tabs.get(tabId);
      } catch {
        sendResponse({ ok: false, reason: "Tab is gone." });
        return;
      }
      const host = hostnameFromUrl(tab.url || "");
      if (!host) {
        sendResponse({ ok: false, reason: "Open a website first." });
        return;
      }
      if (await isWhitelisted(host)) {
        sendResponse({ ok: false, reason: "This site is trusted." });
        return;
      }
      const settings = await getSettings();
      await setSitePrefs(host, settings.defaultCategoryBlocking);
      await applyBlockingForHost(host);
      await chrome.tabs.reload(tabId);
      sendResponse({ ok: true, tabId, host });
    })();
    return true;
  }

  if (message?.type === "GET_LIVE_TABS") {
    (async () => {
      sendResponse({ tabs: await collectLiveTabs() });
    })();
    return true;
  }

  if (message?.type === "GET_DASHBOARD_DATA") {
    (async () => {
      const stored = await chrome.storage.local.get([
        "lifetimeBlocked",
        "lifetimeThreatsBlocked",
        "visitHistory",
        "threatLog",
        "whitelist",
        "trackerExceptions",
        "downloadScanHistory",
        "downloadScans"
      ]);
      const settings = await getSettings();
      const visitHistory = stored.visitHistory || {};
      const pause = await getPauseState();
      const watchers = rankWatchers(visitHistory, await sessionTrackerHosts());
      sendResponse({
        lifetimeBlocked: stored.lifetimeBlocked || 0,
        lifetimeThreatsBlocked: stored.lifetimeThreatsBlocked || 0,
        visitHistory,
        threatLog: stored.threatLog || [],
        whitelist: stored.whitelist || [],
        trackerExceptions: stored.trackerExceptions || [],
        settings,
        protectionScore: protectionScore(visitHistory),
        paused: pause.paused,
        pauseUntil: pause.until,
        watchers,
        downloadScanHistory: stored.downloadScanHistory || [],
        downloadScans: stored.downloadScans || {}
      });
    })();
    return true;
  }

  if (message?.type === "GET_DOWNLOAD_SCANS") {
    (async () => {
      const stored = await chrome.storage.local.get(["downloadScans", "downloadScanHistory"]);
      const scans = stored.downloadScans || {};
      const history = stored.downloadScanHistory || [];
      const latest =
        history[0] ||
        Object.values(scans).sort((a, b) => (b.ts || 0) - (a.ts || 0))[0] ||
        null;
      sendResponse({ scans, history, latest });
    })();
    return true;
  }

  if (message?.type === "DELETE_SCANNED_FILE") {
    (async () => {
      const downloadId = Number(message.downloadId);
      if (!Number.isFinite(downloadId)) {
        sendResponse({ ok: false, error: "Missing download." });
        return;
      }
      try {
        await chrome.downloads.removeFile(downloadId);
      } catch (error) {
        sendResponse({ ok: false, error: error.message || "Could not delete that file." });
        return;
      }
      await setScanRecord(downloadId, { action: "deleted" });
      const stored = await chrome.storage.local.get(["downloadScans", "downloadScanHistory"]);
      sendResponse({
        ok: true,
        scans: stored.downloadScans || {},
        history: stored.downloadScanHistory || []
      });
    })();
    return true;
  }

  if (message?.type === "SHOW_SCANNED_FILE") {
    (async () => {
      const downloadId = Number(message.downloadId);
      if (!Number.isFinite(downloadId)) {
        sendResponse({ ok: false, error: "Missing download." });
        return;
      }
      try {
        await chrome.downloads.show(downloadId);
        await setScanRecord(downloadId, { action: "kept" });
        const stored = await chrome.storage.local.get(["downloadScans", "downloadScanHistory"]);
        sendResponse({
          ok: true,
          scans: stored.downloadScans || {},
          history: stored.downloadScanHistory || []
        });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || "Could not open that file location." });
      }
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
      const host = parseTypedHost(message.host) || normalizeHost(message.host);
      await setWhitelisted(host, false);
      await applyBlockingForMatchingTabs(host);
      sendResponse({ ok: true, whitelist: await getWhitelist() });
    })();
    return true;
  }

  if (message?.type === "ADD_WHITELIST_ENTRY") {
    (async () => {
      const host = parseTypedHost(message.host);
      if (!host) {
        sendResponse({ ok: false, error: "Enter a valid domain." });
        return;
      }
      await setWhitelisted(host, true);
      await applyBlockingForMatchingTabs(host);
      sendResponse({ ok: true, whitelist: await getWhitelist(), host });
    })();
    return true;
  }

  if (message?.type === "CLEAR_HISTORY") {
    (async () => {
      await clearVisitHistory();
      sendResponse({ ok: true, visitHistory: {} });
    })();
    return true;
  }

  if (message?.type === "DELETE_HISTORY_ENTRY") {
    (async () => {
      const visitHistory = await deleteHistoryEntry(message.day, normalizeHost(message.host));
      sendResponse({ ok: true, visitHistory });
    })();
    return true;
  }

  if (message?.type === "SET_PAUSE") {
    (async () => {
      const result = await setPause(message.until ?? null);
      sendResponse({ ok: true, ...result });
    })();
    return true;
  }

  if (message?.type === "GET_PAUSE") {
    (async () => {
      sendResponse({ ok: true, ...(await getPauseState()) });
    })();
    return true;
  }

  if (message?.type === "ADD_TRACKER_EXCEPTION") {
    (async () => {
      const site = normalizeHost(message.site);
      const tracker = normalizeHost(message.tracker);
      const list = await addTrackerException(site, tracker);
      await syncTrackerExceptionRules();
      sendResponse({ ok: true, trackerExceptions: list });
    })();
    return true;
  }

  if (message?.type === "REMOVE_TRACKER_EXCEPTION") {
    (async () => {
      const site = normalizeHost(message.site);
      const tracker = normalizeHost(message.tracker);
      const list = await removeTrackerException(site, tracker);
      await syncTrackerExceptionRules();
      sendResponse({ ok: true, trackerExceptions: list });
    })();
    return true;
  }

  if (message?.type === "REGENERATE_RULES") {
    (async () => {
      await installThreatRules();
      sendResponse({
        ok: true,
        message: "Bundled threat rules reloaded."
      });
    })();
    return true;
  }

  if (message?.type === "DEBUG_GET_MATCHED_RULES") {
    (async () => {
      try {
        const tabId = Number(message.tabId);
        const result = await debugGetMatchedRules(tabId);
        sendResponse({ ok: true, result });
      } catch (error) {
        sendResponse({ ok: false, error: String(error?.message || error) });
      }
    })();
    return true;
  }

  return false;
});

async function syncActiveTabBlocking() {
  try {
    await pruneHistory();
    await flushStaleSessionTabs();
    if (await isPaused()) {
      await disableAllProtection();
      return;
    }
    await installThreatRules();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const host = tab ? hostnameFromUrl(tab.url || "") : "";
    await applyBlockingForHost(host);
    if (tab) {
      await refreshTabUi(tab.id, tab.url);
    }
  } catch (error) {
    console.warn("[Glass] sync blocking", error);
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === PAUSE_ALARM) {
    setPause(null);
    return;
  }
  if (alarm.name.startsWith(HISTORY_FLUSH_PREFIX)) {
    const tabId = Number(alarm.name.slice(HISTORY_FLUSH_PREFIX.length));
    if (Number.isFinite(tabId)) {
      enqueueTab(tabId, () => flushHistoryForTab(tabId));
    }
  }
});

chrome.runtime.onInstalled.addListener(syncActiveTabBlocking);
chrome.runtime.onStartup.addListener(async () => {
  const stored = await chrome.storage.local.get("pauseState");
  if (stored.pauseState?.until === "startup") {
    await chrome.storage.local.remove("pauseState");
  }
  await syncActiveTabBlocking();
});
syncActiveTabBlocking();

console.log("[Glass] service worker ready");
