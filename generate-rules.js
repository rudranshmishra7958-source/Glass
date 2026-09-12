const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const RULES_DIR = path.join(ROOT, "rules");
const MAX_RULES = 30000;
const MAX_COSMETIC = 3000;
const FILTER_SOURCES = [
  { url: "https://easylist.to/easylist/easylist.txt", cache: "easylist.txt" },
  { url: "https://easylist.to/easylist/easyprivacy.txt", cache: "easyprivacy.txt" },
  {
    url: "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
    cache: "easyprivacy_general.txt"
  },
  {
    url: "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt",
    cache: "easyprivacy_specific.txt"
  }
];

const CATEGORY_ORDER = ["advertising", "analytics", "social", "other"];
const RULE_ID_BASE = {
  advertising: 1,
  analytics: 30001,
  social: 60001,
  other: 90001
};

const RESOURCE_TYPES = [
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

const CATEGORY_KEYWORDS = {
  advertising: [
    "ad",
    "ads",
    "advert",
    "doubleclick",
    "pubmatic",
    "criteo",
    "taboola",
    "outbrain",
    "openx",
    "rubicon",
    "adnxs",
    "adsrvr",
    "adform",
    "adroll",
    "moat",
    "casale",
    "bidswitch",
    "smartad",
    "yield",
    "prebid",
    "amazon-adsystem",
    "googlesyndication",
    "googleadservices",
    "advertising",
    "pagead",
    "adservice",
    "adserver"
  ],
  analytics: [
    "analytics",
    "metric",
    "stats",
    "stat.",
    "track",
    "pixel",
    "segment",
    "mixpanel",
    "hotjar",
    "amplitude",
    "fullstory",
    "heap",
    "mouseflow",
    "clarity",
    "crazyegg",
    "optimizely",
    "quantcast",
    "scorecard",
    "chartbeat",
    "matomo",
    "piwik",
    "snowplow",
    "newrelic",
    "sentry",
    "omtrdc",
    "omniture",
    "marketo",
    "hubspot",
    "pendo",
    "logrocket",
    "inspectlet",
    "luckyorange",
    "parsely",
    "clicky",
    "histats",
    "yandex"
  ],
  social: [
    "facebook",
    "twitter",
    "linkedin",
    "pinterest",
    "instagram",
    "tiktok",
    "snapchat",
    "reddit",
    "share",
    "social",
    "addthis",
    "sharethis",
    "disqus",
    "youtube",
    "platform.twitter",
    "connect.facebook"
  ]
};

const UNSAFE_COSMETIC = /:has\(|:-abp-|:xpath|:matches-path|:style\(|\+js\(|:remove\(|:upward|:nth-ancestor|:min-text-length|:watch-attr|:matches-attr|:matches-css|:matches-prop|:shadow|:is\(|:not\(|::|\[style/i;

function normalizeHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^www\./, "");
}

function categorize(domain, fallback = "other") {
  for (const category of ["advertising", "analytics", "social"]) {
    for (const keyword of CATEGORY_KEYWORDS[category]) {
      if (domain.includes(keyword)) {
        return category;
      }
    }
  }
  return fallback;
}

function parseDomains(text) {
  const domains = new Set();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[") || line.startsWith("@@")) {
      continue;
    }
    const match = line.match(/\|\|([^|^/$]+)\^/);
    if (!match) {
      continue;
    }
    const domain = normalizeHost(match[1]);
    if (!domain || domain.includes("/") || domain.includes("*")) {
      continue;
    }
    if (!/^[a-z0-9.-]+$/.test(domain)) {
      continue;
    }
    domains.add(domain);
  }
  return [...domains];
}

function parseCosmeticSelectors(text) {
  const selectors = [];
  const seen = new Set();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith("##") || line.startsWith("##^")) {
      continue;
    }
    const selector = line.slice(2).trim();
    if (!selector || selector.length > 180) {
      continue;
    }
    if (UNSAFE_COSMETIC.test(selector)) {
      continue;
    }
    if (!/^[a-zA-Z0-9.#\[\]="'*_\-\s>+~,^$|]+$/.test(selector)) {
      continue;
    }
    if (seen.has(selector)) {
      continue;
    }
    seen.add(selector);
    selectors.push(selector);
    if (selectors.length >= MAX_COSMETIC) {
      break;
    }
  }
  return selectors;
}

function buildRules(category, domains) {
  let id = RULE_ID_BASE[category];
  const rules = [];
  const indexEntries = [];
  for (const domain of domains) {
    rules.push({
      id,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "||" + domain + "^",
        resourceTypes: RESOURCE_TYPES,
        domainType: "thirdParty"
      }
    });
    indexEntries.push({ id, domain, category });
    id += 1;
  }
  return { rules, indexEntries };
}

async function fetchText(source) {
  const cachePath = path.join(ROOT, ".filter-cache", source.cache);
  if (fs.existsSync(cachePath) && fs.statSync(cachePath).size > 1000) {
    console.log("Using cache", source.cache);
    return fs.readFileSync(cachePath, "utf8");
  }
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetch(source.url, {
        headers: { "user-agent": "GlassFilterCompiler/1.0" }
      });
      if (!response.ok) {
        console.warn("Skip", source.url, response.status);
        return "";
      }
      return await response.text();
    } catch (error) {
      console.warn("Retry", source.url, attempt, error.message);
      if (attempt === 3) {
        return "";
      }
    }
  }
  return "";
}

function writeCosmeticSelectors(selectors) {
  const body = selectors.map((selector) => JSON.stringify(selector)).join(",\n  ");
  const source = `const COSMETIC_SELECTORS = [
  ${body}
];

if (typeof self !== "undefined") {
  self.COSMETIC_SELECTORS = COSMETIC_SELECTORS;
}
`;
  fs.writeFileSync(path.join(ROOT, "cosmetic-selectors.js"), source, "utf8");
}

async function main() {
  console.log("Fetching EasyList + EasyPrivacy…");
  const domainMeta = new Map();
  const cosmetics = [];
  const seenCosmetic = new Set();
  for (const source of FILTER_SOURCES) {
    const text = await fetchText(source);
    if (!text) {
      continue;
    }
    const fromEasyList = source.cache === "easylist.txt";
    for (const domain of parseDomains(text)) {
      const fallback = fromEasyList ? "advertising" : "other";
      const category = categorize(domain, fallback);
      const existing = domainMeta.get(domain);
      if (!existing || (existing === "other" && category !== "other")) {
        domainMeta.set(domain, category);
      }
    }
    if (cosmetics.length < MAX_COSMETIC) {
      for (const selector of parseCosmeticSelectors(text)) {
        if (seenCosmetic.has(selector)) {
          continue;
        }
        seenCosmetic.add(selector);
        cosmetics.push(selector);
        if (cosmetics.length >= MAX_COSMETIC) {
          break;
        }
      }
    }
    console.log("Loaded from", source.cache, "domains", domainMeta.size, "cosmetics", cosmetics.length);
  }

  const buckets = {
    advertising: [],
    analytics: [],
    social: [],
    other: []
  };
  for (const [domain, category] of domainMeta) {
    buckets[category].push(domain);
  }
  const quotas = {
    advertising: 16000,
    analytics: 8000,
    social: 2000,
    other: 4000
  };
  const packed = {
    advertising: buckets.advertising.slice(0, quotas.advertising),
    analytics: buckets.analytics.slice(0, quotas.analytics),
    social: buckets.social.slice(0, quotas.social),
    other: buckets.other.slice(0, quotas.other)
  };
  let remaining = MAX_RULES - (
    packed.advertising.length +
    packed.analytics.length +
    packed.social.length +
    packed.other.length
  );
  for (const category of CATEGORY_ORDER) {
    if (remaining <= 0) {
      break;
    }
    const extra = buckets[category].slice(packed[category].length, packed[category].length + remaining);
    packed[category].push(...extra);
    remaining -= extra.length;
  }
  const preferredCount =
    packed.advertising.length + packed.analytics.length + packed.social.length + packed.other.length;
  Object.assign(buckets, packed);
  console.log("Packed domains:", preferredCount);

  fs.mkdirSync(RULES_DIR, { recursive: true });
  const byId = {};
  const entries = [];

  for (const category of CATEGORY_ORDER) {
    const { rules, indexEntries } = buildRules(category, buckets[category]);
    if (rules.length > 30000) {
      throw new Error(category + " exceeds 30000 DNR rules");
    }
    fs.writeFileSync(
      path.join(RULES_DIR, category + ".json"),
      JSON.stringify(rules),
      "utf8"
    );
    for (const entry of indexEntries) {
      byId[entry.id] = { domain: entry.domain, category: entry.category };
      entries.push({ domain: entry.domain, category: entry.category });
    }
    console.log(category + ":", rules.length);
  }

  entries.sort((a, b) => b.domain.length - a.domain.length);

  const ruleIndexJs =
    "self.RULE_INDEX = self.RULE_INDEX || " +
    JSON.stringify({ byId, entries }) +
    ";\n";
  fs.writeFileSync(path.join(ROOT, "rule-index.js"), ruleIndexJs, "utf8");

  const trackerListJs = `const CATEGORY_ORDER = ${JSON.stringify(CATEGORY_ORDER)};

const RULESET_ID_BY_CATEGORY = {
  advertising: "ruleset_advertising",
  analytics: "ruleset_analytics",
  social: "ruleset_social",
  other: "ruleset_other"
};

const RULE_ID_BASE = ${JSON.stringify(RULE_ID_BASE, null, 2)};

const THREAT_RULESET_ID = "ruleset_threats";

function normalizeTrackerHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/\\.$/, "")
    .replace(/^www\\./, "");
}

function buildRuleIndex() {
  return self.RULE_INDEX;
}
`;
  fs.writeFileSync(path.join(ROOT, "tracker-list.js"), trackerListJs, "utf8");
  writeCosmeticSelectors(cosmetics.length ? cosmetics : [
    "div[id*='google_ads']",
    ".adsbygoogle",
    "ins.adsbygoogle"
  ]);
  console.log("Wrote rules/, rule-index.js, tracker-list.js, cosmetic-selectors.js");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
