const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const RULES_DIR = path.join(ROOT, "rules");
const MAX_RULES = 25000;
const EASYPRIVACY_URLS = [
  "https://easylist.to/easylist/easyprivacy.txt",
  "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
  "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt"
];

const CATEGORY_ORDER = ["advertising", "analytics", "social", "other"];
const RULE_ID_BASE = {
  advertising: 1,
  analytics: 10001,
  social: 20001,
  other: 30001
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
    "advertising"
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

function normalizeHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^www\./, "");
}

function categorize(domain) {
  for (const category of ["advertising", "analytics", "social"]) {
    for (const keyword of CATEGORY_KEYWORDS[category]) {
      if (domain.includes(keyword)) {
        return category;
      }
    }
  }
  return "other";
}

function parseDomains(text) {
  const domains = new Set();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) {
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

async function main() {
  console.log("Fetching EasyPrivacy…");
  const domainSet = new Set();
  for (const url of EASYPRIVACY_URLS) {
    const response = await fetch(url);
    if (!response.ok) {
      console.warn("Skip", url, response.status);
      continue;
    }
    const text = await response.text();
    for (const domain of parseDomains(text)) {
      domainSet.add(domain);
      if (domainSet.size >= MAX_RULES) {
        break;
      }
    }
    console.log("Loaded from", url, "total", domainSet.size);
    if (domainSet.size >= MAX_RULES) {
      break;
    }
  }
  const allDomains = [...domainSet].slice(0, MAX_RULES);
  console.log("Parsed domains:", allDomains.length);

  const buckets = {
    advertising: [],
    analytics: [],
    social: [],
    other: []
  };
  for (const domain of allDomains) {
    buckets[categorize(domain)].push(domain);
  }

  fs.mkdirSync(RULES_DIR, { recursive: true });
  const byId = {};
  const entries = [];

  for (const category of CATEGORY_ORDER) {
    const { rules, indexEntries } = buildRules(category, buckets[category]);
    fs.writeFileSync(
      path.join(RULES_DIR, category + ".json"),
      JSON.stringify(rules, null, 2),
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
    JSON.stringify({ byId, entries }, null, 2) +
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
  console.log("Wrote rules/, rule-index.js, tracker-list.js");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
