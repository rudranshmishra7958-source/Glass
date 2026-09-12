const CATEGORY_ORDER = ["advertising","analytics","social","other"];

const RULESET_ID_BY_CATEGORY = {
  advertising: "ruleset_advertising",
  analytics: "ruleset_analytics",
  social: "ruleset_social",
  other: "ruleset_other"
};

const RULE_ID_BASE = {
  "advertising": 1,
  "analytics": 30001,
  "social": 60001,
  "other": 90001
};

const THREAT_RULESET_ID = "ruleset_threats";

function normalizeTrackerHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^www\./, "");
}

function buildRuleIndex() {
  return self.RULE_INDEX;
}
