const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const THREAT_ID_BASE = 600001;
const URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_recent/";

// Optional manual entries for Layer 1 redirect testing — remove after confirming redirect.
const MANUAL_THREAT_DOMAINS = ["test-glass-threat-domain.com"];

function normalizeHost(value) {
  try {
    const url = value.includes("://") ? value : "http://" + value;
    const host = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      return null;
    }
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) {
      return null;
    }
    return host;
  } catch {
    return null;
  }
}

async function main() {
  console.log("Fetching URLhaus recent list…");
  const response = await fetch(URLHAUS_URL);
  if (!response.ok) {
    throw new Error("Failed to fetch URLhaus: " + response.status);
  }
  const text = await response.text();
  const domains = new Set();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const host = normalizeHost(trimmed.split(/\s+/)[0]);
    if (host) {
      domains.add(host);
    }
  }

  const list = [...new Set([...MANUAL_THREAT_DOMAINS, ...domains])].slice(0, 500);
  console.log("Threat domains:", list.length, "(manual:", MANUAL_THREAT_DOMAINS.length + ")");

  fs.mkdirSync(path.join(ROOT, "rules"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, "rules", "threats.json"), "[]\n", "utf8");

  const threatListJs =
    "const THREAT_DOMAINS = " +
    JSON.stringify(list, null, 2) +
    ";\nconst THREAT_RULE_ID_BASE = " +
    THREAT_ID_BASE +
    ";\nconst THREAT_RULE_ID_MAX = " +
    (THREAT_ID_BASE + list.length) +
    ";\n";
  fs.writeFileSync(path.join(ROOT, "threat-list.js"), threatListJs, "utf8");
  console.log("Wrote threat-list.js and empty rules/threats.json");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
