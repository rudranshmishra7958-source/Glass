// Maps well-known tracker registrable domains to parent companies.
// Unknown hosts fall back to a cleaned label (the name before a short TLD).
self.COMPANY_MAP = {
  "doubleclick.net": "Google",
  "google-analytics.com": "Google",
  "googlesyndication.com": "Google",
  "googleadservices.com": "Google",
  "googletagmanager.com": "Google",
  "googletagservices.com": "Google",
  "google.com": "Google",
  "g.doubleclick.net": "Google",
  "2mdn.net": "Google",
  "adservice.google.com": "Google",
  "facebook.net": "Meta",
  "facebook.com": "Meta",
  "fbcdn.net": "Meta",
  "instagram.com": "Meta",
  "criteo.com": "Criteo",
  "criteo.net": "Criteo",
  "scorecardresearch.com": "Comscore",
  "comscore.com": "Comscore",
  "optimizely.com": "Optimizely",
  "taboola.com": "Taboola",
  "outbrain.com": "Outbrain",
  "adsrvr.org": "The Trade Desk",
  "amazon-adsystem.com": "Amazon",
  "ads-twitter.com": "X",
  "twitter.com": "X",
  "t.co": "X",
  "linkedin.com": "Microsoft",
  "licdn.com": "Microsoft",
  "adnxs.com": "Microsoft",
  "hotjar.com": "Hotjar",
  "newrelic.com": "New Relic",
  "nr-data.net": "New Relic",
  "segment.io": "Twilio",
  "segment.com": "Twilio",
  "mixpanel.com": "Mixpanel",
  "quantserve.com": "Quantcast",
  "quantcount.com": "Quantcast",
  "rubiconproject.com": "Magnite",
  "openx.net": "OpenX",
  "pubmatic.com": "PubMatic",
  "casalemedia.com": "Index Exchange",
  "chartbeat.com": "Chartbeat",
  "mouseflow.com": "Mouseflow",
  "tiktok.com": "TikTok",
  "analytics.tiktok.com": "TikTok",
  "byteoversea.com": "TikTok",
  "snapchat.com": "Snap",
  "sc-static.net": "Snap",
  "pinterest.com": "Pinterest",
  "pinimg.com": "Pinterest",
  "yandex.ru": "Yandex",
  "mc.yandex.ru": "Yandex",
  "clarity.ms": "Microsoft",
  "bing.com": "Microsoft"
};

self.companyFromHost = function companyFromHost(host) {
  const normalized = String(host || "")
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^www\./, "");
  if (!normalized) {
    return "Unknown";
  }
  const parts = normalized.split(".");
  for (let i = 0; i < parts.length - 1; i += 1) {
    const suffix = parts.slice(i).join(".");
    if (self.COMPANY_MAP[suffix]) {
      return self.COMPANY_MAP[suffix];
    }
  }
  // Fallback: label before a short TLD (com|net|org|io|co), else the first label, capitalized.
  const shortTld = /^(com|net|org|io|co)$/i;
  const label =
    parts.length >= 2 && shortTld.test(parts[parts.length - 1])
      ? parts[parts.length - 2]
      : parts[0];
  return label.charAt(0).toUpperCase() + label.slice(1);
};
