const SURROGATE_RULE_ID_BASE = 700001;
const SURROGATES = [
  {
    id: 0,
    category: "analytics",
    requestDomains: ["www.google-analytics.com", "google-analytics.com", "ssl.google-analytics.com"],
    urlFilter: "||google-analytics.com/analytics.js",
    path: "/surrogates/ga.js"
  },
  {
    id: 1,
    category: "analytics",
    requestDomains: ["www.googletagmanager.com", "googletagmanager.com"],
    urlFilter: "||googletagmanager.com/gtag/js",
    path: "/surrogates/ga.js"
  },
  {
    id: 2,
    category: "social",
    requestDomains: ["connect.facebook.net"],
    urlFilter: "||connect.facebook.net/en_US/fbevents.js",
    path: "/surrogates/fbq.js"
  }
];
const SURROGATE_RULE_ID_MAX = SURROGATE_RULE_ID_BASE + SURROGATES.length;
