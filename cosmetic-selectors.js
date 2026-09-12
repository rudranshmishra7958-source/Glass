const COSMETIC_SELECTORS = [
  "div[id*='google_ads']",
  "div[id*='googlead']",
  "div[id*='div-gpt-ad']",
  "div[id^='ad-']",
  "div[id$='-ad']",
  "div[class*='ad-slot']",
  "div[class*='adslot']",
  "div[class*='adsbygoogle']",
  ".adsbygoogle",
  "ins.adsbygoogle",
  "iframe[src*='doubleclick']",
  "iframe[src*='googlesyndication']",
  "iframe[id*='google_ads']",
  "div[class*='advertisement']",
  "div[data-ad-slot]",
  "div[data-google-query-id]",
  "aside[class*='ad-']",
  "div[class*='sponsored-slot']",
  "div[class*='promo-ad']",
  "[aria-label='Advertisement']",
  "div[class*='taboola']",
  "div[id*='taboola']",
  "div[class*='outbrain']",
  "div[id*='outbrain']",
  "div[class*='ad-banner']",
  "div[class*='banner-ad']",
  "div[class*='ad-unit']",
  "div[class*='adunit']"
];

if (typeof self !== "undefined") {
  self.COSMETIC_SELECTORS = COSMETIC_SELECTORS;
}
