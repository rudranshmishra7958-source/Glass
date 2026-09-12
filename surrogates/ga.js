(function () {
  function noop() {
    return noop;
  }
  noop.q = [];
  noop.l = Date.now();
  window.ga = window.ga || noop;
  window.gtag = window.gtag || function () {};
  window.dataLayer = window.dataLayer || [];
  window.GoogleAnalyticsObject = window.GoogleAnalyticsObject || "ga";
})();
