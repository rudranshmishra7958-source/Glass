(function () {
  function fbq() {}
  fbq.callMethod = function () {};
  fbq.queue = [];
  fbq.loaded = true;
  fbq.version = "2.0";
  fbq.push = fbq;
  window.fbq = window.fbq || fbq;
  window._fbq = window._fbq || fbq;
})();
