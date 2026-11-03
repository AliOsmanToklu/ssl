// Poll a running scan and reload the page once it has finished.
(function () {
  "use strict";
  var box = document.querySelector("[data-scan-poll]");
  if (!box) return;
  var url = box.getAttribute("data-scan-poll");
  var label = box.querySelector("[data-scan-status]");
  var labels = {
    queued: box.getAttribute("data-label-queued"),
    running: box.getAttribute("data-label-running")
  };

  function poll() {
    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error(response.status);
        return response.json();
      })
      .then(function (data) {
        if (data.status === "done" || data.status === "failed") {
          window.location.reload();
          return;
        }
        if (label && labels[data.status]) label.textContent = labels[data.status];
        window.setTimeout(poll, 2500);
      })
      .catch(function () {
        window.setTimeout(poll, 6000);
      });
  }

  window.setTimeout(poll, 2000);
})();
