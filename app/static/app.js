// Progressive enhancement only: the pages stay usable when this file is blocked.
// Event delegation keeps the templates free of inline handlers so the served
// Content-Security-Policy can forbid inline and third-party scripts.
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    var trigger = event.target.closest("[data-action='toggle-sidebar']");
    if (!trigger) {
      return;
    }
    var sidebar = document.getElementById("sidebar");
    if (sidebar) {
      sidebar.classList.toggle("open");
    }
  });

  document.addEventListener("change", function (event) {
    var field = event.target.closest("[data-submit-on-change]");
    if (field && field.form) {
      field.form.submit();
    }
  });
})();
