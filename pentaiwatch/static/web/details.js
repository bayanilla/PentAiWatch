// Upload page: the report details sit outside both forms, so they are copied into whichever form is
// sent (after VulnScope MAX 6a7ac93, vulnflow/static/upload.js).
(function () {
  const names = ["report_name", "report_description"];
  document.querySelectorAll('form[action="/analyze"],form[action="/analyze-folder"]').forEach(f => f.addEventListener("submit", () => {
    names.forEach(n => {
      let h = f.querySelector('input[type=hidden][name="' + n + '"]');
      if (!h) { h = document.createElement("input"); h.type = "hidden"; h.name = n; f.prepend(h); }
      h.value = document.getElementById(n).value;
    });
  }));
})();
