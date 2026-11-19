// Upload page: when the folder typed or picked is a finished report's output folder, the folder form's
// button says "Open report" (the report is written again from it, without reading the logs), after
// VulnScope MAX 6a7ac93 (vulnflow/static/upload.js).
(function () {
  const cfg = JSON.parse(document.getElementById("pw-page").textContent);
  const $ = id => document.getElementById(id), path = $("path"), btn = $("analyze-folder");
  if (!path || !btn) return;
  const form = path.form, label = btn.textContent, busy = form.dataset.busy, hint = form.dataset.busyHint;
  let seq = 0, timer = null;
  async function check() {
    const p = path.value.trim(), mine = ++seq;
    let report = false;
    if (p) {
      try {
        const r = await fetch("/folder-kind", {method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({csrf: cfg.csrf, path: p})});
        report = !!(await r.json()).report;
      } catch (e) {}
    }
    if (mine !== seq) return;
    btn.textContent = report ? "Open report" : label;
    form.dataset.busy = report ? "Opening report…" : busy;
    form.dataset.busyHint = report ? "" : hint;
    $("kind-msg").textContent = report ? "This is a finished report's folder: it opens as it was saved, written again " +
      "with this version, without reading the logs. Report details and internal networks are not used." : "";
  }
  path.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(check, 300); });
  path.addEventListener("change", check);
  check();
})();
