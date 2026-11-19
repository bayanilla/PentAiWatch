// Browse… for the folder path field (#path), after VulnScope MAX 6a7ac93 (vulnflow/static/folder_picker.js).
// On a Mac the server opens the system's Choose Folder dialog; elsewhere (or if that fails) a small
// in-page folder list served by /browse. Either way only the folder's path comes back: nothing is
// read or uploaded until the form is sent.
(function () {
  const cfg = JSON.parse(document.getElementById("pw-page").textContent);
  const $ = id => document.getElementById(id), box = $("picker"), list = $("pk-list"), path = $("path");
  if (!path || !box) return;
  let cur = null, parent = null;
  async function call(url, body) {
    const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf: cfg.csrf}, body))});
    return r.json();
  }
  const submit = () => path.form.querySelector('button[type="submit"]');
  function set(p) {
    path.value = p; box.hidden = true;
    path.dispatchEvent(new Event("change", {bubbles: true}));
    const b = submit(); if (b) b.focus();
  }
  async function show(where) {
    let d;
    try { d = await call("/browse", {path: where}); } catch (e) { d = {error: "The folder list could not be loaded."}; }
    if (d.error) { $("pk-info").textContent = d.error; box.hidden = false; return; }
    cur = d.path; parent = d.parent; $("pk-where").textContent = d.path; $("pk-up").disabled = !d.parent;
    list.innerHTML = "";
    d.dirs.forEach(name => {
      const li = document.createElement("li"); li.textContent = name; li.tabIndex = 0;
      const go = () => show((d.path.endsWith(d.sep) ? d.path : d.path + d.sep) + name);
      li.onclick = go; li.onkeydown = e => { if (e.key === "Enter") { e.preventDefault(); go(); } };
      list.appendChild(li);
    });
    $("pk-info").textContent = d.files + " file" + (d.files === 1 ? "" : "s") + " here" +
      (d.dirs.length ? ", " + d.dirs.length + " subfolder" + (d.dirs.length === 1 ? "" : "s") : "");
    box.hidden = false;
  }
  const msg = t => { $("pick-msg").textContent = t || ""; };
  $("browse").onclick = async () => {
    msg("");
    if (cfg.native) {
      $("browse").disabled = true;
      try {
        const d = await call("/pick-folder", {path: path.value});
        if (d.path) { set(d.path); return; }
        if (d.cancelled) return;
      } catch (e) {} finally { $("browse").disabled = false; }
    }
    show(path.value);
  };
  $("pk-up").onclick = () => parent && show(parent);
  path.form.addEventListener("submit", e => {
    if (!path.value.trim()) { e.preventDefault(); msg("Choose a folder first: click Browse… and pick one, or type its full path."); path.focus(); }
  });
  $("pk-use").onclick = () => { if (cur) set(cur); else box.hidden = true; };
  $("pk-cancel").onclick = () => { box.hidden = true; path.focus(); };
})();
