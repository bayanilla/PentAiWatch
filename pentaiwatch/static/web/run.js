// A run's page while the analysis runs: the overlay's timer counts from when the run started, and the
// page asks the server how the run is doing every two seconds. When it is no longer running, the page
// reloads and shows the results, or what went wrong. Closing the tab does not stop the run.
(function () {
  const cfg = JSON.parse(document.getElementById("pw-page").textContent);
  const clock = document.getElementById("busy-time"), note = document.getElementById("busy-note");
  const start = Date.now() - (cfg.elapsed || 0) * 1000;
  const tick = () => {
    const s = Math.max(0, Math.floor((Date.now() - start) / 1000));
    clock.textContent = (s >= 3600 ? Math.floor(s / 3600) + ":" + String(Math.floor(s / 60) % 60).padStart(2, "0")
                                   : Math.floor(s / 60)) + ":" + String(s % 60).padStart(2, "0");
  };
  tick(); setInterval(tick, 1000);
  let wait = 2000;
  async function ask() {
    try {
      const r = await fetch(cfg.status, {cache: "no-store"});
      const d = await r.json();
      note.textContent = "";
      wait = 2000;
      if (d.state !== "running") { location.reload(); return; }
    } catch (e) {
      note.textContent = "The upload page is not answering. Is the server still running?";
      wait = Math.min(wait * 2, 30000);
    }
    setTimeout(ask, wait);
  }
  setTimeout(ask, wait);
})();
