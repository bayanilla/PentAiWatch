// Timeline ("time tunnel"): replays what one outside source did, in the order it did it. Time runs along
// the tunnel. The source rides the INTERNET band on top, each lane on the wall is a subnet it went to, and
// every session is a line from the source down to the host, drawn at the moment the session started. The
// bars above the band are the source's bursts, exactly as the timing signal cut them, so the rhythm the
// detection read (a few sessions, a pause, a few sessions) can be seen.
//
// After the Timeline of VulnScope MAX (vulnflow/static/timeline3d.js): the same tunnel, lanes, camera and
// mouse controls. What is drawn is this tool's: D.timelines, written by explore.py for the sources that
// narrowed. Nothing is scored here: which bursts count comes with the data.
vfWhenReady(function (D) {   // starts once vf_data.js has unpacked the data, after explorer.js
'use strict';
const own = (o, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(o, k);
const TL = D.timelines || {}, SRC = (D.sources || []).filter(s => own(TL, s.ip));
const root = document.getElementById('timeline-view'), openBtn = document.getElementById('btn-timeline');
const NONE = {open() {}, close() {}, isOpen: () => false, has: () => false, stats: () => ({open: false})};
if (!root || !openBtn) { window.PWTimeline = NONE; return; }
if (!SRC.length || !(window.THREE && window.VF3D && window.VF3D.supported())) { openBtn.hidden = true; window.PWTimeline = NONE; return; }
openBtn.hidden = false;

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmt = n => Number(n || 0).toLocaleString('en-US');
const plural = (n, word) => `${fmt(n)} ${n === 1 ? word : word + 's'}`;
const kv = (k, v) => `<div class="kv"><span>${esc(k)}</span><b>${esc(v)}</b></div>`;
const COL = {t0: css('--t0'), l1: css('--l1'), l2: css('--l2'), l3: css('--l3'), accent: css('--accent'), failed: css('--tried'),
  answered: css('--answered'), other: '#4d5054', idle: css('--sweep'), guide: '#34363a', band: '#3d4046', tick: '#44464b'};
const TIMING = D.timing || {}, num = (v, d) => Number.isFinite(Number(v ?? d)) ? Number(v ?? d) : d;
const LO = num(TIMING.pause_min_seconds, 20), HI = num(TIMING.pause_max_seconds, 35), MAXB = num(TIMING.max_burst_sessions, 15);
const BAND = `${LO} to ${HI} second`;
const levelKey = s => !s.flagged ? 'accent' : ['t0', 'l1', 'l2', 'l3'][Math.max(0, Math.min(3, s.level || 0))];
const levelTag = s => !s.flagged ? 'Not flagged' : s.level ? 'Level ' + s.level : 'Tier 0';
// what a session is (explore.py): the first attempt on a service, by its outcome; a return to a service the
// source narrowed onto; any other later session. 8 is added when its only time is an end time.
const FAILED = 0, ANSWERED = 1, RETURN = 3, UNTIMED = 8;
// a burst is [first start, last start, sessions, the pause after it in seconds, how it counts]: 2 when it
// is one of the signal's cycles (a short burst, then a pause in the band), 1 when only its pause fits
const inBand = b => b[4] >= 1, paced = b => b[4] === 2;
const STILL = /[?&#]still\b/.test(location.search + location.hash);
const MOTION = !STILL && !matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---------------------------------------------------------------- page chrome
root.tabIndex = -1;
root.innerHTML = `<canvas id="tl-canvas" aria-label="One source's sessions over time"></canvas><div id="tl-labels"></div>
<header class="tl-top"><div class="tl-title"><div class="brand"><b>PentAIWatch</b><span class="view">Timeline</span></div><div class="s" id="tl-sub"></div></div>
  <button type="button" id="tl-back" title="Back to the map (Esc)">← Map</button>
  <div class="seg" role="group" aria-label="View"><button type="button" data-view="flat" title="Flat view (2)">Flat</button><button type="button" data-view="3d" title="3D view (3)">3D</button><button type="button" class="on" aria-current="true" title="Timeline (Esc goes back to the map)">Timeline</button></div>
  <button type="button" id="tl-about-toggle" aria-controls="tl-about" aria-expanded="false" aria-label="What am I looking at?" title="What am I looking at? (?)">?</button></header>
<aside class="tl-side"><div id="tl-src"></div><h3>Time window</h3><div class="tl-winbtns" role="group" aria-label="Window length" id="tl-wins"></div>
  <input id="tl-scrub" type="range" min="0" step="any" aria-label="Window start">
  <button type="button" id="tl-play" title="Replay the sessions in the order they started (Space)">▶ Replay</button>
  <div id="tl-win"></div><div id="tl-notes"></div></aside>
<p id="tl-about" role="note" hidden>Time runs <b>left to right</b> along the tunnel. The source rides the <b>INTERNET</b> band on top and each lane on the wall is a subnet it went to. Every session is a <b>line</b> from the source down to the host, drawn at the moment it started: the grey fan is the sweep, the coloured lines are its returns to the services that answered. The <b>bars</b> above the band are its bursts, and a thin line joins two bursts when the pause between them was ${BAND}s long. Pick a shorter window to see single bursts, drag it through the campaign, or press <b>Replay</b>.</p>
<div class="tl-legend" id="tl-legend"></div>
<div class="tl-cams" role="group" aria-label="Camera"><button type="button" data-p="angled" title="Angled view">Angled</button><button type="button" data-p="side" title="Side view">Side</button><button type="button" data-p="down" title="Look down the tunnel">Down the tunnel</button><button type="button" data-p="above" title="Top-down view">Above</button><button type="button" id="tl-spin" title="Turn slowly (stops when you move the camera)">Spin</button></div>
<div id="tl-tip" role="tooltip" hidden></div>`;

// ---------------------------------------------------------------- the source on show
let S = null, T = null, SPAN = 1, WINS = [], WIN = 1, w0 = 0, hostA = [], lanes = [], INET = 0, levelCol = COL.accent, MULTI = false;
const LEN = 900, X0 = -LEN / 2, PAD = LEN * .03, R = 70, RX = 112;
const tx = ms => X0 + PAD + (ms - w0) / WIN * (LEN - 2 * PAD);
const at = ms => new Date(T.t0_ms + ms).toISOString();
const hms = ms => at(ms).slice(11, 19);
const day = ms => at(ms).slice(0, 19).replace('T', ' ');
const clock = ms => (MULTI ? at(ms).slice(5, 10) + ' ' : '') + hms(ms);       // with the date when the campaign runs past midnight
const long = ms => { const s = ms / 1000; return s >= 5400 ? +(s / 3600).toFixed(1) + ' h' : s >= 60 ? +(s / 60).toFixed(s < 600 ? 1 : 0) + ' min' : Math.round(s) + ' s'; };
const lower = (list, key, ms) => { let a = 0, b = list.length; while (a < b) { const m = (a + b) >> 1; if (key(list[m]) < ms) a = m + 1; else b = m; } return a; };
const atEnd = () => w0 + WIN >= SPAN - 1e-6;
// the sessions and bursts inside the window [w0, w0 + WIN); the last window also takes the very end
function range() { return [lower(T.sessions, s => s[0], w0), atEnd() ? T.sessions.length : lower(T.sessions, s => s[0], w0 + WIN)]; }
function burstsIn() { const ids = []; T.bursts.forEach((b, i) => { if (b[1] >= w0 && (b[0] < w0 + WIN || atEnd())) ids.push(i); }); return ids; }

function pickSource(ip) {
  S = SRC.find(s => s.ip === ip) || SRC[0]; T = TL[S.ip];
  SPAN = Math.max(1000, T.seconds * 1000); levelCol = COL[levelKey(S)]; MULTI = at(0).slice(0, 10) !== at(SPAN).slice(0, 10);
  root.style.setProperty('--tl-level', levelCol);
  // window lengths on offer: everything, then shorter ones down to a minute. One is the scoring window.
  const scoring = num(D.window_hours, 2) * 3600e3;
  WINS = [SPAN].concat([...new Set([43200e3, scoring, 1800e3, 300e3, 60e3])].sort((a, b) => b - a).filter(w => w < SPAN * .75));
  WIN = SPAN; w0 = 0;
  // lanes share the wall below the INTERNET band, each as wide as the hosts it holds need
  lanes = T.lanes.map(([id, name, n]) => ({id, name, n, k: 0}));
  INET = Math.PI * .55; const gap = .05, rest = Math.PI * 2 - INET - gap * (lanes.length + 1);
  const wsum = lanes.reduce((a, l) => a + Math.sqrt(l.n + 2), 0);
  let a = INET / 2 + gap;
  lanes.forEach(l => { l.span = Math.sqrt(l.n + 2) / wsum * rest; l.a0 = a; a += l.span + gap; });
  hostA = T.hosts.map(([, li]) => { const l = lanes[li]; return l.a0 + (l.k++ + .5) / Math.max(1, l.n) * l.span; });
  side(); legend();
  $('tl-sub').textContent = `${S.ip} · ${levelTag(S)} · ${day(0)} → ${MULTI ? day(SPAN) : hms(SPAN)} UTC · ${plural(T.sessions_total, 'session')}`;
}
function side() {
  const b = T.bursts, m = T.marks;
  const pick = SRC.length > 1 ? `<select id="tl-pick" aria-label="Source">${SRC.map(s => `<option value="${esc(s.ip)}"${s === S ? ' selected' : ''}>${esc(s.ip)} · ${esc(levelTag(s))}</option>`).join('')}</select>`
    : `<div class="who mono">${esc(S.ip)}</div>`;
  $('tl-src').innerHTML = `<h3>Source</h3>${pick}` +
    `<div class="verdict"><span class="pill ${S.flagged ? 'c-' + levelKey(S) : 'c-none'}">${esc(levelTag(S))}</span><span>${esc(S.label)}</span></div>` +
    kv('Sweep', `${clock(m.probe_start)} to ${clock(m.probe_end)}`) + kv('Narrowing starts', clock(m.narrowing_start)) +
    kv('Sessions', fmt(T.sessions_total)) + kv('Bursts', fmt(T.bursts_total)) +
    kv(`Short, then a ${BAND} pause`, fmt(b.filter(paced).length)) + kv('Scoring windows in which timing fired', fmt(T.fired.length));
  if ($('tl-pick')) $('tl-pick').onchange = e => { stopPlay(); pickSource(e.target.value); setupWindow(); setHash('#timeline=' + encodeURIComponent(S.ip)); };
  const untimed = T.sessions.filter(s => s[2] & UNTIMED).length, notes = [];
  if (T.every > 1) notes.push(`This source has ${fmt(T.sessions_total)} sessions, more than can be drawn. Every ${T.every}${T.every === 2 ? 'nd' : T.every === 3 ? 'rd' : 'th'} one is drawn (${fmt(T.sessions.length)}). The bursts are counted from all of them.`);
  if (untimed) notes.push(`${plural(untimed, 'session')} drawn here ${untimed === 1 ? 'has' : 'have'} only an end time. ${untimed === 1 ? 'It is drawn at that time and belongs' : 'They are drawn at that time and belong'} to no burst.`);
  if (!b.length) notes.push('None of this source\'s sessions has a start time, so there are no bursts to draw.');
  if (T.bursts_total > b.length) notes.push(`The first ${fmt(b.length)} of ${fmt(T.bursts_total)} bursts are drawn.`);
  $('tl-notes').innerHTML = notes.map(n => `<p>${esc(n)}</p>`).join('');
}
function legend() {
  const el = $('tl-legend');
  el.innerHTML = [[COL.failed, 'Sweep, no answer'], [COL.answered, 'Sweep, answered'], [levelCol, 'Return to a narrowed service'], [COL.other, 'Other session'],
    [levelCol, `Short burst, then a ${LO} to ${HI} s pause`, 'bar'], [COL.idle, 'Other burst', 'bar']].concat(T.fired.length ? [[levelCol, 'Scoring window in which timing fired', 'rail']] : [])
    .map(([c, t, k]) => `<span><i class="${k || ''}" style="--c:${c}"></i>${esc(t)}</span>`).join('') +
    '<span class="cal">Drag: rotate · right-drag: pan · middle-drag: up/down · scroll: zoom · click a bar: zoom in</span>';
  root.style.setProperty('--tl-legend-h', el.offsetHeight + 'px');
}

// ---------------------------------------------------------------- scene
let renderer, scene, camera, group = null, built = false, raf = 0, last = 0;
let sessionLines = [], bars = null, head = null, labels = [], barBurst = [], rails = 0;
const cam = {theta: -1, phi: 1.22, r: 1000, tx: 0, ty: -12, tz: 0, spin: MOTION, preset: 'angled'};
const play = {on: false, t: 0}, PLAY_SECONDS = 20;       // a replay crosses one window in this long

// ms: the moment the label belongs to, so a replay shows it only once it has got there
function label(text, x, y, z, cls, ms) {
  const el = document.createElement('div'); el.className = 'tl-l ' + cls; el.textContent = text; $('tl-labels').appendChild(el);
  labels.push({el, cls, v: new THREE.Vector3(x, y, z), ms, w: 0});
}
function circle(radius, x, color, opacity) {
  const pts = []; for (let i = 0; i <= 96; i++) { const a = i / 96 * Math.PI * 2; pts.push(new THREE.Vector3(0, Math.cos(a) * radius, Math.sin(a) * radius)); }
  const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({color, transparent: true, opacity}));
  l.position.x = x; group.add(l); return l;
}
function lines(p, c, opacity) {
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(p, 3)); g.setAttribute('color', new THREE.Float32BufferAttribute(c, 3));
  const l = new THREE.LineSegments(g, new THREE.LineBasicMaterial({vertexColors: true, transparent: true, opacity, depthWrite: false}));
  group.add(l); return l;
}
// the sessions of the window as lines from the source's track down to the host, in time order
function chords(lo, hi, want, opacity) {
  const p = [], c = [], times = [], col = new THREE.Color();
  for (let i = lo; i < hi; i++) {
    const [ms, h, kind] = T.sessions[i], k = kind & 7; if (!want(k)) continue;
    const x = tx(ms), a = hostA[h]; col.set(k === FAILED ? COL.failed : k === ANSWERED ? COL.answered : k === RETURN ? levelCol : COL.other);
    p.push(x, RX, 0, x, Math.cos(a) * R, Math.sin(a) * R); c.push(col.r, col.g, col.b, col.r, col.g, col.b); times.push(ms);
  }
  const l = lines(p, c, opacity); l.userData.times = times; return l;
}
function tickStep() {
  for (const s of [10e3, 30e3, 60e3, 300e3, 900e3, 1800e3, 3600e3, 10800e3, 21600e3, 43200e3, 86400e3]) if (WIN / s <= 12) return s;
  return 7 * 86400e3;
}
function dispose() {
  if (!group) return;
  group.traverse(o => { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); if (o.isInstancedMesh) o.dispose(); });
  scene.remove(group); group = null;
  for (const l of labels) l.el.remove();
  labels = [];
}
function buildWindow() {
  dispose(); group = new THREE.Group(); scene.add(group); $('tl-tip').hidden = true;
  const xa = X0, xb = X0 + LEN, clip = x => Math.max(xa, Math.min(xb, x));
  // lane edges along the wall and their names, the INTERNET band on top with the source's track in it
  const gp = [], gc = [], g1 = new THREE.Color(COL.guide), g2 = new THREE.Color(COL.band);
  const edge = (a, r, c) => { gp.push(xa, Math.cos(a) * r, Math.sin(a) * r, xb, Math.cos(a) * r, Math.sin(a) * r); gc.push(c.r, c.g, c.b, c.r, c.g, c.b); };
  lanes.forEach(l => { edge(l.a0, R, g1); edge(l.a0 + l.span, R, g1); const m = l.a0 + l.span / 2;
    label(`${l.name && l.id !== '*' ? l.name + ' · ' : ''}${l.id === '*' ? 'other subnets' : l.id} · ${plural(l.n, 'host')}`, xa - 8, Math.cos(m) * (R + 8), Math.sin(m) * (R + 8), 'lane'); });
  edge(-INET / 2, RX, g2); edge(INET / 2, RX, g2); edge(0, RX, g2);
  label(`INTERNET · ${S.ip}`, xa - 8, RX + 12, 0, 'inet');
  lines(gp, gc, .7);
  // time rings
  const step = tickStep();
  for (let t = Math.ceil((T.t0_ms + w0) / step) * step - T.t0_ms; t <= w0 + WIN; t += step) {
    circle(R, tx(t), COL.tick, .55); label(WIN > 86400e3 || MULTI && step >= 3600e3 ? at(t).slice(5, 16).replace('T', ' ') : step < 60e3 ? hms(t) : hms(t).slice(0, 5), tx(t), -R - 14, 0, 'day');
  }
  // sessions
  const [lo, hi] = range();
  // (the few sweep attempts that were answered are drawn apart, so they stand out of the many that failed)
  sessionLines = [chords(lo, hi, k => k < RETURN && k !== ANSWERED, .5), chords(lo, hi, k => k >= RETURN, .85), chords(lo, hi, k => k === ANSWERED, 1)];
  // bursts as bars above the band, and a thin line across each pause that is in the band
  const ids = burstsIn(), cap = Math.max(1, ids.length * 2 + 1), m4 = new THREE.Matrix4(), col = new THREE.Color();
  bars = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), new THREE.MeshBasicMaterial(), cap);
  bars.frustumCulled = false;          // its bounds are one unit box, wherever the bars are
  const starts = [], thick = [], ext = []; barBurst = []; let n = 0;
  const put = (x1, x2, wide, color, start, burst) => {
    if (x2 < xa || x1 > xb) return;
    const a = clip(x1), b = Math.max(clip(x2), a + (wide > 1 ? .8 : 0)); if (b <= a) return;
    m4.makeScale(b - a, wide, wide).setPosition((a + b) / 2, RX + 8, 0); bars.setMatrixAt(n, m4); bars.setColorAt(n, col.set(color));
    starts.push(start); barBurst.push(burst); thick.push(wide > 1); ext.push(a, b); n++;
  };
  const pauseLine = i => { const b = T.bursts[i]; if (inBand(b)) put(tx(b[1]), tx(b[1] + b[3] * 1000), .7, levelCol, b[1], i); };
  const before = (ids.length ? ids[0] : lower(T.bursts, b => b[0], w0)) - 1;   // the burst whose pause runs into the window
  if (before >= 0) pauseLine(before);
  const few = ids.length <= 16;        // few enough to say how many sessions each burst has and how long each pause is
  for (const i of ids) { const b = T.bursts[i];
    put(tx(b[0]), tx(b[1]), 2.6, paced(b) ? levelCol : COL.idle, b[0], i); pauseLine(i);
    if (few) { label(fmt(b[2]), clip(tx((b[0] + b[1]) / 2)), RX + 18, 0, 'bn', b[0]);
      if (inBand(b) && b[1] + b[3] * 500 <= w0 + WIN) label(Math.round(b[3]) + ' s', tx(b[1] + b[3] * 500), RX + 18, 0, 'pz', b[1]); } }
  bars.count = n; bars.userData = {n, starts, thick, ext}; bars.instanceMatrix.needsUpdate = true; if (bars.instanceColor) bars.instanceColor.needsUpdate = true;
  group.add(bars);
  // where the sweep starts and ends and where narrowing starts
  const mk = T.marks, seen = t => t >= w0 && t <= w0 + WIN;
  [[mk.probe_start, 'SWEEP STARTS'], [mk.probe_end, 'SWEEP ENDS'], [mk.narrowing_start, 'NARROWING STARTS']].forEach(([t, text]) => {
    if (seen(t)) { circle(R + 3, tx(t), COL.answered, .9); label(`${text} ${hms(t)}`, tx(t), -R - 30, 0, 'mark', t); } });
  // the source's track is lit over the scoring windows in which the timing signal fired
  const hot = [], scoring = num(D.window_hours, 2) * 3600e3;
  for (const [t] of T.fired) { const e = t + scoring, l = hot[hot.length - 1]; if (l && t <= l[1]) l[1] = Math.max(l[1], e); else hot.push([t, e]); }
  rails = 0;
  for (const [a, b] of hot) { const x1 = clip(tx(Math.max(a, 0))), x2 = clip(tx(Math.min(b, SPAN))); if (x2 - x1 < .5) continue;
    const rail = new THREE.Mesh(new THREE.BoxGeometry(x2 - x1, 1.1, 1.1), new THREE.MeshBasicMaterial({color: levelCol}));
    rail.position.set((x1 + x2) / 2, RX, 0); group.add(rail); rails++; if (!few) label('TIMING SIGNAL FIRED', (x1 + x2) / 2, RX + 32, 0, 'fired'); }
  head = circle(R + 5, 0, '#ffffff', .9); head.visible = false;
  reveal(play.on ? play.t : null);
}
// replay: draw only what started before t (null: everything in the window)
function reveal(t) {
  for (const l of sessionLines) { const tm = l.userData.times; l.geometry.setDrawRange(0, 2 * (t == null ? tm.length : lower(tm, v => v, t))); }
  bars.count = t == null ? bars.userData.n : lower(bars.userData.starts, v => v, t);
  head.visible = t != null; if (t != null) head.position.x = tx(Math.min(t, w0 + WIN));
}
function winText() {
  const [lo, hi] = range(), ids = burstsIn(); let sweep = 0, answered = 0, back = 0;
  for (let i = lo; i < hi; i++) { const k = T.sessions[i][2] & 7; if (k < RETURN) sweep++; if (k === ANSWERED) answered++; if (k === RETURN) back++; }
  $('tl-win').innerHTML = kv(`${clock(w0)} → ${clock(Math.min(w0 + WIN, SPAN))}`, long(Math.min(WIN, SPAN))) +
    kv(T.every > 1 ? 'Sessions drawn' : 'Sessions', fmt(hi - lo)) + kv('Sweep attempts', `${fmt(sweep)} (${fmt(answered)} answered)`) +
    kv('Returns to narrowed services', fmt(back)) + kv('Bursts', fmt(ids.length)) +
    kv(`Short, then a ${BAND} pause`, fmt(ids.filter(i => paced(T.bursts[i])).length)) +
    kv('Replay speed', `${fmt(Math.max(1, Math.round(WIN / 1000 / PLAY_SECONDS)))}× real time`);
}
function setWindow(start) {
  w0 = Math.max(0, Math.min(SPAN - WIN, start)); $('tl-scrub').value = w0;
  buildWindow(); winText();
}
function setLength(i, start) {
  WIN = WINS[i]; const sc = $('tl-scrub'); sc.max = Math.max(0, SPAN - WIN); sc.disabled = SPAN - WIN <= 0;
  $('tl-wins').querySelectorAll('button').forEach(b => b.classList.toggle('on', +b.dataset.w === i));
  setWindow(start);
}
function setupWindow() {
  $('tl-wins').innerHTML = WINS.map((w, i) => `<button type="button" data-w="${i}">${i ? long(w) : 'All'}</button>`).join('');
  $('tl-wins').querySelectorAll('button').forEach(b => { b.onclick = () => { stopPlay(); setLength(+b.dataset.w, w0); }; });
  setLength(0, 0);
}
$('tl-scrub').oninput = e => { stopPlay(); setWindow(+e.target.value); };
function startPlay() { play.on = true; play.t = w0; $('tl-play').textContent = '❚❚ Pause'; reveal(play.t); }
function stopPlay() { if (!play.on) return; play.on = false; $('tl-play').textContent = '▶ Replay'; if (bars) reveal(null); }
$('tl-play').onclick = () => { if (play.on) stopPlay(); else startPlay(); };

function build() {
  renderer = new THREE.WebGLRenderer({canvas: $('tl-canvas'), antialias: true, alpha: true});
  renderer.setClearColor(0x000000, 0);
  scene = new THREE.Scene(); camera = new THREE.PerspectiveCamera(45, 1, 1, 10000);
  controls(); built = true;
}

// ---------------------------------------------------------------- camera: moves only when you drag or zoom, or while Spin is on
const PRESETS = {angled: {theta: -1, phi: 1.22, r: LEN * 1.05, t: [-LEN * .12, -12, 0]}, side: {theta: 0, phi: 1.42, r: LEN * 1.15, t: [-LEN * .03, 0, 0]},
  down: {theta: -Math.PI / 2 + .25, phi: 1.3, r: LEN / 2 + 160, t: [LEN * .12, 0, 0]}, above: {theta: 0, phi: .25, r: LEN * 1.15, t: [-LEN * .03, 0, 0]}};
function applyCam() {
  cam.phi = Math.max(.05, Math.min(Math.PI - .05, cam.phi)); const sp = Math.sin(cam.phi);
  camera.position.set(cam.tx + cam.r * sp * Math.sin(cam.theta), cam.ty + cam.r * Math.cos(cam.phi), cam.tz + cam.r * sp * Math.cos(cam.theta));
  camera.lookAt(cam.tx, cam.ty, cam.tz);
}
function setPreset(name) { const p = PRESETS[name] || PRESETS.angled; cam.preset = PRESETS[name] ? name : 'angled'; Object.assign(cam, {theta: p.theta, phi: p.phi, r: p.r, tx: p.t[0], ty: p.t[1], tz: p.t[2]}); applyCam(); markCam(); }
function setSpin(on) { cam.spin = on; markCam(); }
function markCam() { root.querySelectorAll('.tl-cams [data-p]').forEach(b => b.setAttribute('aria-pressed', b.dataset.p === cam.preset)); $('tl-spin').setAttribute('aria-pressed', cam.spin); }
root.querySelectorAll('.tl-cams [data-p]').forEach(b => { b.onclick = () => setPreset(b.dataset.p); });
$('tl-spin').onclick = () => setSpin(!cam.spin);
// the burst whose bar, or the line across its pause, is nearest the pointer and within a few px of it, as
// an index into T.bursts. The bars are thin, so the pointer does not have to be exactly on one.
function hit(e) {
  if (!bars || !bars.count) return null;
  const r = renderer.domElement.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top, ext = bars.userData.ext;
  let best = null, near = 49;
  for (let j = 0; j < bars.count; j++) {
    _v.set(ext[2 * j], RX + 8, 0).project(camera); if (Math.abs(_v.z) > 1) continue;      // behind the camera
    const ax = (_v.x + 1) / 2 * r.width, ay = (1 - _v.y) / 2 * r.height;
    _v.set(ext[2 * j + 1], RX + 8, 0).project(camera); if (Math.abs(_v.z) > 1) continue;
    const dx = (_v.x + 1) / 2 * r.width - ax, dy = (1 - _v.y) / 2 * r.height - ay, len = dx * dx + dy * dy;
    const t = len ? Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / len)) : 0, qx = ax + t * dx - px, qy = ay + t * dy - py;
    if (qx * qx + qy * qy < near) { near = qx * qx + qy * qy; best = barBurst[j]; }
  }
  return best;
}
function burstTip(i) {
  const b = T.bursts[i], [first, lastStart, n, pause] = b;
  return `<b>Burst of ${plural(n, 'session')}</b> · ${hms(first)}${lastStart > first ? ' to ' + hms(lastStart) : ''}<br>` +
    (pause == null ? 'The last burst: no pause follows.' : `Then a pause of ${pause >= 90 ? long(pause * 1000) : Number(pause).toFixed(1) + ' s'}, ${inBand(b) ? 'inside' : 'outside'} the ${BAND} band.`) +
    (inBand(b) && !paced(b) ? `<br>Longer than ${fmt(MAXB)} sessions, so it does not count as a short burst.` : '') + '<br><span class="m">Click to zoom to it</span>';
}
function zoomTo(i) {   // a window short enough to tell the bursts around it apart
  const want = WINS.findIndex(w => w <= 300e3); if (want < 1) return;
  stopPlay(); setLength(want, T.bursts[i][0] - WINS[want] / 2);
}
function controls() {
  const el = renderer.domElement, pts = new Map(); let drag = null;
  el.addEventListener('contextmenu', e => e.preventDefault());
  el.addEventListener('mousedown', e => { if (e.button === 1) e.preventDefault(); });   // no browser autoscroll on the middle button
  el.addEventListener('pointerdown', e => { if (e.button === 1) e.preventDefault(); el.setPointerCapture(e.pointerId); pts.set(e.pointerId, {x: e.clientX, y: e.clientY});
    drag = {pan: e.button === 2 || e.shiftKey, vert: e.button === 1, moved: 0}; el.classList.add('drag'); });
  el.addEventListener('pointermove', e => {
    if (!drag) { const b = hit(e), tip = $('tl-tip');
      if (b != null) { tip.innerHTML = burstTip(b); tip.hidden = false; el.classList.add('hover');
        tip.style.left = Math.min(innerWidth - tip.offsetWidth - 8, e.clientX + 14) + 'px'; tip.style.top = Math.min(innerHeight - tip.offsetHeight - 8, e.clientY + 14) + 'px'; }
      else { tip.hidden = true; el.classList.remove('hover'); }
      return; }
    const prev = pts.get(e.pointerId); if (!prev) return;
    if (pts.size === 2) { const [a, b] = [...pts.values()], d0 = Math.hypot(a.x - b.x, a.y - b.y); pts.set(e.pointerId, {x: e.clientX, y: e.clientY});
      const [c, d] = [...pts.values()], d1 = Math.hypot(c.x - d.x, c.y - d.y); if (d0 && d1) { cam.r *= d0 / d1; applyCam(); } setSpin(false); return; }
    const dx = e.clientX - prev.x, dy = e.clientY - prev.y; pts.set(e.pointerId, {x: e.clientX, y: e.clientY}); drag.moved += Math.abs(dx) + Math.abs(dy);
    if (drag.moved > 3) { setSpin(false); cam.preset = ''; markCam(); $('tl-tip').hidden = true; }
    if (drag.vert) { const s = cam.r * .0016, up = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 1);   // middle-drag: straight up or down on screen
      cam.tx += dy * s * up.x; cam.ty += dy * s * up.y; cam.tz += dy * s * up.z; }
    else if (drag.pan) { const s = cam.r * .0016, right = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 0), up = new THREE.Vector3().setFromMatrixColumn(camera.matrix, 1);
      cam.tx += -dx * s * right.x + dy * s * up.x; cam.ty += -dx * s * right.y + dy * s * up.y; cam.tz += -dx * s * right.z + dy * s * up.z; }
    else { cam.theta -= dx * .005; cam.phi -= dy * .005; }
    applyCam();
  });
  const end = e => { pts.delete(e.pointerId); if (drag && drag.moved < 4 && !pts.size && e.type === 'pointerup') { const b = hit(e); if (b != null) zoomTo(b); }
    if (!pts.size) { drag = null; el.classList.remove('drag'); } };
  el.addEventListener('pointerup', end); el.addEventListener('pointercancel', end);
  el.addEventListener('wheel', e => { e.preventDefault(); cam.r = Math.max(40, Math.min(5000, cam.r * Math.exp(e.deltaY * .0012))); applyCam(); setSpin(false); cam.preset = ''; markCam(); }, {passive: false});
}
const _v = new THREE.Vector3();
let frames = 0;
function frame(now) {
  raf = requestAnimationFrame(frame);
  const dt = Math.min(.05, (now - (last || now)) / 1000); last = now; frames++;
  if (cam.spin) { cam.theta -= dt * .06; applyCam(); }
  if (play.on) {
    play.t += dt * WIN / PLAY_SECONDS;
    if (play.t >= w0 + WIN) { if (atEnd()) stopPlay(); else setWindow(w0 + WIN); }
    if (play.on) reveal(play.t);
  }
  renderer.render(scene, camera);
  // labels follow their place in the scene. Lane names end at the tunnel's mouth and stay on screen. A time
  // label steps down where it would sit on a lane name; the sweep and narrowing marks step down where
  // they would sit on either, and line up under one another in the order they happened.
  const W = innerWidth, H = innerHeight, placed = [];
  for (const l of labels) { _v.copy(l.v).project(camera);
    const vis = _v.z < 1 && Math.abs(_v.x) < 1.1 && Math.abs(_v.y) < 1.1 && (!play.on || l.ms == null || l.ms <= play.t);
    l.el.style.display = vis ? '' : 'none'; if (!vis) continue;
    let x = (_v.x + 1) / 2 * W, y = (1 - _v.y) / 2 * H;
    const ends = l.cls === 'lane' || l.cls === 'inet', mark = l.cls === 'mark';
    if (ends || mark || l.cls === 'day') {
      const w = l.w || (l.w = l.el.offsetWidth); if (ends) x = Math.max(x, w + 6);
      const x0 = ends ? x - w : x - w / 2, x1 = x0 + w;
      if (!ends) for (let again = true, n = 0; again && n < 8; n++) { again = false;
        for (const q of placed) if (x0 < q.x1 + 6 && x1 > q.x0 - 6 && (mark && q.mark ? y < q.y + 14 : Math.abs(q.y - y) < 14)) { y = q.y + 14; again = true; } }
      placed.push({x0, x1, y, mark});
    }
    l.el.style.transform = `translate(${x}px,${y}px) translate(${ends ? '-100%' : '-50%'},-50%)`; }
}
function resize() {
  if (!renderer) return;
  renderer.setPixelRatio(Math.min(2, devicePixelRatio || 1)); renderer.setSize(innerWidth, innerHeight, false); camera.aspect = innerWidth / innerHeight;
  // the side panel covers the right of the screen (not on narrow ones): centre the picture in what is left
  camera.setViewOffset(innerWidth, innerHeight, innerWidth > 900 ? 150 : 0, 0, innerWidth, innerHeight);
  root.style.setProperty('--tl-legend-h', $('tl-legend').offsetHeight + 'px');
}
addEventListener('resize', () => { if (isOpen) resize(); });

// ---------------------------------------------------------------- note, open and close, switching views
const ABOUT_MS = 15000; let aboutTimer = 0;
function closeAbout() { clearTimeout(aboutTimer); $('tl-about').hidden = true; $('tl-about-toggle').setAttribute('aria-expanded', 'false'); }
function openAbout(ms = ABOUT_MS) { $('tl-about').hidden = false; $('tl-about-toggle').setAttribute('aria-expanded', 'true'); clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, ms); }
function toggleAbout() { if ($('tl-about').hidden) openAbout(); else closeAbout(); }
$('tl-about-toggle').onclick = toggleAbout;
$('tl-about').addEventListener('mouseenter', () => clearTimeout(aboutTimer));
$('tl-about').addEventListener('mouseleave', () => { clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, 3000); });
let isOpen = false, prevHash = '';
const HASH = /[#&]timeline=([^&]+)/;
function setHash(h) { try { history.replaceState(null, '', h || '#'); } catch (_) {} }
// while the Timeline covers the map, the map's own controls take no focus and no clicks
const UNDER = ['controls', 'viewctl', 'rail', 'panel', 'legend'].map($).filter(Boolean);
function open(ip) {
  if (!built) { try { build(); } catch (err) { console.warn('Timeline unavailable', err); openBtn.hidden = true; return; } }
  const sel = window.PWExplorer && window.PWExplorer.stats ? window.PWExplorer.stats().selected : null;
  stopPlay(); pickSource(own(TL, ip) ? ip : own(TL, sel) ? sel : S ? S.ip : SRC[0].ip);
  if (!isOpen) { prevHash = HASH.test(location.hash) ? '' : location.hash; UNDER.forEach(el => { el.inert = true; }); }
  isOpen = true; root.hidden = false; openBtn.setAttribute('aria-expanded', 'true');
  setupWindow(); setPreset('angled'); setSpin(MOTION); legend();
  resize(); last = 0; cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); if (MOTION) openAbout();
  setHash('#timeline=' + encodeURIComponent(S.ip));
  root.focus({preventScroll: true});
}
function close() {
  if (!isOpen) return;
  stopPlay(); isOpen = false; root.hidden = true; cancelAnimationFrame(raf); closeAbout(); $('tl-tip').hidden = true; openBtn.setAttribute('aria-expanded', 'false');
  UNDER.forEach(el => { el.inert = false; }); setHash(prevHash); openBtn.focus({preventScroll: true});
}
function showView(v) { close(); if (window.PWExplorer) window.PWExplorer.set3d(v === '3d'); }
openBtn.onclick = () => { if (!isOpen) open(); };
$('tl-back').onclick = close;
root.querySelectorAll('.seg [data-view]').forEach(b => { b.onclick = () => showView(b.dataset.view);
  if (b.dataset.view === '3d' && !(window.PWExplorer && window.PWExplorer.can3d)) b.hidden = true; });
// while open, keys belong to this view so the map underneath does not react
addEventListener('keydown', e => {
  if (!isOpen) return;
  e.stopImmediatePropagation();
  const el = e.target, typing = el.tagName === 'SELECT' || el.tagName === 'TEXTAREA' || el.tagName === 'INPUT';
  if (e.key === 'Escape') close();
  else if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  else if (e.key === '?') toggleAbout();
  else if (e.key === ' ' && el.tagName !== 'BUTTON') { e.preventDefault(); if (play.on) stopPlay(); else startPlay(); }
  else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { stopPlay(); setWindow(w0 + (e.key === 'ArrowRight' ? WIN : -WIN) / 2); }
  else if (e.key === '2') showView('flat');
  else if (e.key === '3' && window.PWExplorer && window.PWExplorer.can3d) showView('3d');
}, true);
// where(i): the middle of burst i's bar on screen, in CSS px, or null when it is not drawn. For the browser
// check, which points at a bar and clicks it.
function where(i) {
  const j = barBurst.findIndex((b, n) => b === i && n < bars.count && bars.userData.thick[n]); if (j < 0) return null;
  const m = new THREE.Matrix4(); bars.getMatrixAt(j, m); _v.setFromMatrixPosition(m).project(camera);
  return [(_v.x + 1) / 2 * innerWidth, (1 - _v.y) / 2 * innerHeight];
}
// stats(): read-only counts for the browser check (scripts/smoke): what the window holds and what is drawn
function stats() {
  if (!isOpen || !T) return {open: false};
  const [lo, hi] = range(), ids = burstsIn(), out = {open: true, source: S.ip, sessions: T.sessions.length, inWindow: hi - lo, drawn: 0, shown: 0, misplaced: 0,
    bursts: ids.length, paced: ids.filter(i => paced(T.bursts[i])).length, bars: bars.userData.n, barsShown: bars.count, rails,
    window: [w0, WIN], windows: WINS.slice(), span: SPAN, playing: play.on, at: play.on ? play.t : null, frames, labels: labels.length, lanes: lanes.length, hosts: hostA.length,
    groups: sessionLines.map(l => l.userData.times.length)};
  for (const l of sessionLines) {
    const a = l.geometry.getAttribute('position').array, r = l.geometry.drawRange.count;
    out.drawn += a.length / 6; out.shown += Number.isFinite(r) ? Math.min(r, a.length / 3) / 2 : a.length / 6;
    for (const v of a) if (!Number.isFinite(v)) out.misplaced++;
  }
  for (const a of hostA) if (!Number.isFinite(a)) out.misplaced++;
  return out;
}
window.PWTimeline = {open, close, isOpen: () => isOpen, has: ip => own(TL, ip), stats, where,
  length: i => { stopPlay(); setLength(Math.max(0, Math.min(WINS.length - 1, i | 0)), w0); }, start: ms => { stopPlay(); setWindow(Number(ms) || 0); },
  play: on => { if (on) startPlay(); else stopPlay(); }};
let asked = (location.hash.match(HASH) || [])[1];
if (asked) { try { asked = decodeURIComponent(asked); } catch (_) { asked = ''; } if (own(TL, asked)) open(asked); }
});
