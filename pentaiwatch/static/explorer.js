// PentAIWatch Explorer: the map of the outside sources that swept the network and the hosts they tried.
//
// What is drawn is this tool's own: sources on the INTERNET arc, each source's sweep as dashed beams to
// the subnets it tried, and solid beams to the services it kept coming back to. How it is drawn and
// driven follows VulnScope MAX's Explorer (vulnflow/static/explorer.js), so both tools feel the same:
// its subnet packing, camera, mouse and keyboard controls, label placement and "?" note are carried over.
// explorer3d.js draws the 3D view; the 2D canvas draws labels on top of it and is the Flat view.
vfWhenReady(function (D) {   // starts once vf_data.js has unpacked the data
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const fmt = n => Number(n || 0).toLocaleString('en-US');
const plural = (n, word, many) => `${fmt(n)} ${n === 1 ? word : many || word + 's'}`;
const cv = $('stage'), ctx = cv.getContext('2d'), cv3 = $('stage3d');
const can3d = !!(cv3 && window.VF3D && window.VF3D.supported());
let R3 = null, R3inst = null;
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const QUERY = location.search + location.hash;
const still = /[?&#]still\b/.test(QUERY);
const SUBNETS = D.subnets || [], HOSTS = D.hosts || [], SOURCES = D.sources || [], CNT = D.counts || {};

// ---------------------------------------------------------------- look (Graphite)
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const BG_IN = '#1b1c20', BG_OUT = css('--bg') || '#111214', LABEL_HALO = 'rgba(3,6,12,.85)';
const MONO = 'ui-monospace,Menlo,monospace', SANS = 'system-ui,-apple-system,Segoe UI,sans-serif';
const COL = {t0: css('--t0'), l1: css('--l1'), l2: css('--l2'), l3: css('--l3'), sweep: css('--sweep'),
  answered: css('--answered'), tried: css('--tried'), accent: css('--accent'),
  name: '#dcdcd8', dim: '#8e8f8b', subnet: '#b4b5b1', ring: '#777a80', bright: '#f0f0ee'};
// a flagged source's tier or level, as a colour key, a short tag and its name
const levelKey = d => !d.flagged ? 'sweep' : ['t0', 'l1', 'l2', 'l3'][Math.max(0, Math.min(3, d.level || 0))];
const levelTag = d => !d.flagged ? 'Not flagged' : d.level ? 'Level ' + d.level : 'Tier 0';
const LOG_TEXT = {zeek: 'Zeek conn.log', paloalto: 'Palo Alto traffic log'};
const START_TEXT = {zeek_ts: 'Zeek ts (always the session start)', start_field: 'firewall start-time field',
  end_minus_elapsed: 'firewall end time minus elapsed seconds', none: 'no start time available', '': 'not stated by the log reader'};
const when = iso => iso ? String(iso).replace('T', ' ').replace('Z', ' UTC') : 'not seen';
const clock = iso => iso ? String(iso).slice(11, 19) : '';
const span = h => h >= 48 ? (h / 24).toFixed(1) + ' days' : h >= 1 ? h.toFixed(1) + ' hours' : Math.round(h * 60) + ' minutes';
const pct = x => Math.round((x || 0) * 100) + '%';
const listAnd = a => a.length > 1 ? a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1] : a.join('');
const portText = (port, proto) => port == null || proto === 'icmp' ? proto : `${port}/${proto}`;

let W = 0, H = 0, DPR = 1;
// (uy, tuy): the user's own up/down shift of the 3D picture in screen px (middle-drag), cleared when the view is refit
const cam = {x: 0, y: 0, z: 0.25, tx: 0, ty: 0, tz: 1, sx: 0, sy: 0, tsx: 0, tsy: 0, uy: 0, tuy: 0};
const state = {sel: null, hover: null, hoverCluster: null, labels: true, motion: !reduced && !still};
// painted: the first frame is out. Before it the camera is not set, so nothing is yet where it will be
// on screen and the pointer picks nothing (browsers send a pointer move as soon as the page is laid out).
let t0 = performance.now(), painted = false, frames = 0;
// 3D camera: the user's own orbit (oyaw around the plane, opitch from straight above). The map opens on
// the low view, slowly turning to the left (view.spin). The turn stops as soon as the user moves the
// camera, picks a view or picks something on the map; switching to 3D, "← All sources", Reset or the
// Spin button go back to the low view and restart it.
const VIEWS = {top: 0, tilted: 0.82, low: 1.25};
const DEFAULT_VIEW = 'low', SPIN = Math.PI * 2 / 150;   // one full turn every 150 s
const view = {yaw: 0, pitch: VIEWS[DEFAULT_VIEW], dist: 1.6, oyaw: 0, opitch: VIEWS[DEFAULT_VIEW], spin: true};
const hash01 = s => { let h = 2166136261; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return ((h >>> 0) % 10007) / 10007; };

// ---------------------------------------------------------------- nodes
// a host's dot: bigger and on a taller pillar the more a source kept coming back to it
const hostR = d => d.state === 'narrowed' ? 8 + Math.min(5, Math.log2(1 + d.sessions) * 0.5) : d.state === 'answered' ? 5.5 : 4.2;
const pillarH = d => d.state === 'narrowed' ? 40 + Math.min(220, Math.log2(1 + d.sessions) * 18) : d.state === 'answered' ? 14 : 3;
const body = (kind, i, d, r, color) => ({kind, i, d, id: d.ip, x: 0, y: 0, z: 0, tx: 0, ty: 0, tz: 0, ox: 0, oy: 0, oz: 0,
  a: 0, ta: 1, r, tr: r, color, lab: null, at: {}, born: performance.now() + Math.random() * 900});
const hostNodes = HOSTS.map((d, i) => Object.assign(body('host', i, d, hostR(d), d.state === 'answered' ? COL.answered : COL.tried),
  {cluster: null, srcs: [], by: [], ports: []}));
// a source's diamond: the flagged ones biggest; never smaller on screen than MIN_PX, however far out the view is
const srcR = d => d.flagged ? 14 : 8 + Math.min(4, Math.log2(1 + d.hosts_probed) * 0.5);
const minPx = n => n.kind === 'src' ? (n.d.flagged ? 6 : 4) : 1.6;
const srcNodes = SOURCES.map((d, i) => Object.assign(body('src', i, d, srcR(d), COL[levelKey(d)]),
  {nets: [], narrow: [], answered: [], tried: new Set(d.tried || []), narrowSet: new Set(), labelled: false,
    hash: hash01(d.ip), stagger: (i % 3) * 26, ax: 0, ay: 0, fx: 0, fy: 0}));
const nodes = hostNodes.concat(srcNodes);
const hostByIp = new Map(hostNodes.map(n => [n.id, n]));
// what each source did to the drawn hosts: the services it narrowed onto (grouped by host), the hosts
// that answered its sweep, and the hosts it tried
srcNodes.forEach(s => {
  const byHost = new Map();
  (s.d.services || []).forEach(([ip, port, proto, sessions, ts]) => {
    const h = hostByIp.get(ip); if (!h) return;
    if (!byHost.has(h)) byHost.set(h, {h, sessions: 0, services: []});
    const b = byHost.get(h); b.sessions += sessions; b.services.push({port, proto, sessions, ts});
    const p = portText(port, proto); if (!h.ports.includes(p)) h.ports.push(p);
  });
  s.narrow = [...byHost.values()];
  s.narrow.forEach(b => { s.narrowSet.add(b.h); b.h.by.push(s); });
  s.answered = (s.d.answered || []).map(([hi, n]) => ({h: hostNodes[hi], n})).filter(b => b.h && !s.narrowSet.has(b.h));
  s.tried.forEach(hi => { if (hostNodes[hi]) hostNodes[hi].srcs.push(s); });
});
// a host a source narrowed onto takes the colour of the most serious such source (sources come most serious first)
hostNodes.forEach(h => { if (h.by.length) h.color = h.by[0].color; });
// hosts a source narrowed onto, most sessions first
const narrowedHosts = hostNodes.filter(h => h.by.length).sort((a, b) => b.d.sessions - a.d.sessions || (a.id < b.id ? -1 : 1));
const fewNarrowed = narrowedHosts.length <= 14;
// names next to the sources: the flagged ones (up to ten); of those that only swept, all when there are
// at most six and otherwise the three biggest sweeps. The rest show their name under the pointer and in the list.
{
  const flagged = srcNodes.filter(s => s.d.flagged).length, swept = srcNodes.length - flagged;
  srcNodes.forEach((s, i) => { s.labelled = s.d.flagged ? i < 10 : i - flagged < (swept <= 6 ? 6 : 3); });
}

// ---------------------------------------------------------------- layout
// subnets packed as in MAX: each at the first spot on an outward spiral that clears every placed subnet
// by GAP plus a share of both radii; big subnets pack their hosts a little tighter
const SP = 48, GAP = 180, GAP_K = 0.3, spacing = n => SP / Math.pow(Math.max(1, n / 30), 0.25);
const golden = Math.PI * (3 - Math.sqrt(5));
function spiralSpot(placed, r, gap, step = 6, k = GAP_K) {
  for (let t = 0; t < 20000; t++) {
    const a = t * 0.12, rr = step * a;
    const x = rr * Math.cos(a), y = rr * Math.sin(a) * 0.8;
    if (placed.every(p => Math.hypot(p.x - x, p.y - y) >= (p.r + r) * (1 + k) + gap)) return [x, y];
  }
  return [0, 0];
}
const STATE_RANK = {narrowed: 0, answered: 1, tried: 2};
const clusters = [], clusterAtIdx = new Map();
{
  const members = SUBNETS.map(() => []);
  hostNodes.forEach(n => { if (members[n.d.net]) members[n.d.net].push(n); });
  const placed = [];
  // the data lists subnets by what happened in them (narrowed onto, then answered, then tried), so the
  // ones that matter most sit in the middle
  SUBNETS.forEach((s, i) => {
    const m = members[i]; if (!m.length) return;
    m.sort((a, b) => STATE_RANK[a.d.state] - STATE_RANK[b.d.state] || b.d.sessions - a.d.sessions || b.d.answered - a.d.answered || (a.id < b.id ? -1 : 1));
    const cr = 40 + spacing(m.length) * Math.sqrt(m.length);
    const [x, y] = placed.length ? spiralSpot(placed, cr, GAP) : [0, 0];
    placed.push({x, y, r: cr});
    const top = m.find(n => n.by.length);
    const c = {i, s, x, y, r: cr + 18, members: m, labelled: clusters.length < 14, color: top ? top.color : null};
    clusters.push(c); clusterAtIdx.set(i, c);
    m.forEach((n, k) => {
      const rr = k === 0 && m.length === 1 ? 0 : spacing(m.length) * Math.sqrt(k + 0.5), a = k * golden;
      n.cluster = c; n.ox = x + rr * Math.cos(a); n.oy = y + rr * Math.sin(a); n.oz = pillarH(n.d);
    });
  });
}
srcNodes.forEach(s => {
  s.nets = (s.d.nets || []).map(([ni, hosts, services, failed, answered]) => ({c: clusterAtIdx.get(ni), hosts, services, failed, answered})).filter(b => b.c);
});
const ring = (() => {
  let minX = 0, maxX = 0, minY = 0, maxY = 0;
  clusters.forEach(c => { minX = Math.min(minX, c.x - c.r); maxX = Math.max(maxX, c.x + c.r); minY = Math.min(minY, c.y - c.r); maxY = Math.max(maxY, c.y + c.r); });
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2, R = Math.max(260, Math.hypot(maxX - minX, maxY - minY) / 2 * 1.05);
  return {cx, cy, R, z: 200 + R * 0.4, lift: 0, minX, maxX, minY, maxY};
})();
// The internet arc always sits overhead on the far side of the network from the camera, so it never
// blocks the view; when the view is rotated the arc glides round to stay behind. Each source sits above
// what it went for (the hosts it narrowed onto count most), so the order along the arc follows the view.
// Positions are compared in coarse steps, so two sources swap only when one has clearly moved past the other.
const ARC = Math.PI - 0.6, arcCenter = yaw => 1.5 * Math.PI - yaw;
function arcOrder(yaw) {
  const rx = Math.cos(yaw), ry = -Math.sin(yaw), stepX = ring.R * 0.08;   // (rx, ry): screen-right on the plane
  return srcNodes.map(n => {
    let sx = 0, w = 0;
    const add = (x, y, k) => { sx += ((x - ring.cx) * rx + (y - ring.cy) * ry) * k; w += k; };
    n.narrow.forEach(b => add(b.h.ox, b.h.oy, 4));
    n.nets.forEach(b => add(b.c.x, b.c.y, 1));
    return {n, x: Math.round((w ? sx / w : (n.hash - 0.5) * ring.R) / stepX)};
  }).sort((a, b) => a.x - b.x || a.n.i - b.n.i).map(o => o.n);
}
function placeArc(yaw) {
  const order = arcOrder(yaw);
  order.forEach((n, i) => {
    const ang = arcCenter(yaw) - ((i + 0.5) / order.length - 0.5) * ARC;
    n.ax = ring.cx + ring.R * 1.08 * Math.cos(ang); n.ay = ring.cy + ring.R * 1.08 * Math.sin(ang);
    if (R3) { n.tx = n.ax; n.ty = n.ay; }
  });
}
// Flat: the sources in a row above the network, each above what it went for
const flatRowY = () => ring.minY - Math.max(170, (ring.maxY - ring.minY) * 0.22);
function placeFlat() {
  const order = arcOrder(0), wide = Math.max(ring.maxX - ring.minX, 120 * order.length), y = flatRowY();
  order.forEach((n, i) => { n.fx = ring.cx + ((i + 0.5) / order.length - 0.5) * wide; n.fy = y; });
}
// where every body belongs in the current view
function settle() {
  hostNodes.forEach(n => { n.tx = n.ox; n.ty = n.oy; n.tz = R3 ? n.oz : 0; });
  srcNodes.forEach(n => {
    if (R3) { n.tx = n.ax; n.ty = n.ay; n.tz = ring.z + ring.lift + n.stagger; } else { n.tx = n.fx; n.ty = n.fy; n.tz = 0; }
  });
}
placeArc(0); placeFlat();
nodes.forEach(n => { n.x = n.ox * 1.8; n.y = n.oy * 1.8; n.z = -40 - hash01(n.id + '~') * 260; });
srcNodes.forEach(n => { n.x = ring.cx; n.y = ring.cy; n.z = ring.z + 400; });
// room the list takes on the left and an open panel on the right (none on narrow screens)
function railWidth() { if (W <= 900) return 0; const r = $('rail').getBoundingClientRect(); return r.width ? Math.max(280, r.right + 2) : 0; }
function panelWidth() { const p = $('panel'); if (W <= 900 || p.hidden) return 0; const r = p.getBoundingClientRect(); return r.width ? W - r.left + 6 : 0; }
function clusterAt(sx, sy) {
  let best = null, bd = 1e9;
  if (!painted) return null;
  clusters.forEach(c => {
    const [x, y, sc] = Pw(c.x, c.y, 0), d = Math.hypot(x - sx, (y - sy) / (R3 ? Math.max(0.35, Math.cos(view.pitch)) : 1));
    if (d < c.r * sc && d < bd) { bd = d; best = c; }
  });
  return best;
}
function zoomCluster(c) {
  const railW = railWidth(), right = panelWidth();
  stopSpin();
  cam.tz = Math.min(1.6, Math.max(0.3, Math.min((W - railW - right - 80) / (c.r * 2 + 260), (H - 200) / (c.r * 2 + 360)) * 1.3));
  if (R3) { cam.tx = c.x; cam.ty = c.y; cam.tsx = (railW - right) / 2; cam.tsy = 0; }
  else { cam.tx = c.x - (railW - right) / 2 / cam.tz; cam.ty = c.y; }
}
// The whole picture always fits, however many subnets there are: the fit may go below the closest the
// wheel zooms out to (ZOOM_MIN), down to ZOOM_FLOOR.
const ZOOM_MIN = 0.12, ZOOM_FLOOR = 0.02;
function fitOverview() {
  cam.tuy = 0;
  const railW = railWidth(), right = panelWidth();
  if (R3) {
    const w = ring.R * 2.2, h = ring.R * 2;
    cam.tz = Math.min(1.5, Math.max(ZOOM_FLOOR, Math.min((W - railW - right - 60) / (w + 120), (H - 170) / (h * 0.75 + 120)))) * 0.85;
    // orbit pivot = the network's centre; the screen shift keeps it clear of the list and the panel
    cam.tx = ring.cx; cam.ty = ring.cy; cam.tsx = (railW - right) / 2; cam.tsy = ring.R * 0.3 * cam.tz;
    return;
  }
  let minX = ring.minX, maxX = ring.maxX, minY = ring.minY;
  srcNodes.forEach(n => { minX = Math.min(minX, n.fx - 60); maxX = Math.max(maxX, n.fx + 60); minY = Math.min(minY, n.fy - 60); });
  // the row of sources sits a little lower than centred, which leaves room above it for their names
  cam.tz = Math.min(1.5, Math.max(ZOOM_FLOOR, Math.min((W - railW - right - 80) / (maxX - minX + 200), (H - 250) / (ring.maxY - minY + 200))));
  cam.tx = (minX + maxX) / 2 - (railW - right) / 2 / cam.tz; cam.ty = (minY + ring.maxY) / 2 - 28 / cam.tz;
}
function snap() { nodes.forEach(n => { n.x = n.tx; n.y = n.ty; n.z = n.tz; n.a = n.ta; n.r = n.tr; }); cam.x = cam.tx; cam.y = cam.ty; cam.z = cam.tz; cam.sx = cam.tsx; cam.sy = cam.tsy; cam.uy = cam.tuy; view.dist = 1; view.yaw = view.oyaw; view.pitch = view.opitch; }

// ---------------------------------------------------------------- drawing
const toS = (x, y) => [(x - cam.x) * cam.z + W / 2, (y - cam.y) * cam.z + H / 2];
const toW = (sx, sy) => [(sx - W / 2) / cam.z + cam.x, (sy - H / 2) / cam.z + cam.y];
// screen position and CSS px per world unit, through the 3D camera when it is on
const Pw = (x, y, z) => R3 ? R3.project(x, y, z || 0) : [(x - cam.x) * cam.z + W / 2, (y - cam.y) * cam.z + H / 2, cam.z];
const P = n => Pw(n.x, n.y, n.z);
function resize() {
  DPR = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
  cv.width = W * DPR; cv.height = H * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  if (R3inst) R3inst.setSize(W, H, DPR);
}
// what the pointer or the selection singles out: a source, or a host
function active() {
  const A = state.hover || state.sel;
  return {A, aSrc: A && A.kind === 'src' ? A : null, aHost: A && A.kind === 'host' ? A : null};
}
// how strongly each body shows: everything at rest; with a source singled out, the hosts it tried;
// with a host singled out, the sources that tried it
function emphasis() {
  const {A, aSrc, aHost} = active();
  hostNodes.forEach(h => {
    const base = h.d.state === 'tried' ? 0.6 : 1;
    h.ta = !A ? base : aSrc ? (aSrc.tried.has(h.i) ? Math.max(base, 0.9) : 0.16) : h === aHost ? 1 : base * 0.45;
  });
  srcNodes.forEach(s => { s.ta = !A || s === aSrc || (aHost && s.tried.has(aHost.i)) ? 1 : 0.3; });
}
// Every beam on screen, the same in both views: cb(source, x, y, z, width, alpha, dashed, sessions).
// Dashed: a source's sweep, one beam per subnet, wider the more hosts it tried there. Solid: a host
// it kept coming back to. Thin solid, only for what is singled out: a host that answered its sweep.
// Sweeps are drawn fainter the more of them there are, so that a hundred of them read as a haze over
// the network and the few solid beams stand out: a source's own, by how many subnets it swept (OWN);
// those of the sources that only swept, by how many such beams there are in all (HAZE).
const HAZE = Math.max(0.25, Math.min(1, 30 / Math.max(1, srcNodes.reduce((t, s) => t + (s.d.flagged ? 0 : s.nets.length), 0))));
const OWN = s => Math.max(0.5, Math.min(1, 16 / Math.max(1, s.nets.length)));
// beamCount: what the last frame drew, for stats(): all sweep and narrowed beams, and those of the selected source.
let beamCount = {sweep: 0, narrowed: 0, selSweep: 0, selNarrowed: 0};
function eachBeam(cb) {
  const {A, aSrc, aHost} = active(), n = {sweep: 0, narrowed: 0, selSweep: 0, selNarrowed: 0};
  srcNodes.forEach(s => {
    if (s.a < 0.02) return;
    const mine = aSrc === s, f = s.d.flagged, own = OWN(s), sel = state.sel === s;
    s.nets.forEach(b => {
      const on = !A || mine || (aHost && aHost.cluster === b.c && s.tried.has(aHost.i));
      const al = s.a * (on ? (mine ? 0.5 * own : A ? 0.5 : f ? 0.22 * own : 0.12 * HAZE) : f ? 0.04 : 0.025 * HAZE);
      if (al < 0.01) return;
      cb(s, b.c.x, b.c.y, 0, 0.8 + Math.min(1.4, Math.log2(1 + b.hosts) * 0.18), al, true, 0);
      n.sweep++; if (sel) n.selSweep++;
    });
    s.narrow.forEach(b => {
      if (b.h.a < 0.02) return;
      const on = !A || mine || aHost === b.h;
      cb(s, b.h.x, b.h.y, b.h.z, 1.4 + Math.min(2.6, Math.log2(1 + b.sessions) * 0.25), Math.min(1, b.h.a) * (on ? (A ? 0.95 : 0.75) : 0.1), false, on ? b.sessions : 0);
      n.narrowed++; if (sel) n.selNarrowed++;
    });
    s.answered.forEach(b => { if (mine || aHost === b.h) cb(s, b.h.x, b.h.y, b.h.z, 0.8, 0.3, false, 0); });
  });
  beamCount = n;
}
function frame(now) {
  const dt = Math.min(0.05, (now - t0) / 1000); t0 = now;
  const k = state.motion ? 1 - Math.pow(0.0015, dt) : 1;
  cam.x += (cam.tx - cam.x) * k; cam.y += (cam.ty - cam.y) * k; cam.z += (cam.tz - cam.z) * k;
  if (!R3) { cam.tsx = 0; cam.tsy = 0; }
  cam.sx += (cam.tsx - cam.sx) * k; cam.sy += (cam.tsy - cam.sy) * k; cam.uy += (cam.tuy - cam.uy) * k;
  emphasis();
  nodes.forEach(n => {
    const ready = now > n.born;
    n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k; n.r += (n.tr - n.r) * k;
    n.z += (n.tz - n.z) * (ready ? k * 0.8 : 0);
    n.a += ((ready ? n.ta : 0) - n.a) * Math.min(1, k * 1.4);
  });
  ctx.clearRect(0, 0, W, H);
  if (R3) draw3d(now, dt); else drawFlat(now);
  painted = true; frames++;
  requestAnimationFrame(frame);
}
const qpt = (p, t) => { const u = 1 - t; return [u * u * p[0] + 2 * u * t * p[2] + t * t * p[4], u * u * p[1] + 2 * u * t * p[3] + t * t * p[5]]; };
function drawFlat(now) {
  const T = now / 1000, hc = state.hoverCluster;
  const g = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.75);
  g.addColorStop(0, BG_IN); g.addColorStop(1, BG_OUT);
  ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
  const step = 120 * cam.z;
  if (step >= 24) {
    ctx.strokeStyle = 'rgba(150,152,156,.05)'; ctx.lineWidth = 1;
    const [ox, oy] = toS(0, 0);
    ctx.beginPath();
    for (let x = ox % step; x < W; x += step) { ctx.moveTo(x, 0); ctx.lineTo(x, H); }
    for (let y = oy % step; y < H; y += step) { ctx.moveTo(0, y); ctx.lineTo(W, y); }
    ctx.stroke();
  }
  clusters.forEach(c => {
    const [x, y] = toS(c.x, c.y);
    ctx.globalAlpha = hc && hc !== c ? 0.3 : 0.7; ctx.strokeStyle = c.color || 'rgba(150,152,156,.5)';
    ctx.setLineDash([3, 6]); ctx.lineWidth = hc === c ? 1.8 : 1;
    ctx.beginPath(); ctx.arc(x, y, c.r * cam.z, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
  });
  ctx.globalAlpha = 1;
  let n = 0;
  eachBeam((s, x, y, z, w, al, dashed, sessions) => {
    const [x1, y1] = toS(s.x, s.y), [x2, y2] = toS(x, y), dx = x2 - x1, dy = y2 - y1;
    const p = [x1, y1, (x1 + x2) / 2 - dy * 0.08, (y1 + y2) / 2 + dx * 0.08, x2, y2];
    ctx.globalAlpha = Math.min(1, al * 1.4); ctx.strokeStyle = s.color; ctx.lineWidth = w; ctx.setLineDash(dashed ? [5, 6] : []);
    ctx.beginPath(); ctx.moveTo(p[0], p[1]); ctx.quadraticCurveTo(p[2], p[3], p[4], p[5]); ctx.stroke(); ctx.setLineDash([]);
    if (sessions && state.motion) {
      const dots = flowDots(sessions);
      ctx.fillStyle = COL.bright;
      for (let j = 0; j < dots; j++) {
        const [fx, fy] = qpt(p, (T * 0.18 + n * 0.137 + j / dots) % 1);
        ctx.globalAlpha = Math.min(1, al * 1.2); ctx.beginPath(); ctx.arc(fx, fy, 1.6 + w * 0.4, 0, 7); ctx.fill();
      }
      n++;
    }
  });
  ctx.globalAlpha = 1;
  arcTitleBoxes = [];
  const taken = hostLabels(state.labels, sourceLabels(state.labels));
  if (state.labels) clusterLabels(taken);
  [...nodes].filter(o => o.a > 0.02).sort((a, b) => a.a - b.a).forEach(o => drawNode(o));
}
// dots that run down a solid beam: more for a service it came back to more often
const flowDots = sessions => 1 + Math.min(3, Math.floor(Math.log2(1 + sessions) / 4));
function shade(hex) { const c = parseInt(hex.slice(1), 16); return `rgb(${(c >> 16 & 255) * 0.35 | 0},${(c >> 8 & 255) * 0.35 | 0},${(c & 255) * 0.35 | 0})`; }
// The names under a subnet's ring: its range and network name, then what happened in it. They give way
// to the names of sources and hosts (`taken`: the boxes those use) and to each other, the subnets that
// matter most first: a name with no room drops its second line, then waits for the pointer. The subnet
// under the pointer is always named.
function clusterLabels(taken) {
  const boxes = [...taken], hc = state.hoverCluster, yaw = R3 ? view.yaw : 0;
  const clear = b => !boxes.some(o => b.x0 < o.x1 && o.x0 < b.x1 && b.y0 < o.y1 && o.y0 < b.y1);
  ctx.textAlign = 'center'; ctx.lineWidth = 4; ctx.strokeStyle = LABEL_HALO;
  (hc ? [hc].concat(clusters.filter(c => c !== hc)) : clusters).forEach(c => {
    const hov = hc === c;
    if (!hov && !c.labelled) return;
    // under the ring as it is seen: the point of it nearest the camera, whichever way the view is turned
    const [x, y, sc] = Pw(c.x + c.r * Math.sin(yaw), c.y + c.r * Math.cos(yaw), 0);
    if (!(x > -50 && x < W + 50 && y > -50 && y < H + 50)) return;
    const s = c.s, t1 = s.name ? `${s.id} · ${s.name}` : s.id, t2 = sc > 0.25 || hov ? subnetBits(s).join(' · ') : '';
    const f1 = (hov ? '600 ' : '') + '11px ' + MONO, f2 = '10px ' + MONO;
    ctx.font = f1; const w1 = ctx.measureText(t1).width;
    ctx.font = f2; const w2 = t2 ? ctx.measureText(t2).width : 0;
    const box = (w, lines) => ({x0: x - w / 2 - 5, x1: x + w / 2 + 5, y0: y + 3, y1: y + 18 + (lines - 1) * 13});
    let lines = t2 ? 2 : 1, b = box(Math.max(w1, w2), lines);
    if (!hov && lines > 1 && !clear(b)) { lines = 1; b = box(w1, 1); }
    if (!hov && !clear(b)) return;
    boxes.push(b);
    ctx.globalAlpha = hov ? 1 : 0.85;
    ctx.font = f1; ctx.fillStyle = hov ? COL.bright : COL.subnet;
    ctx.strokeText(t1, x, y + 14); ctx.fillText(t1, x, y + 14);
    if (lines > 1) { ctx.font = f2; ctx.fillStyle = c.color || COL.dim; ctx.strokeText(t2, x, y + 27); ctx.fillText(t2, x, y + 27); }
  });
  ctx.globalAlpha = 1;
}
function subnetBits(s) {
  const bits = [`${fmt(s.tried)} tried`];
  if (s.answered) bits.push(`${fmt(s.answered)} answered`);
  if (s.narrowed) bits.push(`${fmt(s.narrowed)} narrowed onto`);
  if (s.drawn < s.tried) bits.push(`${fmt(s.tried - s.drawn)} not drawn`);
  return bits;
}
// A body's mark and name on the 2D canvas. In 3D the bodies themselves are drawn by explorer3d.js, so
// only the selection ring, the hover ring and the names are drawn here.
const FONT_NAME = '12px ' + SANS, FONT_SEL = '600 14px ' + SANS, FONT_SUB = '600 10.5px ' + MONO;
function nodeLines(n) {    // [name, second line, its colour]
  if (n.kind === 'src') return [n.id, n.d.flagged ? levelTag(n.d).toUpperCase() : '', n.color];
  const p = n.ports;
  return [n.id, p.length ? p.slice(0, 2).join(', ') + (p.length > 2 ? ` +${p.length - 2}` : '') : '', COL.dim];
}
function drawNode(n) {
  const [x, y, sc] = P(n), r = Math.max(minPx(n), n.r * sc);
  if (!(x > -80 && y > -80 && x < W + 80 && y < H + 80)) return;
  const sel = state.sel === n, hov = state.hover === n;
  ctx.globalAlpha = n.a;
  if (!R3) {
    if (n.kind === 'src') {   // outside sources are diamonds, hollow when they swept and did not narrow
      ctx.fillStyle = n.d.flagged ? n.color : BG_OUT; ctx.strokeStyle = n.color; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(x, y - r * 1.25); ctx.lineTo(x + r * 1.25, y); ctx.lineTo(x, y + r * 1.25); ctx.lineTo(x - r * 1.25, y); ctx.closePath();
      ctx.fill(); ctx.stroke();
    } else if (n.d.state === 'tried') {
      ctx.fillStyle = n.color; ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fill();
    } else {
      const gr = ctx.createRadialGradient(x - r * 0.3, y - r * 0.3, r * 0.1, x, y, r);
      gr.addColorStop(0, COL.bright); gr.addColorStop(0.25, n.color); gr.addColorStop(1, shade(n.color));
      ctx.fillStyle = gr; ctx.beginPath(); ctx.arc(x, y, r, 0, 7); ctx.fill();
    }
  }
  if (sel) { ctx.globalAlpha = 1; ctx.strokeStyle = COL.accent; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, r + 6, 0, 7); ctx.stroke(); }
  else if (hov) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, r + 4, 0, 7); ctx.stroke(); }
  // names: what is singled out always; otherwise the named sources, and the hosts hostLabels found room for
  let show = sel || hov;
  if (!show && state.labels && n.a > 0.5) show = !!n.lab;
  if (show) {
    const [name, sub, subCol] = nodeLines(n);
    const [lx, ly] = n.lab || (n.kind === 'src' ? [x, y - r * 1.25 - (sub ? 24 : 10)] : [x, y + r + 15]);
    ctx.globalAlpha = Math.max(n.a, sel || hov ? 1 : 0); ctx.textAlign = 'center'; ctx.lineWidth = 4; ctx.strokeStyle = LABEL_HALO;
    ctx.font = sel ? FONT_SEL : FONT_NAME;
    ctx.strokeText(name, lx, ly); ctx.fillStyle = sel ? '#ffffff' : COL.name; ctx.fillText(name, lx, ly);
    if (sub) { ctx.font = FONT_SUB; ctx.fillStyle = subCol; ctx.strokeText(sub, lx, ly + 14); ctx.fillText(sub, lx, ly + 14); }
  }
  ctx.globalAlpha = 1;
}

// ---- label placement (from MAX): the first spot where a name fits, kept from frame to frame
// the part of the canvas that no side panel covers, [left, right]: names stay inside it
let labelSpan = [0, 0];
function openSpan() {
  const box = id => { const el = $(id); if (!el || el.hidden) return null; const b = el.getBoundingClientRect(); return b.width && b.height ? b : null; };
  let l = 0, r = W;
  const rail = W > 900 && box('rail'); if (rail) l = rail.right;
  const b = box('panel'); if (b && b.left > W / 2) r = Math.min(r, b.left);
  return [l, r];
}
const labelBox = (x, y, w, lines) => ({x0: x - w / 2 - 6, x1: x + w / 2 + 6, y0: y - 14, y1: y + 4 + (lines - 1) * 16});
// a name of width w whose first baseline is at y and that has `lines` lines, if it is clear of the side
// panels and the page header and covers no box yet taken, with `pad` pixels to spare (it then takes its own box)
const HEADER_H = 62;
function claim(boxes, x, y, w, lines, pad = 0) {
  const b = labelBox(x, y, w, lines);
  const t = {x0: b.x0 - pad, x1: b.x1 + pad, y0: b.y0 - pad, y1: b.y1 + pad};
  if (x - w / 2 < labelSpan[0] || x + w / 2 > labelSpan[1] || b.y0 < HEADER_H) return false;
  if (boxes.some(o => t.x0 < o.x1 && o.x0 < t.x1 && t.y0 < o.y1 && o.y0 < t.y1)) return false;
  boxes.push(b);
  return true;
}
// A name leaves the spot it had last frame for a better one only with room to spare, so it does not
// flick between two while the view turns.
function place(o, key, spots, lines, w, boxes) {
  const last = o.at[key];
  for (let i = 0; i < spots.length; i++) {
    const [x, y] = spots[i](lines, w);
    if (claim(boxes, x, y, w, lines, last != null && i < last ? 10 : 0)) { o.at[key] = i; return [x, y]; }
  }
  return null;
}
// Names of the sources, most serious first, wherever one covers neither the arc's title, a name already
// placed, nor another source. On the 3D arc: left of the source, else right of it, then over or under
// it, a row further out each time. In the Flat row, where the lines leave downwards: over it, a row
// higher each time. A source with no room anywhere shows its name under the pointer. Returns the boxes in use.
let arcTitleBoxes = [];
function sourceLabels(on) {
  srcNodes.forEach(n => { n.lab = null; });
  if (!on) return [];
  labelSpan = openSpan();
  const marks = srcNodes.filter(n => n.a > 0.25).map(n => {
    const [x, y, sc] = P(n), r = Math.max(minPx(n), n.r * sc) * 1.25, g = r + 2;
    return {n, x, y, r, box: {x0: x - g, x1: x + g, y0: y - g, y1: y + g}};
  });
  const names = [...arcTitleBoxes];
  // the selected source and the one under the pointer are always named, and choose their spot first
  const first = n => n === state.sel ? 0 : n === state.hover ? 1 : 2;
  [...marks].sort((a, b) => first(a.n) - first(b.n) || a.n.i - b.n.i).forEach(m => {
    const {n, x, y, r} = m, lines = n.d.flagged ? 2 : 1;
    if (!n.labelled && first(n) === 2) return;
    const boxes = names.concat(marks.filter(o => o !== m).map(o => o.box));
    const over = k => l => [x, y - r - 9 - 24 * k - (l - 1) * 15];
    ctx.font = n === state.sel ? FONT_SEL : FONT_NAME;   // the selected name is drawn bigger
    n.lab = place(n, R3 ? 'arc' : 'row', R3 ? [(l, w) => [x - r - 8 - w / 2, y + 4 - (l - 1) * 7], (l, w) => [x + r + 8 + w / 2, y + 4 - (l - 1) * 7],
      ...[0, 1, 2].flatMap(k => [over(k), () => [x, y + r + 18 + 24 * k]])] : [0, 1, 2].map(over),
      lines, Math.max(ctx.measureText(n.id).width, lines > 1 ? 52 : 0), boxes);
    if (n.lab) names.push(boxes[boxes.length - 1]);
  });
  return names.concat(marks.map(m => m.box));
}
// Names of hosts, where there is room: every host a source narrowed onto when there are few of them, else
// those in view when zoomed in, and always those of the source singled out. Most sessions first; under the
// host, else right of it, left of it or over it, then the same a row further out. `taken`: boxes already in use.
// Returns every box now in use.
const HOST_NAMES_MAX = 60;
function hostLabels(on, taken) {
  hostNodes.forEach(n => { n.lab = null; });
  if (!on) return taken;
  const {aSrc} = active();
  const marks = [];
  for (const n of narrowedHosts) {
    if (n.a <= 0.5) continue;
    const [x, y, sc] = P(n);
    if (!(x > -40 && y > -40 && x < W + 40 && y < H + 40)) continue;
    if (!(fewNarrowed || sc > 0.55 || (aSrc && aSrc.narrowSet.has(n)) || state.sel === n || state.hover === n)) continue;
    const r = Math.max(minPx(n), n.r * sc), g = r + 2;
    marks.push({n, x, y, r, box: {x0: x - g, x1: x + g, y0: y - g, y1: y + g}});
    if (marks.length >= HOST_NAMES_MAX) break;
  }
  const names = [...taken];
  ctx.font = FONT_NAME;
  marks.forEach(m => {
    const {n, x, y, r} = m, [name, sub] = nodeLines(n), lines = sub ? 2 : 1, boxes = names.concat(marks.filter(o => o !== m).map(o => o.box));
    const w = Math.max(ctx.measureText(name).width, sub.length * 6.4);
    n.lab = place(n, 'host', [0, 1].flatMap(k => [() => [x, y + r + 15 + 30 * k], (l, ww) => [x + r + 8 + ww / 2 + 40 * k, y + 4 - (l - 1) * 7],
      (l, ww) => [x - r - 8 - ww / 2 - 40 * k, y + 4 - (l - 1) * 7], l => [x, y - r - 9 - (l - 1) * 14 - 30 * k]]), lines, w, boxes);
    if (n.lab) names.push(boxes[boxes.length - 1]);
  });
  return names.concat(marks.map(m => m.box));
}
const nFlagged = srcNodes.filter(n => n.d.flagged).length, nSwept = srcNodes.length - nFlagged;
const ARC_TITLE = 'INTERNET · ' + [nFlagged ? `${nFlagged} FLAGGED SOURCE${nFlagged === 1 ? '' : 'S'}` : '', nSwept ? `${nSwept} SWEPT ONLY` : ''].filter(Boolean).join(' · ');
const notDrawn = Math.max(0, (CNT.sweeping || 0) - srcNodes.length), quiet = Math.max(0, (CNT.outside_sources || 0) - (CNT.sweeping || 0));
const ARC_SUB = [notDrawn ? `${fmt(notDrawn)} MORE SWEEPING SOURCE${notDrawn === 1 ? '' : 'S'} NOT DRAWN` : '',
  quiet ? `${fmt(quiet)} OTHER OUTSIDE SOURCE${quiet === 1 ? '' : 'S'} DID NOT SWEEP` : ''].filter(Boolean).join(' · ');
function arcTitle() {
  arcTitleBoxes = [];
  if (!srcNodes.length) return;
  const ac = arcCenter(view.yaw), [x, y] = Pw(ring.cx + ring.R * 1.08 * Math.cos(ac), ring.cy + ring.R * 1.08 * Math.sin(ac), ring.z + ring.lift + 70);
  if (!(y > 70)) return;
  ctx.font = '600 11px ' + MONO;
  // over the middle of the arc, and clear of the sources below it however far out the view is
  const half = ctx.measureText(ARC_TITLE).width / 2 + 30;
  let top = y;
  srcNodes.forEach(n => { const [sx, sy, sc] = P(n); if (Math.abs(sx - x) < half) top = Math.min(top, sy - Math.max(minPx(n), n.r * sc) * 1.25); });
  const ty = Math.max(84, Math.min(y - 18, top - (ARC_SUB ? 30 : 16)));
  ctx.globalAlpha = 0.8; ctx.textAlign = 'center'; ctx.fillStyle = COL.accent;
  ctx.fillText(ARC_TITLE, x, ty);
  // names keep off the title and the space above it, so none sits over the title, away from its source
  arcTitleBoxes.push({...labelBox(x, ty, ctx.measureText(ARC_TITLE).width, 1), y0: -Infinity});
  if (ARC_SUB) {
    ctx.font = '10px ' + MONO; ctx.fillStyle = COL.dim; ctx.fillText(ARC_SUB, x, ty + 14);
    arcTitleBoxes.push(labelBox(x, ty + 14, ctx.measureText(ARC_SUB).width, 1));
  }
  ctx.globalAlpha = 1;
}

// ---------------------------------------------------------------- 3D (explorer3d.js) drawing
function rotateView(dir) { view.spin = false; view.oyaw += dir * Math.PI / 4; placeArc(view.oyaw); markView(); }
function setView(name, reset) {
  view.opitch = VIEWS[name];
  if (reset) { view.oyaw = 0; placeArc(0); fitOverview(); }
  view.spin = !!reset;
  markView();
}
// back to the opening camera: Low view, facing front, slowly turning left (not under Reduce motion)
function homeView() { view.opitch = VIEWS[DEFAULT_VIEW]; view.oyaw = 0; placeArc(0); view.spin = true; markView(); }
function stopSpin() { if (view.spin) { view.spin = false; markView(); } }
function markView() {
  for (const name of Object.keys(VIEWS)) $('vc-' + name).setAttribute('aria-pressed', String(Math.abs(view.opitch - VIEWS[name]) < 0.02));
  $('vc-spin').setAttribute('aria-pressed', String(view.spin && state.motion));
}
function set3d(on, byUser) {
  on = !!on && can3d;
  if (on && !R3inst) {
    try { R3inst = window.VF3D.create(cv3, {bgIn: BG_IN, bgOut: BG_OUT, calm: true, light: false, onLost: () => set3d(false, false)}); R3inst.setSize(W, H, DPR); }
    catch (err) { console.warn('3D view unavailable, using the flat view', err); R3inst = null; on = false; }
  }
  R3 = on ? R3inst : null;
  cv3.hidden = !on;
  document.body.classList.toggle('gl3d', on);
  $('vw-flat').classList.toggle('on', !on); $('btn-3d').classList.toggle('on', on);
  $('vw-flat').setAttribute('aria-current', String(!on)); $('btn-3d').setAttribute('aria-current', String(on));
  if (on && byUser && state.motion) view.dist = 1.6;
  if (on && byUser) homeView();   // entering 3D always starts on Low, slowly turning left
  settle(); fitOverview(); placeViewctl(); updateAbout();
  if (!state.motion) snap();
}
const RGB = hex => window.VF3D.rgb(hex);
const qb = (c, t) => { const u = 1 - t, A = u * u, B = 2 * u * t, C = t * t;
  return [A * c[0] + B * c[3] + C * c[6], A * c[1] + B * c[4] + C * c[7], A * c[2] + B * c[5] + C * c[8]]; };
// a paler shade of a beam's colour for the dots that run along it, so they show on a bright beam
const PALER = new Map();
const paler = hex => PALER.get(hex) || PALER.set(hex, RGB(hex).map(v => v + (1 - v) * 0.45)).get(hex);
function draw3d(now, dt) {
  const T = now / 1000, motion = state.motion, kv = motion ? 1 - Math.pow(0.02, dt) : 1;
  // slow turn to the left, until the user takes the camera
  if (view.spin && motion) { view.oyaw += SPIN * Math.min(dt, 0.1); placeArc(view.oyaw); }
  view.yaw += (view.oyaw - view.yaw) * kv;
  view.pitch += (view.opitch - view.pitch) * kv;
  // the closer the camera is to the Low view, the higher the internet arc rides, so on Low it sits centred
  // in the space above the network instead of crowding it; from Tilted up to Top it stays where it was
  const lift = ring.R * 0.3 * Math.max(0, Math.min(1, (view.pitch - VIEWS.tilted) / (VIEWS.low - VIEWS.tilted)));
  if (lift !== ring.lift) { const dz = lift - ring.lift; ring.lift = lift; srcNodes.forEach(n => { n.tz += dz; n.z += dz; }); }
  view.dist += (1 - view.dist) * (motion ? 1 - Math.pow(0.05, dt) : 1);
  R3.setCamera(cam.x, cam.y, cam.z, view.yaw, view.pitch, view.dist, true, cam.sx, cam.sy + cam.uy);

  // ribbons: subnet rings, host pillars, the arc, the beams, rings round what is selected
  const L = R3.lines, hc = state.hoverCluster, {A} = active(), ringCol = RGB(COL.ring), flows = [];
  L.begin();
  clusters.forEach(c => {
    const on = !hc || hc === c;
    L.circle(c.x, c.y, 0, c.r, 80, hc === c ? 2.2 : 1.4, c.color ? RGB(c.color) : ringCol, on ? 0.5 : 0.18, false);
    L.circle(c.x, c.y, 0, c.r * 0.97, 80, 0.8, ringCol, 0.12, true);
  });
  hostNodes.forEach(n => {
    if (n.a < 0.02 || n.oz < 6) return;
    L.strip(2, i => [n.x, n.y, i ? n.z : 0], n.by.length ? 3.2 : 2, RGB(n.color), Math.min(1, n.a * (A === n ? 0.95 : 0.5)), false);
  });
  if (srcNodes.length) {
    const acc = RGB(COL.accent);
    const arcAt = (f, dz) => { const ang = arcCenter(view.yaw) - (f - 0.5) * ARC;
      return [ring.cx + ring.R * 1.08 * Math.cos(ang), ring.cy + ring.R * 1.08 * Math.sin(ang), ring.z + ring.lift + dz]; };
    L.strip(61, i => arcAt(i / 60, -14), 1.1, acc, 0.25, true);
    L.strip(61, i => arcAt(i / 60, 66), 0.7, acc, 0.1, false);
  }
  eachBeam((s, x, y, z, w, al, dashed, sessions) => {
    const c = [s.x, s.y, s.z, (s.x + x) / 2, (s.y + y) / 2, (s.z + z) / 2 + 60, x, y, z], segs = dashed ? 10 : 14;
    L.strip(segs + 1, i => qb(c, i / segs), w, RGB(s.color), al, dashed);
    if (sessions && al > 0.1) flows.push({c, col: paler(s.color), size: 3.4, n: flowDots(sessions)});
  });
  if (state.sel && motion) for (let i = 0; i < 3; i++) {
    const n = state.sel, ph = (T * 0.45 + i / 3) % 1;
    L.circle(n.x, n.y, n.z, n.r + 6 + ph * 70, 48, 1.4, RGB(COL.accent), (1 - ph) * 0.55, false);
  }
  L.end();

  const N = R3.nodes; N.begin();
  nodes.forEach(n => {
    if (n.a < 0.01) return;
    const src = n.kind === 'src', glow = state.sel === n ? 1.6 : state.hover === n ? 1.2 : src ? 0.45 : n.by.length ? 0.75 : 0.2;
    N.add(n.x, n.y, n.z, n.r, RGB(n.color), n.a, src ? 1 : 0, src && !n.d.flagged ? 1 : 0, glow, src ? minPx(n) * 2 : 2);
  });
  N.end();

  const S = R3.sparks; S.begin();
  if (motion) flows.forEach((f, i) => {
    for (let j = 0; j < f.n; j++) { const p = qb(f.c, (T * 0.18 + i * 0.137 + j / f.n) % 1); S.add(p[0], p[1], p[2], 0, f.col, 1, 0, 0, 0, f.size); }
  });
  S.end();
  R3.render(T);

  // canvas overlay: the arc's title, the names of sources and hosts, subnet names where those leave room, rings
  if (state.labels) arcTitle(); else arcTitleBoxes = [];
  const taken = hostLabels(state.labels, sourceLabels(state.labels));
  if (state.labels) clusterLabels(taken);
  [...nodes].filter(n => n.a > 0.02).sort((a, b) => a.a - b.a).forEach(n => drawNode(n));
}

// ---------------------------------------------------------------- interaction
function pick(sx, sy) {
  let best = null, bd = 1e9;
  if (!painted) return null;
  nodes.forEach(n => {
    if (n.a < 0.12) return;
    const [x, y, sc] = P(n), d = Math.hypot(x - sx, y - sy), r = Math.max(8, Math.max(minPx(n), n.r * sc) + 6);
    // sources and the hosts a source narrowed onto win over the many small dots around them
    const score = d - (n.kind === 'src' ? 6 : n.by.length ? 3 : 0);
    if (d < r && score < bd) { bd = score; best = n; }
  });
  return best;
}
let drag = null;
// drag rotates (3D), right-drag or Shift-drag pans, middle-drag moves the picture straight up or down
cv.addEventListener('pointerdown', e => {
  if (e.button === 1) e.preventDefault();   // no browser autoscroll on the middle button
  const vert = e.button === 1;
  drag = {x: e.clientX, y: e.clientY, vert, node: pick(e.clientX, e.clientY), moved: false, lx: e.clientX, ly: e.clientY,
    orbit: !!R3 && !vert && !(e.button === 2 || e.shiftKey), yaw: view.oyaw, pitch: view.opitch};
  cv.setPointerCapture(e.pointerId);
});
cv.addEventListener('contextmenu', e => { if (R3) e.preventDefault(); });
cv.addEventListener('mousedown', e => { if (e.button === 1) e.preventDefault(); });   // autoscroll starts on mousedown in some browsers
cv.addEventListener('pointermove', e => {
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) { if (!drag.moved) { stopSpin(); drag.yaw = view.oyaw; } drag.moved = true; cv.classList.add('dragging'); tip(null); }
    if (drag.moved && drag.orbit) {
      view.oyaw = drag.yaw - dx * 0.006; view.opitch = Math.max(0, Math.min(1.4, drag.pitch - dy * 0.004));
      placeArc(view.oyaw); markView();
      view.yaw = view.oyaw; view.pitch = view.opitch;
    } else if (drag.moved && drag.vert) {
      if (R3) { cam.tuy += e.clientY - drag.ly; cam.uy = cam.tuy; }
      else panBy(drag.lx, drag.ly, drag.lx, e.clientY);
    } else if (drag.moved) {
      panBy(drag.lx, drag.ly, e.clientX, e.clientY);
    }
    drag.lx = e.clientX; drag.ly = e.clientY;
    return;
  }
  const n = pick(e.clientX, e.clientY);
  const hc = n ? null : clusterAt(e.clientX, e.clientY);
  state.hover = n; state.hoverCluster = hc; cv.classList.toggle('hover', !!(n || hc));
  if (hc) subnetTip(hc, e.clientX, e.clientY); else tip(n, e.clientX, e.clientY);
});
cv.addEventListener('pointerup', e => {
  const wasDrag = drag && drag.moved, startNode = drag && drag.node;
  drag = null; cv.classList.remove('dragging');
  if (wasDrag) return;
  const n = pick(e.clientX, e.clientY) || startNode;
  if (n) { tip(null); select(n); return; }
  const c = clusterAt(e.clientX, e.clientY); if (c) zoomCluster(c);
});
cv.addEventListener('dblclick', e => { if (!pick(e.clientX, e.clientY) && !clusterAt(e.clientX, e.clientY)) overview(); });
cv.addEventListener('pointerleave', () => { state.hover = null; state.hoverCluster = null; tip(null); });
// move the view so the point under (sx0, sy0) ends up under (sx1, sy1); in 3D this follows the
// camera's current yaw and tilt, so dragging left always moves the network left on screen
function panBy(sx0, sy0, sx1, sy1) {
  stopSpin();
  if (R3) {
    const a = R3.unproject(sx0, sy0), b = R3.unproject(sx1, sy1);
    if (a && b) { cam.tx += a[0] - b[0]; cam.ty += a[1] - b[1]; }
  } else { cam.tx -= (sx1 - sx0) / cam.z; cam.ty -= (sy1 - sy0) / cam.z; }
  cam.x = cam.tx; cam.y = cam.ty;
}
cv.addEventListener('wheel', e => {
  e.preventDefault();
  stopSpin();
  // trackpad two-finger swipe sideways pans; pinch (ctrl+wheel) and the mouse wheel zoom
  if (!e.ctrlKey && Math.abs(e.deltaX) > Math.abs(e.deltaY) * 0.5) {
    const k = e.deltaMode === 1 ? 16 : 1;
    panBy(e.clientX, e.clientY, e.clientX - e.deltaX * k, e.clientY - e.deltaY * k);
    return;
  }
  // never out past the fitted overview of a big network, and never a jump in when it is already further out
  const z = Math.max(Math.min(ZOOM_MIN, cam.tz), Math.min(4, cam.tz * Math.exp(-e.deltaY * 0.0015)));
  if (R3) {   // zoom towards the point under the cursor on the network plane
    const w = R3.unproject(e.clientX, e.clientY);
    if (w) { const f = cam.tz / z; cam.tx = w[0] + (cam.tx - w[0]) * f; cam.ty = w[1] + (cam.ty - w[1]) * f; }
    cam.tz = z;
    return;
  }
  const [wx, wy] = toW(e.clientX, e.clientY);
  cam.tz = z; cam.tx = wx - (e.clientX - W / 2) / z; cam.ty = wy - (e.clientY - H / 2) / z;
}, {passive: false});
function placeTip(h, x, y) {
  const el = $('tip');
  el.innerHTML = h; el.hidden = false;
  const r = el.getBoundingClientRect();
  el.style.left = Math.max(6, Math.min(W - r.width - 10, x + 16)) + 'px'; el.style.top = Math.max(6, Math.min(H - r.height - 10, y + 16)) + 'px';
}
const netName = s => s.name ? `${esc(s.id)} · ${esc(s.name)}` : esc(s.id);
function subnetTip(c, x, y) {
  const s = c.s, by = srcNodes.filter(n => n.nets.some(b => b.c === c));
  placeTip(`<b>${esc(s.id)}</b> <span class="m">subnet${s.name ? ' · ' + esc(s.name) : ''}</span><br>${subnetBits(s).join(' · ')}` +
    `<br><span class="m">Swept by ${plural(by.length, 'source')}` + (by.length ? ': ' + by.slice(0, 4).map(n => esc(n.id)).join(', ') + (by.length > 4 ? ` and ${by.length - 4} more` : '') : '') +
    '<br>Click to zoom in</span>', x, y);
}
function sweepLine(d) {
  return `${plural(d.services_probed, 'service')} tried on ${plural(d.hosts_probed, 'host')} and ${plural(d.ports_probed, 'port')}; ` +
    `${pct(d.failed_share)} failed, ${fmt(d.services_answered)} answered`;
}
function tip(n, x, y) {
  if (!n) { $('tip').hidden = true; return; }
  let h;
  if (n.kind === 'src') {
    const d = n.d;
    h = `<b>${esc(d.ip)}</b> <span class="m">outside source</span><br><span style="color:${n.color}">${esc(d.flagged ? levelTag(d) + ': ' + d.label : d.label)}</span>` +
      `<br><span class="m">${sweepLine(d)}</span>` +
      (d.flagged ? `<br>Kept coming back to ${plural(d.services_total, 'service')} on ${plural(d.hosts_hit, 'host')}` : '') +
      (state.sel === n ? '' : '<br><span class="m">Click for its evidence</span>');
  } else {
    const d = n.d, s = n.cluster.s;
    h = `<b>${esc(d.ip)}</b> <span class="m">internal host · ${netName(s)}</span><br>` +
      (n.by.length ? `<span style="color:${n.color}">${plural(n.by.length, 'source')} kept coming back to it</span>` + (n.ports.length ? ` <span class="m">(${esc(n.ports.slice(0, 4).join(', '))}${n.ports.length > 4 ? ` +${n.ports.length - 4}` : ''})</span>` : '')
        : d.state === 'answered' ? 'Answered a sweep; no source kept coming back to it' : 'Tried, no answer') +
      `<br><span class="m">Tried by ${plural(d.sources, 'source')}` + (d.answered ? `; ${plural(d.answered, 'service')} answered` : '') + '</span>' +
      (state.sel === n ? '' : '<br><span class="m">Click to see which sources</span>');
  }
  placeTip(h, x, y);
}
addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') { if (e.key === 'Escape') e.target.blur(); return; }
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'Escape') overview();
  else if (e.key === '/') { e.preventDefault(); $('search').focus(); }
  else if (e.key === '?') toggleAbout();
  else if (e.key === 'l' || e.key === 'L') toggleLabels();
  else if (e.key === 'm' || e.key === 'M') toggleMotion();
  else if (e.key === '3' && can3d) set3d(!R3, true);
  else if (e.key === '2') set3d(false, true);
  else if (R3 && 'qQeEtTyYuUrR'.includes(e.key)) {
    const k = e.key.toLowerCase();
    if (k === 'q') rotateView(1); else if (k === 'e') rotateView(-1);
    else if (k === 't') setView('top'); else if (k === 'y') setView('tilted'); else if (k === 'u') setView('low'); else setView(DEFAULT_VIEW, true);
  }
  else if (e.shiftKey && e.key.startsWith('Arrow')) {   // Shift+arrows pan
    const d = 80, cx = W / 2, cy = H / 2;
    panBy(cx, cy, cx + (e.key === 'ArrowLeft' ? d : e.key === 'ArrowRight' ? -d : 0), cy + (e.key === 'ArrowUp' ? d : e.key === 'ArrowDown' ? -d : 0));
  }
  else if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && srcNodes.length) {   // step through the sources
    const i = state.sel && state.sel.kind === 'src' ? state.sel.i : e.key === 'ArrowRight' ? -1 : 0;
    select(srcNodes[(i + (e.key === 'ArrowRight' ? 1 : srcNodes.length - 1)) % srcNodes.length]);
  }
});
addEventListener('resize', () => { resize(); placeViewctl(); fitOverview(); });

// ---------------------------------------------------------------- selection, list and panel
function select(n) {
  if (!n) { overview(); return; }
  state.sel = n; stopSpin();
  document.body.classList.add('picked'); $('hint').classList.add('gone');
  try { history.replaceState(null, '', '#' + (n.kind === 'src' ? 'source=' : 'host=') + encodeURIComponent(n.id)); } catch (_) {}
  renderPanel(); renderList(); fitOverview(); updateAbout();
  if (!state.motion) snap();
}
function overview() {
  const had = !!state.sel;
  state.sel = null; state.hover = null;
  document.body.classList.remove('picked');
  if (had) { try { history.replaceState(null, '', '#'); } catch (_) {} }
  $('panel').hidden = true;
  if (R3) homeView();
  fitOverview(); renderList(); updateAbout();
  if (!state.motion) snap();
}
const mark = n => n.kind === 'src' ? `<span class="dm ${n.d.flagged ? 'c-' + levelKey(n.d) : 'hollow'}"></span>`
  : `<span class="sw ${n.by.length ? 'c-' + levelKey(n.by[0].d) : 'c-' + n.d.state}"></span>`;
const openGroups = new Set(narrowedHosts.length <= 12 ? clusters.map(c => c.i) : []);
function matches(n, q) {
  if (!q) return true;
  if (n.id.toLowerCase().includes(q)) return true;
  if (n.kind === 'src') return n.d.label.toLowerCase().includes(q) || levelTag(n.d).toLowerCase().includes(q) ||
    n.narrow.some(b => b.h.id.includes(q) || b.services.some(v => String(v.port) === q || portText(v.port, v.proto) === q));
  const s = n.cluster.s;
  return s.id.includes(q) || (s.name || '').toLowerCase().includes(q) || n.ports.some(p => p === q || p.split('/')[0] === q);
}
function srcRow(n) {
  const d = n.d, note = d.flagged ? `${levelTag(d)} · ${plural(d.services_total, 'service')}` : plural(d.hosts_probed, 'host');
  return `<div class="hrow${state.sel === n ? ' on' : ''}" role="listitem" tabindex="0" data-src="${n.i}">${mark(n)}<span class="nm">${esc(d.ip)}</span><span class="ip">${esc(note)}</span></div>`;
}
function hostRow(n) {
  const note = n.by.length ? n.ports.slice(0, 2).join(', ') + (n.ports.length > 2 ? ` +${n.ports.length - 2}` : '') : n.d.state === 'answered' ? 'answered' : 'no answer';
  return `<div class="hrow${state.sel === n ? ' on' : ''}" role="listitem" tabindex="0" data-host="${n.i}">${mark(n)}<span class="nm">${esc(n.id)}</span><span class="ip">${esc(note)}</span></div>`;
}
const LIST_MAX = 200;   // rows of search results shown per section
function renderList() {
  const q = $('search').value.trim().toLowerCase();
  const flagged = srcNodes.filter(n => n.d.flagged && matches(n, q)), swept = srcNodes.filter(n => !n.d.flagged && matches(n, q));
  let h = `<div class="lhead">Flagged sources <span>${fmt(q ? flagged.length : CNT.flagged)}</span></div>`;
  h += flagged.length ? flagged.map(srcRow).join('') : `<div class="lnote">${q ? 'None match.' : 'No source swept and then narrowed.'}</div>`;
  if (!q && CNT.flagged > nFlagged) h += `<div class="lnote">${fmt(CNT.flagged - nFlagged)} more are in the report.</div>`;
  if (swept.length || (!q && nSwept)) {
    h += `<div class="lhead">Swept, did not narrow <span>${fmt(q ? swept.length : Math.max(0, (CNT.sweeping || 0) - (CNT.flagged || 0)))}</span></div>` + swept.map(srcRow).join('');
    if (!q && notDrawn) h += `<div class="lnote">The ${fmt(nSwept)} largest sweeps are drawn.</div>`;
  }
  if (q) {
    const found = hostNodes.filter(n => matches(n, q)).sort((a, b) => STATE_RANK[a.d.state] - STATE_RANK[b.d.state] || (a.id < b.id ? -1 : 1));
    h += `<div class="lhead">Hosts <span>${fmt(found.length)}</span></div>` + (found.length ? found.slice(0, LIST_MAX).map(hostRow).join('') : '<div class="lnote">None match among the hosts drawn.</div>') +
      (found.length > LIST_MAX ? `<div class="lnote">${fmt(found.length - LIST_MAX)} more match.</div>` : '');
  } else if (narrowedHosts.length) {
    h += `<div class="lhead">Hosts narrowed onto <span>${fmt(narrowedHosts.length)}</span></div>`;
    clusters.forEach(c => {
      const m = c.members.filter(n => n.by.length); if (!m.length) return;
      const open = openGroups.has(c.i);
      h += `<div class="hgroup${open ? ' open' : ''}"><div class="hghead" role="button" tabindex="0" aria-expanded="${open}" data-group="${c.i}">` +
        `<span class="chev"></span><span class="hgname">${netName(c.s)}</span><span class="hgcount">${plural(m.length, 'host')} narrowed onto · ${fmt(c.s.tried)} tried</span></div>` +
        (open ? m.map(hostRow).join('') : '') + '</div>';
    });
  }
  $('hostlist').innerHTML = h;
}
function listTarget(e) {
  const row = e.target.closest('[data-src],[data-host],[data-group]'); if (!row) return null;
  if (row.dataset.group != null) return {group: Number(row.dataset.group)};
  return {node: row.dataset.src != null ? srcNodes[row.dataset.src] : hostNodes[row.dataset.host]};
}
function listAct(e) {
  const t = listTarget(e); if (!t) return;
  if (t.group != null) { if (openGroups.has(t.group)) openGroups.delete(t.group); else openGroups.add(t.group); renderList(); return; }
  if (t.node) select(t.node);
}
$('hostlist').addEventListener('click', listAct);
$('hostlist').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); listAct(e); } });
$('hostlist').addEventListener('mouseover', e => { const t = listTarget(e); state.hover = t && t.node ? t.node : null; });
$('hostlist').addEventListener('mouseleave', () => { state.hover = null; });
$('search').addEventListener('input', renderList);
$('search').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const q = e.target.value.trim().toLowerCase(), n = q && (srcNodes.find(s => matches(s, q)) || hostNodes.find(h => matches(h, q)));
  if (n) { select(n); e.target.blur(); }
});

const stat = (n, text) => `<div class="stat"><b>${n}</b><span>${esc(text)}</span></div>`;
function sourcePanel(n) {
  const d = n.d, f = d.flagged;
  let h = `<h2>${esc(d.ip)}</h2><div class="ipline">Outside source · seen in ${esc(listAnd((d.log_sources || []).map(s => LOG_TEXT[s] || s)) || 'the logs')}</div>` +
    `<div class="verdict"><span class="pill ${f ? 'c-' + levelKey(d) : 'c-none'}">${esc(levelTag(d))}</span><span>${esc(d.label)}</span></div>` +
    '<div class="stats">' + stat(fmt(d.services_probed), 'services tried') + stat(fmt(d.hosts_probed), `hosts, on ${plural(d.ports_probed, 'port')}`) +
    stat(pct(d.failed_share), 'of the sweep failed') + (f ? stat(fmt(d.services_total), `service${d.services_total === 1 ? '' : 's'} it came back to`)
      : stat(fmt(d.services_answered), `service${d.services_answered === 1 ? '' : 's'} answered`)) + '</div>';
  h += `<h3>Sweep</h3><p>${when(d.probe_start)} to ${clock(d.probe_end)}. ${sweepLine(d)}.</p>`;
  const nets = [...n.nets].sort((a, b) => b.hosts - a.hosts || a.c.i - b.c.i);
  h += nets.slice(0, 12).map(b => `<div class="row go" tabindex="0" data-zoom="${b.c.i}"><span class="sw ${b.c.color ? '' : 'c-tried'}"${b.c.color ? ` style="background:${b.c.color}"` : ''}></span>` +
    `<span class="who">${esc(b.c.s.id)}</span><span class="n">${plural(b.hosts, 'host')}</span>` +
    `<span class="sub">${b.c.s.name ? esc(b.c.s.name) + ' · ' : ''}${plural(b.services, 'service')} tried, ${fmt(b.answered)} answered</span></div>`).join('');
  const rest = nets.length - Math.min(12, nets.length);
  if (rest > 0 || d.hosts_elsewhere > 0) h += `<p>${[rest > 0 ? `${plural(rest, 'more subnet')} on the map` : '', d.hosts_elsewhere > 0 ? `${plural(d.hosts_elsewhere, 'host')} in subnets that are not drawn` : ''].filter(Boolean).join('; ')}.</p>`;
  if (f) {
    h += `<h3>Narrowing</h3><p>Started ${when(d.narrowing_start)}. After that, <b>${pct(d.focus_share)}</b> of its sessions went to services that had answered.</p>` +
      '<h3>Services it narrowed to</h3>';
    h += (d.services || []).map(([ip, port, proto, sessions, ts]) => {
      const hn = hostByIp.get(ip), net = hn && hn.cluster.s.name;
      return `<div class="row${hn ? ' go' : ''}"${hn ? ` tabindex="0" data-host="${hn.i}"` : ''}><span class="sw c-${levelKey(d)}"></span>` +
        `<span class="who">${esc(ip)} ${esc(portText(port, proto))}</span><span class="n">${plural(sessions, 'session')}</span>` +
        `<span class="sub">${net ? esc(net) + ' · ' : ''}first return ${when(ts)}${hn ? '' : ' · host not drawn'}</span></div>`;
    }).join('');
    if (d.services_total > (d.services || []).length) h += `<p>and ${fmt(d.services_total - d.services.length)} more.</p>`;
    h += `<h3>Timing</h3><p>${esc(d.timing)}</p><h3>Exploit evidence</h3><p>${esc(d.threat_evidence)}</p>`;
  } else {
    h += '<h3>Why it is not flagged</h3><p>It swept many hosts or ports and did not then keep coming back to the few services that answered. That looks like plain scanning.</p>';
  }
  h += `<h3>Campaign</h3><p>${span(d.campaign_hours || 0)}, ${when(d.first_seen)} to ${when(d.last_seen)}, ${plural(d.sessions, 'session')}.</p>`;
  if (f && d.start_times) h += `<p>Start times resolved by ${Object.entries(d.start_times).map(([k, v]) => `${esc(START_TEXT[k] || k)} (${plural(v, 'session')})`).join('; ')}.</p>`;
  (d.notes || []).forEach(t => { h += `<p>${esc(t)}</p>`; });
  return h + '<div class="note">Counted from connection metadata only. A lead to check, not proof of an attack.</div>';
}
function hostPanel(n) {
  const d = n.d, s = n.cluster.s;
  let h = `<h2>${esc(d.ip)}</h2><div class="ipline">Internal host · ${netName(s)}</div>` +
    '<div class="stats">' + stat(fmt(d.sources), `source${d.sources === 1 ? '' : 's'} tried it`) + stat(fmt(n.by.length), `kept coming back to it`) +
    stat(fmt(d.services), 'services tried on it') + stat(fmt(d.answered), 'of them answered') + '</div>';
  h += '<h3>Sources</h3>' + n.srcs.map(sn => {
    const b = sn.narrow.find(o => o.h === n), a = (sn.d.answered || []).find(o => o[0] === n.i);
    const what = b ? 'Kept coming back to ' + b.services.map(v => `${esc(portText(v.port, v.proto))} (${plural(v.sessions, 'session')})`).join(', ')
      : a ? `${plural(a[1], 'service')} answered its sweep; it did not keep coming back` : 'Tried it, no answer';
    return `<div class="row go" tabindex="0" data-src="${sn.i}">${mark(sn)}<span class="who">${esc(sn.id)}</span><span class="n">${esc(levelTag(sn.d))}</span><span class="sub">${what}</span></div>`;
  }).join('');
  if (d.sources > n.srcs.length) h += `<p>${plural(d.sources - n.srcs.length, 'more source')} not drawn.</p>`;
  return h + '<div class="note">Only what the drawn sources did inside the window each one is judged by. The report has the full findings.</div>';
}
function renderPanel() {
  const n = state.sel, el = $('panel');
  if (!n) { el.hidden = true; return; }
  el.innerHTML = n.kind === 'src' ? sourcePanel(n) : hostPanel(n);
  el.hidden = false; el.scrollTop = 0;
}
function panelAct(e) {
  const row = e.target.closest('[data-src],[data-host],[data-zoom]'); if (!row) return;
  if (row.dataset.zoom != null) { const c = clusterAtIdx.get(Number(row.dataset.zoom)); if (c) zoomCluster(c); return; }
  select(row.dataset.src != null ? srcNodes[row.dataset.src] : hostNodes[row.dataset.host]);
}
$('panel').addEventListener('click', panelAct);
$('panel').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); panelAct(e); } });
$('panel').addEventListener('mouseover', e => {
  const row = e.target.closest('[data-src],[data-host]');
  state.hover = row ? (row.dataset.src != null ? srcNodes[row.dataset.src] : hostNodes[row.dataset.host]) : null;
});
$('panel').addEventListener('mouseleave', () => { state.hover = null; });

// ---------------------------------------------------------------- controls
function toggleLabels() { state.labels = !state.labels; $('btn-labels').setAttribute('aria-pressed', state.labels); }
function toggleMotion() { state.motion = !state.motion; $('btn-motion').setAttribute('aria-pressed', state.motion); markView(); }
$('btn-overview').onclick = overview;
$('btn-labels').onclick = toggleLabels;
$('btn-motion').onclick = toggleMotion;
$('btn-3d').hidden = !can3d;
$('vw-flat').onclick = () => set3d(false, true);
$('btn-3d').onclick = () => set3d(true, true);
// "What am I looking at": the ? at the right end of the top buttons opens a short note, worded for what is
// on screen, centered under the picture. It opens by itself for 15 s when the page loads or the view
// changes, then folds back into the ? (hovering keeps it open); the ? or the ? key opens and closes it.
const ABOUT_MS = 15000;
let aboutTimer = 0, aboutShown = '';
const ABOUT = {
  '3d': 'Each ring is a subnet and each dot a host that an outside source tried. The sources sit on the arc above: <b>dashed beams</b> are a source\'s sweep, <b>solid beams</b> go down to the services it kept coming back to, and those hosts stand tallest. Click a source for its evidence.',
  flat: 'Each ring is a subnet and each dot a host that an outside source tried; the diamonds above are the sources. <b>Dashed lines</b> are a source\'s sweep, <b>solid lines</b> go to the services it kept coming back to. Click a source for its evidence.',
  src: n => `<b>${esc(n.id)}</b> and what it did: its sweep (dashed), the hosts it tried (lit) and the services it kept coming back to (solid). Esc or ← All sources goes back.`,
  host: n => `<b>${esc(n.id)}</b> and every drawn source that tried it; a solid beam is a source that kept coming back. Esc or ← All sources goes back.`,
};
function aboutKey() { return state.sel ? state.sel.kind + ':' + state.sel.id : R3 ? '3d' : 'flat'; }
function aboutHtml() { return state.sel ? ABOUT[state.sel.kind](state.sel) : ABOUT[R3 ? '3d' : 'flat']; }
// The note sits centered under the picture: above the legend, between the list on the left and
// whatever is open on the right (the panel, the 3D camera controls).
function placeAbout() {
  const box = id => { const el = $(id); if (!el || el.hidden) return null; const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return null; const b = el.getBoundingClientRect(); return b.width && b.height ? b : null; };
  let l = 18, r = innerWidth - 18, bottom = innerHeight - 14;
  const rail = box('rail'); if (rail) l = Math.max(l, rail.right + 14);
  for (const id of ['panel', 'viewctl']) { const b = box(id); if (b && b.bottom > innerHeight / 2) r = Math.min(r, b.left - 14); }
  const lg = box('legend'); if (lg) bottom = lg.top - 10;
  if (r - l < 280) { l = 18; r = innerWidth - 18; }   // no room between the side panels: use the full width
  const root = document.documentElement.style;
  root.setProperty('--about-left', Math.round(l) + 'px');
  root.setProperty('--about-right', Math.round(innerWidth - r) + 'px');
  root.setProperty('--about-bottom', Math.round(innerHeight - bottom) + 'px');
}
function closeAbout() { clearTimeout(aboutTimer); $('about').hidden = true; $('about-toggle').setAttribute('aria-expanded', 'false'); }
function openAbout(ms = ABOUT_MS) {
  $('about').innerHTML = aboutHtml(); aboutShown = aboutKey(); placeAbout();
  $('about').hidden = false; $('about-toggle').setAttribute('aria-expanded', 'true');
  requestAnimationFrame(placeAbout);   // the panel may still be opening
  clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, ms);
}
// called whenever what is on screen may have changed: something new opens the note again, the same only refreshes it
function updateAbout() {
  if (!SOURCES.length) return;
  if (aboutKey() !== aboutShown) openAbout(); else if (!$('about').hidden) { $('about').innerHTML = aboutHtml(); placeAbout(); requestAnimationFrame(placeAbout); }
}
function toggleAbout() { if ($('about').hidden) openAbout(); else closeAbout(); }
$('about-toggle').onclick = toggleAbout;
$('about').addEventListener('mouseenter', () => clearTimeout(aboutTimer));
$('about').addEventListener('mouseleave', () => { clearTimeout(aboutTimer); aboutTimer = setTimeout(closeAbout, 3000); });
addEventListener('resize', () => { if (!$('about').hidden) placeAbout(); });
// the 3D camera controls sit in the lower right, just above the legend
function placeViewctl() { document.documentElement.style.setProperty('--legend-h', ($('legend').offsetHeight + 24) + 'px'); }
$('vc-left').onclick = () => rotateView(1);
$('vc-right').onclick = () => rotateView(-1);
$('vc-top').onclick = () => setView('top');
$('vc-tilted').onclick = () => setView('tilted');
$('vc-low').onclick = () => setView('low');
$('vc-reset').onclick = () => setView(DEFAULT_VIEW, true);
$('vc-spin').onclick = () => { view.spin = !(view.spin && state.motion); if (view.spin && !state.motion) toggleMotion(); markView(); };
markView();
if (!state.motion) $('btn-motion').setAttribute('aria-pressed', 'false');

// one-line key: the tiers and levels present, then what the lines and dots mean
{
  const keys = [...new Set(srcNodes.filter(n => n.d.flagged).map(n => levelKey(n.d)))];
  const names = {t0: 'tier 0', l1: 'level 1', l2: 'level 2', l3: 'level 3'}, first = keys[0] || 't0';
  $('legend').innerHTML = keys.map(k => `<span><span class="dm c-${k}"></span>Flagged source, ${names[k]}</span>`).join('') +
    (nSwept ? '<span><span class="dm hollow"></span>Swept, did not narrow</span>' : '') +
    `<span><i style="background:repeating-linear-gradient(90deg,${COL.sweep} 0 5px,transparent 5px 9px)"></i>Sweep</span>` +
    (keys.length ? `<span><i style="background:${COL[first]}"></i>Service it kept coming back to</span>` : '') +
    (keys.length ? `<span><span class="sw c-${first}"></span>Host narrowed onto</span>` : '') +
    '<span><span class="sw c-answered"></span>Answered a sweep</span><span><span class="sw c-tried"></span>Tried, no answer</span>' +
    '<span class="cal">Connection metadata only: leads to check, not proof of an attack</span>';
}
{
  const w = D.window || [], bits = [`${fmt(CNT.flagged)} flagged`, `${fmt(Math.max(0, (CNT.sweeping || 0) - (CNT.flagged || 0)))} swept only`,
    `${fmt(CNT.inbound_sessions)} inbound sessions from ${plural(CNT.outside_sources || 0, 'outside source')}`];
  if (w[0]) bits.push(`${when(w[0]).slice(0, 16)} → ${when(w[1])}`);
  $('subtitle').textContent = bits.join(' · ');
}

// ---------------------------------------------------------------- start
resize();
if (!SOURCES.length) {   // nothing swept: say so instead of showing an empty map
  document.body.classList.add('nothing');
  $('empty').innerHTML = '<div><b>Nothing to draw.</b>' + (CNT.inbound_sessions
    ? `No outside source swept your hosts in these logs: ${fmt(CNT.inbound_sessions)} inbound sessions from ${plural(CNT.outside_sources || 0, 'outside source')} were scored.`
    : 'No sessions from outside addresses to internal hosts were found in these logs.') + ' The <a href="report.html">report</a> lists what was read.</div>';
  $('empty').hidden = false;
}
set3d(can3d && !/[?&#]2d\b/.test(QUERY), false);
renderList(); placeViewctl(); fitOverview();
const introText = `Mapping ${plural(srcNodes.length, 'outside source')} against ${plural(CNT.hosts_tried || hostNodes.length, 'host')}`;
if (state.motion && SOURCES.length) {
  let i = 0; const it = setInterval(() => { $('intro-text').textContent = introText.slice(0, ++i) + (i < introText.length ? '▌' : ''); if (i >= introText.length) clearInterval(it); }, 22);
  setTimeout(() => $('intro').classList.add('gone'), 1500);
} else { $('intro').style.display = 'none'; nodes.forEach(n => { n.born = 0; }); emphasis(); snap(); }
setTimeout(() => $('hint').classList.add('gone'), 20000);
{
  const m = location.hash.match(/(source|host)=([^&]+)/);
  const n = m && (m[1] === 'source' ? srcNodes.find(s => s.id === decodeURIComponent(m[2])) : hostByIp.get(decodeURIComponent(m[2])));
  if (n) { if (state.motion) setTimeout(() => select(n), 900); else select(n); }
}
// stats(): read-only counts for the browser check (scripts/smoke): what the data holds and what the last frame drew
const stats = () => Object.assign({sources: srcNodes.length, hosts: hostNodes.length, subnets: clusters.length, is3d: !!R3,
  selected: state.sel ? state.sel.id : null, beams: beamCount, frames}, R3 && R3.stats ? R3.stats() : {});
window.PWExplorer = {select: id => select(srcNodes.find(s => s.id === id) || hostByIp.get(id) || null), overview, set3d: on => set3d(on, true),
  is3d: () => !!R3, can3d, stats};
requestAnimationFrame(frame);
});
