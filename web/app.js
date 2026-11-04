"use strict";

const $ = (id) => document.getElementById(id);
const LANES = { file: 0, process: 1, network: 2, blocked: 2 };
const LANE_H = 56;

const state = {
  events: [],
  maxTs: 1,
  es: null,
  selected: null,
  running: false,
};

// ---- environment ----------------------------------------------------------
async function loadHealth() {
  try {
    const h = await (await fetch("/api/health")).json();
    setStatus("st-runtime", h.runtime === "runsc" ? "gVisor runsc"
      : h.runtime === "runc" ? "runc" : "unavailable",
      h.runtime === "runsc" ? "good" : h.runtime === "runc" ? "warn" : "off");
    setStatus("st-egress", h.docker ? "sealed · none" : "n/a",
      h.docker ? "good" : "off");
    setStatus("st-inference", h.inference === "vultr" ? "Vultr" : "offline",
      h.inference === "vultr" ? "good" : "off");
    setStatus("st-chamber", h.sandbox_image ? "armed" : (h.docker ? "no image" : "demo only"),
      h.sandbox_image ? "good" : "warn");
  } catch {
    setStatus("st-chamber", "demo only", "warn");
  }
}
function setStatus(id, text, cls) {
  const el = $(id);
  el.textContent = text;
  el.className = cls || "";
}

// ---- target kind hint -----------------------------------------------------
function detectKind(v) {
  const s = v.trim().toLowerCase();
  if (!s) return "auto";
  if (s.startsWith("npm:")) return "npm";
  if (s.startsWith("pypi:") || s.startsWith("pip:")) return "pypi";
  if (s.startsWith("demo:")) return "demo";
  if (s.startsWith("http://") || s.startsWith("https://")) return "url";
  if (s.includes("github.com/")) return "github";
  if (s.split("/").length === 2 && !s.includes(" ")) return "github";
  return "npm";
}
$("target").addEventListener("input", (e) => {
  const k = detectKind(e.target.value);
  const tag = $("kindtag");
  tag.textContent = k;
  tag.dataset.k = k === "auto" ? "" : k;
});
document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => {
    $("target").value = c.dataset.fill;
    $("target").dispatchEvent(new Event("input"));
    $("target").focus();
  }));

// ---- submit / stream ------------------------------------------------------
$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("target").value.trim();
  if (!target || state.running) return;
  resetRun();
  state.running = true;
  document.body.classList.add("running");
  $("detonate").disabled = true;

  let job;
  try {
    const r = await fetch("/api/detonate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!r.ok) throw new Error((await r.json()).detail || "request failed");
    job = await r.json();
  } catch (err) {
    endRun();
    pushLog({ kind: "blocked", op: "error", target: String(err), result: "error", ts: 0, severity: 2 });
    return;
  }
  state.jobId = job.job_id;
  if (job.synthetic) $("synthBanner").hidden = false;
  setFeedStatus("running", "live");
  feedRaw(`<span class="ps1">chamber@sandbox:~$</span> detonate ${esc(target)}`, "k-process");
  openStream(job.job_id);
});

function openStream(jobId) {
  const es = new EventSource(`/api/stream/${jobId}`);
  state.es = es;
  es.addEventListener("plan", (e) => {
    const d = JSON.parse(e.data);
    $("agentPlan").textContent = d.plan;
    const src = $("agentSrc");
    src.textContent = d.agent === "vultr" ? "Vultr inference" : "offline heuristic";
    src.classList.toggle("live", d.agent === "vultr");
    feedRaw(`<span class="ft">[plan]</span> ${esc(d.plan)}`, "k-plan");
  });
  es.addEventListener("event", (e) => {
    const ev = JSON.parse(e.data).event;
    addEvent(ev);
  });
  es.addEventListener("verdict", (e) => {
    const d = JSON.parse(e.data);
    renderVerdict(d.verdict);
    $("agentSummary").hidden = false;
    $("agentSummary").textContent = d.summary;
  });
  es.addEventListener("status", (e) => {
    const d = JSON.parse(e.data);
    if (d.status === "done") {
      endRun();
      setFeedStatus("complete", "done");
      feedRaw('<span class="ft">·</span> sandbox destroyed · run recorded', "k-system");
      loadActivity();
    }
  });
  es.addEventListener("end", () => { es.close(); endRun(); });
  es.onerror = () => { es.close(); endRun(); };
}

function resetRun() {
  if (state.es) state.es.close();
  state.events = []; state.maxTs = 1; state.selected = null;
  $("lanes").innerHTML = ""; $("axis").innerHTML = "";
  $("log").innerHTML = ""; $("logcount").textContent = "0";
  $("reasons").innerHTML = ""; $("iocs").innerHTML = "";
  $("iocsWrap").hidden = true; $("synthBanner").hidden = true;
  $("reportBtn").hidden = true;
  $("stripEmpty").style.display = "none";
  $("agentSummary").hidden = true; $("agentPlan").textContent = "Planning…";
  $("eventDetail").hidden = true;
  feedReset();
  const vp = $("verdictPanel");
  vp.dataset.label = "pending";
  $("labelText").textContent = "analysing"; $("riskScore").textContent = "—";
  $("headline").textContent = "Detonation in progress…";
  $("meterFill").style.transform = "scaleX(0)";
  $("strip").classList.remove("has-sel");
}
function endRun() {
  state.running = false;
  document.body.classList.remove("running");
  $("detonate").disabled = false;
}

// ---- events / strip -------------------------------------------------------
function addEvent(ev) {
  state.events.push(ev);
  pushLog(ev);
  feedEvent(ev);
  const end = (ev.ts || 0) + (ev.duration || 0);
  if (end > state.maxTs) { state.maxTs = end; rescaleAxis(); rescaleBands(); }
  if (ev.kind in LANES) drawBand(ev);
  $("clock").textContent = `t+${(ev.ts || 0).toFixed(1)}s · ${state.events.length} events`;
}

function bandGeom(ev) {
  const pad = 0.015, usable = 0.94;
  const left = (pad + (ev.ts / state.maxTs) * usable) * 100;
  const w = Math.max(1.1, ((ev.duration || 0) / state.maxTs) * usable * 100);
  const lane = LANES[ev.kind] ?? 2;
  return { left, w, top: lane * LANE_H };
}
function drawBand(ev) {
  const b = document.createElement("div");
  b.className = "band";
  b.dataset.k = ev.kind;
  if ((ev.severity || 0) >= 3 || ev.result === "blocked") b.classList.add("threat");
  const g = bandGeom(ev);
  b.style.left = g.left + "%"; b.style.width = g.w + "%"; b.style.top = g.top + "px";
  b.dataset.seq = ev.seq;
  b.addEventListener("click", () => selectEvent(ev.seq));
  b.title = `${ev.kind} ${ev.op} ${ev.target}`;
  $("lanes").appendChild(b);
}
function rescaleBands() {
  document.querySelectorAll(".band").forEach((b) => {
    const ev = state.events.find((e) => e.seq == b.dataset.seq);
    if (!ev) return;
    const g = bandGeom(ev);
    b.style.left = g.left + "%"; b.style.width = g.w + "%";
  });
}
function rescaleAxis() {
  const ax = $("axis"); ax.innerHTML = "";
  for (let i = 0; i <= 4; i++) {
    const t = (state.maxTs * i) / 4;
    const tick = document.createElement("span");
    tick.className = "tick";
    tick.style.left = (1.5 + (i / 4) * 94) + "%";
    tick.textContent = t.toFixed(t < 10 ? 1 : 0) + "s";
    ax.appendChild(tick);
  }
}

// ---- log ------------------------------------------------------------------
function pushLog(ev) {
  const li = document.createElement("li");
  li.dataset.seq = ev.seq;
  if ((ev.severity || 0) >= 3) li.classList.add("sev3");
  li.innerHTML =
    `<span class="t">${(ev.ts || 0).toFixed(1)}</span>` +
    `<span class="k" data-k="${ev.kind}">${ev.kind}</span>` +
    `<span class="op">${esc(ev.op)}</span>` +
    `<span class="tg">${esc(ev.target)}</span>` +
    `<span class="r ${ev.result}">${ev.result === "ok" ? "" : esc(ev.result)}</span>`;
  li.addEventListener("click", () => selectEvent(ev.seq));
  const log = $("log");
  log.appendChild(li);
  log.scrollTop = log.scrollHeight;
  $("logcount").textContent = state.events.length;
}

// ---- selection ------------------------------------------------------------
function selectEvent(seq) {
  const strip = $("strip");
  if (state.selected === seq) { clearSelection(); return; }
  state.selected = seq;
  strip.classList.add("has-sel");
  document.querySelectorAll(".band").forEach((b) =>
    b.classList.toggle("sel", b.dataset.seq == seq));
  document.querySelectorAll(".log li").forEach((l) =>
    l.classList.toggle("sel", l.dataset.seq == seq));
  const ev = state.events.find((e) => e.seq == seq);
  if (ev) showDetail(ev);
}
function clearSelection() {
  state.selected = null;
  $("strip").classList.remove("has-sel");
  document.querySelectorAll(".band.sel, .log li.sel").forEach((e) => e.classList.remove("sel"));
  $("eventDetail").hidden = true;
}
function showDetail(ev) {
  const d = $("eventDetail");
  const det = ev.detail && Object.keys(ev.detail).length
    ? " · " + Object.entries(ev.detail).filter(([k]) => k !== "synthetic")
        .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ")
    : "";
  d.innerHTML = `<span class="d-k">${ev.kind}/${esc(ev.op)}</span> ` +
    `<b>${esc(ev.target)}</b> <span class="d-k">t+${(ev.ts||0).toFixed(2)}s ${ev.result}</span>${esc(det)}`;
  d.hidden = false;
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape") clearSelection(); });

// ---- verdict --------------------------------------------------------------
function renderVerdict(v) {
  const vp = $("verdictPanel");
  vp.dataset.label = v.label;
  if (state.jobId) {
    const rb = $("reportBtn");
    rb.href = `/api/report/${state.jobId}`;
    rb.hidden = false;
  }
  $("labelText").textContent = v.label;
  $("riskScore").textContent = `risk ${v.score}/100`;
  $("headline").textContent = v.headline;
  $("meterFill").style.transform = "scaleX(" + (v.score/100) + ")";
  const rs = $("reasons"); rs.innerHTML = "";
  v.reasons.forEach((r) => { const li = document.createElement("li"); li.textContent = r; rs.appendChild(li); });
  const wrap = $("iocsWrap"), list = $("iocs");
  list.innerHTML = "";
  if (v.iocs && v.iocs.length) {
    wrap.hidden = false;
    v.iocs.forEach((i) => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="typ">${esc(i.type)}</span><span class="val">${esc(i.value)}</span>` +
        (i.note ? `<span class="note">${esc(i.note)}</span>` : "");
      list.appendChild(li);
    });
    $("copyIocs").onclick = () => {
      const text = v.iocs.map((i) => `${i.type}\t${i.value}\t${i.note}`).join("\n");
      navigator.clipboard.writeText(text).then(() => {
        const b = $("copyIocs"); b.textContent = "copied"; b.classList.add("done");
        setTimeout(() => { b.textContent = "copy"; b.classList.remove("done"); }, 1600);
      });
    };
  } else { wrap.hidden = true; }
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---- live console feed ----------------------------------------------------
function feedReset() {
  const feed = $("feed");
  feed.innerHTML =
    '<div class="feed-line dim">detonation-chamber · sealed sandbox syscall monitor · gVisor runsc</div>' +
    '<div class="feed-prompt" id="feedPrompt"><span class="ps1">chamber@sandbox:~$</span> <span class="cursor">▋</span></div>';
  setFeedStatus("idle", "");
}
function setFeedStatus(text, cls) {
  const s = $("feedStatus"); s.textContent = text; s.className = "feed-status" + (cls ? " " + cls : "");
}
function feedRaw(html, cls) {
  const feed = $("feed"), prompt = $("feedPrompt");
  if (!prompt) return;
  const line = document.createElement("div");
  line.className = "feed-line" + (cls ? " " + cls : "");
  line.innerHTML = html;
  feed.insertBefore(line, prompt);
  feed.scrollTop = feed.scrollHeight;
}
function feedEvent(ev) {
  const t = `t+${(ev.ts || 0).toFixed(1)}`.padEnd(6, " ");
  let tag = "";
  if (ev.detail && ev.detail.canary) tag = ' <span class="tag-canary">⚠ CANARY</span>';
  if (ev.result === "blocked") tag = ' <span class="tag-blocked">✗ BLOCKED</span>';
  if (ev.kind === "system") {
    feedRaw(`<span class="ft">${t}</span> ${esc(ev.target)}${tag}`, "k-system");
    return;
  }
  feedRaw(`<span class="ft">${t}</span> <span class="fv">${esc(ev.op)}</span> ${esc(ev.target)}${tag}`,
    "k-" + ev.kind);
}

// ---- telemetry: stats + history ------------------------------------------
async function loadActivity() {
  try {
    const [s, h] = await Promise.all([
      fetch("/api/stats").then((r) => r.json()),
      fetch("/api/history?limit=12").then((r) => r.json()),
    ]);
    renderStats(s); renderHistory(h.runs || []);
  } catch { /* offline/fixture */ }
}
function renderStats(s) {
  const tiles = [
    ["total", "detonations"], ["threats_contained", "threats contained", "hot"],
    ["canary_hits", "canary reads", s.canary_hits ? "hot" : ""],
    ["egress_blocked", "egress blocked", s.egress_blocked ? "hot" : ""],
    ["live_runs", "live runs", "good"],
    ["avg_score", "avg risk"], ["max_score", "max risk"],
    ["events", "events analysed"], ["processes", "processes observed"],
    ["compute_seconds", "compute · s"],
  ];
  $("statGrid").innerHTML = tiles.map(([k, label, cls]) =>
    `<li class="${cls || ""}"><span class="sv">${fmtNum(s[k])}</span><span class="sl">${label}</span></li>`).join("");
  const total = Math.max(1, s.total || 0);
  $("vbars").innerHTML = ["malicious", "suspicious", "benign"].map((k) => {
    const n = s[k] || 0, frac = (n / total).toFixed(3);
    return `<div class="vbar" data-k="${k}"><span class="vl">${k}</span>` +
      `<span class="vtrack"><span class="vfill" style="transform:scaleX(${frac})"></span></span>` +
      `<span class="vn">${n}</span></div>`;
  }).join("");
  const iocs = s.top_iocs || [];
  $("topIocs").innerHTML = iocs.length
    ? iocs.map((i) => `<li><span class="it">${esc(i.type)}</span><span class="iv">${esc(i.value)}</span><span class="ic">×${i.count}</span></li>`).join("")
    : '<li class="tele-empty">No indicators yet — run a detonation.</li>';
  $("statUpdated").textContent = s.total ? `${s.total} runs recorded` : "no runs yet";
}
function renderHistory(runs) {
  $("histCount").textContent = runs.length ? `${runs.length} shown` : "";
  if (!runs.length) { $("hist").innerHTML = '<li class="tele-empty">Nothing detonated yet.</li>'; return; }
  $("hist").innerHTML = runs.map((r) => {
    const name = (r.type === "demo" ? "demo:" : r.type + ":") + r.name;
    return `<li>` +
      `<span class="ht">${rel(r.created)} ago</span>` +
      `<span class="hn">${esc(name)}${r.synthetic ? ' <span class="syn">· syn</span>' : ""}</span>` +
      `<span class="verdict-chip" data-l="${r.label}">${r.label}</span>` +
      `<span class="hr">${r.score}</span>` +
      `<span class="hc ${r.canary_hits ? "hit" : ""}">${r.canary_hits}</span>` +
      `<span class="hb ${r.egress_blocked ? "hit" : ""}">${r.egress_blocked}</span>` +
      `<a class="hrep" href="/api/report/${r.id}" download>↓ json</a>` +
      `</li>`;
  }).join("");
}
function fmtNum(n) {
  n = Number(n || 0);
  return n >= 1000 ? (n / 1000).toFixed(1).replace(/\.0$/, "") + "k" : String(n);
}
function rel(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.floor(s) + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

// ---- design fixture (no network) -----------------------------------------
// ?fixture=exfil renders a representative completed run synchronously, for
// design review and screenshots. Never used in normal operation.
function renderFixture(name) {
  setStatus("st-runtime", "gVisor runsc", "good");
  setStatus("st-egress", "sealed · none", "good");
  setStatus("st-inference", "Vultr", "good");
  setStatus("st-chamber", "armed", "good");
  resetRun();
  state.jobId = "demo";
  $("synthBanner").hidden = false;
  $("kindtag").textContent = "npm"; $("kindtag").dataset.k = "npm";
  $("target").value = "npm:reqeusts-helper@2.1.4";
  $("agentSrc").textContent = "Vultr inference"; $("agentSrc").classList.add("live");
  $("agentPlan").textContent =
    "Fetch the tarball on the host, then run npm install with scripts enabled " +
    "inside a network-isolated container. Watch install and postinstall for " +
    "secret access and outbound connections.";
  const H = "/home/sandbox";
  const evs = [
    ["system","note","planted 5 canary credentials in "+H,"ok",0,0.3],
    ["process","exec","/usr/local/bin/node","ok",1,0.4],
    ["process","exec","/bin/sh -c node postinstall.js","ok",1,0.5],
    ["file","read","/work/node_modules/reqeusts-helper/postinstall.js","ok",0,0.3],
    ["file","read",H+"/.aws/credentials","ok",3,0.3,{canary:true}],
    ["file","read",H+"/.env","ok",3,0.3,{canary:true}],
    ["file","read",H+"/.ssh/id_rsa","ok",3,0.3,{canary:true}],
    ["network","connect","registry.npmjs.org:443","ok",2,0.6],
    ["blocked","connect","185.220.101.44:443","blocked",3,0.8,{errno:"ENETUNREACH"}],
    ["blocked","connect","collector.exfil-demo.invalid:443","blocked",3,0.7,{errno:"EAI_AGAIN"}],
  ];
  feedRaw('<span class="ps1">chamber@sandbox:~$</span> detonate npm:reqeusts-helper@2.1.4', "k-process");
  feedRaw('<span class="ft">[plan]</span> ' + $("agentPlan").textContent, "k-plan");
  let seq = 0, t = 0;
  evs.forEach((r) => {
    t += 0.3 + Math.random() * 0.4;
    addEvent({ seq: ++seq, ts: t, kind: r[0], op: r[1], target: r[2],
               result: r[3], severity: r[4], duration: r[5], detail: r[6] || {} });
  });
  setFeedStatus("complete", "done");
  feedRaw('<span class="ft">·</span> sandbox destroyed · run recorded', "k-system");
  renderVerdict({
    label: "malicious", score: 85,
    headline: "A postinstall script read planted credentials and tried to " +
      "phone home; the sandbox blocked every outbound connection.",
    reasons: [
      "Read 3 planted canary credentials — benign installers never do this.",
      "Attempted 2 outbound connections that the sandbox blocked (contained; nothing left the machine).",
    ],
    iocs: [
      { type: "credential", value: H + "/.aws/credentials", note: "canary credential accessed" },
      { type: "credential", value: H + "/.env", note: "canary credential accessed" },
      { type: "credential", value: H + "/.ssh/id_rsa", note: "canary credential accessed" },
      { type: "ip", value: "185.220.101.44", note: "blocked outbound connection" },
      { type: "domain", value: "collector.exfil-demo.invalid", note: "blocked outbound connection" },
    ],
  });
  $("agentSummary").hidden = false;
  $("agentSummary").textContent =
    "The package's postinstall script enumerated and read three credential " +
    "files it has no reason to touch, then opened connections to a hard-coded " +
    "IP and an external collector. Both attempts failed inside the sealed " +
    "container — nothing left the machine. Treat this package as malicious.";
}

const _fx = new URLSearchParams(location.search).get("fixture");
if (_fx) { renderFixture(_fx); renderFixtureActivity(); }
else { loadHealth(); loadActivity(); }

function renderFixtureActivity() {
  renderStats({
    total: 42, malicious: 19, suspicious: 8, benign: 15, live_runs: 27,
    canary_hits: 61, egress_blocked: 88, sensitive: 73, events: 1240,
    processes: 206, avg_score: 48.5, max_score: 100, compute_seconds: 512.4,
    threats_contained: 149,
    top_iocs: [
      { type: "ip", value: "185.220.101.44", count: 7 },
      { type: "credential", value: "/home/sandbox/.aws/credentials", count: 6 },
      { type: "domain", value: "data.collect-metrics.invalid", count: 4 },
      { type: "credential", value: "/home/sandbox/.ssh/id_rsa", count: 4 },
      { type: "path", value: "/etc/passwd", count: 3 },
    ],
  });
  const now = Date.now() / 1000;
  renderHistory([
    { id: "a", created: now - 120, type: "demo", name: "apt", synthetic: 1, label: "malicious", score: 100, canary_hits: 5, egress_blocked: 5 },
    { id: "b", created: now - 640, type: "npm", name: "left-pad", synthetic: 0, label: "benign", score: 0, canary_hits: 0, egress_blocked: 0 },
    { id: "c", created: now - 1900, type: "url", name: "account-verify.phish", synthetic: 0, label: "malicious", score: 60, canary_hits: 0, egress_blocked: 0 },
    { id: "d", created: now - 5400, type: "pypi", name: "fast-json-tools", synthetic: 1, label: "suspicious", score: 33, canary_hits: 0, egress_blocked: 2 },
    { id: "e", created: now - 9000, type: "github", name: "acme/widget", synthetic: 0, label: "benign", score: 2, canary_hits: 0, egress_blocked: 0 },
  ]);
}
