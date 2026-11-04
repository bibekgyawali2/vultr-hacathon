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
    if (d.status === "done") endRun();
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
  let seq = 0, t = 0;
  evs.forEach((r) => {
    t += 0.3 + Math.random() * 0.4;
    addEvent({ seq: ++seq, ts: t, kind: r[0], op: r[1], target: r[2],
               result: r[3], severity: r[4], duration: r[5], detail: r[6] || {} });
  });
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
if (_fx) { renderFixture(_fx); } else { loadHealth(); }
