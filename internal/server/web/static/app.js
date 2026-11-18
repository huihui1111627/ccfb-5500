// BGP 仿真平台前端逻辑（无框架、无构建，原生 JS）。
"use strict";

const state = {
  topo: null,
  ribNode: null,
  ribRows: [],
  ribPage: 0,
  pageSize: 50,
  selectedPrefix: null,
  snapshots: [],
  replayIdx: 0,
  replayTimer: null,
  faultTargets: [],
};

const api = {
  async get(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    return res.json();
  },
  async post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? "" : JSON.stringify(body),
    });
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    return res.json();
  },
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function setStatus(text, ok = true) {
  const el = $("#global-status");
  el.textContent = text;
  el.style.color = ok ? "var(--accent2)" : "var(--danger)";
}

// ---------- 标签页切换 ----------
$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.remove("active"));
    $$(".tab-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("#tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "topology" && state.topo) drawTopo();
    if (tab.dataset.tab === "fault" && state.topo) drawReplay();
  });
});

// ---------- 场景生成 ----------
$("#btn-generate").addEventListener("click", async () => {
  try {
    setStatus("生成场景中…");
    const scale = $("#scale").value;
    const info = await api.post("/api/scenario/generate?scale=" + scale);
    await loadTopology();
    await loadNodeSelectors();
    setStatus(`已加载: ${info.nodes} 节点 / ${info.prefixes} 外部前缀`);
    $("#btn-run").click();
  } catch (e) {
    setStatus("生成失败: " + e.message, false);
  }
});

$("#btn-run").addEventListener("click", async () => {
  try {
    setStatus("仿真运行中…");
    const r = await api.post("/api/run");
    setStatus(`已收敛，共 ${r.converged_round} 轮，消息 ${r.stats.messages} 条`);
    await Promise.all([loadRIB(), loadSnapshots(), loadFaultTargets(), refreshTrafficSilent()]);
    drawTopo();
  } catch (e) {
    setStatus("运行失败: " + e.message, false);
  }
});

async function loadTopology() {
  state.topo = await api.get("/api/topology");
}

async function loadNodeSelectors() {
  const nodes = state.topo.nodes.filter((n) => n.asn === state.topo.local_as);
  const ribSel = $("#rib-node");
  const pmSel = $("#pm-router");
  ribSel.innerHTML = "";
  pmSel.innerHTML = "";
  nodes.forEach((n) => {
    ribSel.add(new Option(`${n.name} (${n.id})`, n.id));
    if (n.role === "edge") pmSel.add(new Option(`${n.name} (${n.id})`, n.id));
  });
  state.ribNode = ribSel.value;
  ribSel.onchange = async () => { state.ribNode = ribSel.value; state.ribPage = 0; await loadRIB(); };
}

// ---------- 拓扑画布 ----------
const roleColor = {
  core: getCss("--core"), rr: getCss("--rr"), agg: getCss("--agg"),
  edge: getCss("--edge"), external: getCss("--ext"),
};
function getCss(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function nodeById(id) { return state.topo.nodes.find((n) => n.id === id); }

function drawTopo() {
  const canvas = $("#topo-canvas");
  drawGraph(canvas, state.topo, {});
}

// 通用绘图：根据节点预置坐标画链路与节点，支持故障高亮与点击。
function drawGraph(canvas, topo, opts) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);

  // 坐标归一化到画布。
  const xs = topo.nodes.map((n) => n.x), ys = topo.nodes.map((n) => n.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const pad = 50;
  const sx = (x) => pad + ((x - minX) / Math.max(1, maxX - minX)) * (rect.width - 2 * pad);
  const sy = (y) => pad + ((y - minY) / Math.max(1, maxY - minY)) * (rect.height - 2 * pad);
  const pos = {};
  topo.nodes.forEach((n) => { pos[n.id] = { x: sx(n.x), y: sy(n.y) }; });

  // 链路。
  topo.links.forEach((l) => {
    const a = pos[l.a], b = pos[l.b];
    if (!a || !b) return;
    const isExt = nodeById(l.a).asn !== nodeById(l.b).asn;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = l.up ? (isExt ? getCss("--ext") : getCss("--line")) : getCss("--danger");
    ctx.lineWidth = l.up ? (isExt ? 2 : 1.4) : 2.4;
    if (!l.up) ctx.setLineDash([6, 5]);
    ctx.stroke();
    ctx.setLineDash([]);
  });

  // 节点。
  topo.nodes.forEach((n) => {
    const p = pos[n.id];
    const r = n.role === "external" ? 9 : 11;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = n.up ? roleColor[n.role] || "#888" : getCss("--danger");
    ctx.fill();
    ctx.strokeStyle = "#0f1622";
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = getCss("--text");
    ctx.font = "11px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(n.name || n.id, p.x, p.y + r + 13);
  });

  // 点击检测。
  canvas.onclick = (ev) => {
    const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
    let hitNode = null;
    for (const n of topo.nodes) {
      const p = pos[n.id];
      if (Math.hypot(mx - p.x, my - p.y) < 14) { hitNode = n; break; }
    }
    if (hitNode) {
      const links = topo.links.filter((l) => l.a === hitNode.id || l.b === hitNode.id);
      $("#topo-info").textContent =
        `节点 ${hitNode.name} (${hitNode.id})\n角色: ${hitNode.role}  ASN: ${hitNode.asn}  ` +
        `RouterID: ${hitNode.router_id}  状态: ${hitNode.up ? "在线" : "故障"}\n` +
        `邻居链路: ${links.map((l) => l.id + (l.up ? "" : "(断)")).join(", ")}` +
        (hitNode.rr_client_of && hitNode.rr_client_of.length ? `\nRR 客户端归属: ${hitNode.rr_client_of.join(", ")}` : "");
      if (opts.onNode) opts.onNode(hitNode);
    }
  };
}

// ---------- 路由表 ----------
async function loadRIB() {
  if (!state.ribNode) return;
  const data = await api.get(`/api/rib?node=${encodeURIComponent(state.ribNode)}`);
  state.ribRows = data.routes || [];
  renderRIB();
}

function renderRIB() {
  const filter = $("#rib-prefix-filter").value.trim();
  const rows = filter ? state.ribRows.filter((r) => r.prefix.includes(filter)) : state.ribRows;
  const totalPages = Math.max(1, Math.ceil(rows.length / state.pageSize));
  state.ribPage = Math.min(state.ribPage, totalPages - 1);
  const slice = rows.slice(state.ribPage * state.pageSize, (state.ribPage + 1) * state.pageSize);
  const tbody = $("#rib-table tbody");
  tbody.innerHTML = "";
  slice.forEach((r) => {
    const tr = document.createElement("tr");
    if (r.prefix === state.selectedPrefix) tr.classList.add("selected");
    tr.innerHTML = `<td>${r.prefix}</td><td>${r.primary_from}</td><td>${r.primary_next_hop}</td>
      <td>${r.igp_cost}</td><td>${r.local_pref}</td><td>${(r.as_path || []).join(" ")}</td>
      <td>${r.origin}</td><td>${r.med}</td><td>${rpkiBadge(r.rpki)}</td>`;
    tr.onclick = () => showDecision(r.prefix, tr);
    tbody.appendChild(tr);
  });
  $("#rib-page-info").textContent = `第 ${state.ribPage + 1}/${totalPages} 页，共 ${rows.length} 条`;
}

function rpkiBadge(state) {
  const cls = state === "valid" ? "valid" : state === "invalid" ? "invalid" : "notfound";
  return `<span class="badge ${cls}">${state}</span>`;
}

$("#rib-apply").onclick = () => { state.ribPage = 0; renderRIB(); };
$("#rib-prev").onclick = () => { if (state.ribPage > 0) { state.ribPage--; renderRIB(); } };
$("#rib-next").onclick = () => { state.ribPage++; renderRIB(); };

// ---------- 选路决策逐级解释 ----------
async function showDecision(prefix, tr) {
  state.selectedPrefix = prefix;
  $$("#rib-table tbody tr").forEach((x) => x.classList.remove("selected"));
  if (tr) tr.classList.add("selected");
  const detail = await api.get(
    `/api/prefix?node=${encodeURIComponent(state.ribNode)}&prefix=${encodeURIComponent(prefix)}`);
  const panel = $("#decision-panel");
  let html = `<h3>${prefix} 的选路解释</h3>
    <p>胜出来源: <b>${detail.winner || "（无可用路由）"}</b></p>`;
  if (detail.ecmp && detail.ecmp.length > 1)
    html += `<p>等价路径(ECMP): ${detail.ecmp.join(", ")}</p>`;
  html += `<h3>候选路由 (${detail.candidates.length})</h3>`;
  detail.candidates.forEach((c) => {
    html += `<div class="stage"><div class="rule">来源 ${c.source} [${c.peer_type}]</div>
      <div>LocalPref=${c.local_pref} · MED=${c.med} · 起源=${c.origin} · IGP开销=${c.igp_cost}</div>
      <div class="keep">AS 路径: ${(c.as_path || []).join(" ")} 下一跳: ${c.next_hop} ${rpkiBadge(c.rpki)}</div>
      ${c.suppressed ? `<div class="elim">⚠ 翻动抑制中（惩罚值 ${c.penalty.toFixed(0)}）</div>` : ""}
      </div>`;
  });
  html += `<h3>逐级比较过程</h3>`;
  (detail.trace.stages || []).forEach((st) => {
    html += `<div class="stage"><div class="rule">${st.rule}</div>
      <div class="keep">保留: ${(st.surviving || []).map((s) => s.split("from=")[1]?.split("|")[0] || s).join(", ") || "—"}</div>`;
    const elims = Object.entries(st.eliminated || {});
    elims.forEach(([k, why]) => {
      html += `<div class="elim">淘汰 ${k.split("from=")[1]?.split("|")[0] || k}: ${why}</div>`;
    });
    html += `</div>`;
  });
  panel.innerHTML = html;
}

// ---------- 策略编辑 ----------
$("#pm-apply").addEventListener("click", async () => {
  try {
    const name = $("#pm-name").value.trim() || "CUSTOM";
    const seq = parseInt($("#pm-seq").value, 10) || 10;
    const prefixLines = $("#pm-prefixes").value.split("\n").map((s) => s.trim()).filter(Boolean);
    const community = $("#pm-community").value.trim();
    const aspath = $("#pm-aspath").value.trim();
    const lpRaw = $("#pm-lp").value.trim();
    const prependRaw = $("#pm-prepend").value.trim();
    const addComm = $("#pm-addcomm").value.trim();
    const result = $("#pm-result").value;
    const router = $("#pm-router").value;

    const body = {
      name, seq, router, result,
      prefixes: prefixLines,
      community: community || null,
      as_path_regexp: aspath || null,
      set_local_pref: lpRaw ? parseInt(lpRaw, 10) : null,
      prepend: prependRaw ? prependRaw.split(",").map((x) => parseInt(x.trim(), 10)) : null,
      add_community: addComm || null,
    };
    setStatus("应用策略并重跑…");
    const r = await api.post("/api/policy/apply", body);
    await loadPolicies();
    await Promise.all([loadRIB(), loadSnapshots(), refreshTrafficSilent()]);
    setStatus(`策略已应用，重跑收敛于 ${r.converged_round} 轮`);
    drawTopo();
  } catch (e) {
    setStatus("策略应用失败: " + e.message, false);
  }
});

async function loadPolicies() {
  try {
    const data = await api.get("/api/policies");
    const has = (data.route_maps && data.route_maps.length) || (data.prefix_lists && data.prefix_lists.length);
    $("#policy-view").textContent = has ? JSON.stringify(
      { prefix_lists: data.prefix_lists, route_maps: data.route_maps, router_policies: data.router_policies },
      null, 2) : "（暂无自定义策略）";
  } catch (e) { /* 忽略 */ }
}

// ---------- 故障仿真与收敛回放 ----------
async function loadFaultTargets() {
  const sel = $("#fault-target");
  sel.innerHTML = "";
  state.topo.links.forEach((l) => {
    const label = `链路 ${l.id}: ${l.a} ↔ ${l.b}${l.up ? "" : "（已断）"}`;
    sel.add(new Option(label, "link:" + l.id));
  });
  state.topo.nodes.filter((n) => n.asn === state.topo.local_as).forEach((n) => {
    sel.add(new Option(`路由器 ${n.name} (${n.id})`, "node:" + n.id));
  });
}

function parseTarget() {
  const v = $("#fault-target").value || "";
  const [kind, id] = v.split(":");
  return { kind, id };
}

async function injectFault(kind, restore) {
  try {
    const { id } = parseTarget();
    const path = kind === "link"
      ? (restore ? "/api/restore/link" : "/api/fail/link")
      : (restore ? "/api/restore/router" : "/api/fail/router");
    setStatus((restore ? "恢复" : "注入故障") + "中…");
    await api.post(path, { id });
    const r = await api.post("/api/run");
    await loadTopology();
    await loadFaultTargets();
    await Promise.all([loadSnapshots(), loadRIB(), refreshTrafficSilent()]);
    state.replayIdx = state.snapshots.length - 1;
    drawTopo();
    drawReplay();
    setStatus(`收敛于 ${r.converged_round} 轮，环=${r.stats.loops_detected} 黑洞=${r.stats.blackholes}`);
  } catch (e) {
    setStatus("故障操作失败: " + e.message, false);
  }
}
$("#btn-fail-link").onclick = () => injectFault("link", false);
$("#btn-fail-router").onclick = () => injectFault("node", false);
$("#btn-restore").onclick = () => {
  const { kind } = parseTarget();
  injectFault(kind, true);
};

async function loadSnapshots() {
  const data = await api.get("/api/snapshots");
  state.snapshots = data.snapshots || [];
  state.replayIdx = Math.max(0, state.snapshots.length - 1);
}

function drawReplay() {
  const snaps = state.snapshots;
  if (!snaps.length) return;
  const idx = Math.min(state.replayIdx, snaps.length - 1);
  state.replayIdx = idx;
  const snap = snaps[idx];
  $("#replay-round").textContent = `第 ${snap.round} 轮 (t=${snap.time_sec}s)`;
  $("#replay-stats").innerHTML = statChips(snap.stats);

  // 用该轮节点/链路 up 状态覆盖拓扑后绘制。
  const view = JSON.parse(JSON.stringify(state.topo));
  const upMap = {};
  snap.routers.forEach((r) => { upMap[r.node_id] = r.up; });
  view.nodes.forEach((n) => { if (n.id in upMap) n.up = upMap[n.id]; });
  if (snap.up_links) view.links.forEach((l) => { if (l.id in snap.up_links) l.up = snap.up_links[l.id]; });
  drawGraph($("#replay-canvas"), view, {});

  // 与上一轮对比路由表变化。
  if (idx === 0) {
    $("#replay-diff").textContent = "第 1 轮：初始路由注入，无前置轮次可对比。";
    return;
  }
  const prev = snaps[idx - 1];
  const diff = diffRIB(prev, snap);
  $("#replay-diff").innerHTML = diff.length
    ? diff.map((d) => `${d.icon} ${d.node} <b>${d.prefix}</b>: ${d.change}`).join("\n")
    : "本轮路由表无变化（已收敛）。";
}

function statChips(s) {
  const items = [
    ["消息数", s.messages], ["最优路径变更", s.best_path_changes], ["收敛轮", s.converged_in_round],
    ["策略拒绝", s.policy_denied], ["RPKI丢弃", s.rpki_dropped], ["RR防环拦截", s.rr_loop_blocked],
    ["路由环", s.loops_detected], ["黑洞", s.blackholes],
  ];
  return items.map(([k, v]) => `<span>${k}: <b>${v}</b></span>`).join("");
}

function diffRIB(prev, cur) {
  const mapOf = (snap) => {
    const m = new Map();
    snap.routers.forEach((r) => r.routes.forEach((rt) => m.set(r.node_id + "|" + rt.prefix, rt.primary_from)));
    return m;
  };
  const a = mapOf(prev), b = mapOf(cur), out = [];
  for (const [k, from] of b) {
    const [node, prefix] = k.split("|");
    if (!a.has(k)) out.push({ icon: "🟢", node, prefix, change: `新增选路 → ${from}` });
    else if (a.get(k) !== from) out.push({ icon: "🟡", node, prefix, change: `切换 ${a.get(k)} → ${from}` });
  }
  for (const [k] of a) {
    if (!b.has(k)) {
      const [node, prefix] = k.split("|");
      out.push({ icon: "🔴", node, prefix, change: "路由撤回（无可用路径）" });
    }
  }
  return out.slice(0, 200);
}

$("#replay-first").onclick = () => { state.replayIdx = 0; drawReplay(); };
$("#replay-prev").onclick = () => { state.replayIdx = Math.max(0, state.replayIdx - 1); drawReplay(); };
$("#replay-next").onclick = () => {
  state.replayIdx = Math.min(state.snapshots.length - 1, state.replayIdx + 1); drawReplay();
};
$("#replay-last").onclick = () => { state.replayIdx = state.snapshots.length - 1; drawReplay(); };
$("#replay-auto").onclick = (ev) => {
  if (state.replayTimer) {
    clearInterval(state.replayTimer); state.replayTimer = null; ev.target.textContent = "自动播放"; return;
  }
  ev.target.textContent = "暂停";
  state.replayIdx = 0; drawReplay();
  state.replayTimer = setInterval(() => {
    if (state.replayIdx >= state.snapshots.length - 1) {
      clearInterval(state.replayTimer); state.replayTimer = null;
      $("#replay-auto").textContent = "自动播放"; return;
    }
    state.replayIdx++; drawReplay();
  }, 1200);
};

// ---------- 流量与利用率 ----------
async function refreshTrafficSilent() {
  try { await renderTraffic(); } catch (e) { /* 场景未就绪时忽略 */ }
}
$("#btn-traffic-refresh").onclick = () => refreshTrafficSilent();

async function renderTraffic() {
  const data = await api.get("/api/traffic");
  const loads = data.link_loads || [];
  const tbody = $("#traffic-table tbody");
  tbody.innerHTML = "";
  const bars = $("#traffic-bars");
  bars.innerHTML = "";
  loads.forEach((l) => {
    const pct = l.utilization * 100;
    const cls = pct >= 100 ? "over" : pct >= 70 ? "warn" : "ok";
    const bar = document.createElement("div");
    bar.className = "bar-row";
    bar.innerHTML = `<div class="bar-label">${l.edge_id} → ${l.upstream_id}</div>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div>
      <div class="bar-pct">${pct.toFixed(1)}%</div>`;
    bars.appendChild(bar);
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${l.edge_id}</td><td>${l.upstream_id}</td><td>${l.load_mbps.toFixed(1)}</td>
      <td>${l.capacity_mbps.toFixed(0)}</td><td><span class="badge ${pct >= 100 ? "invalid" : pct >= 70 ? "notfound" : "valid"}">${pct.toFixed(1)}%</span></td>
      <td>${l.prefixes}</td>`;
    tbody.appendChild(tr);
  });
  if (!loads.length) bars.innerHTML = `<div class="info-box">暂无流量数据。</div>`;
}
