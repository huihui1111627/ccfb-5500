'use strict';

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const el = (tag, attrs = {}, ...children) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
};
const fmt = (v, d = 0) => v === undefined || v === null ? '—' : Number(v).toFixed(d);
const pct = v => `${(v * 100).toFixed(1)}%`;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

let toastTimer = null;
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
const state = {
  topology: null,
  state: null,
  ribRouter: null,
  ribOffset: 0,
  ribLimit: 100,
  policies: [],
  selectedPolicy: -1,
  replay: null,
  replayIdx: 0,
  replayTimer: null,
  traffic: null,
};

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
function activateTab(tab) {
  if (!tab || !$('#tab-' + tab)) tab = 'topology';
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + tab));
  if (location.hash !== '#' + tab) history.replaceState(null, '', '#' + tab);
  if (tab === 'rib' && !state.ribRouter) loadRIB();
  if (tab === 'traffic' && !state.traffic) loadTraffic();
  if (tab === 'policy' && !state.policies.length) loadPolicies();
  if (tab === 'fault' && !state.replay) loadReplay();
}

$('#tabs').addEventListener('click', e => {
  const btn = e.target.closest('button[data-tab]');
  if (!btn) return;
  activateTab(btn.dataset.tab);
});
window.addEventListener('hashchange', () => activateTab((location.hash || '#topology').slice(1)));

// ---------------------------------------------------------------------------
// Network summary
// ---------------------------------------------------------------------------
async function loadState() {
  state.state = await api('/api/state');
  const s = state.state;
  $('#netinfo').textContent =
    `${s.routers} 台路由器 · ${s.prefixes} 条前缀 · ${s.sessions} 个会话 · ` +
    `基线 ${s.baselineRounds} 轮 · RPKI 无效 ${s.rpki.invalid}`;
}

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------
const ROLE_COLOR = {
  core: '#4aa3ff',
  rr: '#a371f7',
  agg: '#3fb950',
  edge: '#8b98a8',
  border: '#d29922',
  upstream: '#c98b4a',
};
const ROLE_LABEL = {
  core: '核心 P 路由器', rr: '路由反射器', agg: '汇聚', edge: '接入（前缀起源）',
  border: '省际边界', upstream: '上游运营商',
};
const ROLE_R = { core: 9, rr: 9, agg: 7, edge: 5, border: 8, upstream: 9 };

function layoutTopology(topo) {
  // Hand-rolled deterministic layout: upstreams on the right, borders next to
  // them, RRs and core in the middle column, aggregation sites in a ring and
  // edge routers clustered under their aggregation site.
  const W = 1200, H = 720;
  const byRole = r => topo.routers.filter(x => x.role === r);
  const core = byRole('core'), rr = byRole('rr'), agg = byRole('agg');
  const edge = byRole('edge'), border = byRole('border'), up = byRole('upstream');

  // Right column: upstream carriers, spaced vertically.
  up.forEach((r, i) => {
    r.x = W - 120;
    r.y = 120 + (i * (H - 240)) / Math.max(1, up.length - 1 || 1);
  });
  // Border routers just left of the upstreams.
  border.forEach((r, i) => {
    r.x = W - 300;
    r.y = 100 + (i * (H - 200)) / Math.max(1, border.length - 1 || 1);
  });
  // RRs in a vertical line at x=560, core at x=420.
  rr.forEach((r, i) => {
    r.x = 620;
    r.y = 120 + (i * (H - 240)) / Math.max(1, rr.length - 1 || 1);
  });
  core.forEach((r, i) => {
    const a = (i / Math.max(1, core.length)) * Math.PI * 2 - Math.PI / 2;
    r.x = 420 + Math.cos(a) * 90;
    r.y = H / 2 + Math.sin(a) * 90;
  });
  // Aggregation sites in a two-column grid on the left, so the picture stays
  // readable at twelve sites and does not collapse into a hairball.
  const cols = Math.ceil(agg.length / 2);
  const colX = [110, 260];
  agg.forEach((r, i) => {
    const col = i < cols ? 0 : 1;
    const row = i < cols ? i : i - cols;
    const rows = col === 0 ? cols : agg.length - cols;
    r.x = colX[col];
    r.y = 100 + (row + 0.5) * ((H - 200) / Math.max(1, rows));
  });
  // Edge routers fanned to the left of their aggregation site.
  const edgesByTier = {};
  edge.forEach(r => {
    (edgesByTier[r.tier] = edgesByTier[r.tier] || []).push(r);
  });
  for (const [tier, list] of Object.entries(edgesByTier)) {
    const parent = agg.find(a => a.tier === tier);
    if (!parent) { list.forEach((r, i) => { r.x = 40 + i * 18; r.y = 40; }); continue; }
    list.forEach((r, i) => {
      r.x = parent.x - 72;
      r.y = parent.y + (i - (list.length - 1) / 2) * 24;
    });
  }
  return topo;
}

function renderTopology() {
  const topo = state.topology;
  if (!topo) return;
  const svg = $('#topo-svg');
  svg.innerHTML = '';
  const NS = 'http://www.w3.org/2000/svg';
  const mk = (tag, attrs = {}) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  };
  const nodeById = new Map(topo.routers.map(r => [r.id, r]));

  const overLinks = new Set();
  if (state.traffic) {
    state.traffic.links.forEach(l => { if (l.up && l.utilisation > 1) overLinks.add(`${l.a}|${l.b}`); });
  }

  // Links first so nodes draw on top.
  const gLinks = mk('g');
  for (const l of topo.links) {
    const a = nodeById.get(l.a), b = nodeById.get(l.b);
    if (!a || !b) continue;
    let cls = 'link';
    if (l.ebgp) cls += ' ebgp';
    if (l.kind === 'upstream' || a.role === 'upstream' || b.role === 'upstream') cls += ' upstream';
    if (l.down) cls += ' down';
    if (overLinks.has(`${l.a}|${l.b}`) || overLinks.has(`${l.b}|${l.a}`)) cls += ' overloaded';
    const line = mk('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: cls });
    // A route reflector peers with every client; drawing all of those lines
    // at full strength turns the topology into a hairball.  Fade the iBGP
    // fan-out while keeping physical and eBGP links prominent.
    if (a.rr || b.rr) { if (!l.ebgp && l.kind !== 'upstream') line.setAttribute('opacity', '0.28'); }
    line.appendChild(mk('title')).textContent = `${l.actorA} — ${l.actorB}  cost=${l.cost}  ${l.capacityGbps}Gbps`;
    gLinks.appendChild(line);
  }
  svg.appendChild(gLinks);

  const gNodes = mk('g');
  for (const r of topo.routers) {
    const g = mk('g', { class: 'node' + (r.down ? ' down' : '') });
    const circle = mk('circle', {
      cx: r.x, cy: r.y, r: ROLE_R[r.role] || 6,
      fill: ROLE_COLOR[r.role] || '#888',
      stroke: r.rr ? '#a371f7' : '#11161d',
      'stroke-width': r.rr ? 2 : 1,
    });
    g.appendChild(circle);
    const lx = r.role === 'edge' ? r.x + (ROLE_R[r.role] || 5) + 3 : r.x + (ROLE_R[r.role] || 6) + 4;
    const label = mk('text', { x: lx, y: r.y + 3 });
    label.textContent = r.name;
    g.appendChild(label);
    g.addEventListener('click', () => showNode(r));
    g.dataset.nodeId = r.id;
    gNodes.appendChild(g);
  }
  svg.appendChild(gNodes);

  // Legend
  const lg = $('#topo-legend');
  lg.innerHTML = '';
  const seen = new Set();
  for (const r of topo.routers) {
    if (seen.has(r.role)) continue;
    seen.add(r.role);
    lg.appendChild(el('span', { html: `<i style="background:${ROLE_COLOR[r.role]}"></i>${ROLE_LABEL[r.role] || r.role}` }));
  }
  lg.appendChild(el('span', { html: '<i style="background:#2f3945"></i>iBGP / 物理链路' }));
  lg.appendChild(el('span', { html: '<i style="background:#3d7a5c"></i>eBGP 链路' }));
  lg.appendChild(el('span', { html: '<i style="background:#f85149"></i>故障 / 过载' }));
}

async function showNode(r) {
  $$('.node.sel').forEach(n => n.classList.remove('sel'));
  const g = $(`.node[data-node-id="${r.id}"]`);
  if (g) g.classList.add('sel');
  const box = $('#node-detail');
  box.classList.remove('empty');
  box.innerHTML = '';
  box.appendChild(el('div', { class: 'pname', style: 'font-weight:600;font-size:14px;margin-bottom:6px' }, r.name));
  const rows = [
    ['角色', ROLE_LABEL[r.role] || r.role],
    ['AS', String(r.asn)],
    ['区域', r.tier || '—'],
    ['路由反射器', r.rr ? '是' : '否'],
    ['BGP 会话', String(r.peers)],
    ['本地起源前缀', String(r.prefixes)],
    ['状态', r.down ? '宕机' : '正常'],
  ];
  const tbl = el('table', { class: 'grid' });
  rows.forEach(([k, v]) => {
    tbl.appendChild(el('tr', {}, el('td', { class: 'nomono', style: 'color:var(--muted);width:100px' }, k), el('td', {}, v)));
  });
  box.appendChild(tbl);
  // Link the node detail to the RIB page.
  const btn = el('button', { class: 'btn', style: 'margin-top:12px' }, '查看该路由器路由表');
  btn.addEventListener('click', () => {
    state.ribRouter = r.name;
    state.ribOffset = 0;
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === 'rib'));
    $$('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-rib'));
    loadRIB();
  });
  box.appendChild(btn);
}

async function loadTopology() {
  state.topology = layoutTopology(await api('/api/topology'));
  renderTopology();
  buildRouterList();
  buildFaultLists();
}

// ---------------------------------------------------------------------------
// RIB
// ---------------------------------------------------------------------------
function buildRouterList() {
  const list = $('#router-list');
  if (!list || !state.topology) return;
  list.innerHTML = '';
  for (const r of state.topology.routers) {
    const item = el('div', { class: 'item' }, el('span', {}, r.name), el('span', { class: 'badge' }, String(r.prefixes)));
    item.dataset.name = r.name;
    item.addEventListener('click', () => {
      state.ribRouter = r.name;
      state.ribOffset = 0;
      loadRIB();
    });
    list.appendChild(item);
  }
  $('#rib-search').oninput = e => {
    const q = e.target.value.trim().toLowerCase();
    $$('#router-list .item').forEach(it => {
      it.style.display = it.dataset.name.toLowerCase().includes(q) ? '' : 'none';
    });
  };
}

async function loadRIB() {
  if (!state.ribRouter) {
    // Default to a core router so the first view is interesting.
    const core = state.topology.routers.find(r => r.role === 'core');
    state.ribRouter = core ? core.name : state.topology.routers[0].name;
  }
  $$('#router-list .item').forEach(it => it.classList.toggle('active', it.dataset.name === state.ribRouter));
  const prefix = $('#rib-prefix').value.trim();
  const q = new URLSearchParams({
    router: state.ribRouter,
    offset: state.ribOffset,
    limit: state.ribLimit,
  });
  if (prefix) q.set('prefix', prefix);
  const data = await api('/api/rib?' + q);
  $('#rib-title').textContent = `路由表 · ${data.router}`;
  const tbody = $('#rib-table tbody');
  tbody.innerHTML = '';
  for (const e of data.entries) {
    const b = e.best || {};
    const rpki = e.rpki === 'invalid' ? el('span', { class: 'tag bad' }, 'invalid')
      : e.rpki === 'valid' ? el('span', { class: 'tag ok' }, 'valid')
      : el('span', { class: 'tag dim' }, 'notfound');
    const ecmpTag = (e.ecmp && e.ecmp.length > 1)
      ? el('span', { class: 'tag ecmp' }, String(e.ecmp.length))
      : el('span', { class: 'tag dim' }, '1');
    const btn = el('button', { class: 'btn small ghost' }, '为什么？');
    btn.addEventListener('click', ev => { ev.stopPropagation(); showDecision(e.prefix); });
    const tr = el('tr', {},
      el('td', {}, e.prefix),
      el('td', {}, b.nextHop || '—'),
      el('td', {}, b.egress || '—'),
      el('td', {}, b.asPath || '(local)'),
      el('td', {}, String(b.localPref ?? '')),
      el('td', {}, String(b.med ?? '')),
      el('td', {}, b.origin || ''),
      el('td', {}, rpki),
      el('td', {}, ecmpTag),
      el('td', {}, btn),
    );
    if (e.blackhole) tr.style.background = 'rgba(248,81,73,.08)';
    tbody.appendChild(tr);
  }
  const page = Math.floor(data.offset / data.limit) + 1;
  const pages = Math.max(1, Math.ceil(data.total / data.limit));
  $('#rib-pageinfo').textContent = `第 ${page}/${pages} 页 · 共 ${data.total} 条`;
  $('#rib-prev').disabled = state.ribOffset === 0;
  $('#rib-next').disabled = state.ribOffset + state.ribLimit >= data.total;
}

$('#rib-prefix').addEventListener('input', () => { state.ribOffset = 0; loadRIB(); });
$('#rib-prev').addEventListener('click', () => {
  state.ribOffset = Math.max(0, state.ribOffset - state.ribLimit);
  loadRIB();
});
$('#rib-next').addEventListener('click', () => {
  state.ribOffset += state.ribLimit;
  loadRIB();
});

const STEP_NAMES = [
  '本地起源（weight）', '最高本地优先级', '最短 AS_PATH', '最低 ORIGIN 类型',
  '最低 MED', 'eBGP 优于 iBGP', '最低 IGP 开销', '最低路由器 ID',
  '最短 CLUSTER_LIST', '最低对等体 ID',
];

async function showDecision(prefix) {
  const q = new URLSearchParams({ router: state.ribRouter, prefix });
  const data = await api('/api/decision?' + q);
  const box = $('#rib-decision');
  box.classList.remove('hidden');
  box.innerHTML = '';
  if (!data.decision) {
    box.appendChild(el('div', { class: 'muted' }, `无法选择路径（该路由器没有到达 ${prefix} 的路由）`));
    return;
  }
  const d = data.decision;
  box.appendChild(el('h3', {}, `为什么选择这条路径 · ${data.router} → ${data.prefix}`));

  // Steps, in protocol order.
  const steps = el('div', { class: 'steps' });
  for (let i = 0; i < STEP_NAMES.length; i++) {
    const s = d.steps.find(x => x.index === i);
    const ran = !!s;
    const div = el('div', { class: 'step ' + (ran ? 'ran' : 'skipped') },
      el('span', { class: 'num' }, String(i + 1)),
      el('span', { class: 'sname' }, STEP_NAMES[i]),
      el('span', { class: 'detail' }, ran ? s.detail : '上一步已唯一确定，跳过'),
      el('span', { class: 'count' }, ran ? `${s.before} → ${s.after}` : ''),
    );
    steps.appendChild(div);
  }
  box.appendChild(steps);

  // Candidates.
  const cands = el('div');
  for (const c of d.candidates) {
    const cls = 'cand' + (c.winner ? ' winner' : c.ecmp ? ' ecmp' : '');
    const tags = [];
    if (c.winner) tags.push(el('span', { class: 'tag ok' }, '最优'));
    else if (c.ecmp) tags.push(el('span', { class: 'tag ecmp' }, 'ECMP 成员'));
    if (c.rpki === 'invalid') tags.push(el('span', { class: 'tag bad' }, 'RPKI invalid'));
    else if (c.rpki === 'valid') tags.push(el('span', { class: 'tag ok' }, 'RPKI valid'));
    if (c.local) tags.push(el('span', { class: 'tag dim' }, '本地起源'));
    if (c.fromEBGP) tags.push(el('span', { class: 'tag dim' }, 'eBGP'));
    const metaBits = [
      `LP ${c.localPref}`, `AS_PATH 长度 ${c.asLen}`, `ORIGIN ${c.origin}`,
      `MED ${c.med}`, c.igpCost >= 0 ? `IGP 开销 ${c.igpCost}` : 'IGP 不可达',
      `对等体 ${c.peer}`, `下一跳 ${c.nextHop}`, `出口 ${c.egress}`,
    ];
    if (c.clusterList && c.clusterList.length) metaBits.push(`CLUSTER_LIST [${c.clusterList.join(', ')}]`);
    if (c.communities && c.communities.length) metaBits.push(`团体 ${c.communities.join(' ')}`);
    const card = el('div', { class: cls },
      el('div', {}, el('span', { class: 'path' }, c.asPath || '(本地)'), ' ', ...tags),
      el('div', { class: 'meta' }, metaBits.join(' · ')),
      el('div', { class: 'reason' }, c.reason || ''),
    );
    cands.appendChild(card);
  }
  box.appendChild(cands);
}

// ---------------------------------------------------------------------------
// Policy editor
// ---------------------------------------------------------------------------
async function loadPolicies() {
  const data = await api('/api/policies');
  state.policies = data.policies.map(p => p.policy);
  renderPolicyList();
}

function renderPolicyList() {
  const list = $('#policy-list');
  list.innerHTML = '';
  state.policies.forEach((p, i) => {
    const item = el('div', { class: 'item' + (i === state.selectedPolicy ? ' active' : '') },
      el('div', { class: 'pname' }, p.name || `策略 ${i + 1}`),
      el('div', { class: 'pdesc' }, describePolicy(p)),
    );
    item.addEventListener('click', () => { state.selectedPolicy = i; renderPolicyList(); renderEditor(); });
    list.appendChild(item);
  });
}

function describePolicy(p) {
  const parts = [];
  if (p.router) parts.push(`路由器 ${p.router}`);
  if (p.neighbor) parts.push(`邻居 ${p.neighbor}`);
  parts.push(p.direction === 'export' ? '出方向' : p.direction === 'import' ? '入方向' : '双向');
  if (p.match?.communities?.length) parts.push(`团体 ${p.match.communities.join(',')}`);
  if (p.match?.asPathRegex) parts.push(`AS_PATH ~${p.match.asPathRegex}`);
  if (p.match?.prefixList?.length) parts.push(`${p.match.prefixList.length} 条前缀列表`);
  const a = p.actions || {};
  if (a.action === 'deny') parts.push('拒绝');
  if (a.setLocalPref != null) parts.push(`LP=${a.setLocalPref}`);
  if (a.prependCount) parts.push(`前置 AS×${a.prependCount}`);
  if (a.addCommunities?.length) parts.push(`打标 ${a.addCommunities.join(',')}`);
  return parts.join(' · ');
}

function renderEditor() {
  const box = $('#policy-editor');
  const i = state.selectedPolicy;
  if (i < 0 || !state.policies[i]) {
    box.className = 'empty';
    box.textContent = '从左侧选择一条策略，或新建一条';
    return;
  }
  box.className = '';
  const p = state.policies[i];
  box.innerHTML = '';
  box.appendChild(el('h2', { style: 'font-size:14px;margin:0 0 14px' }, p.name || `策略 ${i + 1}`));

  const grid = el('div', { class: 'editor-grid' });
  const mkField = (label, input, hint) => {
    const f = el('div', { class: 'field' }, el('label', {}, label), input);
    if (hint) f.appendChild(el('div', { class: 'hint', html: hint }));
    return f;
  };

  const nameIn = el('input', { class: 'input', value: p.name || '' });
  nameIn.oninput = () => { p.name = nameIn.value; renderPolicyList(); };
  grid.appendChild(mkField('策略名称', nameIn));

  const routerIn = el('input', { class: 'input', value: p.router || '', placeholder: '留空表示全部路由器' });
  routerIn.oninput = () => { p.router = routerIn.value || undefined; renderPolicyList(); };
  grid.appendChild(mkField('绑定路由器', routerIn, '留空则对所有路由器生效，例如 <code>border-1-1</code>'));

  const neighIn = el('input', { class: 'input', value: p.neighbor || '', placeholder: '留空表示所有邻居' });
  neighIn.oninput = () => { p.neighbor = neighIn.value || undefined; };
  grid.appendChild(mkField('绑定邻居', neighIn));

  const dirSel = el('select', { class: 'input' });
  for (const [v, label] of [['import', '入方向 import'], ['export', '出方向 export'], ['both', '双向 both']]) {
    const o = el('option', { value: v }, label);
    if ((p.direction || 'both') === v) o.selected = true;
    dirSel.appendChild(o);
  }
  dirSel.onchange = () => { p.direction = dirSel.value; renderPolicyList(); };
  grid.appendChild(mkField('方向', dirSel));

  // --- match ---
  p.match = p.match || {};
  p.actions = p.actions || {};

  const commIn = el('input', {
    class: 'input',
    value: (p.match.communities || []).join(', '),
    placeholder: '如 65535:65001, 64500:100',
  });
  commIn.oninput = () => {
    p.match.communities = commIn.value.split(',').map(s => s.trim()).filter(Boolean);
    renderPolicyList();
  };
  grid.appendChild(mkField('匹配团体属性', commIn, '格式 <code>ASN:value</code>，多个用逗号分隔'));

  const commMode = el('select', { class: 'input' });
  for (const v of ['any', 'all']) {
    const o = el('option', { value: v }, v === 'any' ? '匹配任意一个（any）' : '全部匹配（all）');
    if ((p.match.communityMatch || 'any') === v) o.selected = true;
    commMode.appendChild(o);
  }
  commMode.onchange = () => { p.match.communityMatch = commMode.value; };
  grid.appendChild(mkField('团体匹配方式', commMode));

  const reIn = el('input', { class: 'input', value: p.match.asPathRegex || '', placeholder: '如 _64500_ 或 ^65001' });
  reIn.oninput = () => { p.match.asPathRegex = reIn.value || undefined; renderPolicyList(); };
  grid.appendChild(mkField('AS_PATH 正则', reIn, '下划线 <code>_</code> 表示 AS 边界，例如 <code>_64500_</code> 匹配路径中的 AS64500'));

  const rpkiSel = el('select', { class: 'input', multiple: 'multiple', style: 'height:78px' });
  for (const v of ['valid', 'invalid', 'notfound']) {
    const o = el('option', { value: v }, v);
    if ((p.match.rpkiStates || []).includes(v)) o.selected = true;
    rpkiSel.appendChild(o);
  }
  rpkiSel.onchange = () => {
    p.match.rpkiStates = $$('option', rpkiSel).filter(o => o.selected).map(o => o.value);
    if (!p.match.rpkiStates.length) delete p.match.rpkiStates;
    renderPolicyList();
  };
  grid.appendChild(mkField('匹配 RPKI 状态', rpkiSel, '按住 ⌘/Ctrl 多选；不选表示不限制'));

  // Prefix list editor.
  const plWrap = el('div', { class: 'prefix-rows' });
  const pl = p.match.prefixList = p.match.prefixList || [];
  const rerenderPL = () => {
    plWrap.innerHTML = '';
    pl.forEach((entry, k) => {
      const pIn = el('input', { class: 'input', value: entry.prefix });
      pIn.oninput = () => { entry.prefix = pIn.value; renderPolicyList(); };
      const geIn = el('input', { class: 'input narrow', type: 'number', value: entry.ge ?? '', placeholder: 'ge' });
      geIn.oninput = () => { entry.ge = geIn.value ? Number(geIn.value) : undefined; };
      const leIn = el('input', { class: 'input narrow', type: 'number', value: entry.le ?? '', placeholder: 'le' });
      leIn.oninput = () => { entry.le = leIn.value ? Number(leIn.value) : undefined; };
      const actSel = el('select', { class: 'input narrow', style: 'width:78px' });
      for (const v of ['permit', 'deny']) {
        const o = el('option', { value: v }, v);
        if ((entry.action || 'permit') === v) o.selected = true;
        actSel.appendChild(o);
      }
      actSel.onchange = () => { entry.action = actSel.value; renderPolicyList(); };
      const del = el('button', { class: 'btn small ghost' }, '✕');
      del.onclick = () => { pl.splice(k, 1); rerenderPL(); renderPolicyList(); };
      plWrap.appendChild(el('div', { class: 'prefix-row' }, pIn, geIn, leIn, actSel, del));
    });
    const add = el('button', { class: 'btn small' }, '+ 添加前缀');
    add.onclick = () => { pl.push({ prefix: '0.0.0.0/0', ge: 0, le: 32, action: 'permit' }); rerenderPL(); };
    plWrap.appendChild(add);
  };
  rerenderPL();
  const plField = el('div', { class: 'field' }, el('label', {}, '前缀列表'),
    plWrap, el('div', { class: 'hint', html: '第一条匹配的条目决定结果；<code>ge/le</code> 限定前缀长度范围' }));
  plField.style.gridColumn = '1 / -1';
  grid.appendChild(plField);

  // --- actions ---
  const actSel = el('select', { class: 'input' });
  for (const [v, label] of [['permit', '放行 permit'], ['deny', '丢弃 deny']]) {
    const o = el('option', { value: v }, label);
    if ((p.actions.action || 'permit') === v) o.selected = true;
    actSel.appendChild(o);
  }
  actSel.onchange = () => { p.actions.action = actSel.value; renderPolicyList(); };
  grid.appendChild(mkField('动作', actSel));

  const lpIn = el('input', { class: 'input', type: 'number', value: p.actions.setLocalPref ?? '', placeholder: '如 200' });
  lpIn.oninput = () => {
    if (lpIn.value === '') delete p.actions.setLocalPref;
    else p.actions.setLocalPref = Number(lpIn.value);
    renderPolicyList();
  };
  grid.appendChild(mkField('设置本地优先级', lpIn, '数值越大越优先；未设置则沿用路由自身属性'));

  const prepIn = el('input', { class: 'input', type: 'number', value: p.actions.prependCount ?? '', placeholder: '如 3' });
  prepIn.oninput = () => {
    if (prepIn.value === '') delete p.actions.prependCount;
    else p.actions.prependCount = Number(prepIn.value);
    renderPolicyList();
  };
  grid.appendChild(mkField('前置 AS_PATH 次数', prepIn, '每前置一次 AS_PATH 长度 +1，用于降低被选中的机会'));

  const prepASIn = el('input', { class: 'input', type: 'number', value: p.actions.prependAsn ?? '', placeholder: '留空使用本机 AS' });
  prepASIn.oninput = () => {
    if (prepASIn.value === '') delete p.actions.prependAsn;
    else p.actions.prependAsn = Number(prepASIn.value);
  };
  grid.appendChild(mkField('前置使用的 AS 号', prepASIn));

  const addCommIn = el('input', {
    class: 'input',
    value: (p.actions.addCommunities || []).join(', '),
    placeholder: '如 64500:200',
  });
  addCommIn.oninput = () => {
    p.actions.addCommunities = addCommIn.value.split(',').map(s => s.trim()).filter(Boolean);
    renderPolicyList();
  };
  grid.appendChild(mkField('打上团体标签', addCommIn, '导出到其他 AS 时团体属性默认会传递，可用于下游策略匹配'));

  box.appendChild(grid);

  const del = el('button', { class: 'btn', style: 'color:var(--bad);border-color:var(--bad);margin-top:14px' }, '删除该策略');
  del.onclick = () => {
    state.policies.splice(i, 1);
    state.selectedPolicy = -1;
    renderPolicyList();
    renderEditor();
  };
  box.appendChild(del);
}

$('#policy-new').addEventListener('click', () => {
  state.policies.push({
    name: `policy-${state.policies.length + 1}`,
    direction: 'import',
    match: {},
    actions: {},
  });
  state.selectedPolicy = state.policies.length - 1;
  renderPolicyList();
  renderEditor();
});

$('#policy-apply').addEventListener('click', async () => {
  const res = $('#policy-result');
  res.textContent = '正在应用并重新收敛…';
  try {
    const data = await api('/api/policies/apply', {
      method: 'POST',
      body: JSON.stringify({ policies: state.policies }),
    });
    res.textContent = `已应用 ${data.policies} 条策略，${data.rounds} 轮收敛，${data.updates} 条更新（${data.elapsed}）`;
    toast('策略已应用，路由已重新收敛', 'ok');
    await refreshAll();
  } catch (e) {
    res.textContent = '应用失败：' + e.message;
    toast(e.message, 'bad');
  }
});

// ---------------------------------------------------------------------------
// Faults and replay
// ---------------------------------------------------------------------------
function buildFaultLists() {
  const rt = $('#fault-routers');
  rt.innerHTML = '';
  const topo = state.topology;
  const interesting = topo.routers.filter(r => r.role !== 'edge' && r.role !== 'upstream');
  for (const r of interesting) {
    const cb = el('input', { type: 'checkbox', value: String(r.id) });
    const sw = el('span', { class: 'swatch', style: `background:${ROLE_COLOR[r.role]}` });
    rt.appendChild(el('label', {}, cb, sw, r.name));
  }
  const lk = $('#fault-links');
  lk.innerHTML = '';
  for (const l of topo.links) {
    if (l.kind === 'access') continue;
    const cb = el('input', { type: 'checkbox', value: String(l.id) });
    lk.appendChild(el('label', {}, cb, `${l.actorA} — ${l.actorB}`));
  }
}

$('#fault-run').addEventListener('click', async () => {
  const routers = $$('#fault-routers input:checked').map(i => Number(i.value));
  const links = $$('#fault-links input:checked').map(i => Number(i.value));
  if (!routers.length && !links.length) {
    toast('请至少选择一台路由器或一条链路', 'bad');
    return;
  }
  const res = $('#fault-result');
  res.textContent = '正在仿真收敛…';
  try {
    const data = await api('/api/faults', {
      method: 'POST',
      body: JSON.stringify({ routerDown: routers, linkDown: links }),
    });
    res.textContent = `已断开 ${routers.length} 台路由器、${links.length} 条链路；` +
      `${data.rounds} 轮收敛，${data.updates} 条更新，共 ${data.changes} 条变更（${data.elapsed}）`;
    toast(`收敛完成：${data.rounds} 轮`, 'ok');
    await loadReplay();
    await refreshTopologyOnly();
  } catch (e) {
    res.textContent = '仿真失败：' + e.message;
    toast(e.message, 'bad');
  }
});

$('#fault-reset').addEventListener('click', async () => {
  $$('#fault-routers input, #fault-links input').forEach(i => { i.checked = false; });
  const data = await api('/api/faults', { method: 'POST', body: JSON.stringify({ routerDown: [], linkDown: [] }) });
  $('#fault-result').textContent = '已清除故障，网络回到基线';
  state.replay = null;
  $('#replay-range').max = 0;
  $('#replay-range').value = 0;
  $('#replay-table tbody').innerHTML = '';
  $('#replay-stats').innerHTML = '';
  await refreshTopologyOnly();
});

async function loadReplay() {
  const data = await api('/api/replay');
  state.replay = data;
  const max = data.rounds.length ? data.rounds[data.rounds.length - 1].round : 0;
  const range = $('#replay-range');
  range.max = max;
  range.value = 1;
  state.replayIdx = 0;
  renderReplay();
}

function renderReplay() {
  if (!state.replay) return;
  const rounds = state.replay.rounds;
  const idx = Math.min(state.replayIdx, Math.max(0, rounds.length - 1));
  const cur = rounds[idx];
  const label = $('#replay-round-label');
  const stats = $('#replay-stats');
  const tbody = $('#replay-table tbody');

  if (!cur) {
    label.textContent = '没有路由变更';
    stats.innerHTML = '';
    tbody.innerHTML = '';
    return;
  }
  label.textContent = `第 ${cur.round} 轮 / 共 ${rounds.length} 轮`;

  let announce = 0, withdraw = 0, seen = 0;
  for (let i = 0; i <= idx; i++) {
    announce += rounds[i].counts.announce || 0;
    withdraw += rounds[i].counts.withdraw || 0;
    seen += rounds[i].changes.length;
  }
  stats.innerHTML = '';
  const mkStat = (v, l, cls = '') => el('div', { class: 'stat ' + cls }, el('div', { class: 'v' }, String(v)), el('div', { class: 'l' }, l));
  stats.appendChild(mkStat(cur.round, '当前轮次'));
  stats.appendChild(mkStat(cur.changes.length, '本轮变更'));
  stats.appendChild(mkStat(announce, '累计通告', 'ok'));
  stats.appendChild(mkStat(withdraw, '累计撤销', 'warn'));
  stats.appendChild(mkStat(rounds.length, '总轮数'));

  tbody.innerHTML = '';
  for (const c of cur.changes) {
    const evt = c.withdrawn
      ? el('span', { class: 'tag bad' }, '撤销')
      : el('span', { class: 'tag ok' }, '通告');
    const tr = el('tr', {},
      el('td', {}, c.router),
      el('td', {}, c.prefix),
      el('td', {}, evt),
      el('td', {}, c.asPath || '—'),
      el('td', {}, String(c.localPref ?? '')),
      el('td', {}, c.nextHop || '—'),
    );
    if (c.blackhole) tr.style.background = 'rgba(248,81,73,.08)';
    tbody.appendChild(tr);
  }
}

$('#replay-range').addEventListener('input', e => {
  state.replayIdx = Number(e.target.value) - 1;
  renderReplay();
});
$('#replay-first').addEventListener('click', () => { state.replayIdx = 0; $('#replay-range').value = 1; renderReplay(); });
$('#replay-play').addEventListener('click', () => {
  if (state.replayTimer) {
    clearInterval(state.replayTimer);
    state.replayTimer = null;
    $('#replay-play').textContent = '▶ 播放';
    return;
  }
  $('#replay-play').textContent = '⏸ 暂停';
  state.replayTimer = setInterval(() => {
    if (!state.replay || state.replayIdx + 1 >= state.replay.rounds.length) {
      clearInterval(state.replayTimer);
      state.replayTimer = null;
      $('#replay-play').textContent = '▶ 播放';
      return;
    }
    state.replayIdx++;
    $('#replay-range').value = state.replayIdx + 1;
    renderReplay();
  }, 900);
});

// ---------------------------------------------------------------------------
// Traffic
// ---------------------------------------------------------------------------
async function loadTraffic() {
  const flows = Number($('#traffic-flows').value) || 512;
  const data = await api('/api/traffic?flows=' + flows);
  state.traffic = data;
  const box = $('#upstream-bars');
  box.innerHTML = '';
  if (!data.upstreams.length) {
    box.appendChild(el('div', { class: 'muted' }, '没有上游链路'));
  }
  for (const u of data.upstreams) {
    const cls = u.utilisation > 1 ? 'bad' : u.utilisation > 0.8 ? 'warn' : 'ok';
    const track = el('div', { class: 'bar-track' });
    const fill = el('div', { class: 'bar-fill ' + cls, style: `width:${Math.min(100, u.utilisation * 100)}%` });
    track.appendChild(fill);
    track.appendChild(el('div', { class: 'bar-mark', style: `left:${100}%`, title: '100% 容量' }));
    box.appendChild(el('div', { class: 'bar-row' },
      el('span', {}, u.link),
      track,
      el('span', { class: 'bar-label' }, `${fmt(u.loadGbps, 2)} / ${fmt(u.capacityGbps, 0)} G · ${pct(u.utilisation)}`),
    ));
  }
  const summary = el('div', { class: 'muted', style: 'margin-top:12px' },
    `总流量 ${fmt(data.totalGbps, 1)} Gbps · 已选路 ${fmt(data.routedGbps, 1)} Gbps · ` +
    `未选路 ${fmt(data.unroutedGbps, 2)} Gbps · 最高链路利用率 ${pct(data.maxUtil)}` +
    (data.overloaded.length ? ` · ${data.overloaded.length} 条链路超过 100%` : ''));
  box.appendChild(summary);

  const tbody = $('#traffic-table tbody');
  tbody.innerHTML = '';
  const links = [...data.links].sort((a, b) => b.utilisation - a.utilisation);
  for (const l of links) {
    const cls = !l.up ? 'dim' : l.utilisation > 1 ? 'bad' : l.utilisation > 0.8 ? 'warn' : 'ok';
    const label = !l.up ? '故障' : l.utilisation > 1 ? '过载' : l.utilisation > 0.8 ? '偏高' : '正常';
    tbody.appendChild(el('tr', {},
      el('td', {}, l.link),
      el('td', {}, l.kind || '—'),
      el('td', {}, fmt(l.capacityGbps, 0)),
      el('td', {}, fmt(l.loadGbps, 2)),
      el('td', {}, pct(l.utilisation)),
      el('td', {}, el('span', { class: 'tag ' + cls }, label)),
    ));
  }
  renderTopology();
}

$('#traffic-run').addEventListener('click', loadTraffic);

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------
async function runVerify() {
  const note = $('#verify-note');
  note.textContent = '正在生成网络并运行全部场景，可能需要几十秒…';
  const tbody = $('#verify-table tbody');
  tbody.innerHTML = '';
  try {
    const data = await api('/api/scenarios', { method: 'POST' });
    note.textContent = `共 ${data.results.length} 个场景`;
    for (const r of data.results) {
      const conv = r.converged ? el('span', { class: 'tag ok' }, '是') : el('span', { class: 'tag bad' }, '否');
      const bh = r.blackholes ? el('span', { class: 'tag bad' }, String(r.blackholes)) : el('span', { class: 'tag ok' }, '0');
      const lp = r.loops ? el('span', { class: 'tag bad' }, String(r.loops)) : el('span', { class: 'tag ok' }, '0');
      tbody.appendChild(el('tr', {},
        el('td', {}, r.name),
        el('td', { class: 'nomono' }, r.kind),
        el('td', {}, String(r.rounds)),
        el('td', {}, String(r.updates)),
        el('td', {}, conv),
        el('td', {}, bh),
        el('td', {}, lp),
        el('td', {}, r.lostPrefixes && r.lostPrefixes.length ? el('span', { class: 'tag warn' }, String(r.lostPrefixes.length)) : el('span', { class: 'tag ok' }, '0')),
        el('td', { class: 'nomono', style: 'color:var(--muted)' }, (r.notes || []).join('；') || r.description),
      ));
    }
    toast('场景验证完成', 'ok');
  } catch (e) {
    note.textContent = '验证失败：' + e.message;
    toast(e.message, 'bad');
  }
}
$('#verify-run').addEventListener('click', runVerify);

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function refreshTopologyOnly() {
  state.topology = layoutTopology(await api('/api/topology'));
  renderTopology();
  await loadState();
}

async function refreshAll() {
  await loadState();
  await refreshTopologyOnly();
  if ($('#tab-rib').classList.contains('active')) await loadRIB();
  if ($('#tab-traffic').classList.contains('active')) await loadTraffic();
}

(async function boot() {
  try {
    await loadState();
    await loadTopology();
    await loadRIB();
    const initial = (location.hash || '#topology').slice(1);
    activateTab(initial);
    if (initial === 'traffic') await loadTraffic();
    if (initial === 'policy') await loadPolicies();
  } catch (e) {
    toast('初始化失败：' + e.message, 'bad');
    console.error(e);
  }
})();

// Test hook: allow the decision panel to be opened from the URL (used by the
// screenshot smoke test and handy for sharing a specific explanation).
(function () {
  const m = location.hash.match(/^#rib\/([^/]+)\/([^/]+)$/);
  if (!m) return;
  window.addEventListener('load', () => {
    setTimeout(async () => {
      state.ribRouter = decodeURIComponent(m[1]);
      activateTab('rib');
      await loadRIB();
      showDecision(decodeURIComponent(m[2]));
    }, 400);
  });
})();

// Deep link to the policy editor: #policy/<index> or #policy/<name>.
(function () {
  const m = location.hash.match(/^#policy\/(.+)$/);
  if (!m) return;
  window.addEventListener('load', () => {
    setTimeout(async () => {
      if (!state.policies.length) await loadPolicies();
      const want = decodeURIComponent(m[1]);
      const idx = state.policies.findIndex((p, i) => p.name === want || String(i) === want);
      if (idx >= 0) {
        state.selectedPolicy = idx;
        renderPolicyList();
        renderEditor();
      }
      activateTab('policy');
    }, 300);
  });
})();

// Deep link that runs the verification suite on load: #verify (auto-run).
(function () {
  if (location.hash !== '#verify') return;
  window.addEventListener('load', () => {
    setTimeout(async () => {
      activateTab('verify');
      if (!$('#verify-table tbody').children.length) await runVerify();
    }, 500);
  });
})();
