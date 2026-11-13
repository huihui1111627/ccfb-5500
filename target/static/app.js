/* 充电桩运营后台 SPA —— 单页应用,所有数据通过 /api/* 获取 */
(function () {
  'use strict';

  const state = { user: null, view: 'dashboard' };
  const $ = (sel, el = document) => el.querySelector(sel);
  const view = $('#view');

  const TITLES = {
    dashboard: '运营概览', orders: '订单管理', stations: '场站管理', invoices: '发票管理',
    feedback: '客服工单', users: '用户管理', settlement: '运营结算', tools: '系统工具', profile: '个人中心',
  };

  // 故意使用 innerHTML 拼接(靶场 XSS 面)
  function h(html) { view.innerHTML = html; }

  function money(n) { return '¥' + Number(n || 0).toFixed(2); }

  function statusTag(s) {
    const map = { completed: 'success', paid: 'success', pending: 'warn', open: 'warn', cancelled: 'muted', refunded: 'danger', issued: 'success', closed: 'muted', online: 'success', maintenance: 'warn' };
    return `<span class="tag ${map[s] || 'muted'}">${s}</span>`;
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: 'include',
      headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {}),
      ...opts,
    });
    if (res.status === 401) { location.href = '/'; throw new Error('unauthorized'); }
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
    return data;
  }

  function toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }

  function openModal(title, bodyHtml, footHtml) {
    $('#modal-root').innerHTML = `
      <div class="modal-mask" onclick="if(event.target===this)this.remove()">
        <div class="modal">
          <div class="modal-head"><h3>${title}</h3><button class="x" onclick="this.closest('.modal-mask').remove()">×</button></div>
          <div class="modal-body">${bodyHtml}</div>
          <div class="modal-foot">${footHtml || '<button class="btn" onclick="this.closest(\'.modal-mask\').remove()">关闭</button>'}</div>
        </div>
      </div>`;
  }

  // ---------------------------------------------------------------- 概览
  async function viewDashboard() {
    const [orders, stations, me] = await Promise.all([
      api('/api/orders'), api('/api/stations'), api('/api/auth/me'),
    ]);
    state.user = me.user;
    const total = orders.items.reduce((s, o) => s + o.amount, 0);
    const active = stations.items.filter(s => s.status === 'online').length;
    const welcome = decodeURIComponent((location.hash.match(/welcome=([^&]*)/) || [])[1] || '');
    // 漏洞:DOM XSS,直接拼接 location.hash 内容
    h(`
      ${welcome ? `<div class="welcome">${welcome}</div>` : ''}
      <div class="stats">
        <div class="stat"><div class="stat-label">订单总数</div><div class="stat-num">${orders.items.length}</div><div class="stat-sub">近 30 天</div></div>
        <div class="stat"><div class="stat-label">充电金额</div><div class="stat-num">${money(total)}</div><div class="stat-sub">含已退款</div></div>
        <div class="stat"><div class="stat-label">在线场站</div><div class="stat-num">${active}/${stations.items.length}</div><div class="stat-sub">实时状态</div></div>
        <div class="stat"><div class="stat-label">当前角色</div><div class="stat-num small-num">${state.user.role_label}</div><div class="stat-sub">${state.user.username}</div></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>最近订单</h2><a href="#orders" class="link" data-view="orders">查看全部 →</a></div>
        <table class="table">
          <thead><tr><th>订单号</th><th>站点</th><th>电量</th><th>金额</th><th>状态</th><th>时间</th></tr></thead>
          <tbody>
            ${orders.items.slice(-6).reverse().map(o => `
              <tr><td><a href="#order/${o.id}" data-order="${o.id}">${o.order_no}</a></td>
              <td>${o.station_id}</td><td>${o.kwh} kWh</td><td>${money(o.amount)}</td>
              <td>${statusTag(o.status)}</td><td class="muted">${o.started_at}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>`);
    bindOrderLinks();
  }

  // ---------------------------------------------------------------- 订单
  async function viewOrders(query = {}) {
    const qs = new URLSearchParams({ status: query.status || '', q: query.q || '', sort: query.sort || 'id' });
    const data = await api('/api/orders?' + qs.toString());
    h(`
      <div class="card">
        <div class="toolbar">
          <input id="order-q" placeholder="搜索订单号 / 车牌" value="${query.q || ''}">
          <select id="order-status">
            <option value="">全部状态</option>
            ${['completed', 'paid', 'pending', 'cancelled', 'refunded'].map(s => `<option ${query.status === s ? 'selected' : ''}>${s}</option>`).join('')}
          </select>
          <select id="order-sort">
            <option value="id">按 ID</option><option value="amount">按金额</option><option value="started_at">按时间</option>
          </select>
          <button class="btn-primary" id="order-search">查询</button>
        </div>
        <table class="table">
          <thead><tr><th>ID</th><th>订单号</th><th>车牌</th><th>站点</th><th>金额</th><th>状态</th><th>备注</th><th>操作</th></tr></thead>
          <tbody>
            ${data.items.map(o => `<tr>
              <td>${o.id}</td><td>${o.order_no}</td><td>${o.vehicle_plate || '-'}</td><td>${o.station_id}</td>
              <td>${money(o.amount)}</td><td>${statusTag(o.status)}</td>
              <td class="remark">${o.remark || ''}</td>
              <td><a data-order="${o.id}" href="#order/${o.id}">详情</a></td></tr>`).join('')}
          </tbody>
        </table>
        <div class="muted small">共 ${data.total} 条 · SQL: ${data.query}</div>
      </div>`);
    $('#order-search').onclick = () => viewOrders({ q: $('#order-q').value, status: $('#order-status').value, sort: $('#order-sort').value });
    bindOrderLinks();
  }

  async function showOrder(id) {
    const data = await api('/api/orders/' + id);
    const o = data.order;
    openModal('订单详情 ' + o.order_no, `
      <dl class="dl">
        <dt>订单号</dt><dd>${o.order_no}</dd>
        <dt>站点</dt><dd>${o.station_name}(${o.station_address})</dd>
        <dt>车主</dt><dd>${o.user_name} / ${o.username} / ${o.user_phone} / ${o.user_email}</dd>
        <dt>电量 / 单价</dt><dd>${o.kwh} kWh × ${money(o.unit_price)}</dd>
        <dt>金额</dt><dd>${money(o.amount)}</dd>
        <dt>状态</dt><dd>${statusTag(o.status)}</dd>
        <dt>时间</dt><dd>${o.started_at} ~ ${o.ended_at}</dd>
        <dt>备注</dt><dd class="remark">${o.remark || '-'}</dd>
      </dl>`, `<button class="btn" onclick="fetch('/api/orders/${o.id}/cancel',{method:'POST',credentials:'include'}).then(()=>location.reload())">取消订单</button>`);
  }

  function bindOrderLinks() {
    view.querySelectorAll('[data-order]').forEach(a => a.addEventListener('click', (e) => {
      e.preventDefault(); showOrder(a.dataset.order);
    }));
  }

  // ---------------------------------------------------------------- 站点
  async function viewStations() {
    const data = await api('/api/stations');
    h(`
      <div class="card">
        <div class="toolbar">
          <input id="station-kw" placeholder="搜索站点名称 / 地址">
          <button class="btn-primary" id="station-search">搜索</button>
        </div>
        <div class="grid">
          ${data.items.map(s => `<div class="station">
            <div class="station-cover" id="cover-${s.id}">⚡</div>
            <div class="station-body">
              <h3>${s.name}</h3>
              <p class="muted">${s.city} · ${s.address}</p>
              <p>容量 ${s.capacity} 枪 ${statusTag(s.status)}</p>
              <button class="btn-link" data-cover="${s.id}">加载封面</button>
              <button class="btn-link" data-station="${s.id}">详情</button>
            </div>
          </div>`).join('')}
        </div>
      </div>`);
    view.querySelectorAll('[data-station]').forEach(b => b.onclick = async () => {
      const d = await api('/api/stations/' + b.dataset.station);
      openModal('场站详情', `<pre>${JSON.stringify(d.station, null, 2)}</pre>`);
    });
    view.querySelectorAll('[data-cover]').forEach(b => b.onclick = () => {
      const url = prompt('封面图片 URL', 'https://www.example.com/logo.png');
      if (!url) return;
      $('#cover-' + b.dataset.cover).innerHTML = `<img src="/api/stations/${b.dataset.cover}/cover?url=${encodeURIComponent(url)}" style="max-width:100%">`;
    });
    $('#station-search').onclick = async () => {
      const d = await api('/api/stations/search?keyword=' + encodeURIComponent($('#station-kw').value));
      toast(`命中 ${d.items.length} 个场站`);
      view.querySelectorAll('.station').forEach((el, i) => { el.style.display = d.items.some(x => x.id === data.items[i].id) ? '' : 'none'; });
    };
  }

  // ---------------------------------------------------------------- 发票
  async function viewInvoices() {
    const data = await api('/api/invoices');
    h(`
      <div class="card">
        <table class="table">
          <thead><tr><th>ID</th><th>抬头</th><th>税号</th><th>金额</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>${data.items.map(i => `<tr>
            <td>${i.id}</td><td>${i.title}</td><td>${i.tax_no || '-'}</td><td>${money(i.amount)}</td>
            <td>${statusTag(i.status)}</td>
            <td><a data-invoice="${i.id}" href="#invoice/${i.id}">查看</a></td></tr>`).join('')}</tbody>
        </table>
      </div>`);
    view.querySelectorAll('[data-invoice]').forEach(a => a.onclick = async (e) => {
      e.preventDefault();
      const d = await api('/api/invoices/' + a.dataset.invoice);
      const inv = d.invoice;
      openModal('发票 #' + inv.id, `
        <dl class="dl"><dt>抬头</dt><dd>${inv.title}</dd><dt>税号</dt><dd>${inv.tax_no || '-'}</dd>
        <dt>开票人</dt><dd>${inv.user_name} / ${inv.user_phone} / ${inv.user_email}</dd>
        <dt>金额</dt><dd>${money(inv.amount)}</dd><dt>状态</dt><dd>${statusTag(inv.status)}</dd></dl>
        <p><a class="link" href="/api/invoices/${inv.id}/attachment?file=default.pdf" target="_blank">下载 PDF 附件</a></p>`);
    });
  }

  // ---------------------------------------------------------------- 反馈
  async function viewFeedback() {
    const data = await api('/api/feedback');
    h(`
      <div class="card">
        <div class="card-head"><h2>工单列表</h2><button class="btn-primary" id="fb-new">新建工单</button></div>
        <table class="table">
          <thead><tr><th>ID</th><th>分类</th><th>内容</th><th>联系方式</th><th>状态</th><th>时间</th><th>操作</th></tr></thead>
          <tbody>${data.items.map(f => `<tr>
            <td>${f.id}</td><td>${f.category}</td><td class="remark">${f.content}</td><td>${f.contact}</td>
            <td>${statusTag(f.status)}</td><td class="muted">${f.created_at}</td>
            <td><a data-fb="${f.id}" href="#feedback/${f.id}">详情</a></td></tr>`).join('')}</tbody>
        </table>
      </div>`);
    view.querySelectorAll('[data-fb]').forEach(a => a.onclick = async (e) => {
      e.preventDefault();
      const d = await api('/api/feedback/' + a.dataset.fb);
      const f = d.feedback;
      openModal('工单 #' + f.id, `<dl class="dl"><dt>提交人</dt><dd>${f.user_name}</dd>
        <dt>分类</dt><dd>${f.category}</dd><dt>内容</dt><dd class="remark">${f.content}</dd>
        <dt>联系方式</dt><dd>${f.contact}</dd><dt>时间</dt><dd>${f.created_at}</dd></dl>`);
    });
    $('#fb-new').onclick = () => {
      openModal('新建工单', `<textarea id="fb-content" rows="4" placeholder="请描述问题"></textarea>
        <select id="fb-cat"><option value="charge">充电异常</option><option value="scan">扫码问题</option>
        <option value="invoice">发票问题</option><option value="other">其他</option></select>`,
        `<button class="btn-primary" id="fb-submit">提交</button>`);
      $('#fb-submit').onclick = async () => {
        await api('/api/feedback', { method: 'POST', body: JSON.stringify({ content: $('#fb-content').value, category: $('#fb-cat').value }) });
        toast('提交成功'); $('.modal-mask').remove(); viewFeedback();
      };
    };
  }

  // ---------------------------------------------------------------- 用户
  async function viewUsers() {
    let data;
    try { data = await api('/api/admin/users'); }
    catch (e) { view.innerHTML = `<div class="card empty">无权访问用户管理:${e.message}</div>`; return; }
    h(`<div class="card"><table class="table">
      <thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>姓名</th><th>手机</th><th>余额</th><th>操作</th></tr></thead>
      <tbody>${data.items.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.role}</td>
        <td>${u.display_name}</td><td>${u.phone}</td><td>${money(u.balance)}</td>
        <td><a data-user="${u.id}" href="#user/${u.id}">档案</a></td></tr>`).join('')}</tbody></table></div>`);
    view.querySelectorAll('[data-user]').forEach(a => a.onclick = async (e) => {
      e.preventDefault();
      const d = await api('/api/users/' + a.dataset.user);
      openModal('用户档案', `<pre>${JSON.stringify(d.user, null, 2)}</pre>`);
    });
  }

  // ---------------------------------------------------------------- 结算
  async function viewSettlement() {
    const data = await api('/api/finance/settlements');
    h(`<div class="card"><div class="card-head"><h2>${data.period} 运营结算</h2><span>合计 ${money(data.total)}</span></div>
      <table class="table"><thead><tr><th>ID</th><th>场站</th><th>负责人</th><th>结算账户</th><th>开户行</th><th>结算金额</th></tr></thead>
      <tbody>${data.items.map(s => `<tr><td>${s.id}</td><td>${s.name}</td><td>${s.owner}</td>
        <td>${s.settlement_account}</td><td>${s.bank}</td><td>${money(s.settled_amount)}</td></tr>`).join('')}</tbody></table></div>`);
  }

  // ---------------------------------------------------------------- 工具
  async function viewTools() {
    h(`<div class="grid2">
      <div class="card"><h2>远程资源抓取</h2><p class="muted">拉取合作方接口数据用于对账</p>
        <input id="fetch-url" placeholder="https://api.example.com/data" style="width:100%">
        <button class="btn-primary" id="fetch-btn">抓取</button>
        <pre id="fetch-out" class="out"></pre></div>
      <div class="card"><h2>话术模板下载</h2><p class="muted">客服话术与发票模板</p>
        <input id="dl-name" value="avatars/default.txt" style="width:100%">
        <button class="btn" id="dl-btn">下载</button><pre id="dl-out" class="out"></pre></div>
      <div class="card"><h2>API 密钥</h2>
        <button class="btn" id="keys-btn">查看密钥</button><pre id="keys-out" class="out"></pre></div>
      <div class="card"><h2>系统诊断</h2>
        <button class="btn" id="diag-btn">运行诊断</button><pre id="diag-out" class="out"></pre></div>
      <div class="card"><h2>帮助与公告</h2>
        <ul class="links">
          <li><a href="/help/search" target="_blank">帮助中心搜索</a></li>
          <li><a href="/notice" target="_blank">站点公告 / 待处理工单</a></li>
          <li><a href="/profile/${state.user ? state.user.id : 1}" target="_blank">我的档案(服务端渲染)</a></li>
        </ul>
      </div>
    </div>`);
    $('#fetch-btn').onclick = async () => {
      try { const d = await api('/api/integrations/fetch?url=' + encodeURIComponent($('#fetch-url').value)); $('#fetch-out').textContent = JSON.stringify(d, null, 2); }
      catch (e) { $('#fetch-out').textContent = e.message; }
    };
    $('#dl-btn').onclick = async () => {
      const res = await fetch('/api/files/download?path=' + encodeURIComponent($('#dl-name').value), { credentials: 'include' });
      $('#dl-out').textContent = res.ok ? await res.text() : '文件不存在';
    };
    $('#keys-btn').onclick = async () => {
      try { const d = await api('/api/admin/api-keys'); $('#keys-out').textContent = JSON.stringify(d.items, null, 2); }
      catch (e) { $('#keys-out').textContent = e.message; }
    };
    $('#diag-btn').onclick = async () => {
      try { const d = await api('/api/debug/config'); $('#diag-out').textContent = JSON.stringify(d, null, 2); }
      catch (e) { $('#diag-out').textContent = e.message; }
    };
  }

  // ---------------------------------------------------------------- 个人中心
  async function viewProfile() {
    const d = await api('/api/auth/me');
    const u = d.user;
    h(`<div class="card"><h2>个人资料</h2>
      <form id="profile-form" class="form-grid">
        <label>显示名称<input name="display_name" value="${u.display_name}"></label>
        <label>邮箱<input name="email" value="${u.email}"></label>
        <label>手机<input name="phone" value="${u.phone}"></label>
        <button class="btn-primary" type="submit">保存</button>
      </form>
      <p class="muted">用户名 ${u.username} · 角色 ${u.role_label}</p></div>`);
    $('#profile-form').onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      await api('/api/profile', { method: 'PUT', body: JSON.stringify(Object.fromEntries(fd)) });
      toast('资料已更新');
    };
  }

  // ---------------------------------------------------------------- 路由
  const ROUTES = {
    dashboard: viewDashboard, orders: viewOrders, stations: viewStations,
    invoices: viewInvoices, feedback: viewFeedback, users: viewUsers,
    settlement: viewSettlement, tools: viewTools, profile: viewProfile,
  };

  async function render(name) {
    state.view = name;
    const fn = ROUTES[name] || viewDashboard;
    document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.view === name));
    $('#view-title').textContent = TITLES[name] || name;
    try { await fn(); } catch (e) { view.innerHTML = `<div class="card empty">加载失败:${e.message}</div>`; }
  }

  function route() {
    const hash = location.hash.replace(/^#/, '');
    const [head, id] = hash.split('/');
    if (id && head === 'order') { render('orders').then(() => showOrder(id)); return; }
    if (head && ROUTES[head]) return render(head);
    if (hash.startsWith('welcome=')) return render('dashboard');
    render('dashboard');
  }

  function boot() {
    api('/api/auth/me').then(d => {
      state.user = d.user;
      $('#side-name').textContent = d.user.display_name;
      $('#side-role').textContent = d.user.role_label;
      $('#side-avatar').textContent = d.user.display_name.slice(-1);
      $('#role-pill').textContent = d.user.role_label + ' · ' + d.user.username;
    }).catch(() => {});
    document.querySelectorAll('#nav a, [data-view]').forEach(a => a.addEventListener('click', (e) => {
      const name = a.dataset.view;
      if (name) { e.preventDefault(); location.hash = name; }
    }));
    $('#logout').onclick = async () => { await api('/api/auth/logout', { method: 'POST' }); location.href = '/'; };
    setInterval(() => { $('#clock').textContent = new Date().toLocaleTimeString('zh-CN'); }, 1000);
    window.addEventListener('hashchange', route);
    route();
  }

  boot();
})();
