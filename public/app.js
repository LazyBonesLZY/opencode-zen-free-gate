// app.js - OpenCode Zen Free 状态页
function esc(str) {
  return String(str).replace(/[&<>"']/g, function (m) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];
  });
}

var STATES = {
  "operational": { label: "正常", pill: "pill-green" },
  "cooldown":    { label: "冷却", pill: "pill-yellow" },
  "down":        { label: "异常", pill: "pill-red" },
  "unknown":     { label: "待检测", pill: "pill-unknown" }
};

function overallState(slots) {
  var hasDown = false, hasCool = false, hasOp = false;
  (slots || []).forEach(function (s) {
    if (s.state === 'down') hasDown = true;
    else if (s.state === 'cooldown') hasCool = true;
    else if (s.state === 'operational') hasOp = true;
  });
  if (hasDown) return 'down';
  if (hasCool) return 'cooldown';
  if (hasOp) return 'operational';
  return 'unknown';
}

function renderBanner(snap) {
  var b = document.getElementById('statusBanner');
  if (!b) return;
  var overall = snap.overall || 'unknown';
  var st = STATES[overall] || STATES.unknown;
  var title, sub, cls;

  if (overall === 'down') { title = '部分出口异常'; cls = 'red'; }
  else if (overall === 'cooldown') { title = '部分出口冷却中'; cls = 'blue'; }
  else if (overall === 'operational') { title = '整体运行正常'; cls = 'green'; }
  else { title = '状态未知'; cls = 'unknown'; }

  var counts = {};
  (snap.slots || []).forEach(function (s) { counts[s.state] = (counts[s.state] || 0) + 1; });
  var parts = [];
  if (counts.operational) parts.push('正常 ' + counts.operational);
  if (counts.cooldown) parts.push('冷却 ' + counts.cooldown);
  if (counts.down) parts.push('异常 ' + counts.down);
  if (counts.unknown) parts.push('待检测 ' + counts.unknown);
  sub = parts.join(' · ') || '暂无出口';

  var st2 = snap.stats || {};
  if (st2.total) sub += ' · 请求 ' + st2.total + ' 次';

  b.className = 'status-banner status-' + cls;
  document.getElementById('bannerTitle').textContent = title;
  document.getElementById('bannerSub').textContent = sub;

  var ms = document.getElementById('mastStatus');
  if (ms) {
    ms.className = 'mast-status ' + (st.pill || 'pill-unknown');
    ms.innerHTML = '<span class="dot"></span>' + (st.label || '');
  }
}

// 数字格式化为 K/M，保留 1 位小数：1234 → 1.2K，1234567 → 1.2M
function fmtTokens(n) {
  n = Number(n) || 0;
  if (n >= 1000000) {
    var m = Math.round(n / 1000000 * 10) / 10;
    return m + 'M';
  }
  if (n >= 1000) {
    var k = Math.round(n / 1000 * 10) / 10;
    if (k >= 1000) return (Math.round(k / 1000 * 10) / 10) + 'M';
    return k + 'K';
  }
  return String(n);
}

function renderTokens(snap) {
  var t = snap.tokens || {};
  var totalEl = document.getElementById('tokenTotal');
  if (totalEl) {
    totalEl.innerHTML =
      '<span><b>' + fmtTokens(t.total || 0) + '</b> tok</span>' +
      '<span><b>' + fmtTokens(t.prompt || 0) + '</b> 输入</span>' +
      '<span><b>' + fmtTokens(t.completion || 0) + '</b> 输出</span>';
  }
  var byModel = t.by_model || [];
  var chipsEl = document.getElementById('tokenByModel');
  if (chipsEl) {
    chipsEl.innerHTML = byModel.length
      ? byModel.map(function (m) {
          return '<div class="token-model-chip">' +
            '<span class="m">' + esc(m.model) + '</span> ' +
            '<span>' + fmtTokens(m.tokens) + ' tok</span>' +
          '</div>';
        }).join("")
      : '<span class="muted">暂无用量</span>';
  }
}

function renderSlots(snap) {
  var slots = (snap && snap.slots) || [];
  var el = document.getElementById('slots');
  if (!el) return;
  if (!slots.length) {
    el.innerHTML = '<div class="component-row component-empty">暂无数据</div>';
    return;
  }
  var html = slots.map(function (s) {
    var st = STATES[s.state] || STATES.unknown;
    var lat = s.latency_ms != null ? s.latency_ms + 'ms' : '—';
    var badges = '<span class="mini-pill pill-blue">延迟 ' + esc(lat) + '</span>' +
      '<span class="mini-pill pill-violet">切换 ' + (s.switches || 0) + '</span>';
    return '<div class="component-row">' +
      '<span class="component-name">出口 ' + String(s.slot).padStart(2, "0") + '</span>' +
      '<div class="slot-badges">' + badges + '</div>' +
      '<span class="status-pill ' + st.pill + '"><span class="dot"></span>' + st.label + '</span>' +
    '</div>';
  }).join("");
  el.innerHTML = html;
}

function renderModels(snap) {
  var fm = (snap && snap.free_models) || [];
  var el = document.getElementById('freeModels');
  if (el) {
    el.innerHTML = fm.length
      ? fm.map(function (x) { return '<span class="free-model">' + esc(x) + '</span>'; }).join("")
      : '<span class="muted">暂无</span>';
  }
}

function renderFooter(snap) {
  var uptime = Math.round((snap.uptime || 0) / 60);
  var st = snap.stats || {};
  var label = '运行 ' + fmtUptime(uptime) +
    ' · 请求 ' + (st.total || 0) +
    ' · 限流 ' + (st.rateLimited || 0) +
    ' · 自动切换 ' + (st.switches || 0) + ' 次';
  var el = document.getElementById('footerMeta');
  if (el) el.textContent = label;
}

function fmtUptime(mins) {
  if (mins < 60) return mins + ' 分钟';
  var h = Math.floor(mins / 60);
  var m = mins % 60;
  if (h < 24) return h + ' 小时 ' + m + ' 分';
  var d = Math.floor(h / 24);
  return d + ' 天 ' + (h % 24) + ' 小时';
}

function render(snap) {
  if (!snap) return;
  renderBanner(snap);
  renderTokens(snap);
  renderSlots(snap);
  renderModels(snap);
  renderFooter(snap);
}

function poll() {
  fetch("/api/status")
    .then(function (r) { return r.json(); })
    .then(function (snap) {
      document.getElementById('lastSync').textContent =
        '最后更新 ' + new Date().toLocaleTimeString('zh-CN', {hour:'2-digit', minute:'2-digit'});
      render(snap);
    })
    .catch(function () {});
}

setInterval(poll, 5000);
poll();
