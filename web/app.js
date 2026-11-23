/* proxygw 管理面板前端（原生 JS，无框架/无 CDN）
 *
 * 设计要点：
 *  - 唯一入口 /api/v1，登录态通过 GET /session 判断；CSRF token 仅保存在内存变量。
 *  - 所有非 GET 请求带 X-CSRF-Token；fetch 使用 credentials: "same-origin"。
 *  - 所有来自 API 的字符串一律通过 textContent / DOM 属性写入，禁止 innerHTML 拼接。
 *  - SSE(/events) 推送 + 3s 轮询降级；页面隐藏时暂停轮询。
 *  - CSP：无内联脚本、无内联事件，所有交互通过 addEventListener 委托 data-action。
 */
(function () {
  'use strict';

  var API = '/api/v1';

  /* ================================================================== 常量 */

  var PAGE_TITLES = {
    overview: '总览',
    nodes: '节点',
    groups: '节点组',
    credentials: '凭据',
    rules: '连接与规则',
    settings: '运行设置',
    audit: '审计',
    cert: '证书',
    geo: '归属地',
    access: '接入'
  };

  var COUNTRY_NAMES = {
    AD: '安道尔', AE: '阿联酋', AF: '阿富汗', AG: '安提瓜和巴布达', AL: '阿尔巴尼亚',
    AM: '亚美尼亚', AO: '安哥拉', AR: '阿根廷', AT: '奥地利', AU: '澳大利亚',
    AZ: '阿塞拜疆', BA: '波黑', BD: '孟加拉国', BE: '比利时', BG: '保加利亚',
    BH: '巴林', BM: '百慕大', BO: '玻利维亚', BR: '巴西', BY: '白俄罗斯',
    CA: '加拿大', CH: '瑞士', CL: '智利', CN: '中国', CO: '哥伦比亚',
    CR: '哥斯达黎加', CU: '古巴', CY: '塞浦路斯', CZ: '捷克', DE: '德国',
    DK: '丹麦', DO: '多米尼加', DZ: '阿尔及利亚', EC: '厄瓜多尔', EE: '爱沙尼亚',
    EG: '埃及', ES: '西班牙', ET: '埃塞俄比亚', FI: '芬兰', FR: '法国',
    GB: '英国', GE: '格鲁吉亚', GR: '希腊', GT: '危地马拉', HK: '中国香港',
    HR: '克罗地亚', HU: '匈牙利', ID: '印度尼西亚', IE: '爱尔兰', IL: '以色列',
    IN: '印度', IQ: '伊拉克', IR: '伊朗', IS: '冰岛', IT: '意大利',
    JM: '牙买加', JO: '约旦', JP: '日本', KE: '肯尼亚', KG: '吉尔吉斯斯坦',
    KH: '柬埔寨', KP: '朝鲜', KR: '韩国', KW: '科威特', KZ: '哈萨克斯坦',
    LA: '老挝', LB: '黎巴嫩', LK: '斯里兰卡', LT: '立陶宛', LU: '卢森堡',
    LV: '拉脱维亚', LY: '利比亚', MA: '摩洛哥', MD: '摩尔多瓦', ME: '黑山',
    MK: '北马其顿', MM: '缅甸', MN: '蒙古', MO: '中国澳门', MT: '马耳他',
    MU: '毛里求斯', MV: '马尔代夫', MX: '墨西哥', MY: '马来西亚', NG: '尼日利亚',
    NL: '荷兰', NO: '挪威', NP: '尼泊尔', NZ: '新西兰', OM: '阿曼',
    PA: '巴拿马', PE: '秘鲁', PH: '菲律宾', PK: '巴基斯坦', PL: '波兰',
    PR: '波多黎各', PT: '葡萄牙', PY: '巴拉圭', QA: '卡塔尔', RO: '罗马尼亚',
    RS: '塞尔维亚', RU: '俄罗斯', SA: '沙特阿拉伯', SE: '瑞典', SG: '新加坡',
    SI: '斯洛文尼亚', SK: '斯洛伐克', TH: '泰国', TN: '突尼斯', TR: '土耳其',
    TW: '中国台湾', TZ: '坦桑尼亚', UA: '乌克兰', US: '美国', UY: '乌拉圭',
    UZ: '乌兹别克斯坦', VE: '委内瑞拉', VN: '越南', ZA: '南非', ZM: '赞比亚'
  };

  var STRATEGY_OPTIONS = [
    { value: 'random', label: '随机（random）' },
    { value: 'least_inflight', label: '最少在途（least_inflight）' },
    { value: 'fastest', label: '最快 EWMA（fastest）' },
    { value: 'weighted', label: '加权轮询（weighted）' }
  ];

  var BREAKER_LABELS = { closed: '正常', open: '熔断中', half_open: '半开探测' };
  var BREAKER_CLASS = { closed: 'closed', open: 'open', half_open: 'half_open' };

  var TRANSPORT_LABELS = { quic: 'QUIC', ws: 'WebSocket', wss: 'WebSocket' };

  var PROTOCOL_OPTIONS = [
    { value: 'http', label: 'HTTP' },
    { value: 'connect', label: 'CONNECT' },
    { value: 'socks5', label: 'SOCKS5' }
  ];

  var ACL_PROTOCOL_OPTIONS = [
    { value: 'http', label: 'HTTP' },
    { value: 'connect', label: 'CONNECT' },
    { value: 'socks5', label: 'SOCKS5' },
    { value: 'tcp', label: 'TCP' }
  ];

  var PIN_PLACEHOLDERS = [
    '<pin>', '<PIN>', '<Pin>', '<SPKI_PIN>', '<spki_pin>', '<YOUR_PIN>',
    '{{PIN}}', '{{pin}}', '{PIN}', '{pin}', '${PIN}', '${pin}',
    'YOUR_PIN', 'YOUR-SPKI-PIN', 'YOUR_SPKI_PIN', 'SPKI_PIN_PLACEHOLDER',
    'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'sha256/...', 'sha256/…'
  ];

  var ACTION_LABELS = {
    login: '登录', logout: '退出登录', 'login.failed': '登录失败',
    'node.kick': '强制下线节点', 'node.update': '更新节点',
    'node.enable': '启用节点', 'node.disable': '禁用节点',
    'node.probe': '节点拨测', 'node.online': '节点上线', 'node.offline': '节点离线',
    'credential.create': '创建凭据', 'credential.update': '更新凭据',
    'credential.delete': '删除凭据', 'credential.kick': '踢凭据会话',
    'credential.kick_sessions': '踢凭据会话',
    'group.create': '创建节点组', 'group.update': '更新节点组', 'group.delete': '删除节点组',
    'acl.create': '创建 ACL 规则', 'acl.update': '更新 ACL 规则',
    'acl.delete': '删除 ACL 规则', 'acl.replace': '全量替换 ACL',
    'settings.update': '更新运行设置', 'settings.undo': '撤销运行设置',
    'settings.reset': '恢复默认运行设置',
    'sticky.create': '创建粘性黑名单', 'sticky.update': '更新粘性黑名单',
    'sticky.delete': '删除粘性黑名单',
    'cert.rotate': '生成下一枚 pin', 'cert.rotate_pin': '生成下一枚 pin',
    'cert.reload': '重载证书',
    'geo.provider.update': '更新归属地 provider',
    'geo.provider.test': '测试归属地 provider',
    'token.create': '签发节点令牌', 'token.revoke': '吊销节点令牌'
  };

  var SETTINGS_SECTIONS = [
    {
      title: '调度与容错',
      fields: [
        { path: 'scheduler.strategy', label: '路由策略', type: 'select', options: STRATEGY_OPTIONS, hint: '加权策略使用节点 weight' },
        { path: 'scheduler.sticky.enabled', label: '会话粘性', type: 'checkbox', hint: '按「凭据 + 源 IP」将请求固定到节点' },
        { path: 'scheduler.sticky.ttl', label: '粘性 TTL', type: 'text', hint: '时长字符串，如 10m / 30s' },
        { path: 'scheduler.sticky.max_keys_per_node', label: '每节点粘性 key 上限', type: 'number', numeric: 'int' },
        { path: 'scheduler.breaker.failure_threshold', label: '熔断连续失败阈值', type: 'number', numeric: 'int' },
        { path: 'scheduler.breaker.failure_rate', label: '熔断失败率阈值', type: 'number', numeric: 'float', step: '0.01', hint: '0–1，例如 0.5' },
        { path: 'scheduler.breaker.min_samples', label: '失败率最小样本数', type: 'number', numeric: 'int' },
        { path: 'scheduler.breaker.open_timeout', label: '熔断冷却时间', type: 'text', hint: '如 30s' },
        { path: 'scheduler.retry.enabled', label: '透明重试', type: 'checkbox', hint: '仅在响应首字节前重试' },
        { path: 'scheduler.retry.max_attempts', label: '最大尝试次数', type: 'number', numeric: 'int', hint: '1–3（含首次）' }
      ]
    },
    {
      title: '限流',
      fields: [
        { path: 'limits.global_down_kbps', label: '全局下行限速（kbps）', type: 'number', numeric: 'int', hint: '0 = 不限' },
        { path: 'limits.per_node_down_kbps', label: '单节点下行限速（kbps）', type: 'number', numeric: 'int', hint: '0 = 不限' },
        { path: 'limits.per_credential_down_kbps', label: '单凭据下行限速（kbps）', type: 'number', numeric: 'int', hint: '0 = 不限' },
        { path: 'limits.max_streams_per_node', label: '单节点并发流上限', type: 'number', numeric: 'int' }
      ]
    },
    {
      title: '超时',
      fields: [
        { path: 'timeouts.open', label: '建流超时 open', type: 'text', hint: '如 10s' },
        { path: 'timeouts.read_header', label: '入口读头 read_header', type: 'text', hint: '如 10s' },
        { path: 'timeouts.idle', label: '空闲 idle', type: 'text', hint: '如 30m' },
        { path: 'timeouts.write_block', label: '写阻塞 write_block', type: 'text', hint: '如 30s' },
        { path: 'timeouts.linger', label: '半关闭 linger', type: 'text', hint: '如 30s' },
        { path: 'timeouts.drain', label: '排空 drain', type: 'text', hint: '如 10s' },
        { path: 'timeouts.window_stall', label: '窗口停滞 window_stall', type: 'text', hint: '如 30s' },
        { path: 'timeouts.dial_target', label: '节点拨号目标 dial_target', type: 'text', hint: '如 10s' }
      ]
    },
    {
      title: '其他',
      fields: [
        { path: 'compression_enabled', label: '启用 zstd 压缩', type: 'checkbox', hint: '两端都支持时生效' },
        { path: 'default_acl_action', label: 'ACL 默认动作', type: 'select', options: [{ value: 'allow', label: 'allow（放行）' }, { value: 'deny', label: 'deny（拒绝）' }] }
      ]
    }
  ];

  /* ================================================================== 状态 */

  var state = {
    session: null,
    csrf: '',
    page: 'overview',
    handling401: false,
    clockSkew: null,
    overview: null,
    nodes: { items: [], total: 0, summary: {}, page: 1, size: 50, loaded: false, lastFetch: 0 },
    groups: { items: [], loaded: false },
    credentials: { items: [], loaded: false },
    settings: null,
    sticky: { items: [], loaded: false },
    acl: { items: [], loaded: false, defaultAction: '' },
    aclForced: { items: [], loaded: false },
    audit: { items: [], expanded: new Set(), oldest: null, canMore: false, loaded: false, loading: false },
    cert: null,
    geo: { items: [], loaded: false },
    sse: { connected: false, es: null, retry: 0, timer: null, everConnected: false },
    live: { timer: null, lastRefresh: 0, throttle: {} }
  };

  var modalState = { current: null };
  var fieldSeq = 0;
  var loadingPage = false;

  /* ================================================================== 基础工具 */

  function $(id) {
    return document.getElementById(id);
  }

  function qs(selector, root) {
    return (root || document).querySelector(selector);
  }

  function qsa(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function append(parent) {
    for (var i = 1; i < arguments.length; i++) {
      var child = arguments[i];
      if (child === null || child === undefined || child === false) continue;
      if (Array.isArray(child)) {
        append.apply(null, [parent].concat(child));
      } else if (child instanceof Node) {
        parent.appendChild(child);
      } else {
        parent.appendChild(document.createTextNode(String(child)));
      }
    }
    return parent;
  }

  function clear(node) {
    if (node) node.replaceChildren();
    return node;
  }

  function setText(id, text) {
    var node = typeof id === 'string' ? $(id) : id;
    if (node) node.textContent = text === undefined || text === null ? '' : String(text);
  }

  function setHidden(id, hidden) {
    var node = typeof id === 'string' ? $(id) : id;
    if (node) node.hidden = !!hidden;
  }

  /* escapeHtml 工具：动态数据优先使用 textContent；仅在必须生成 HTML 字符串时使用。 */
  function escapeHtml(value) {
    return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, function (ch) {
      switch (ch) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        default: return '&#39;';
      }
    });
  }

  function enc(value) {
    return encodeURIComponent(String(value === undefined || value === null ? '' : value));
  }

  function splitList(value) {
    return String(value === undefined || value === null ? '' : value)
      .split(/[\s,，;；]+/)
      .map(function (s) { return s.trim(); })
      .filter(Boolean);
  }

  function joinList(list, sep) {
    return Array.isArray(list) ? list.join(sep || ', ') : '';
  }

  function toInt(value, fallback) {
    var n = parseInt(String(value === undefined || value === null ? '' : value), 10);
    return Number.isFinite(n) ? n : (fallback === undefined ? 0 : fallback);
  }

  function toFloat(value, fallback) {
    var n = parseFloat(String(value === undefined || value === null ? '' : value));
    return Number.isFinite(n) ? n : (fallback === undefined ? 0 : fallback);
  }

  function pad2(n) {
    return String(n).padStart(2, '0');
  }

  function fmtNum(value) {
    if (value === null || value === undefined || value === '') return '—';
    var n = Number(value);
    if (!Number.isFinite(n)) return '—';
    return n.toLocaleString('zh-CN');
  }

  function fmtBytes(value) {
    var n = Number(value);
    if (!Number.isFinite(n) || n < 0) return '—';
    var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n = n / 1024;
      i++;
    }
    var digits = i === 0 ? 0 : (n >= 100 ? 0 : 1);
    return n.toFixed(digits) + ' ' + units[i];
  }

  function fmtLatency(value) {
    var n = Number(value);
    if (!Number.isFinite(n) || value === null || value === '') return '—';
    if (n >= 1000) return n.toFixed(0) + ' ms';
    if (n >= 100) return n.toFixed(0) + ' ms';
    return n.toFixed(1) + ' ms';
  }

  function toDate(value) {
    if (value === null || value === undefined || value === '') return null;
    if (typeof value === 'number') {
      var ms = value < 1e12 ? value * 1000 : value;
      var dn = new Date(ms);
      return isNaN(dn.getTime()) ? null : dn;
    }
    var s = String(value);
    if (/^\d+$/.test(s)) {
      var num = Number(s);
      var dnum = new Date(num < 1e12 ? num * 1000 : num);
      return isNaN(dnum.getTime()) ? null : dnum;
    }
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  function fmtDateTime(value) {
    var d = toDate(value);
    if (!d) return '—';
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
      pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  function fmtTimeHM(value) {
    var d = toDate(value);
    if (!d) return '—';
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }

  function fmtRelative(value) {
    var d = toDate(value);
    if (!d) return '—';
    var diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 0) {
      var ahead = -diff;
      if (ahead < 60) return '即将';
      if (ahead < 3600) return Math.floor(ahead / 60) + ' 分钟后';
      return fmtDateTime(value);
    }
    if (diff < 10) return '刚刚';
    if (diff < 60) return Math.floor(diff) + ' 秒前';
    if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
    if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
    if (diff < 30 * 86400) return Math.floor(diff / 86400) + ' 天前';
    return fmtDateTime(value);
  }

  function toLocalInput(value) {
    var d = toDate(value);
    if (!d) return '';
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' +
      pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }

  function fromLocalInput(value) {
    if (!value) return null;
    var d = new Date(value);
    return isNaN(d.getTime()) ? null : d.toISOString();
  }

  function daysUntil(value) {
    var d = toDate(value);
    if (!d) return null;
    return Math.ceil((d.getTime() - Date.now()) / 86400000);
  }

  function getPath(obj, path) {
    var parts = String(path).split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur === null || cur === undefined) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function setPath(obj, path, value) {
    var parts = String(path).split('.');
    var cur = obj;
    for (var i = 0; i < parts.length - 1; i++) {
      if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) cur[parts[i]] = {};
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = value;
  }

  function countryInfo(code) {
    var c = String(code === undefined || code === null ? '' : code).trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(c)) {
      return { code: c, name: c || '未知', flag: '🏳️' };
    }
    var flag = '';
    try {
      flag = String.fromCodePoint.apply(null, c.split('').map(function (ch) {
        return 127397 + ch.charCodeAt(0);
      }));
    } catch (e) {
      flag = '';
    }
    return { code: c, name: COUNTRY_NAMES[c] || c, flag: flag };
  }

  function countryLabel(code) {
    var info = countryInfo(code);
    return info.code ? (info.flag + ' ' + info.name) : '—';
  }

  function modeLabel(mode) {
    switch (String(mode || '')) {
      case 'pin': return { label: 'SPKI pin 模式', desc: '自签证书 + SPKI 指纹校验（默认）', variant: 'info' };
      case 'ca': return { label: 'CA 证书模式', desc: '正规 CA 证书，可热重载', variant: 'ok' };
      case 'insecure': return { label: '不安全模式', desc: '仅限回环/开发使用，生产禁止', variant: 'warn' };
      default: return { label: mode || '未知', desc: '', variant: 'muted' };
    }
  }

  function transportBadge(transport) {
    var t = String(transport || '').toLowerCase();
    if (!t) return badge('—', 'muted');
    var key = t === 'wss' ? 'ws' : (t === 'quic' ? 'quic' : (t === 'ws' ? 'ws' : ''));
    return badge(TRANSPORT_LABELS[t] || t, key || 'info');
  }

  function breakerBadge(value) {
    var s = String(value || '').toLowerCase();
    if (!s) return badge('—', 'muted');
    return badge(BREAKER_LABELS[s] || s, BREAKER_CLASS[s] || 'muted');
  }

  function badge(text, variant) {
    var b = el('span', 'badge ' + (variant || 'muted'));
    b.textContent = text === undefined || text === null ? '—' : String(text);
    return b;
  }

  function chip(text, variant) {
    var c = el('span', 'chip ' + (variant || ''));
    c.textContent = text;
    return c;
  }

  function btn(label, options) {
    options = options || {};
    var b = el('button', 'btn ' + (options.variant || 'btn-ghost') + (options.small ? ' btn-sm' : ''), label);
    b.type = 'button';
    if (options.action) b.dataset.action = options.action;
    if (options.id !== undefined && options.id !== null) b.dataset.id = String(options.id);
    if (options.name !== undefined && options.name !== null) b.dataset.name = String(options.name);
    if (options.title) b.title = options.title;
    if (options.disabled) b.disabled = true;
    return b;
  }

  function summaryChip(label, value) {
    var c = el('span', 'summary-chip');
    c.append(document.createTextNode(label + ' '));
    var strong = el('strong', null, value === undefined || value === null ? '—' : String(value));
    c.append(strong);
    return c;
  }

  function timeCell(value) {
    var wrap = el('span');
    wrap.title = fmtDateTime(value);
    var main = el('span', 'cell-main', fmtRelative(value));
    wrap.append(main);
    return wrap;
  }

  function actionLabel(action) {
    return ACTION_LABELS[action] || action || '—';
  }

  function resultBadge(result) {
    var r = String(result || '').toLowerCase();
    if (!r) return badge('—', 'muted');
    if (r === 'ok' || r === 'success' || r === 'allow' || r === 'allowed' || r === 'true') {
      return badge(r === 'allow' || r === 'allowed' ? '放行' : '成功', 'ok');
    }
    if (r === 'fail' || r === 'failed' || r === 'error' || r === 'deny' || r === 'denied') {
      return badge(r === 'deny' || r === 'denied' ? '拒绝' : '失败', 'fail');
    }
    return badge(result, 'muted');
  }

  function groupName(id) {
    var groups = state.groups.items || [];
    for (var i = 0; i < groups.length; i++) {
      if (groups[i] && groups[i].id === id) return groups[i].name || id;
    }
    return id;
  }

  function groupNames(ids) {
    if (!Array.isArray(ids) || !ids.length) return [];
    return ids.map(groupName);
  }

  function decodeBase64Utf8(b64) {
    try {
      var bin = atob(String(b64 || ''));
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function fillPinPlaceholders(template, pin) {
    if (!template) return '';
    var out = String(template);
    if (!pin) return out;
    PIN_PLACEHOLDERS.forEach(function (ph) {
      if (out.indexOf(ph) !== -1) out = out.split(ph).join(pin);
    });
    return out;
  }

  function hasPin(template, pin) {
    return !!(template && pin && String(template).indexOf(pin) !== -1);
  }

  function templateNote(template, pin) {
    if (!template) return '服务端未返回安装模板，以下为内置示例命令。';
    if (!pin) return '模板来自服务端 /nodes/install-template；当前未获取到 SPKI pin，请手动填入。';
    if (hasPin(template, pin)) return '模板来自服务端，且已包含当前 SPKI pin；接入令牌为占位符。';
    if (/--pin\b|-Pin\b/.test(template)) {
      return '模板来自服务端且已包含 pin 参数，请核对与当前证书一致（当前 pin 见下方）；接入令牌为占位符。';
    }
    return '模板来自服务端；未识别到 pin 参数，请手动确认 tls.pin 配置（当前 pin 见下方）。';
  }
  function fallbackLinux(pin) {
    var p = pin || 'sha256/<SPKI指纹>';
    return [
      '# 节点一键接入（Linux 示例）',
      '# 1) 使用一键安装脚本（需先上传 scripts/install-node.sh）',
      'sudo ./scripts/install-node.sh \\',
      '  --server https://<服务器地址> \\',
      '  --token <节点接入令牌> \\',
      '  --pin ' + p + ' \\',
      '  --client-id <节点ID> \\',
      '  --tags <标签>',
      '',
      '# 2) 或手工编写 /etc/proxygw/config.client.yaml',
      'server_url: "https://<服务器地址>"',
      'token: "<节点接入令牌>"',
      'client_id: "<节点ID>"',
      'alias: "<面板显示名>"',
      'tags: ["<标签>"]',
      'tls:',
      '  mode: pin',
      '  pin: "' + p + '"',
      '',
      '# 3) 启动节点',
      './proxygw-client -config /etc/proxygw/config.client.yaml'
    ].join('\n');
  }

  function fallbackWindows(pin) {
    var p = pin || 'sha256/<SPKI指纹>';
    return [
      '# 节点一键接入（Windows PowerShell 示例）',
      'pwsh -File .\\scripts\\install-node.ps1 `',
      '  -Server https://<服务器地址> `',
      '  -Token "<节点接入令牌>" `',
      '  -Pin "' + p + '" `',
      '  -ClientId "<节点ID>" `',
      '  -Tags "<标签>"',
      '',
      '# 或手工编写 config.client.yaml',
      'server_url: "https://<服务器地址>"',
      'token: "<节点接入令牌>"',
      'client_id: "<节点ID>"',
      'tls:',
      '  mode: pin',
      '  pin: "' + p + '"',
      '',
      'Start-Process .\\proxygw-client.exe -ArgumentList "-config","config.client.yaml"'
    ].join('\n');
  }

  /* ================================================================== 提示 / 横幅 / 模态 */

  var banners = {};

  function setBanner(key, text) {
    if (text) banners[key] = text;
    else delete banners[key];
    renderBanner();
  }

  function renderBanner() {
    var banner = $('global-banner');
    var textEl = $('global-banner-text');
    if (!banner || !textEl) return;
    var keys = Object.keys(banners);
    if (!keys.length) {
      banner.hidden = true;
      textEl.textContent = '';
      syncNodesViewportOffset();
      return;
    }
    banner.hidden = false;
    textEl.textContent = keys.map(function (k) { return banners[k]; }).join('　·　');
    syncNodesViewportOffset();
  }

  function toast(message, kind, timeout) {
    var root = $('toast-root');
    if (!root) return;
    kind = kind || 'info';
    var icons = { success: '✓', error: '✕', warn: '!', info: 'i' };
    while (root.children.length >= 6) root.removeChild(root.firstChild);
    var box = el('div', 'toast toast-' + kind);
    var icon = el('span', 'toast-icon', icons[kind] || 'i');
    var text = el('span', 'toast-text');
    text.textContent = String(message === undefined || message === null ? '' : message);
    var close = el('button', 'toast-close', '×');
    close.type = 'button';
    close.setAttribute('aria-label', '关闭提示');
    box.append(icon, text, close);
    root.appendChild(box);
    var timer = null;
    function dismiss() {
      if (!box.isConnected) return;
      if (timer) clearTimeout(timer);
      box.classList.add('toast-out');
      setTimeout(function () {
        if (box.parentNode) box.parentNode.removeChild(box);
      }, 220);
    }
    close.addEventListener('click', dismiss);
    timer = setTimeout(dismiss, timeout || (kind === 'error' ? 8000 : 4500));
  }

  function openModal(options) {
    options = options || {};
    closeModal();
    var overlay = el('div', 'modal-overlay');
    var dialog = el('div', 'modal' + (options.size ? ' modal-' + options.size : ''));
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    if (options.title) dialog.setAttribute('aria-label', options.title);

    var head = el('div', 'modal-head');
    var title = el('h3', 'modal-title', options.title || '');
    var closeBtn = el('button', 'modal-close', '×');
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', '关闭对话框');
    closeBtn.addEventListener('click', closeModal);
    head.append(title, closeBtn);

    var body = el('div', 'modal-body');
    if (options.body) append(body, options.body);

    dialog.append(head, body);
    var footer = null;
    if (options.footer) {
      footer = el('div', 'modal-footer');
      append(footer, options.footer);
      dialog.append(footer);
    }
    overlay.append(dialog);
    overlay.addEventListener('mousedown', function (ev) {
      if (ev.target === overlay) closeModal();
    });

    var root = $('modal-root');
    root.replaceChildren(overlay);
    root.hidden = false;
    document.body.classList.add('modal-open');
    modalState.current = { overlay: overlay, dialog: dialog, body: body, footer: footer, onClose: options.onClose };

    requestAnimationFrame(function () {
      var target = qs('input:not([type="hidden"]),select,textarea', body) || qs('button', footer);
      if (target) {
        try { target.focus(); } catch (e) { /* ignore */ }
      }
    });

    return {
      overlay: overlay,
      dialog: dialog,
      body: body,
      footer: footer,
      close: closeModal
    };
  }

  function closeModal() {
    var current = modalState.current;
    if (!current) return;
    modalState.current = null;
    var root = $('modal-root');
    if (root) {
      root.hidden = true;
      root.replaceChildren();
    }
    document.body.classList.remove('modal-open');
    if (typeof current.onClose === 'function') {
      try { current.onClose(); } catch (e) { /* ignore */ }
    }
  }

  function setBusy(button, busy, busyText) {
    if (!button) return;
    if (busy) {
      if (!button.dataset.prevText) button.dataset.prevText = button.textContent;
      button.disabled = true;
      button.textContent = busyText || '处理中…';
    } else {
      button.disabled = false;
      if (button.dataset.prevText) {
        button.textContent = button.dataset.prevText;
        delete button.dataset.prevText;
      }
    }
  }

  function confirmDialog(options) {
    var body = el('div');
    var p = el('p', 'confirm-text', options.message || '');
    body.append(p);
    if (options.note) body.append(el('p', 'form-note', options.note));
    var cancel = btn('取消', {});
    var confirm = btn(options.confirmText || '确定', {
      variant: options.danger ? 'btn-danger' : 'btn-primary'
    });
    confirm.addEventListener('click', function () {
      if (confirm.disabled) return;
      confirm.disabled = true;
      cancel.disabled = true;
      var oldText = confirm.textContent;
      confirm.textContent = options.busyText || '处理中…';
      Promise.resolve()
        .then(function () { return options.onConfirm(); })
        .then(function () {
          closeModal();
        })
        .catch(function (err) {
          confirm.disabled = false;
          cancel.disabled = false;
          confirm.textContent = oldText;
          showApiError(err);
          applyFieldErrors(body, err);
        });
    });
    cancel.addEventListener('click', closeModal);
    return openModal({
      title: options.title || '确认操作',
      body: body,
      footer: [cancel, confirm],
      size: 'sm'
    });
  }

  /* ================================================================== 表单控件 */

  function field(options) {
    options = options || {};
    var wrap = el('div', 'form-field' + (options.wide ? ' span-2' : ''));
    var id = 'f-' + String(options.name || 'field').replace(/[^a-zA-Z0-9_-]/g, '-') + '-' + (++fieldSeq);
    var label = el('label', null, options.label || '');
    label.htmlFor = id;
    wrap.append(label);

    var input;
    var type = options.type || 'text';
    if (type === 'textarea') {
      input = el('textarea');
      input.rows = options.rows || 3;
    } else if (type === 'select') {
      input = el('select');
      (options.options || []).forEach(function (opt) {
        var option = el('option', null, opt.label !== undefined ? opt.label : opt.value);
        option.value = String(opt.value);
        if (String(opt.value) === String(options.value === undefined || options.value === null ? '' : options.value)) {
          option.selected = true;
        }
        input.append(option);
      });
    } else {
      input = el('input');
      input.type = type;
    }
    input.id = id;
    if (options.name) input.name = options.name;
    if (options.placeholder !== undefined) input.placeholder = options.placeholder;
    if (options.autocomplete !== undefined) input.autocomplete = options.autocomplete;
    if (options.step !== undefined) input.step = options.step;
    if (options.min !== undefined) input.min = options.min;
    if (options.max !== undefined) input.max = options.max;
    if (options.required) input.required = true;
    if (options.disabled) input.disabled = true;
    if (type === 'textarea' || type === 'select') {
      if (options.value !== undefined && options.value !== null) input.value = String(options.value);
    } else if (options.value !== undefined && options.value !== null) {
      input.value = String(options.value);
    }
    wrap.append(input);

    if (options.hint) wrap.append(el('div', 'form-hint', options.hint));
    var error = el('div', 'field-error');
    error.hidden = true;
    wrap.append(error);
    wrap.dataset.field = options.name || '';

    return {
      wrap: wrap,
      input: input,
      error: error,
      id: id,
      get value() { return input.value; },
      set value(v) { input.value = v === undefined || v === null ? '' : String(v); },
      setError: function (message) {
        error.textContent = message || '';
        error.hidden = !message;
        wrap.classList.toggle('has-error', !!message);
      }
    };
  }

  function checkField(options) {
    options = options || {};
    var wrap = el('div', 'form-field' + (options.wide ? ' span-2' : ''));
    var label = el('label', 'check-label');
    var input = el('input');
    input.type = 'checkbox';
    input.checked = !!options.value;
    if (options.name) input.name = options.name;
    label.append(input, el('span', null, options.label || ''));
    wrap.append(label);
    if (options.hint) wrap.append(el('div', 'form-hint', options.hint));
    var error = el('div', 'field-error');
    error.hidden = true;
    wrap.append(error);
    wrap.dataset.field = options.name || '';
    return {
      wrap: wrap,
      input: input,
      error: error,
      get checked() { return input.checked; },
      set checked(v) { input.checked = !!v; },
      setError: function (message) {
        error.textContent = message || '';
        error.hidden = !message;
        wrap.classList.toggle('has-error', !!message);
      }
    };
  }

  function checkGroupField(options) {
    options = options || {};
    var wrap = el('div', 'form-field span-2');
    var label = el('label', null, options.label || '');
    wrap.append(label);
    var group = el('div', 'check-group');
    var inputs = [];
    (options.options || []).forEach(function (opt) {
      var row = el('label', 'check-label');
      var input = el('input');
      input.type = 'checkbox';
      input.value = String(opt.value);
      input.checked = (options.value || []).map(String).indexOf(String(opt.value)) !== -1;
      row.append(input, el('span', null, opt.label !== undefined ? opt.label : opt.value));
      group.append(row);
      inputs.push(input);
    });
    wrap.append(group);
    var empty = el('div', 'form-hint', options.emptyHint || '');
    if (options.emptyHint) wrap.append(empty);
    if (options.hint) wrap.append(el('div', 'form-hint', options.hint));
    var error = el('div', 'field-error');
    error.hidden = true;
    wrap.append(error);
    wrap.dataset.field = options.name || '';
    return {
      wrap: wrap,
      inputs: inputs,
      getValues: function () {
        return inputs.filter(function (i) { return i.checked; }).map(function (i) { return i.value; });
      },
      setError: function (message) {
        error.textContent = message || '';
        error.hidden = !message;
        wrap.classList.toggle('has-error', !!message);
      }
    };
  }

  function setFormAlert(container, message, kind) {
    if (!container) return;
    var alert = qs('.form-alert', container);
    if (!alert) {
      alert = el('div', 'form-alert span-2');
      container.prepend(alert);
    }
    alert.className = 'form-alert span-2' + (kind ? ' ' + kind : '');
    alert.textContent = message || '';
    alert.hidden = !message;
  }

  function applyFieldErrors(container, error) {
    if (!container) return;
    var list = error && error.data && Array.isArray(error.data.field_errors) ? error.data.field_errors : [];
    qsa('.form-field', container).forEach(function (wrap) {
      wrap.classList.remove('has-error');
      var errEl = qs('.field-error', wrap);
      if (errEl) {
        errEl.hidden = true;
        errEl.textContent = '';
      }
    });
    if (!list.length) {
      if (error && error.data && error.code === 'validation_failed') {
        setFormAlert(container, error.message || '提交的数据未通过校验。');
      }
      return;
    }
    var first = null;
    list.forEach(function (fe) {
      var key = String(fe.field || '');
      var target = null;
      qsa('[data-field]', container).forEach(function (wrap) {
        var name = wrap.dataset.field;
        if (!name) return;
        if (name === key || key === name || name.endsWith('.' + key) || key.endsWith('.' + name)) target = wrap;
      });
      if (target) {
        target.classList.add('has-error');
        var errEl = qs('.field-error', target);
        if (errEl) {
          errEl.textContent = fe.message || '校验失败';
          errEl.hidden = false;
        }
        if (!first) first = target;
      }
    });
    setFormAlert(container, '部分字段未通过校验，请检查标红项后重试。' +
      (list.filter(function (f) { return f.message; }).length
        ? '（' + list.map(function (f) { return f.message; }).filter(Boolean).join('；') + '）'
        : ''));
    if (first) {
      var input = qs('input,select,textarea', first);
      if (input) {
        try { input.focus(); } catch (e) { /* ignore */ }
      }
    }
  }

  function wireFormSubmit(form, submitButton, submitFn) {
    var hiddenSubmit = el('button');
    hiddenSubmit.type = 'submit';
    hiddenSubmit.style.display = 'none';
    form.append(hiddenSubmit);
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      submitFn();
    });
    submitButton.addEventListener('click', function (ev) {
      ev.preventDefault();
      submitFn();
    });
  }

  function formModal(options) {
    var form = el('form', 'form-grid');
    form.noValidate = true;
    if (options.note) form.append(el('p', 'form-note span-2', options.note));
    (options.fields || []).forEach(function (widget) {
      if (widget && widget.wrap) form.append(widget.wrap);
      else if (widget instanceof Node) form.append(widget);
    });
    var bodyWrap = el('div');
    bodyWrap.append(form);

    var cancel = btn('取消', {});
    cancel.addEventListener('click', closeModal);
    var submit = btn(options.submitText || '保存', {
      variant: options.submitVariant || 'btn-primary'
    });
    submit.type = 'button';

    var modal = openModal({
      title: options.title || '编辑',
      body: bodyWrap,
      footer: [cancel, submit],
      size: options.size || 'md'
    });

    wireFormSubmit(form, submit, function () {
      if (form.dataset.busy === '1') return;
      form.dataset.busy = '1';
      setBusy(submit, true, '处理中…');
      cancel.disabled = true;
      setFormAlert(form, '');
      Promise.resolve()
        .then(function () { return options.onSubmit(form); })
        .catch(function (err) {
          showApiError(err);
          applyFieldErrors(form, err);
        })
        .then(function () {
          form.dataset.busy = '0';
          setBusy(submit, false);
          cancel.disabled = false;
        });
    });
    return modal;
  }

  /* ================================================================== API 层 */

  function ApiError(code, message, status, data) {
    this.name = 'ApiError';
    this.code = code || 'error';
    this.message = message || code || '请求失败';
    this.status = status || 0;
    this.data = data || null;
    if (Error.captureStackTrace) Error.captureStackTrace(this, ApiError);
  }
  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  var HTTP_MESSAGES = {
    400: '请求参数有误',
    401: '未登录或登录已过期',
    403: '没有权限执行该操作',
    404: '对象不存在或已被删除',
    405: '请求方法不被允许',
    409: '操作冲突，请刷新后重试',
    422: '提交的数据未通过校验',
    429: '请求过于频繁，请稍后重试',
    500: '服务器内部错误',
    502: '网关或上游服务错误',
    503: '当前没有可用资源',
    504: '上游服务超时'
  };

  function errorMessage(code, status) {
    switch (code) {
      case 'invalid_credentials': return '用户名或密码错误';
      case 'totp_required': return '需要 TOTP 验证码';
      case 'locked_out': return '登录失败次数过多，已临时锁定';
      case 'csrf_invalid': return '会话校验失败，请重新登录';
      case 'unauthorized': return '登录已过期，请重新登录';
      case 'not_found': return '对象不存在或已被删除';
      case 'group_in_use': return '该节点组仍被凭据引用，无法删除';
      case 'validation_failed': return '提交的数据未通过校验';
      case 'conflict': return '操作冲突，请刷新后重试';
      case 'internal_error': return '服务器内部错误';
      case 'overloaded': return '服务过载，请稍后重试';
      case 'network': return '无法连接服务器，请检查网络';
      default:
        return HTTP_MESSAGES[status] || (code ? '请求失败（' + code + '）' : '请求失败');
    }
  }

  function api(path, options) {
    options = options || {};
    var method = String(options.method || 'GET').toUpperCase();
    var headers = { Accept: 'application/json' };
    var init = { method: method, headers: headers, credentials: 'same-origin', cache: 'no-store' };
    if (method !== 'GET' && method !== 'HEAD') {
      if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
      if (options.body !== undefined) {
        headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(options.body);
      }
    }
    if (options.signal) init.signal = options.signal;

    return fetch(API + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try { data = JSON.parse(text); } catch (e) { data = null; }
        }
        if (res.status === 401) {
          var code = data && data.error;
          if (code === 'unauthorized' || !code) {
            handleUnauthorized();
            throw new ApiError('unauthorized', '登录已过期，请重新登录', 401, data);
          }
        }
        if (res.status === 403 && data && data.error === 'csrf_invalid') {
          handleUnauthorized('csrf');
          throw new ApiError('csrf_invalid', '会话校验失败，请重新登录', 403, data);
        }
        if (!res.ok) {
          var errCode = (data && data.error) || ('http_' + res.status);
          var message = (data && data.message) || errorMessage(errCode, res.status);
          if (res.status >= 500) setBanner('server', '服务器错误（HTTP ' + res.status + '）：' + message);
          throw new ApiError(errCode, message, res.status, data);
        }
        setBanner('network', null);
        setBanner('server', null);
        return data;
      });
    }).catch(function (err) {
      if (err instanceof ApiError) throw err;
      if (err && err.name === 'AbortError') throw err;
      setBanner('network', '无法连接面板服务器，请检查网络或服务端状态。');
      throw new ApiError('network', '网络错误，无法连接服务器', 0, null);
    });
  }

  function handleUnauthorized(reason) {
    if (state.handling401) return;
    var wasLoggedIn = !!state.session;
    state.handling401 = true;
    state.session = null;
    state.csrf = '';
    stopSSE();
    stopLive();
    closeModal();
    resetDataState();
    showLogin();
    if (wasLoggedIn) {
      toast(reason === 'csrf'
        ? '会话校验失败（可能已过期或跨站保护触发），请重新登录。'
        : '登录状态已失效，请重新登录。', 'warn', 6000);
    }
    setTimeout(function () { state.handling401 = false; }, 700);
  }

  function showApiError(err) {
    if (!err) return;
    if (err.name === 'AbortError') return;
    if (err.code === 'unauthorized' || err.code === 'csrf_invalid') return;
    if (err.code === 'network') {
      setBanner('network', err.message || '网络错误');
      return;
    }
    if (err.status >= 500) {
      setBanner('server', '服务器错误：' + (err.message || '请稍后重试'));
      return;
    }
    toast(err.message || errorMessage(err.code, err.status), 'error');
  }

  function resetDataState() {
    state.overview = null;
    state.nodes = { items: [], total: 0, summary: {}, page: 1, size: 50, loaded: false, lastFetch: 0 };
    state.groups = { items: [], loaded: false };
    state.credentials = { items: [], loaded: false };
    state.settings = null;
    state.sticky = { items: [], loaded: false };
    state.acl = { items: [], loaded: false, defaultAction: '' };
    state.aclForced = { items: [], loaded: false };
    state.audit = { items: [], expanded: new Set(), oldest: null, canMore: false, loaded: false, loading: false };
    state.cert = null;
    state.geo = { items: [], loaded: false };
  }

  /* ================================================================== 复制 */

  function legacyCopy(value) {
    var ta = el('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, value.length);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    if (!ok) throw new Error('copy failed');
  }

  function copyText(value) {
    var text = String(value === undefined || value === null ? '' : value);
    if (!text) {
      toast('没有可复制的内容', 'warn');
      return Promise.resolve(false);
    }
    var doLegacy = function () {
      try {
        legacyCopy(text);
        toast('已复制到剪贴板', 'success', 2200);
        return true;
      } catch (e) {
        toast('复制失败，请手动选择文本复制', 'error');
        return false;
      }
    };
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () {
        toast('已复制到剪贴板', 'success', 2200);
        return true;
      }).catch(function () { return doLegacy(); });
    }
    return Promise.resolve(doLegacy());
  }

  /* ================================================================== 登录 / 路由 */

  function showLogin() {
    var boot = $('boot-screen');
    if (boot) boot.hidden = true;
    var login = $('login-view');
    if (login) login.hidden = false;
    var app = $('app-view');
    if (app) app.hidden = true;
    var errEl = $('login-error');
    if (errEl) {
      errEl.hidden = true;
      errEl.textContent = '';
    }
    document.title = '登录 · proxygw 管理面板';
    document.body.classList.remove('app-nav-open', 'modal-open');
    setTimeout(function () {
      var u = $('login-username');
      if (u && !u.value) {
        try { u.focus(); } catch (e) { /* ignore */ }
      } else {
        var p = $('login-password');
        if (p) { try { p.focus(); } catch (e) { /* ignore */ } }
      }
    }, 40);
  }

  function enterApp() {
    var boot = $('boot-screen');
    if (boot) boot.hidden = true;
    var login = $('login-view');
    if (login) login.hidden = true;
    var app = $('app-view');
    if (app) app.hidden = false;
    setText('admin-name', (state.session && state.session.username) || '');
    var admin = $('admin-name');
    if (admin) admin.title = '当前管理员：' + ((state.session && state.session.username) || '');
    var page = pageFromHash();
    state.page = page;
    showPage(page);
    connectSSE();
  }

  function pageFromHash() {
    var hash = String(location.hash || '').replace(/^#\/?/, '').trim();
    return PAGE_TITLES[hash] ? hash : 'overview';
  }

  function go(page) {
    if (!PAGE_TITLES[page]) page = 'overview';
    if (pageFromHash() === page) {
      onRouteChange();
      return;
    }
    location.hash = '#/' + page;
  }

  function onRouteChange() {
    if (!state.session) return;
    var page = pageFromHash();
    showPage(page);
  }

  function showPage(page) {
    if (!PAGE_TITLES[page]) page = 'overview';
    state.page = page;
    qsa('.page').forEach(function (section) {
      section.hidden = section.dataset.page !== page;
    });
    qsa('.nav-item').forEach(function (navBtn) {
      var active = navBtn.dataset.page === page;
      navBtn.classList.toggle('active', active);
      if (active) navBtn.setAttribute('aria-current', 'page');
      else navBtn.removeAttribute('aria-current');
    });
    document.title = 'proxygw · ' + PAGE_TITLES[page] + ' · 管理面板';
    document.body.classList.remove('app-nav-open');
    var toggle = qs('[data-action="toggle-nav"]');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
    closeModal();
    closeNodeColumnsMenu();
    stopLive();
    updateLiveStatus();
    var loader = LOADERS[page];
    loadingPage = true;
    Promise.resolve()
      .then(function () { return loader ? loader() : null; })
      .catch(function (err) { showApiError(err); })
      .then(function () {
        loadingPage = false;
        scheduleLive();
        updateLiveStatus();
      });
  }

  function refreshCurrentPage() {
    if (!state.session) return;
    closeModal();
    var loader = LOADERS[state.page];
    if (!loader) return;
    toast('正在刷新「' + PAGE_TITLES[state.page] + '」…', 'info', 1800);
    Promise.resolve()
      .then(function () { return loader(); })
      .catch(function (err) { showApiError(err); });
  }

  function onLoginSubmit(ev) {
    ev.preventDefault();
    var form = $('login-form');
    if (!form || form.dataset.busy === '1') return;
    var username = ($('login-username').value || '').trim();
    var password = $('login-password').value || '';
    var totp = ($('login-totp').value || '').trim();
    var errorEl = $('login-error');
    errorEl.hidden = true;
    errorEl.textContent = '';
    if (!username || !password) {
      showLoginError('请输入用户名和密码。');
      return;
    }
    var submit = $('login-submit');
    form.dataset.busy = '1';
    setBusy(submit, true, '登录中…');
    var body = { username: username, password: password };
    if (totp) body.totp = totp;
    api('/login', { method: 'POST', body: body })
      .then(function (session) {
        state.session = session;
        state.csrf = (session && session.csrf) || '';
        $('login-password').value = '';
        $('login-totp').value = '';
        toast('登录成功，欢迎 ' + ((session && session.username) || username), 'success');
        enterApp();
      })
      .catch(function (err) {
        if (err && err.code === 'locked_out') {
          var seconds = err.data && err.data.retry_after_seconds;
          showLoginError('登录失败次数过多，已临时锁定。' +
            (seconds ? '请在 ' + seconds + ' 秒后重试。' : '请稍后重试。'));
        } else if (err && err.code === 'invalid_credentials') {
          showLoginError((err.data && err.data.message) || '用户名或密码错误。');
          try { $('login-password').select(); } catch (e) { /* ignore */ }
        } else if (err && err.code === 'totp_required') {
          showLoginError('该账号已启用 TOTP 二次验证，请填写 6 位验证码后重试。');
          try { $('login-totp').focus(); } catch (e) { /* ignore */ }
        } else if (err && err.code === 'network') {
          showLoginError('无法连接服务器，请检查网络或服务端状态。');
        } else {
          showLoginError((err && err.message) || '登录失败，请稍后重试。');
        }
      })
      .then(function () {
        form.dataset.busy = '0';
        setBusy(submit, false);
      });
  }

  function showLoginError(message) {
    var errorEl = $('login-error');
    if (!errorEl) return;
    errorEl.textContent = message || '登录失败';
    errorEl.hidden = false;
  }

  function logout() {
    api('/logout', { method: 'POST' })
      .catch(function () { /* 忽略退出错误，本地状态照常清理 */ })
      .then(function () {
        state.session = null;
        state.csrf = '';
        stopSSE();
        stopLive();
        closeModal();
        resetDataState();
        showLogin();
        toast('已退出登录', 'info');
      });
  }

  /* ================================================================== 实时数据（SSE + 轮询） */

  function isLivePage() {
    return state.page === 'overview' || state.page === 'nodes';
  }

  function scheduleLive() {
    stopLive();
    if (!state.session || document.hidden || !isLivePage()) {
      updateLiveStatus();
      return;
    }
    if (state.sse.connected) {
      updateLiveStatus();
      return;
    }
    state.live.timer = setInterval(livePoll, 3000);
    updateLiveStatus();
  }

  function stopLive() {
    if (state.live.timer) {
      clearInterval(state.live.timer);
      state.live.timer = null;
    }
  }

  function livePoll() {
    if (document.hidden || !state.session || !isLivePage() || state.sse.connected) return;
    silentLiveRefresh();
  }

  function silentLiveRefresh() {
    var now = Date.now();
    if (now - state.live.lastRefresh < 1800) return;
    state.live.lastRefresh = now;
    var loader = state.page === 'nodes' ? loadNodes : loadOverview;
    Promise.resolve(loader({ silent: true })).catch(function () { /* api 层已提示 */ });
  }

  function throttled(key, fn, gap) {
    var now = Date.now();
    if (now - (state.live.throttle[key] || 0) < (gap || 2800)) return;
    state.live.throttle[key] = now;
    try { fn(); } catch (e) { /* ignore */ }
  }

  function updateLiveStatus() {
    var chipEl = $('live-status');
    if (!chipEl) return;
    if (!state.session || !isLivePage()) {
      chipEl.hidden = true;
      return;
    }
    chipEl.hidden = false;
    chipEl.classList.remove('poll', 'paused');
    if (document.hidden) {
      chipEl.textContent = '实时数据已暂停';
      chipEl.classList.add('paused');
      chipEl.title = '页面隐藏时暂停轮询';
    } else if (state.sse.connected) {
      chipEl.textContent = '实时推送';
      chipEl.title = 'SSE 实时推送已连接';
    } else {
      chipEl.textContent = '3 秒轮询';
      chipEl.classList.add('poll');
      chipEl.title = 'SSE 不可用，已降级为 3 秒轮询';
    }
  }

  function connectSSE() {
    if (!state.session) return;
    stopSSE();
    if (typeof EventSource !== 'function') {
      setBanner('sse', '当前浏览器不支持 SSE，已降级为 3 秒轮询。');
      scheduleLive();
      return;
    }
    var es;
    try {
      es = new EventSource(API + '/events');
    } catch (e) {
      setBanner('sse', '实时推送建立失败，已降级为 3 秒轮询。');
      scheduleLive();
      scheduleSSEReconnect();
      return;
    }
    state.sse.es = es;
    es.onopen = function () {
      state.sse.connected = true;
      state.sse.retry = 0;
      state.sse.everConnected = true;
      setBanner('sse', null);
      scheduleLive();
      updateLiveStatus();
    };
    es.onmessage = function (ev) {
      handleSSEMessage(ev && ev.data);
    };
    es.onerror = function () {
      if (!state.session) {
        try { es.close(); } catch (e) { /* ignore */ }
        return;
      }
      var wasConnected = state.sse.connected;
      state.sse.connected = false;
      try { es.close(); } catch (e) { /* ignore */ }
      state.sse.es = null;
      setBanner('sse', wasConnected
        ? '实时推送连接已断开，已自动降级为 3 秒轮询，正在尝试重连…'
        : '实时推送暂不可用，已自动降级为 3 秒轮询，正在尝试重连…');
      scheduleLive();
      updateLiveStatus();
      scheduleSSEReconnect();
    };
  }

  function scheduleSSEReconnect() {
    if (state.sse.timer) {
      clearTimeout(state.sse.timer);
      state.sse.timer = null;
    }
    if (!state.session) return;
    var attempt = state.sse.retry || 0;
    state.sse.retry = attempt + 1;
    var delay = Math.min(30000, 4000 * Math.pow(1.7, attempt));
    state.sse.timer = setTimeout(function () {
      state.sse.timer = null;
      if (state.session) connectSSE();
    }, delay);
  }

  function stopSSE() {
    if (state.sse.timer) {
      clearTimeout(state.sse.timer);
      state.sse.timer = null;
    }
    if (state.sse.es) {
      try { state.sse.es.close(); } catch (e) { /* ignore */ }
      state.sse.es = null;
    }
    state.sse.connected = false;
    state.sse.retry = 0;
  }

  function hasOverviewShape(obj) {
    if (!obj || typeof obj !== 'object') return false;
    var keys = ['online_nodes', 'nodes_total', 'unique_egress_ips', 'active_connections', 'requests', 'trend', 'transport_mix', 'cert'];
    return keys.some(function (k) {
      return Object.prototype.hasOwnProperty.call(obj, k);
    });
  }

  function handleSSEMessage(raw) {
    var msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (!msg || typeof msg !== 'object') return;

    var sseClockSkew = null;
    if (typeof msg.clock_skew_ms === 'number') sseClockSkew = msg.clock_skew_ms;
    else if (msg.overview && typeof msg.overview.clock_skew_ms === 'number') sseClockSkew = msg.overview.clock_skew_ms;

    var usedOverview = false;
    var usedNodes = false;
    var overviewPayload = null;
    if (msg.overview && typeof msg.overview === 'object') overviewPayload = msg.overview;
    else if (hasOverviewShape(msg)) overviewPayload = msg;

    if (overviewPayload) {
      usedOverview = true;
      applyOverview(Object.assign({}, state.overview || {}, overviewPayload));
    }
    if (sseClockSkew !== null) {
      state.clockSkew = sseClockSkew;
      renderClockSkew();
    }
    var nodesPayload = null;
    if (Array.isArray(msg.nodes)) nodesPayload = msg.nodes;
    else if (Array.isArray(msg.node_stats)) nodesPayload = msg.node_stats;
    if (nodesPayload) {
      usedNodes = true;
      mergeNodesLight(nodesPayload);
    }

    if (state.page === 'overview' && !usedOverview) {
      throttled('sse-overview', function () { loadOverview({ silent: true }); });
    }
    if (state.page === 'nodes' && !usedNodes) {
      throttled('sse-nodes', function () { loadNodes({ silent: true }); });
    }
  }

  function mergeNodesLight(list) {
    if (!Array.isArray(list) || !list.length) return;
    if (!state.nodes.items.length) return;
    var map = new Map();
    state.nodes.items.forEach(function (node) { map.set(node.id, node); });
    var changed = false;
    list.forEach(function (update) {
      if (!update || !update.id) return;
      var current = map.get(update.id);
      if (!current) return;
      map.set(update.id, Object.assign({}, current, update));
      changed = true;
    });
    if (!changed) return;
    state.nodes.items = Array.from(map.values());
    if (state.page === 'nodes') {
      renderNodesTable();
      renderNodesSummary();
    }
  }

  function onVisibilityChange() {
    if (!state.session) return;
    if (document.hidden) {
      stopLive();
      updateLiveStatus();
      return;
    }
    updateLiveStatus();
    var loader = LOADERS[state.page];
    if (loader) {
      Promise.resolve()
        .then(function () { return loader({ silent: true }); })
        .catch(function () { /* ignore */ });
    }
    if (!state.sse.connected) connectSSE();
    scheduleLive();
  }

  /* ================================================================== 通用渲染 */

  function tableMessage(tbody, colspan, message, options) {
    if (!tbody) return;
    options = options || {};
    var row = el('tr');
    var td = el('td', 'table-message');
    td.colSpan = colspan;
    if (options.loading) {
      td.append(el('span', 'spinner-xs'));
    }
    td.append(document.createTextNode(message || ''));
    if (options.actionLabel) {
      var actionBtn = btn(options.actionLabel, { small: true });
      if (options.action) {
        actionBtn.dataset.action = options.action;
        if (options.actionId) actionBtn.dataset.id = options.actionId;
      }
      actionBtn.addEventListener('click', function () {
        if (options.onAction) options.onAction();
      });
      td.append(actionBtn);
    }
    row.append(td);
    tbody.replaceChildren(row);
  }

  function emptyRow(tbody, colspan, message) {
    tableMessage(tbody, colspan, message || '暂无数据。');
  }

  function kvRow(dl, label, value, className) {
    dl.append(el('dt', null, label));
    var dd = el('dd', className || null);
    if (value instanceof Node) dd.append(value);
    else dd.textContent = value === undefined || value === null || value === '' ? '—' : String(value);
    dl.append(dd);
  }

  function renderNodeMiniTable(nodes, emptyText) {
    var wrap = el('div', 'table-wrap');
    if (!Array.isArray(nodes) || !nodes.length) {
      wrap.append(el('div', 'empty-state', emptyText || '没有节点。'));
      return wrap;
    }
    var table = el('table', 'data-table mini');
    var thead = el('thead');
    var headRow = el('tr');
    ['节点', '在线', '出口 IP', '国家/地区', '延迟'].forEach(function (title) {
      headRow.append(el('th', null, title));
    });
    thead.append(headRow);
    var tbody = el('tbody');
    nodes.forEach(function (node) {
      var tr = el('tr');
      var tdNode = el('td');
      tdNode.append(el('span', 'cell-main', node.alias || node.id || '—'));
      tdNode.append(el('span', 'cell-sub', node.id || ''));
      tr.append(tdNode);
      var tdOnline = el('td');
      tdOnline.append(node.online ? badge('在线', 'online') : badge('离线', 'offline'));
      tr.append(tdOnline);
      var tdEgress = el('td');
      tdEgress.append(el('span', 'cell-code', (node.egress_ip && node.egress_ip.v4) || '—'));
      tr.append(tdEgress);
      var tdGeo = el('td');
      var geo = node.geo || {};
      tdGeo.append(document.createTextNode(countryLabel(geo.country)));
      if (geo.city || geo.region) {
        tdGeo.append(el('span', 'cell-sub', [geo.city, geo.region].filter(Boolean).join(' / ')));
      }
      tr.append(tdGeo);
      var tdLatency = el('td', 'col-num', fmtLatency(node.latency_ewma_ms));
      tr.append(tdLatency);
      tbody.append(tr);
    });
    table.append(thead, tbody);
    wrap.append(table);
    return wrap;
  }

  /* ================================================================== 总览 */

  function loadOverview(options) {
    options = options || {};
    return api('/overview').then(function (data) {
      state.overview = data;
      if (typeof data.clock_skew_ms === 'number') {
        state.clockSkew = data.clock_skew_ms;
        renderClockSkew();
      }
      applyOverview(data);
      var upd = $('overview-updated');
      if (upd) upd.textContent = '更新于 ' + fmtDateTime(Date.now());
      loadTunnelSessions();
      loadTopN();
    }).catch(function (err) {
      if (!options.silent) throw err;
    });
  }

  function applyOverview(data) {
    if (!data) return;
    state.overview = Object.assign({}, state.overview || {}, data);
    setText('metric-online-nodes', fmtNum(data.online_nodes));
    setText('metric-online-sub', '共 ' + fmtNum(data.nodes_total) + ' 个节点');
    setText('metric-unique-ips', fmtNum(data.unique_egress_ips));
    setText('metric-active-conns', fmtNum(data.active_connections));
    var requests = data.requests || {};
    setText('stat-requests', fmtNum(requests.total));
    setText('stat-errors', fmtNum(requests.errors));
    setText('stat-retries', fmtNum(requests.retries));
    setText('stat-rate-limited', fmtNum(requests.rate_limited));
    setText('stat-breaker-trips', fmtNum(requests.breaker_trips));
    renderSparkline(Array.isArray(data.trend) ? data.trend : []);
    renderTransportMix(data.transport_mix || {});
    renderOverviewCert(data.cert);
    renderOverviewSettings(data);
    var upd = $('overview-updated');
    if (upd) upd.textContent = '更新于 ' + fmtDateTime(Date.now());
  }

  function renderSparkline(rawTrend) {
    var container = $('overview-sparkline');
    var legend = $('overview-sparkline-legend');
    var note = $('overview-trend-note');
    if (!container) return;
    if (legend) legend.replaceChildren();
    var raw = Array.isArray(rawTrend) ? rawTrend.slice() : [];
    var points = [];
    raw.forEach(function (point) {
      var d = toDate(point && point.ts);
      if (!d) return;
      points.push(Object.assign({}, point, { _ms: d.getTime() }));
    });
    points.sort(function (a, b) { return a._ms - b._ms; });
    if (!points.length) {
      container.replaceChildren(el('div', 'spark-empty', '暂无趋势数据（服务端未返回 trend，可能刚启动或趋势缓冲为空）'));
      if (note) note.textContent = '';
      return;
    }
    var windowMs = 15 * 60 * 1000;
    var lastMs = points[points.length - 1]._ms;
    var trend = points.filter(function (point) { return point._ms >= lastMs - windowMs; });
    if (!trend.length) {
      container.replaceChildren(el('div', 'spark-empty', '最近 15 分钟暂无趋势数据'));
      if (note) note.textContent = '';
      return;
    }
    var series = [
      { key: 'requests', label: '请求', cls: 'requests', color: 'swatch-requests' },
      { key: 'errors', label: '错误', cls: 'errors', color: 'swatch-errors' },
      { key: 'active', label: '活跃连接', cls: 'active', color: 'swatch-active' }
    ];
    var width = 640;
    var height = 190;
    var pad = { l: 8, r: 8, t: 12, b: 26 };
    var last = trend[trend.length - 1] || {};

    if (legend) {
      series.forEach(function (s) {
        var item = el('span', 'legend-item');
        item.append(el('span', 'legend-swatch ' + s.color));
        item.append(document.createTextNode(s.label + ' '));
        item.append(el('span', 'legend-value', fmtNum(last[s.key])));
        legend.append(item);
      });
    }

    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'sparkline-svg');
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', '最近 15 分钟请求、错误、活跃连接趋势，悬停查看数据');

    for (var g = 0; g <= 3; g++) {
      var gy = pad.t + ((height - pad.t - pad.b) * g) / 3;
      var grid = document.createElementNS(ns, 'line');
      grid.setAttribute('x1', String(pad.l));
      grid.setAttribute('y1', String(gy));
      grid.setAttribute('x2', String(width - pad.r));
      grid.setAttribute('y2', String(gy));
      grid.setAttribute('class', 'spark-grid');
      svg.append(grid);
    }

    var firstLabel = document.createElementNS(ns, 'text');
    firstLabel.setAttribute('x', String(pad.l));
    firstLabel.setAttribute('y', String(height - 7));
    firstLabel.setAttribute('class', 'spark-axis');
    firstLabel.textContent = fmtTimeHM(trend[0].ts);
    svg.append(firstLabel);
    if (trend.length > 1) {
      var lastLabel = document.createElementNS(ns, 'text');
      lastLabel.setAttribute('x', String(width - pad.r));
      lastLabel.setAttribute('y', String(height - 7));
      lastLabel.setAttribute('text-anchor', 'end');
      lastLabel.setAttribute('class', 'spark-axis');
      lastLabel.textContent = fmtTimeHM(last.ts);
      svg.append(lastLabel);
    }

    var innerW = width - pad.l - pad.r;
    var innerH = height - pad.t - pad.b;
    var seriesData = [];
    series.forEach(function (s) {
      var values = trend.map(function (point) {
        var v = Number(point && point[s.key]);
        return Number.isFinite(v) ? v : 0;
      });
      var max = Math.max.apply(null, values);
      if (!(max > 0)) max = 1;
      var yFor = function (v) {
        return pad.t + innerH - (Math.max(0, v) / max) * innerH;
      };
      var pointsAttr = values.map(function (v, index) {
        var x = pad.l + (trend.length === 1 ? innerW / 2 : (innerW * index) / (trend.length - 1));
        return x.toFixed(2) + ',' + yFor(v).toFixed(2);
      });
      var polyline = document.createElementNS(ns, 'polyline');
      polyline.setAttribute('points', pointsAttr.join(' '));
      polyline.setAttribute('class', 'spark-line spark-' + s.cls);
      svg.append(polyline);
      var lastPoint = pointsAttr[pointsAttr.length - 1].split(',');
      var dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', lastPoint[0]);
      dot.setAttribute('cy', lastPoint[1]);
      dot.setAttribute('r', '3');
      dot.setAttribute('class', 'spark-dot spark-' + s.cls);
      svg.append(dot);
      seriesData.push({ s: s, values: values, max: max, yFor: yFor });
    });

    var crosshair = document.createElementNS(ns, 'line');
    crosshair.setAttribute('x1', '0');
    crosshair.setAttribute('x2', '0');
    crosshair.setAttribute('y1', String(pad.t));
    crosshair.setAttribute('y2', String(height - pad.b));
    crosshair.setAttribute('class', 'spark-crosshair');
    crosshair.style.visibility = 'hidden';
    svg.append(crosshair);
    var hoverDots = seriesData.map(function (data) {
      var dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('r', '4');
      dot.setAttribute('class', 'spark-hover-dot spark-' + data.s.cls);
      dot.style.visibility = 'hidden';
      svg.append(dot);
      return dot;
    });

    container.replaceChildren(svg);
    var tip = el('div', 'spark-tooltip');
    tip.style.display = 'none';
    container.append(tip);

    function hideTip() {
      tip.style.display = 'none';
      crosshair.style.visibility = 'hidden';
      hoverDots.forEach(function (dot) { dot.style.visibility = 'hidden'; });
    }

    function showTip(evt) {
      var rect = svg.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      var x = ((evt.clientX - rect.left) / rect.width) * width;
      var ratio = trend.length === 1 ? 0 : (x - pad.l) / innerW;
      var index = Math.max(0, Math.min(trend.length - 1, Math.round(ratio * (trend.length - 1))));
      var point = trend[index];
      var crossX = pad.l + (trend.length === 1 ? innerW / 2 : (innerW * index) / (trend.length - 1));
      crosshair.setAttribute('x1', String(crossX));
      crosshair.setAttribute('x2', String(crossX));
      crosshair.style.visibility = 'visible';

      seriesData.forEach(function (data, i) {
        var value = data.values[index];
        hoverDots[i].setAttribute('cx', String(crossX));
        hoverDots[i].setAttribute('cy', String(data.yFor(value)));
        hoverDots[i].style.visibility = 'visible';
      });

      var time = el('div', 'spark-tip-time', fmtDateTime(point.ts));
      var rows = el('div', 'spark-tip-rows');
      series.forEach(function (s) {
        var row = el('div', 'spark-tip-row');
        row.append(el('span', 'legend-swatch ' + s.color));
        row.append(el('span', 'spark-tip-label', s.label));
        row.append(el('span', 'spark-tip-value', fmtNum(point[s.key])));
        rows.append(row);
      });
      tip.replaceChildren(time, rows);
      tip.style.display = 'block';

      var box = container.getBoundingClientRect();
      var left = evt.clientX - box.left + 12;
      var top = evt.clientY - box.top + 12;
      if (left + tip.offsetWidth > container.clientWidth - 6) {
        left = evt.clientX - box.left - tip.offsetWidth - 12;
      }
      if (top + tip.offsetHeight > container.clientHeight - 6) {
        top = container.clientHeight - tip.offsetHeight - 6;
      }
      tip.style.left = Math.max(4, left) + 'px';
      tip.style.top = Math.max(4, top) + 'px';
    }

    svg.addEventListener('mousemove', showTip);
    svg.addEventListener('mouseleave', hideTip);
    svg.addEventListener('touchstart', function (evt) {
      if (evt.touches && evt.touches.length) {
        var touch = evt.touches[0];
        showTip({ clientX: touch.clientX, clientY: touch.clientY });
      }
    }, { passive: true });

    if (note) {
      note.textContent = '窗口：15 分钟 · 数据点 ' + trend.length + ' 个 · 从 ' +
        fmtTimeHM(trend[0].ts) + ' 到 ' + fmtTimeHM(last.ts) +
        '（三条曲线各自独立归一化；悬停查看具体数值）';
    }
  }

  function renderTransportMix(mix) {
    var container = $('overview-transport');
    if (!container) return;
    container.replaceChildren();
    var quic = Number(mix.quic) || 0;
    var ws = Number(mix.ws) || 0;
    var total = quic + ws;
    if (!total) {
      container.append(el('p', 'muted small', '暂无传输连接数据。'));
      return;
    }
    [['quic', 'QUIC', quic], ['ws', 'WebSocket', ws]].forEach(function (item) {
      var row = el('div', 'mix-row');
      var top = el('div', 'mix-top');
      var label = el('span', null, item[1] + ' 连接');
      var value = el('span');
      var percent = Math.round((item[2] / total) * 100);
      value.append(el('strong', null, String(item[2])));
      value.append(document.createTextNode(' 条 · ' + percent + '%'));
      top.append(label, value);
      var bar = el('div', 'mix-bar');
      var fill = el('div', 'mix-fill mix-' + item[0]);
      fill.style.width = percent + '%';
      bar.append(fill);
      row.append(top, bar);
      container.append(row);
    });
    container.append(el('p', 'muted small', '共 ' + total + ' 条传输连接（每节点可有多平面）'));
  }

  function certExpiryInfo(notAfter) {
    var days = daysUntil(notAfter);
    if (days === null) return { label: '未知', variant: 'muted', text: '—', days: null };
    if (days < 0) return { label: '已过期 ' + Math.abs(days) + ' 天', variant: 'expired', text: fmtDateTime(notAfter), days: days };
    if (days <= 7) return { label: '即将到期（' + days + ' 天）', variant: 'expired', text: fmtDateTime(notAfter), days: days };
    if (days <= 30) return { label: '即将到期（' + days + ' 天）', variant: 'expiring', text: fmtDateTime(notAfter), days: days };
    return { label: '有效（剩余 ' + days + ' 天）', variant: 'ok', text: fmtDateTime(notAfter), days: days };
  }

  function renderOverviewCert(cert) {
    var container = $('overview-cert');
    if (!container) return;
    container.replaceChildren();
    if (!cert) {
      container.append(el('p', 'muted small', '总览未返回证书信息，请到「证书」页查看。'));
      return;
    }
    var mode = modeLabel(cert.mode);
    var rowMode = el('div', 'cert-row');
    rowMode.append(el('span', 'label', '模式'));
    var modeValue = el('span');
    modeValue.append(badge(mode.label, mode.variant));
    rowMode.append(modeValue);
    container.append(rowMode);

    var rowPin = el('div', 'cert-row');
    rowPin.append(el('span', 'label', 'pin'));
    var pinWrap = el('span', 'cert-pin-line');
    var pinCode = el('code', null, cert.pin || '—');
    pinCode.title = cert.pin || '';
    pinWrap.append(pinCode);
    if (cert.pin) {
      var copyPin = btn('复制', { small: true });
      copyPin.addEventListener('click', function () { copyText(cert.pin); });
      pinWrap.append(copyPin);
    }
    rowPin.append(pinWrap);
    container.append(rowPin);

    var expiry = certExpiryInfo(cert.not_after);
    var rowExpiry = el('div', 'cert-row');
    rowExpiry.append(el('span', 'label', '到期'));
    var expiryValue = el('span');
    expiryValue.append(document.createTextNode(expiry.text + ' '));
    expiryValue.append(badge(expiry.label, expiry.variant));
    rowExpiry.append(expiryValue);
    container.append(rowExpiry);
  }

  function renderOverviewSettings(data) {
    var container = $('overview-settings');
    if (!container) return;
    container.replaceChildren();
    var dl = el('dl', 'kv');
    kvRow(dl, '设置版本', data.settings_version === undefined || data.settings_version === null
      ? '—' : 'v' + data.settings_version);
    var version = data.version || {};
    kvRow(dl, '服务端版本', version.version || 'dev');
    kvRow(dl, 'Commit', version.commit || 'none');
    kvRow(dl, 'Go 版本', version.go_version || '—');
    container.append(dl);
    container.append(el('p', 'muted small', '运行设置修改后立即热生效并持久化，可在「运行设置」页调整。'));
  }

  function loadTunnelSessions() {
    var container = $('overview-tunnels');
    if (!container) return Promise.resolve();
    return api('/tunnel/sessions').then(function (data) {
      renderTunnelSessions(container, data);
    }).catch(function () {
      if (container) {
        container.replaceChildren(el('p', 'muted small', '隧道会话状态暂不可用。'));
      }
    });
  }

  function renderTunnelSessions(container, data) {
    if (!container) return;
    container.replaceChildren();
    var items = (data && Array.isArray(data.items)) ? data.items : [];
    if (!items.length) {
      container.append(el('p', 'muted small', '当前没有在线隧道会话。'));
      return;
    }
    var table = el('table', 'data-table mini');
    var thead = el('thead');
    var headRow = el('tr');
    ['节点', '传输', '状态', '平面', '已连接', '最近错误'].forEach(function (t) { headRow.append(el('th', null, t)); });
    thead.append(headRow);
    var tbody = el('tbody');
    items.slice(0, 8).forEach(function (item) {
      var tr = el('tr');
      var tdNode = el('td');
      tdNode.append(el('span', 'cell-main', item.node_alias || item.node_id || '—'));
      tr.append(tdNode);
      var tdTransport = el('td');
      tdTransport.append(transportBadge(item.transport));
      tr.append(tdTransport);
      var tdState = el('td');
      var state = String(item.state || '');
      var variant = /ready|online|active|connected/i.test(state) ? 'ok' : (/drain|degrad|close|error|fail/i.test(state) ? 'warn' : 'muted');
      tdState.append(badge(state || '—', variant));
      tr.append(tdState);
      tr.append(el('td', null, item.planes === undefined ? '—' : String(item.planes)));
      tr.append(el('td', null, fmtRelative(item.connected_since)));
      tr.append(el('td', 'cell-sub', item.last_error || '—'));
      tbody.append(tr);
    });
    table.append(thead, tbody);
    container.append(table);
    var mix = (data && data.transport_mix) || {};
    if (mix.quic || mix.ws) {
      container.append(el('p', 'muted small', '传输连接：QUIC ' + fmtNum(mix.quic) + ' · WebSocket ' + fmtNum(mix.ws)));
    }
  }

  function loadTopN() {
    var container = $('overview-topn');
    if (!container) return Promise.resolve();
    return api('/stats/topn?window=15m&n=10').then(function (data) {
      container.replaceChildren();
      var targets = Array.isArray(data && data.targets) ? data.targets : [];
      if (!targets.length) {
        container.append(el('p', 'muted small', '窗口内暂无 TopN 统计。'));
        return;
      }
      var table = el('table', 'data-table mini');
      var thead = el('thead');
      var headRow = el('tr');
      ['目标', '次数', '流量', '错误'].forEach(function (t) { headRow.append(el('th', null, t)); });
      thead.append(headRow);
      var tbody = el('tbody');
      targets.slice(0, 8).forEach(function (item) {
        var tr = el('tr');
        tr.append(el('td', 'cell-code', item.target || '—'));
        tr.append(el('td', 'col-num', fmtNum(item.count)));
        tr.append(el('td', 'col-num', fmtBytes(item.bytes)));
        tr.append(el('td', 'col-num', fmtNum(item.errors)));
        tbody.append(tr);
      });
      table.append(thead, tbody);
      var wrap = el('div', 'mini-table-wrap');
      wrap.append(table);
      container.append(wrap);
    }).catch(function () {
      if (container) {
        container.replaceChildren(el('p', 'muted small', 'TopN 统计暂不可用（后端未就绪时自动隐藏）。'));
      }
    });
  }

  function renderClockSkew() {
    var chipEl = $('clock-skew');
    if (!chipEl) return;
    if (state.clockSkew === null || state.clockSkew === undefined) {
      chipEl.hidden = true;
      return;
    }
    var ms = Number(state.clockSkew);
    if (!Number.isFinite(ms)) {
      chipEl.hidden = true;
      return;
    }
    var abs = Math.abs(ms);
    var text = abs < 1000 ? Math.round(ms) + ' ms' : (ms / 1000).toFixed(1) + ' s';
    chipEl.hidden = false;
    chipEl.textContent = '时钟偏移 ' + (ms > 0 ? '+' : '') + text;
    chipEl.className = 'chip ' + (abs >= 5000 ? 'chip-warn' : 'chip-info');
    chipEl.title = '面板与服务器的时间差（由服务端检测）；正值表示服务器时间较快。';
  }

  /* ================================================================== 节点页 */

  // 节点表格列定义：name / actions 固定显示，其余列可通过「显示列」菜单隐藏。
  var NODE_COLUMN_DEFS = [
    { key: 'name', label: '别名 / ID', fixed: true },
    { key: 'group', label: '组' },
    { key: 'egress', label: '出口 IP' },
    { key: 'country', label: '国家' },
    { key: 'city', label: '城市' },
    { key: 'asn', label: 'ASN' },
    { key: 'isp', label: 'ISP' },
    { key: 'weight', label: '权重' },
    { key: 'inflight', label: '在途' },
    { key: 'latency', label: '延迟' },
    { key: 'bytes', label: '累计流量' },
    { key: 'breaker', label: '熔断' },
    { key: 'version', label: '版本' },
    { key: 'transport', label: '传输' },
    { key: 'online', label: '在线' },
    { key: 'update', label: '更新状态' },
    { key: 'actions', label: '操作', fixed: true }
  ];
  var NODE_COLUMNS_STORAGE_KEY = 'proxygw.nodes.columns';
  var nodeColumnVisibility = null;
  var nodeColumnMenuBuilt = false;

  // node.update.state 的中文展示与徽标颜色（与后端 protocol 常量保持一致）。
  var NODE_UPDATE_ACTIVE_STATES = ['checking', 'downloading', 'verified', 'waiting_restart', 'replacing', 'restarting'];
  var NODE_UPDATE_LABELS = {
    idle: '空闲',
    checking: '检查中',
    downloading: '下载中',
    verified: '已校验',
    waiting_restart: '待重启',
    replacing: '替换中',
    restarting: '重启中',
    success: '成功',
    failed: '失败',
    rolled_back: '已回滚'
  };
  var NODE_UPDATE_VARIANTS = {
    idle: 'muted',
    checking: 'info',
    downloading: 'info',
    verified: 'ok',
    waiting_restart: 'warn',
    replacing: 'warn',
    restarting: 'warn',
    success: 'ok',
    failed: 'fail',
    rolled_back: 'warn'
  };

  function defaultNodeColumnVisibility() {
    var map = {};
    NODE_COLUMN_DEFS.forEach(function (def) { map[def.key] = true; });
    return map;
  }

  function loadNodeColumnVisibility() {
    if (nodeColumnVisibility) return nodeColumnVisibility;
    var visible = defaultNodeColumnVisibility();
    try {
      var raw = window.localStorage ? window.localStorage.getItem(NODE_COLUMNS_STORAGE_KEY) : null;
      if (raw) {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          var wanted = {};
          parsed.forEach(function (key) { wanted[String(key)] = true; });
          NODE_COLUMN_DEFS.forEach(function (def) {
            visible[def.key] = !!def.fixed || !!wanted[def.key];
          });
        }
      }
    } catch (e) {
      /* localStorage 不可用或数据损坏时回退为全部显示 */
    }
    nodeColumnVisibility = visible;
    return nodeColumnVisibility;
  }

  function saveNodeColumnVisibility() {
    if (!nodeColumnVisibility) return;
    try {
      if (!window.localStorage) return;
      var keys = NODE_COLUMN_DEFS.filter(function (def) {
        return !def.fixed && nodeColumnVisibility[def.key];
      }).map(function (def) { return def.key; });
      window.localStorage.setItem(NODE_COLUMNS_STORAGE_KEY, JSON.stringify(keys));
    } catch (e) {
      /* 隐私模式等场景下持久化失败不影响当前展示 */
    }
  }

  function nodeColumnVisible(key) {
    return !!loadNodeColumnVisibility()[key];
  }

  function nodeVisibleColumnCount() {
    var visible = loadNodeColumnVisibility();
    var count = 0;
    NODE_COLUMN_DEFS.forEach(function (def) { if (visible[def.key]) count++; });
    return count || 2;
  }

  function setNodeColumnVisible(key, visible) {
    var def = null;
    NODE_COLUMN_DEFS.forEach(function (item) { if (item.key === key) def = item; });
    if (!def || def.fixed) return;
    loadNodeColumnVisibility()[key] = !!visible;
    saveNodeColumnVisibility();
    applyNodeColumnVisibility();
    syncNodeColumnMenuChecks();
  }

  function applyNodeColumnVisibility(root) {
    var table = $('nodes-table');
    if (!table) return;
    var visible = loadNodeColumnVisibility();
    qsa('[data-col]', root || table).forEach(function (cell) {
      cell.classList.toggle('col-hidden', !visible[cell.dataset.col]);
    });
    var messageCell = qs('#nodes-tbody td.table-message');
    if (messageCell) messageCell.colSpan = nodeVisibleColumnCount();
  }

  function syncNodeColumnMenuChecks() {
    var popover = $('nodes-columns-popover');
    if (!popover) return;
    qsa('input[data-column]', popover).forEach(function (input) {
      input.checked = nodeColumnVisible(input.dataset.column);
    });
  }

  function buildNodeColumnsMenu() {
    if (nodeColumnMenuBuilt) return;
    var popover = $('nodes-columns-popover');
    if (!popover) return;
    nodeColumnMenuBuilt = true;
    clear(popover);
    var head = el('div', 'column-popover-head');
    head.append(el('strong', null, '显示列'));
    head.append(el('span', 'muted small', '名称 / 操作列固定'));
    var options = el('div', 'column-options');
    NODE_COLUMN_DEFS.forEach(function (def) {
      if (def.fixed) return;
      var option = el('label', 'column-option');
      var input = el('input');
      input.type = 'checkbox';
      input.dataset.column = def.key;
      input.checked = nodeColumnVisible(def.key);
      option.append(input, el('span', null, def.label));
      options.append(option);
    });
    var foot = el('div', 'column-popover-foot');
    var showAll = btn('全部显示', { small: true });
    showAll.addEventListener('click', function () {
      var visible = loadNodeColumnVisibility();
      NODE_COLUMN_DEFS.forEach(function (def) { if (!def.fixed) visible[def.key] = true; });
      saveNodeColumnVisibility();
      applyNodeColumnVisibility();
      syncNodeColumnMenuChecks();
    });
    foot.append(showAll);
    popover.append(head, options, foot);
    popover.addEventListener('change', function (ev) {
      var input = ev.target;
      if (!input || input.type !== 'checkbox' || !input.dataset.column) return;
      setNodeColumnVisible(input.dataset.column, input.checked);
    });
  }

  function setNodeColumnsMenuOpen(open) {
    var popover = $('nodes-columns-popover');
    var trigger = qs('[data-action="nodes-columns-toggle"]');
    if (!popover) return;
    if (open) {
      buildNodeColumnsMenu();
      syncNodeColumnMenuChecks();
      popover.hidden = false;
    } else {
      popover.hidden = true;
    }
    if (trigger) trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function closeNodeColumnsMenu() {
    var popover = $('nodes-columns-popover');
    if (popover && !popover.hidden) setNodeColumnsMenuOpen(false);
  }

  function toggleNodeColumnsMenu() {
    var popover = $('nodes-columns-popover');
    setNodeColumnsMenuOpen(!popover || popover.hidden);
  }

  // 固定高度布局里需要扣除提示横幅（global-banner）的实际高度。
  function syncNodesViewportOffset() {
    var banner = $('global-banner');
    var height = banner && !banner.hidden ? Math.ceil(banner.getBoundingClientRect().height) : 0;
    document.documentElement.style.setProperty('--nodes-banner-h', height + 'px');
  }

  function nodeUpdateMeta(node) {
    node = node || {};
    var update = node.update && typeof node.update === 'object' ? node.update : null;
    var state = update && update.state ? String(update.state).toLowerCase() : '';
    var runtime = String(node.runtime || '').toLowerCase();
    var active = NODE_UPDATE_ACTIVE_STATES.indexOf(state) !== -1;
    var capable = node.update_capable !== false;
    return {
      runtime: runtime,
      update: update,
      state: state,
      active: active,
      docker: runtime === 'docker',
      capable: capable,
      canUpdate: runtime === 'binary' && !!node.online && capable && !active
    };
  }

  function nodeUpdateStateLabel(state) {
    return NODE_UPDATE_LABELS[state] || state || '未知';
  }

  function nodeVersionText(value) {
    var text = String(value === undefined || value === null ? '' : value).trim();
    if (!text) return '';
    return /^v/i.test(text) ? text : 'v' + text;
  }

  function truncateCellText(value, max) {
    var text = String(value === undefined || value === null ? '' : value).replace(/\s+/g, ' ').trim();
    if (!text) return '';
    return text.length > max ? text.slice(0, max) + '…' : text;
  }

  function nodeCell(key, className) {
    var td = el('td', className || null);
    td.dataset.col = key;
    if (!nodeColumnVisible(key)) td.classList.add('col-hidden');
    return td;
  }

  function readNodeFilters() {
    return {
      q: ($('nodes-q') && $('nodes-q').value || '').trim(),
      country: ($('nodes-country') && $('nodes-country').value || '').trim(),
      asn: ($('nodes-asn') && $('nodes-asn').value || '').trim(),
      group: ($('nodes-group') && $('nodes-group').value) || '',
      online: !!($('nodes-online') && $('nodes-online').checked),
      unique: !!($('nodes-unique') && $('nodes-unique').checked)
    };
  }

  function buildNodeQuery() {
    var f = readNodeFilters();
    var params = new URLSearchParams();
    if (f.q) params.set('q', f.q);
    if (f.country) params.set('country', f.country.toUpperCase());
    if (f.asn) params.set('asn', f.asn.replace(/^as/i, ''));
    if (f.group) params.set('group', f.group);
    if (f.online) params.set('online', '1');
    if (f.unique) params.set('unique', '1');
    params.set('page', String(state.nodes.page));
    params.set('size', String(state.nodes.size));
    return params.toString();
  }

  function loadNodes(options) {
    options = options || {};
    var tbody = $('nodes-tbody');
    if (!tbody) return Promise.resolve();
    if (!options.silent && !state.nodes.loaded) {
      tableMessage(tbody, nodeVisibleColumnCount(), '正在加载节点…', { loading: true });
    }
    return ensureGroups().then(function () {
      return api('/nodes?' + buildNodeQuery());
    }).then(function (data) {
      state.nodes.items = Array.isArray(data.items) ? data.items : [];
      state.nodes.total = Number(data.total) || state.nodes.items.length;
      state.nodes.summary = data.summary || {};
      state.nodes.loaded = true;
      state.nodes.lastFetch = Date.now();
      renderNodesSummary();
      renderNodesTable();
      updateNodesPager();
      updateNodesCountryList();
    }).catch(function (err) {
      if (options.silent) {
        if (err && err.code !== 'unauthorized' && err.code !== 'csrf_invalid' && err.code !== 'network') showApiError(err);
        return;
      }
      tableMessage(tbody, nodeVisibleColumnCount(), '节点加载失败：' + ((err && err.message) || '未知错误'), {
        actionLabel: '重试',
        onAction: function () { loadNodes(); }
      });
      showApiError(err);
    });
  }

  function findNode(id) {
    for (var i = 0; i < state.nodes.items.length; i++) {
      if (state.nodes.items[i] && state.nodes.items[i].id === id) return state.nodes.items[i];
    }
    return null;
  }

  function renderNodesSummary() {
    var container = $('nodes-summary');
    if (!container) return;
    var summary = state.nodes.summary || {};
    var online = summary.online;
    if (online === undefined || online === null) {
      online = state.nodes.items.filter(function (n) { return n.online; }).length;
    }
    var total = summary.nodes !== undefined && summary.nodes !== null ? summary.nodes : state.nodes.total;
    var unique = summary.unique_egress_ips !== undefined && summary.unique_egress_ips !== null
      ? summary.unique_egress_ips
      : '—';
    container.replaceChildren(
      summaryChip('节点总数', fmtNum(total)),
      summaryChip('在线', fmtNum(online)),
      summaryChip('独立出口 IP', fmtNum(unique)),
      summaryChip('当前筛选', state.nodes.total + ' 个结果')
    );
  }

  function nodeGroupsCell(node) {
    var td = nodeCell('group');
    var names = groupNames(node.groups);
    if (!names.length) {
      td.append(el('span', 'cell-sub', '—'));
      return td;
    }
    var holder = el('span', 'cell-chips');
    names.forEach(function (name) { holder.append(el('span', 'tag', name)); });
    td.append(holder);
    return td;
  }

  function nodeEgressCell(node) {
    var td = nodeCell('egress', 'cell-nowrap');
    var egress = node.egress_ip || {};
    var v4 = el('span', 'cell-code', egress.v4 || '—');
    td.append(v4);
    if (egress.v6) td.append(el('span', 'cell-sub', 'v6: ' + egress.v6));
    if (egress.source) {
      var sourceLabels = { manual: '手工', peer: '对端', echo: '回声' };
      td.append(el('span', 'cell-sub', '来源：' + (sourceLabels[egress.source] || egress.source)));
    }
    return td;
  }

  // nodeUpdateCell 渲染后端 node.update 契约；缺失时展示「—」，Docker 节点给出弱化说明。
  function nodeUpdateCell(node) {
    var td = nodeCell('update', 'cell-nowrap');
    var meta = nodeUpdateMeta(node);
    var update = meta.update;
    if (!update || !meta.state) {
      if (meta.docker) {
        td.append(el('span', 'cell-sub', 'Docker · 镜像更新'));
        td.title = '容器部署的节点通过更新镜像版本升级，面板不执行二进制在线替换。';
      } else {
        td.append(el('span', 'cell-sub', '—'));
      }
      return td;
    }
    var stateLabel = nodeUpdateStateLabel(meta.state);
    var stateBadge = badge(stateLabel, NODE_UPDATE_VARIANTS[meta.state] || 'muted');
    var progress = Number(update.progress);
    if (meta.active && Number.isFinite(progress)) {
      stateBadge.textContent = stateLabel + ' ' + Math.max(0, Math.min(100, Math.round(progress))) + '%';
    }
    td.append(stateBadge);

    var currentVersion = nodeVersionText(update.current_version || node.version);
    var targetVersion = nodeVersionText(update.target_version);
    if (targetVersion) {
      td.append(el('span', 'cell-sub',
        (currentVersion ? currentVersion + ' → ' : '目标 ') + targetVersion));
    }
    var errorText = update.error || ((meta.state === 'failed' || meta.state === 'rolled_back') ? update.message : '');
    if (errorText) td.append(el('span', 'cell-sub', truncateCellText(errorText, 36)));

    var titleParts = ['更新状态：' + stateLabel];
    if (currentVersion || targetVersion) {
      titleParts.push('版本：' + (currentVersion || '—') + ' → ' + (targetVersion || '—'));
    }
    if (update.message) titleParts.push('说明：' + update.message);
    if (update.error) titleParts.push('错误：' + update.error);
    if (update.updated_at) titleParts.push('更新时间：' + fmtDateTime(update.updated_at));
    td.title = titleParts.join('\n');
    return td;
  }

  // 仅 runtime=binary 且在线、update_capable 不为 false 的节点提供可用更新按钮；
  // 更新进行中时按钮禁用并显示「更新中」。
  function nodeUpdateActionButton(node) {
    var meta = nodeUpdateMeta(node);
    if (meta.active) {
      return btn('更新中', {
        small: true,
        action: 'nodes-update',
        id: node.id,
        disabled: true,
        title: '节点正在更新（' + nodeUpdateStateLabel(meta.state) + '），完成前不能重复触发'
      });
    }
    if (!meta.canUpdate) return null;
    return btn('更新', {
      small: true,
      action: 'nodes-update',
      id: node.id,
      title: '在线更新节点二进制到最新版本；更新期间节点会短暂离线'
    });
  }

  function refreshNodesUpdateAllButton() {
    var button = $('nodes-update-all');
    if (!button) return;
    var count = 0;
    if (state.nodes.loaded) {
      state.nodes.items.forEach(function (node) {
        if (nodeUpdateMeta(node).canUpdate) count++;
      });
    }
    button.disabled = count === 0;
    if (count > 0) {
      button.title = '批量更新：当前页有 ' + count + ' 个可更新的二进制节点；由后端滚动执行，节点会短暂离线';
    } else {
      button.title = state.nodes.loaded ? '当前页没有可更新的二进制节点' : '节点列表尚未加载';
    }
  }

  function nodeRow(node) {
    var tr = el('tr');
    var geo = node.geo || {};

    var tdName = nodeCell('name', 'col-name');
    var main = el('span', 'cell-main', node.alias || node.id || '—');
    tdName.append(main);
    if (node.alias && node.id) tdName.append(el('span', 'cell-sub', node.id));
    if (Array.isArray(node.tags) && node.tags.length) {
      var tags = el('span', 'cell-chips');
      node.tags.forEach(function (tag) { tags.append(el('span', 'tag', tag)); });
      tdName.append(tags);
    }
    if (node.duplicate_of) {
      tdName.append(el('span', 'cell-sub', '出口与 ' + node.duplicate_of + ' 重复'));
    }
    if (node.enabled === false) tdName.append(badge('已禁用', 'disabled'));
    tr.append(tdName);
    tr.append(nodeGroupsCell(node));
    tr.append(nodeEgressCell(node));

    var tdCountry = nodeCell('country', 'cell-nowrap');
    tdCountry.append(document.createTextNode(countryLabel(geo.country)));
    tr.append(tdCountry);

    var tdCity = nodeCell('city', 'cell-nowrap');
    tdCity.append(document.createTextNode(geo.city || '—'));
    if (geo.region && geo.region !== geo.city) tdCity.append(el('span', 'cell-sub', geo.region));
    tr.append(tdCity);

    var tdASN = nodeCell('asn', 'cell-nowrap');
    if (geo.asn) {
      tdASN.append(el('span', 'cell-code', 'AS' + geo.asn));
      if (geo.asn_org) tdASN.append(el('span', 'cell-sub', geo.asn_org));
    } else {
      tdASN.append(el('span', 'cell-sub', '—'));
    }
    tr.append(tdASN);

    var tdISP = nodeCell('isp', 'cell-nowrap');
    tdISP.textContent = node.isp_label || geo.isp || '—';
    tr.append(tdISP);

    var tdWeight = nodeCell('weight', 'col-num cell-nowrap');
    tdWeight.textContent = String(node.weight === undefined || node.weight === null ? '—' : node.weight);
    tr.append(tdWeight);

    var tdInflight = nodeCell('inflight', 'col-num cell-nowrap');
    tdInflight.textContent = fmtNum(node.inflight);
    tr.append(tdInflight);

    var tdLatency = nodeCell('latency', 'col-num cell-nowrap');
    tdLatency.textContent = fmtLatency(node.latency_ewma_ms);
    tr.append(tdLatency);

    var tdBytes = nodeCell('bytes', 'col-num cell-nowrap');
    var totalBytes = (Number(node.bytes_in) || 0) + (Number(node.bytes_out) || 0);
    tdBytes.textContent = fmtBytes(totalBytes);
    tdBytes.title = '入 ' + fmtBytes(node.bytes_in) + ' / 出 ' + fmtBytes(node.bytes_out);
    tr.append(tdBytes);

    var tdBreaker = nodeCell('breaker', 'cell-nowrap');
    tdBreaker.append(breakerBadge(node.breaker_state));
    tr.append(tdBreaker);

    var tdVersion = nodeCell('version', 'cell-code cell-nowrap');
    tdVersion.textContent = node.version || '—';
    tr.append(tdVersion);

    var tdTransport = nodeCell('transport', 'cell-nowrap');
    tdTransport.append(transportBadge(node.transport || ''));
    if (node.planes) tdTransport.append(el('span', 'cell-sub', '×' + node.planes + ' 平面'));
    tr.append(tdTransport);

    var tdOnline = nodeCell('online', 'cell-nowrap');
    if (node.online) tdOnline.append(badge('在线', 'online'));
    else tdOnline.append(badge('离线', 'offline'));
    tr.append(tdOnline);

    tr.append(nodeUpdateCell(node));

    var tdActions = nodeCell('actions', 'col-actions');
    var actions = el('span', 'row-actions');
    actions.append(btn('编辑', { small: true, action: 'nodes-edit', id: node.id }));
    actions.append(btn('拨测', { small: true, action: 'nodes-probe', id: node.id }));
    actions.append(btn('安装', { small: true, action: 'nodes-install', id: node.id }));
    var updateBtn = nodeUpdateActionButton(node);
    if (updateBtn) actions.append(updateBtn);
    var kickBtn = btn('下线', { small: true, variant: 'btn-danger-ghost', action: 'nodes-kick', id: node.id });
    if (!node.online) kickBtn.disabled = true;
    actions.append(kickBtn);
    tdActions.append(actions);
    tr.append(tdActions);
    return tr;
  }

  function renderNodesTable() {
    var tbody = $('nodes-tbody');
    if (!tbody) return;
    if (!state.nodes.items.length) {
      emptyRow(tbody, nodeVisibleColumnCount(), '没有匹配的节点。可调整筛选条件，或确认节点客户端是否已启动。');
      refreshNodesUpdateAllButton();
      return;
    }
    var frag = document.createDocumentFragment();
    state.nodes.items.forEach(function (node) { frag.append(nodeRow(node)); });
    tbody.replaceChildren(frag);
    refreshNodesUpdateAllButton();
  }

  function updateNodesPager() {
    var totalPages = Math.max(1, Math.ceil(state.nodes.total / state.nodes.size));
    if (state.nodes.page > totalPages) state.nodes.page = totalPages;
    setText('nodes-total', '共 ' + fmtNum(state.nodes.total) + ' 个节点');
    setText('nodes-page-info', '第 ' + state.nodes.page + ' / ' + totalPages + ' 页');
    var prev = qs('[data-action="nodes-prev"]');
    var next = qs('[data-action="nodes-next"]');
    if (prev) prev.disabled = state.nodes.page <= 1;
    if (next) next.disabled = state.nodes.page >= totalPages;
  }

  function updateNodesCountryList() {
    var list = $('nodes-country-list');
    if (!list) return;
    var seen = {};
    var frag = document.createDocumentFragment();
    state.nodes.items.forEach(function (node) {
      var code = node.geo && node.geo.country;
      if (!code) return;
      var upper = String(code).toUpperCase();
      if (seen[upper]) return;
      seen[upper] = true;
      var option = el('option');
      option.value = upper;
      option.label = countryInfo(upper).name;
      frag.append(option);
    });
    list.replaceChildren(frag);
  }

  function updateGroupSelects() {
    var select = $('nodes-group');
    if (!select) return;
    var current = select.value;
    clear(select);
    var all = el('option', null, '全部组');
    all.value = '';
    select.append(all);
    state.groups.items.forEach(function (group) {
      var option = el('option', null, group.name || group.id);
      option.value = group.id;
      select.append(option);
    });
    if (current && qsa('option', select).some(function (o) { return o.value === current; })) {
      select.value = current;
    }
  }

  function ensureGroups() {
    if (state.groups.loaded) return Promise.resolve(state.groups.items);
    return loadGroups({ silent: true }).then(function () { return state.groups.items; }).catch(function () {
      return state.groups.items;
    });
  }

  /* ------------------------------ 节点操作模态框 */

  function openNodeEdit(id) {
    var node = findNode(id);
    if (!node) {
      toast('节点不在当前列表中，请刷新后重试。', 'warn');
      return;
    }
    var alias = field({ label: '别名', name: 'alias', value: node.alias || '', placeholder: '面板显示名' });
    var tags = field({
      label: '标签', name: 'tags', value: joinList(node.tags),
      hint: '逗号分隔，例如 us-residential, comcast'
    });
    var weight = field({ label: '调度权重', name: 'weight', type: 'number', min: 0, max: 100000, value: node.weight === undefined ? 100 : node.weight, hint: 'weighted 策略使用，数值越大权重越高' });
    var region = field({ label: '手工地区标签', name: 'region', value: node.region || '', hint: '优先于自动识别结果' });
    var isp = field({ label: '手工 ISP 标签', name: 'isp_label', value: node.isp_label || '', hint: '优先于自动识别结果' });
    var enabled = checkField({ label: '启用该节点', name: 'enabled', value: node.enabled !== false, hint: '禁用后调度器不再选择该节点' });

    formModal({
      title: '编辑节点 · ' + (node.alias || node.id),
      fields: [alias, tags, weight, region, isp, enabled],
      submitText: '保存',
      onSubmit: function () {
        var payload = {
          alias: alias.value.trim(),
          tags: splitList(tags.value),
          weight: toInt(weight.value, 100),
          region: region.value.trim(),
          isp_label: isp.value.trim(),
          enabled: enabled.checked
        };
        return api('/nodes/' + enc(node.id), { method: 'PATCH', body: payload }).then(function () {
          closeModal();
          toast('节点已更新', 'success');
          return loadNodes();
        });
      }
    });
  }

  function openNodeKick(id) {
    var node = findNode(id);
    if (!node) {
      toast('节点不在当前列表中，请刷新后重试。', 'warn');
      return;
    }
    var reason = field({ label: '原因（可选，写入审计）', name: 'reason', value: '', placeholder: '例如：维护窗口 / 配置异常' });
    formModal({
      title: '强制下线节点',
      fields: [el('p', 'confirm-text span-2',
        '确定强制下线节点「' + (node.alias || node.id) + '」吗？该节点当前隧道连接会被中断，节点随后可自动重连。'), reason],
      submitText: '强制下线',
      submitVariant: 'btn-danger',
      onSubmit: function () {
        var body = {};
        var text = reason.value.trim();
        if (text) body.reason = text;
        return api('/nodes/' + enc(node.id) + '/kick', { method: 'POST', body: body }).then(function () {
          closeModal();
          toast('已强制下线节点 ' + (node.alias || node.id), 'success');
          return loadNodes();
        });
      }
    });
  }

  function openNodeUpdate(id) {
    var node = findNode(id);
    if (!node) {
      toast('节点不在当前列表中，请刷新后重试。', 'warn');
      return;
    }
    var meta = nodeUpdateMeta(node);
    if (!meta.canUpdate) {
      toast('该节点当前不可更新：' + (meta.active
        ? '更新正在进行中'
        : (!node.online ? '节点离线' : '节点运行方式不支持在线更新')), 'warn');
      return;
    }
    var name = node.alias || node.id;
    confirmDialog({
      title: '更新节点 · ' + name,
      message: '确定将节点「' + name + '」更新到最新版本吗？',
      note: '更新会替换节点二进制并重启进程，节点会短暂离线，现有连接可能中断；更新期间请勿重复操作。',
      confirmText: '开始更新',
      busyText: '正在下发…',
      onConfirm: function () {
        return api('/nodes/' + enc(node.id) + '/update', { method: 'POST', body: {} }).then(function () {
          toast('已下发更新指令，节点将短暂离线；稍后可自动刷新查看更新状态', 'success');
          return loadNodes();
        });
      }
    });
  }

  function updateAllNodes() {
    var count = 0;
    if (state.nodes.loaded) {
      state.nodes.items.forEach(function (node) {
        if (nodeUpdateMeta(node).canUpdate) count++;
      });
    }
    if (!count) {
      toast('当前页没有可更新的二进制节点', 'warn');
      return;
    }
    confirmDialog({
      title: '批量更新可更新节点',
      message: '确定触发可更新节点的批量更新吗？',
      note: '后端会滚动执行更新，相关节点会短暂离线，更新期间连接可能中断。' +
        '当前页检测到 ' + count + ' 个可更新节点。',
      confirmText: '开始批量更新',
      busyText: '正在下发…',
      onConfirm: function () {
        return api('/nodes/update', { method: 'POST', body: {} }).then(function () {
          toast('已触发批量更新，节点会滚动更新并短暂离线；可稍后刷新查看更新状态', 'success');
          return loadNodes();
        });
      }
    });
  }

  function openNodeProbe(id) {
    var node = findNode(id);
    if (!node) {
      toast('节点不在当前列表中，请刷新后重试。', 'warn');
      return;
    }
    var kind = field({
      label: '拨测类型', name: 'kind', type: 'select', value: 'ping',
      options: [
        { value: 'ping', label: 'Ping（隧道 RTT）' },
        { value: 'tcping', label: 'TCPing（目标端口）' },
        { value: 'http', label: 'HTTP GET' },
        { value: 'dns', label: 'DNS 查询' }
      ],
      hint: 'Ping 只测隧道往返；其它类型需填写目标'
    });
    var target = field({
      label: '目标', name: 'target', value: '',
      placeholder: '如 1.1.1.1:443 / https://example.com / example.com',
      hint: '类型为 ping 时可留空'
    });
    var result = el('div', 'preview-result span-2');
    result.hidden = true;

    formModal({
      title: '节点拨测 · ' + (node.alias || node.id),
      fields: [kind, target, result],
      submitText: '开始拨测',
      onSubmit: function () {
        var body = { kind: kind.value };
        if (target.value.trim()) body.target = target.value.trim();
        return api('/nodes/' + enc(node.id) + '/probe', { method: 'POST', body: body })
          .then(function (data) {
            renderProbeResult(result, data || {});
          })
          .catch(function (err) {
            renderProbeResult(result, { ok: false, error: (err && err.message) || '拨测失败' });
            if (err && (err.code === 'network' || err.status >= 500)) showApiError(err);
          });
      }
    });
  }

  function renderProbeResult(target, data) {
    if (!target) return;
    clear(target);
    target.hidden = false;
    var head = el('div', 'result-head');
    head.append(el('strong', null, '拨测结果 '));
    head.append(badge(data.ok ? '成功' : '失败', data.ok ? 'ok' : 'fail'));
    if (data.latency_ms !== undefined && data.latency_ms !== null) {
      head.append(el('span', 'muted small', '耗时 ' + fmtLatency(data.latency_ms)));
    }
    target.append(head);
    var dl = el('dl', 'result-grid');
    kvRow(dl, '详情', data.detail || '—');
    if (data.error) kvRow(dl, '错误', data.error, 'result-error');
    target.append(dl);
    if (data.result_b64) {
      var decoded = decodeBase64Utf8(data.result_b64);
      target.append(el('div', 'result-section-title', '原始结果'));
      var pre = el('pre', 'code-block');
      pre.textContent = decoded === null || decoded === '' ? String(data.result_b64) : decoded;
      target.append(pre);
    }
  }

  function buildCodeTabs(items) {
    var wrap = el('div');
    var tabs = el('div', 'tabs');
    var code = el('pre', 'code-block');
    var copyBtn = btn('复制', { small: true });
    var active = items.length ? items[0].id : '';
    function renderCode() {
      qsa('.tab', tabs).forEach(function (tab) {
        tab.classList.toggle('active', tab.dataset.tab === active);
      });
      var current = items.filter(function (item) { return item.id === active; })[0];
      code.textContent = current ? current.content : '';
    }
    items.forEach(function (item) {
      var tab = el('button', 'tab', item.label);
      tab.type = 'button';
      tab.dataset.tab = item.id;
      tab.addEventListener('click', function () {
        active = item.id;
        renderCode();
      });
      tabs.append(tab);
    });
    var spacer = el('div');
    spacer.style.marginLeft = 'auto';
    copyBtn.addEventListener('click', function () { copyText(code.textContent); });
    spacer.append(copyBtn);
    tabs.append(spacer);
    renderCode();
    wrap.append(tabs, code);
    return wrap;
  }

  function openNodeInstall(id) {
    var node = findNode(id);
    var title = '节点安装命令' + (node ? ' · ' + (node.alias || node.id) : '');
    var body = el('div');
    body.append(el('p', 'muted small', '正在加载安装命令…'));
    openModal({ title: title, body: body, size: 'lg' });

    var promises = [
      api('/nodes/' + enc(id) + '/install-command').then(
        function (value) { return { key: 'command', value: value }; },
        function (err) { return { key: 'command', error: err }; }
      ),
      api('/nodes/install-template').then(
        function (value) { return { key: 'template', value: value }; },
        function (err) { return { key: 'template', error: err }; }
      )
    ];
    return Promise.all(promises).then(function (results) {
      var commandData = null;
      var template = null;
      var errors = [];
      results.forEach(function (result) {
        if (result.error) errors.push(result.key === 'command' ? '节点专属命令获取失败' : '安装模板获取失败');
        else if (result.key === 'command') commandData = result.value;
        else template = result.value;
      });
      clear(body);
      if (errors.length) {
        body.append(el('p', 'form-alert', errors.join('；') + '，已使用可用数据/内置示例。'));
      }
      var pin = (commandData && commandData.pin) || (state.cert && state.cert.pin) || '';
      var serverURL = (commandData && commandData.server_url) || '';
      var linuxCommand = (commandData && commandData.command) ||
        fillPinPlaceholders(template && template.linux, pin) || fallbackLinux(pin);
      var windowsCommand = fillPinPlaceholders(template && template.windows, pin) || fallbackWindows(pin);
      body.append(buildCodeTabs([
        { id: 'linux', label: 'Linux', content: linuxCommand },
        { id: 'windows', label: 'Windows', content: windowsCommand }
      ]));
      var info = el('dl', 'kv');
      if (serverURL) kvRow(info, '服务端地址', serverURL);
      kvRow(info, 'SPKI pin', pin || '未获取到，请到证书页查看');
      body.append(info);
      body.append(el('p', 'muted small',
        '接入令牌为占位符：请替换为服务端首次启动打印的令牌，或 config.server.yaml 中 nodes.tokens 配置的静态令牌。'));
    });
  }

  /* ================================================================== 节点组页 */

  function loadGroups(options) {
    options = options || {};
    return api('/groups').then(function (data) {
      state.groups.items = Array.isArray(data.items) ? data.items : [];
      state.groups.loaded = true;
      updateGroupSelects();
      if (state.page === 'groups') renderGroups();
    }).catch(function (err) {
      if (!options.silent) {
        var grid = $('groups-grid');
        if (grid && state.page === 'groups') {
          grid.replaceChildren(el('p', 'form-alert', '节点组加载失败：' + ((err && err.message) || '未知错误')));
        }
        showApiError(err);
      }
    });
  }

  function findGroup(id) {
    for (var i = 0; i < state.groups.items.length; i++) {
      if (state.groups.items[i] && state.groups.items[i].id === id) return state.groups.items[i];
    }
    return null;
  }

  function renderGroups() {
    var grid = $('groups-grid');
    var empty = $('groups-empty');
    if (!grid) return;
    if (!state.groups.items.length) {
      grid.replaceChildren();
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    var frag = document.createDocumentFragment();
    state.groups.items.forEach(function (group) {
      frag.append(groupCard(group));
    });
    grid.replaceChildren(frag);
  }

  function groupCard(group) {
    var card = el('article', 'card group-card');
    var head = el('div', 'card-head');
    head.append(el('h3', null, group.name || group.id || '—'));
    var memberCount = group.member_count === undefined || group.member_count === null ? '—' : String(group.member_count);
    head.append(chip('成员 ' + memberCount));
    card.append(head);
    if (group.description) card.append(el('p', 'muted small', group.description));

    var match = group.match || {};
    var dl = el('dl', 'kv');
    var tagsWrap = el('span', 'cell-chips');
    (match.tags_any || []).forEach(function (tag) { tagsWrap.append(el('span', 'tag', tag)); });
    kvRow(dl, '标签选择器', (match.tags_any || []).length ? tagsWrap : '—');
    var regionsWrap = el('span', 'cell-chips');
    (match.regions_any || []).forEach(function (region) { regionsWrap.append(el('span', 'tag', region)); });
    kvRow(dl, '地区选择器', (match.regions_any || []).length ? regionsWrap : '—');
    kvRow(dl, '显式加入', (group.nodes_add || []).length ? (group.nodes_add || []).join(', ') : '—');
    kvRow(dl, '显式排除', (group.nodes_remove || []).length ? (group.nodes_remove || []).join(', ') : '—');
    kvRow(dl, '更新时间', fmtRelative(group.updated_at));
    card.append(dl);

    var actions = el('div', 'form-actions');
    actions.append(btn('查看成员', { small: true, action: 'groups-members', id: group.id }));
    actions.append(btn('编辑', { small: true, action: 'groups-edit', id: group.id }));
    actions.append(btn('删除', { small: true, variant: 'btn-danger-ghost', action: 'groups-delete', id: group.id }));
    card.append(actions);
    return card;
  }

  function openGroupForm(group) {
    var isEdit = !!group;
    var current = group || { name: '', description: '', match: {}, nodes_add: [], nodes_remove: [] };
    var match = current.match || {};
    var name = field({ label: '名称', name: 'name', value: current.name || '', required: true, placeholder: '如 us-residential' });
    var description = field({ label: '描述', name: 'description', value: current.description || '', placeholder: '可选' });
    var tags = groupField({
      label: '标签选择器 tags_any', name: 'tags_any', value: joinList(match.tags_any, '\n'),
      hint: '逗号/换行分隔；命中任一标签即匹配。空 = 不按标签匹配。'
    });
    var regions = groupField({
      label: '地区选择器 regions_any', name: 'regions_any', value: joinList(match.regions_any, '\n'),
      hint: '地区名/国家码，如 US、JP、tokyo。空 = 不按地区匹配。'
    });
    var add = groupField({
      label: '显式加入节点 nodes_add', name: 'nodes_add', value: joinList(current.nodes_add, '\n'),
      hint: '节点 ID，逗号/换行分隔'
    });
    var remove = groupField({
      label: '显式排除节点 nodes_remove', name: 'nodes_remove', value: joinList(current.nodes_remove, '\n'),
      hint: '节点 ID，逗号/换行分隔'
    });

    formModal({
      title: isEdit ? '编辑节点组 · ' + current.name : '新建节点组',
      note: '成员 =（选择器匹配 ∪ 显式加入）− 显式排除。空选择器不匹配任何节点，避免意外包含全网节点。',
      fields: [name, description, tags, regions, add, remove],
      submitText: isEdit ? '保存' : '创建',
      onSubmit: function () {
        var payload = {
          name: name.value.trim(),
          description: description.value.trim(),
          match: {
            tags_any: splitList(tags.value),
            regions_any: splitList(regions.value)
          },
          nodes_add: splitList(add.value),
          nodes_remove: splitList(remove.value)
        };
        if (!payload.name) {
          var err = new ApiError('validation_failed', '名称为必填项', 0, {
            error: 'validation_failed',
            field_errors: [{ field: 'name', message: '名称不能为空' }]
          });
          throw err;
        }
        var request = isEdit
          ? api('/groups/' + enc(group.id), { method: 'PATCH', body: payload })
          : api('/groups', { method: 'POST', body: payload });
        return request.then(function () {
          closeModal();
          toast(isEdit ? '节点组已更新' : '节点组已创建', 'success');
          return loadGroups();
        });
      }
    });
  }

  function openGroupMembers(group) {
    var body = el('div');
    body.append(el('p', 'muted small', '正在加载成员…'));
    openModal({ title: '节点组成员 · ' + (group.name || group.id), body: body, size: 'lg' });
    api('/groups/' + enc(group.id) + '/members').then(function (data) {
      clear(body);
      var count = data && data.count !== undefined ? data.count : (data && data.nodes ? data.nodes.length : 0);
      body.append(el('p', 'muted small', '实时成员数：' + fmtNum(count)));
      body.append(renderNodeMiniTable((data && data.nodes) || [], '该组当前没有成员节点。'));
    }).catch(function (err) {
      clear(body);
      body.append(el('p', 'form-alert', '成员加载失败：' + ((err && err.message) || '未知错误')));
      showApiError(err);
    });
  }

  function deleteGroup(group) {
    confirmDialog({
      title: '删除节点组',
      message: '确定删除节点组「' + (group.name || group.id) + '」吗？',
      note: '若该组仍被凭据引用，服务端会拒绝删除（409 group_in_use）。',
      confirmText: '删除',
      danger: true,
      onConfirm: function () {
        return api('/groups/' + enc(group.id), { method: 'DELETE' }).then(function () {
          toast('节点组已删除', 'success');
          return loadGroups();
        });
      }
    });
  }

  /* ================================================================== 凭据页 */

  function loadCredentials() {
    return ensureGroups().then(function () {
      return api('/credentials');
    }).then(function (data) {
      state.credentials.items = Array.isArray(data.items) ? data.items : [];
      state.credentials.loaded = true;
      renderCredentials();
    }).catch(function (err) {
      var tbody = $('credentials-tbody');
      if (tbody) {
        tableMessage(tbody, 8, '凭据加载失败：' + ((err && err.message) || '未知错误'), {
          actionLabel: '重试',
          onAction: loadCredentials
        });
      }
      showApiError(err);
    });
  }

  function findCredential(id) {
    for (var i = 0; i < state.credentials.items.length; i++) {
      if (state.credentials.items[i] && state.credentials.items[i].id === id) return state.credentials.items[i];
    }
    return null;
  }

  function credentialGroupsCell(cred) {
    var td = el('td');
    var groups = Array.isArray(cred.groups) ? cred.groups : [];
    if (!groups.length) {
      td.append(badge('全部节点', 'info'));
      return td;
    }
    var wrap = el('span', 'cell-chips');
    groupNames(groups).forEach(function (name) { wrap.append(el('span', 'tag', name)); });
    td.append(wrap);
    return td;
  }

  function credentialExpiryCell(cred) {
    var td = el('td', 'cell-nowrap');
    if (!cred.expires_at) {
      td.append(el('span', 'muted', '永不过期'));
      return td;
    }
    td.append(document.createTextNode(fmtDateTime(cred.expires_at)));
    var days = daysUntil(cred.expires_at);
    var label;
    var variant;
    if (days === null) {
      label = '未知';
      variant = 'muted';
    } else if (days < 0) {
      label = '已过期';
      variant = 'expired';
    } else if (days <= 7) {
      label = '即将到期（' + days + ' 天）';
      variant = 'expiring';
    } else {
      label = '剩余 ' + days + ' 天';
      variant = 'ok';
    }
    var sub = el('span', 'cell-sub');
    sub.append(badge(label, variant));
    td.append(sub);
    return td;
  }

  function credentialRow(cred) {
    var tr = el('tr');
    var tdUser = el('td', 'col-name');
    tdUser.append(el('span', 'cell-main', cred.username || cred.id || '—'));
    var meta = [];
    if (Array.isArray(cred.allowed_protocols) && cred.allowed_protocols.length) {
      meta.push('协议 ' + cred.allowed_protocols.join('/'));
    }
    if (cred.bandwidth_kbps) meta.push('限速 ' + cred.bandwidth_kbps + ' kbps');
    if (Array.isArray(cred.source_cidrs) && cred.source_cidrs.length) meta.push('来源 ' + cred.source_cidrs.join(', '));
    if (cred.note) meta.push(cred.note);
    if (meta.length) {
      var sub = el('span', 'cell-sub', meta.join(' · '));
      sub.title = meta.join(' · ');
      tdUser.append(sub);
    }
    tr.append(tdUser);
    tr.append(credentialGroupsCell(cred));

    var tdEnabled = el('td');
    tdEnabled.append(cred.enabled === false ? badge('禁用', 'disabled') : badge('启用', 'enabled'));
    tr.append(tdEnabled);
    tr.append(credentialExpiryCell(cred));

    var tdLast = el('td');
    tdLast.append(timeCell(cred.last_used_at));
    tr.append(tdLast);

    var tdUsage = el('td');
    var totalBytes = (Number(cred.bytes_in) || 0) + (Number(cred.bytes_out) || 0);
    tdUsage.append(el('span', 'cell-main', fmtBytes(totalBytes)));
    tdUsage.append(el('span', 'cell-sub', '入 ' + fmtBytes(cred.bytes_in) + ' / 出 ' + fmtBytes(cred.bytes_out)));
    tr.append(tdUsage);

    tr.append(el('td', 'col-num', cred.max_concurrent ? String(cred.max_concurrent) : '不限'));

    var tdActions = el('td', 'col-actions');
    var actions = el('span', 'row-actions');
    actions.append(btn('编辑', { small: true, action: 'credentials-edit', id: cred.id }));
    actions.append(btn('踢会话', { small: true, variant: 'btn-danger-ghost', action: 'credentials-kick', id: cred.id }));
    actions.append(btn('用量', { small: true, action: 'credentials-usage', id: cred.id }));
    actions.append(btn('可见节点', { small: true, action: 'credentials-visible', id: cred.id }));
    actions.append(btn('删除', { small: true, variant: 'btn-danger-ghost', action: 'credentials-delete', id: cred.id }));
    tdActions.append(actions);
    tr.append(tdActions);
    return tr;
  }

  function renderCredentials() {
    var tbody = $('credentials-tbody');
    if (!tbody) return;
    setText('credentials-count', '共 ' + state.credentials.items.length + ' 个凭据');
    if (!state.credentials.items.length) {
      emptyRow(tbody, 8, '还没有代理凭据。点击右上角「新建凭据」创建。');
      return;
    }
    var frag = document.createDocumentFragment();
    state.credentials.items.forEach(function (cred) { frag.append(credentialRow(cred)); });
    tbody.replaceChildren(frag);
  }

  function openCredentialForm(cred) {
    var isEdit = !!cred;
    var current = cred || { enabled: true };
    var username = field({
      label: '用户名', name: 'username', value: current.username || '', required: true,
      autocomplete: 'off', placeholder: '代理账号用户名'
    });
    var password = field({
      label: '密码', name: 'password', type: 'password', value: '',
      autocomplete: 'new-password',
      placeholder: isEdit ? '留空 = 保持不变' : '留空 = 由服务端生成',
      hint: '手动填写密码，或点击下方「生成随机密码」由服务端生成（只展示一次）'
    });
    var generate = checkField({
      label: '生成随机密码（由服务端生成，提交后只展示一次）',
      name: 'generate_password', value: false, wide: true
    });
    var generateBtn = btn('生成随机密码', { small: true });
    var passwordRow = el('div', 'form-actions');
    passwordRow.append(generateBtn);
    password.wrap.append(passwordRow);
    generateBtn.addEventListener('click', function () {
      generate.input.checked = !generate.input.checked;
      generateBtn.textContent = generate.input.checked ? '取消生成（改用手动密码）' : '生成随机密码';
      password.input.disabled = generate.input.checked;
      if (generate.input.checked) password.input.value = '';
    });
    generate.input.addEventListener('change', function () {
      password.input.disabled = generate.input.checked;
      if (generate.input.checked) {
        password.input.value = '';
        generateBtn.textContent = '取消生成（改用手动密码）';
      } else {
        generateBtn.textContent = '生成随机密码';
      }
    });

    var groupsField = checkGroupField({
      label: '节点组（可多选）',
      name: 'groups',
      options: state.groups.items.map(function (group) {
        return { value: group.id, label: group.name || group.id };
      }),
      value: current.groups || [],
      hint: '不选任何组 = 该凭据可见全部节点；绑定组但组内无可用节点时 fail-closed 503。'
    });

    var enabled = checkField({ label: '启用该凭据', name: 'enabled', value: current.enabled !== false });
    var expiresAt = field({
      label: '过期时间', name: 'expires_at', type: 'datetime-local',
      value: toLocalInput(current.expires_at),
      hint: '留空 = 永不过期'
    });
    var maxConcurrent = field({
      label: '并发连接上限', name: 'max_concurrent', type: 'number', min: 0,
      value: current.max_concurrent ? current.max_concurrent : 0, hint: '0 = 不限'
    });
    var bandwidth = field({
      label: '下行限速（kbps）', name: 'bandwidth_kbps', type: 'number', min: 0,
      value: current.bandwidth_kbps ? current.bandwidth_kbps : 0, hint: '0 = 不限'
    });
    var protocols = checkGroupField({
      label: '允许的协议',
      name: 'allowed_protocols',
      options: PROTOCOL_OPTIONS,
      value: current.allowed_protocols || [],
      hint: '不选 = 不限制协议'
    });
    var sourceCIDRs = field({
      label: '来源 CIDR 白名单', name: 'source_cidrs', type: 'textarea', rows: 2,
      value: joinList(current.source_cidrs, '\n'),
      hint: '逗号/换行分隔；留空 = 不限制来源'
    });
    var note = field({
      label: '备注', name: 'note', type: 'textarea', rows: 2,
      value: current.note || '', placeholder: '可选'
    });

    var layout = el('div', 'form-grid');
    [username, password, generate, groupsField, enabled, expiresAt, maxConcurrent, bandwidth,
      protocols, sourceCIDRs, note].forEach(function (widget) {
      layout.append(widget.wrap);
    });

    var cancel = btn('取消', {});
    cancel.addEventListener('click', closeModal);
    var submit = btn(isEdit ? '保存' : '创建', { variant: 'btn-primary' });
    submit.type = 'button';
    var form = el('form', 'form-grid');
    form.noValidate = true;
    form.append(el('div', 'span-2'));
    form.lastChild.append(layout);
    var modal = openModal({
      title: isEdit ? '编辑凭据 · ' + current.username : '新建凭据',
      body: form,
      footer: [cancel, submit],
      size: 'lg'
    });
    function submitCredential() {
      if (form.dataset.busy === '1') return;
      form.dataset.busy = '1';
      setBusy(submit, true, '处理中…');
      cancel.disabled = true;
      setFormAlert(form, '');
      var payload = {
        username: username.value.trim(),
        groups: groupsField.getValues(),
        enabled: enabled.checked,
        expires_at: fromLocalInput(expiresAt.value),
        max_concurrent: toInt(maxConcurrent.value, 0),
        bandwidth_kbps: toInt(bandwidth.value, 0),
        allowed_protocols: protocols.getValues(),
        source_cidrs: splitList(sourceCIDRs.value),
        note: note.value.trim()
      };
      if (generate.input.checked) {
        payload.generate_password = true;
      } else if (password.value) {
        payload.password = password.value;
      }
      var request = isEdit
        ? api('/credentials/' + enc(current.id), { method: 'PATCH', body: payload })
        : api('/credentials', { method: 'POST', body: payload });
      request.then(function (data) {
        closeModal();
        toast(isEdit ? '凭据已更新' : '凭据已创建', 'success');
        var passwordText = data && data.password;
        if (!passwordText && payload.generate_password) {
          toast('服务端未返回生成的明文密码（请确认后端遵循契约）', 'warn');
        }
        return loadCredentials().then(function () {
          if (passwordText) {
            showPasswordOnce(payload.username, passwordText);
          }
        });
      }).catch(function (err) {
        showApiError(err);
        applyFieldErrors(form, err);
      }).then(function () {
        form.dataset.busy = '0';
        setBusy(submit, false);
        cancel.disabled = false;
      });
    }
    wireFormSubmit(form, submit, submitCredential);
    return modal;
  }

  function showPasswordOnce(username, password) {
    var body = el('div');
    body.append(el('p', 'confirm-text', '凭据「' + username + '」的密码已生成。该密码只显示这一次，请立即妥善保存：'));
    body.append(el('div', 'password-display', password));
    body.append(el('p', 'warn-text', '关闭后无法再次查看；如遗失请编辑凭据并重新生成密码。'));
    var copyBtn = btn('复制密码', { variant: 'btn-primary' });
    copyBtn.addEventListener('click', function () { copyText(password); });
    var done = btn('我已保存', {});
    done.addEventListener('click', closeModal);
    openModal({
      title: '凭据密码（仅显示一次）',
      body: body,
      footer: [done, copyBtn],
      size: 'sm'
    });
  }

  function kickCredentialSessions(cred) {
    confirmDialog({
      title: '立即踢掉会话',
      message: '确定立即踢掉凭据「' + cred.username + '」的所有活动会话吗？',
      note: '已建立的代理连接会被中断，客户端需要重新连接。',
      confirmText: '立即踢掉',
      danger: true,
      onConfirm: function () {
        return api('/credentials/' + enc(cred.id) + '/kick-sessions', { method: 'POST' }).then(function (data) {
          var kicked = data && data.kicked !== undefined ? data.kicked : 0;
          toast('已踢掉 ' + kicked + ' 个会话', 'success');
        });
      }
    });
  }

  function openCredentialUsage(cred) {
    var body = el('div');
    body.append(el('p', 'muted small', '正在加载用量…'));
    openModal({ title: '凭据用量 · ' + cred.username, body: body, size: 'sm' });
    api('/credentials/' + enc(cred.id) + '/usage').then(function (data) {
      clear(body);
      var dl = el('dl', 'kv');
      kvRow(dl, '最近使用', fmtDateTime(data && data.last_used_at));
      kvRow(dl, '上行字节', fmtBytes(data && data.bytes_in));
      kvRow(dl, '下行字节', fmtBytes(data && data.bytes_out));
      kvRow(dl, '当前活跃连接', fmtNum(data && data.active_connections));
      body.append(dl);
    }).catch(function (err) {
      clear(body);
      body.append(el('p', 'form-alert', '用量加载失败：' + ((err && err.message) || '未知错误')));
      showApiError(err);
    });
  }

  function openCredentialVisibleNodes(cred) {
    var body = el('div');
    body.append(el('p', 'muted small', '正在计算该凭据可见节点…'));
    openModal({ title: '凭据可见节点 · ' + cred.username, body: body, size: 'lg' });
    api('/credentials/' + enc(cred.id) + '/visible-nodes').then(function (data) {
      clear(body);
      var count = data && data.count !== undefined ? data.count : (data && data.nodes ? data.nodes.length : 0);
      var dl = el('dl', 'kv');
      kvRow(dl, '可见节点数', fmtNum(count));
      kvRow(dl, '说明', '绑定组内无可用节点时按 fail-closed 返回 503，不会回退到全部节点。');
      body.append(dl);
      body.append(renderNodeMiniTable((data && data.nodes) || [], '该凭据当前不可见任何节点（组为空或全部离线/熔断）。'));
    }).catch(function (err) {
      clear(body);
      body.append(el('p', 'form-alert', '可见节点加载失败：' + ((err && err.message) || '未知错误')));
      showApiError(err);
    });
  }

  function deleteCredential(cred) {
    confirmDialog({
      title: '删除凭据',
      message: '确定删除凭据「' + cred.username + '」吗？',
      note: '删除后该凭据已有的代理会话会被同时踢掉，且不可恢复。',
      confirmText: '删除',
      danger: true,
      onConfirm: function () {
        return api('/credentials/' + enc(cred.id), { method: 'DELETE' }).then(function () {
          toast('凭据已删除', 'success');
          return loadCredentials();
        });
      }
    });
  }

  /* ================================================================== 运行设置 */

  function loadSettings() {
    return api('/settings').then(function (data) {
      applySettingsData(data);
    }).catch(function (err) {
      var form = $('settings-form');
      if (form) form.replaceChildren(el('p', 'form-alert', '运行设置加载失败：' + ((err && err.message) || '未知错误')));
      showApiError(err);
    });
  }

  function applySettingsData(data) {
    state.settings = data || null;
    renderSettingsForm($('settings-form'));
    updateSettingsLabels();
    renderSettingsHistory();
  }

  function renderSettingsForm(container) {
    if (!container) return;
    clear(container);
    var current = state.settings && state.settings.current;
    if (!current) {
      container.append(el('p', 'form-alert', '运行设置未加载或读取失败，请刷新页面重试。'));
      container._settingsWidgets = [];
      return;
    }
    var widgets = [];
    SETTINGS_SECTIONS.forEach(function (section) {
      var fieldset = el('fieldset', 'settings-fieldset');
      fieldset.append(el('legend', 'settings-legend', section.title));
      var grid = el('div', 'settings-fields');
      section.fields.forEach(function (def) {
        var value = getPath(current, def.path);
        var widget;
        if (def.type === 'checkbox') {
          widget = checkField({ label: def.label, name: def.path, value: !!value, hint: def.hint });
        } else if (def.type === 'select') {
          widget = field({ label: def.label, name: def.path, type: 'select', options: def.options, value: value === undefined || value === null ? '' : value, hint: def.hint });
        } else {
          widget = field({
            label: def.label,
            name: def.path,
            type: def.type,
            value: value === undefined || value === null ? '' : value,
            hint: def.hint,
            step: def.step
          });
        }
        widget.wrap.title = def.path;
        grid.append(widget.wrap);
        widgets.push({ def: def, widget: widget });
      });
      fieldset.append(grid);
      container.append(fieldset);
    });
    container._settingsWidgets = widgets;
  }

  function collectSettings(container) {
    var widgets = container && container._settingsWidgets;
    if (!widgets || !widgets.length) {
      throw new ApiError('internal_error', '设置表单尚未加载，请刷新后重试', 0, null);
    }
    var output = {
      scheduler: { sticky: {}, breaker: {}, retry: {} },
      limits: {},
      timeouts: {},
      compression_enabled: false,
      default_acl_action: 'allow'
    };
    var errors = [];
    widgets.forEach(function (entry) {
      var def = entry.def;
      var input = entry.widget.input;
      var value;
      if (def.type === 'checkbox') {
        value = !!input.checked;
      } else if (def.type === 'select') {
        value = input.value;
      } else if (def.numeric === 'float') {
        value = parseFloat(input.value);
        if (!Number.isFinite(value)) errors.push({ field: def.path, message: def.label + '需要数字' });
      } else if (def.type === 'number') {
        value = parseInt(input.value, 10);
        if (!Number.isFinite(value)) errors.push({ field: def.path, message: def.label + '需要整数' });
      } else {
        value = String(input.value || '').trim();
        if (!value) errors.push({ field: def.path, message: def.label + '不能为空' });
      }
      setPath(output, def.path, value);
    });
    if (errors.length) {
      throw new ApiError('validation_failed', '部分设置项格式不正确，请检查标红项。', 422, {
        error: 'validation_failed',
        field_errors: errors
      });
    }
    return output;
  }

  function updateSettingsLabels() {
    var settings = state.settings;
    var versionText = settings && settings.version !== undefined && settings.version !== null
      ? '当前版本 v' + settings.version
      : '使用内置默认值';
    setText('rules-settings-version', versionText);
    setText('settings-version', versionText);
    var meta = '';
    if (settings) {
      var parts = [];
      if (settings.updated_by) parts.push('最近操作者 ' + settings.updated_by);
      if (settings.history && settings.history.length) parts.push('历史版本 ' + settings.history.length + ' 条');
      meta = parts.join(' · ');
    }
    setText('settings-meta', meta || '尚未有热更新记录');
  }

  function renderSettingsHistory() {
    var tbody = $('settings-history-tbody');
    if (!tbody) return;
    var history = state.settings && Array.isArray(state.settings.history) ? state.settings.history : [];
    var currentVersion = state.settings && state.settings.version;
    if (!history.length) {
      emptyRow(tbody, 3, '暂无修改历史。');
      return;
    }
    var frag = document.createDocumentFragment();
    history.slice().reverse().forEach(function (item) {
      var tr = el('tr');
      var tdVersion = el('td', 'col-num');
      tdVersion.append(document.createTextNode('v' + (item.version === undefined ? '?' : item.version)));
      if (currentVersion !== undefined && item.version === currentVersion) {
        tdVersion.append(document.createTextNode(' '));
        tdVersion.append(badge('当前', 'info'));
      }
      tr.append(tdVersion);
      tr.append(el('td', null, fmtDateTime(item.updated_at)));
      tr.append(el('td', null, item.updated_by || '—'));
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
  }

  function saveSettings() {
    if (!state.settings) {
      showApiError(new ApiError('internal_error', '运行设置尚未加载，请刷新页面后重试', 0, null));
      return Promise.resolve();
    }
    var container = $('settings-form');
    var button = qs('[data-action="settings-save"]');
    var payload;
    try {
      payload = collectSettings(container);
    } catch (err) {
      applyFieldErrors(container, err);
      showApiError(err);
      return Promise.resolve();
    }
    setBusy(button, true, '保存中…');
    return api('/settings', { method: 'PUT', body: { settings: payload } })
      .then(function (data) {
        var version = data && data.version !== undefined ? data.version : '?';
        toast('运行设置已保存（版本 v' + version + '）', 'success');
        return api('/settings').then(function (fresh) {
          applySettingsData(fresh);
        });
      })
      .catch(function (err) {
        showApiError(err);
        applyFieldErrors(container, err);
      })
      .then(function () {
        setBusy(button, false);
      });
  }

  function settingsAction(action) {
    if (!state.settings) {
      showApiError(new ApiError('internal_error', '运行设置尚未加载，请刷新页面后重试', 0, null));
      return;
    }
    var button = qs('[data-action="settings-' + action + '"]');
    var path = action === 'undo' ? '/settings/undo' : '/settings/reset';
    var run = function () {
      setBusy(button, true, action === 'undo' ? '撤销中…' : '恢复中…');
      return api(path, { method: 'POST' })
        .then(function (data) {
          var version = data && data.version !== undefined ? data.version : '?';
          toast(action === 'undo' ? '已撤销到上一版本（新版本 v' + version + '）' : '已恢复默认设置（版本 v' + version + '）', 'success');
          return api('/settings').then(function (fresh) {
            applySettingsData(fresh);
          });
        })
        .catch(function (err) {
          showApiError(err);
        })
        .then(function () {
          setBusy(button, false);
        });
    };
    if (action === 'reset') {
      confirmDialog({
        title: '恢复默认设置',
        message: '确定恢复配置文件默认的运行设置吗？',
        note: '当前热更新覆盖值会被替换为默认值（该操作可撤销）。',
        confirmText: '恢复默认',
        danger: true,
        onConfirm: run
      });
    } else {
      run();
    }
  }

  /* ================================================================== 连接与规则页 */

  function loadRules() {
    return Promise.all([
      api('/settings').then(
        function (data) { return { key: 'settings', ok: true, data: data }; },
        function (err) { return { key: 'settings', ok: false, error: err }; }
      ),
      api('/rules/sticky').then(
        function (data) { return { key: 'sticky', ok: true, data: data }; },
        function (err) { return { key: 'sticky', ok: false, error: err }; }
      ),
      api('/rules/acl').then(
        function (data) { return { key: 'acl', ok: true, data: data }; },
        function (err) { return { key: 'acl', ok: false, error: err }; }
      ),
      api('/rules/acl/forced').then(
        function (data) { return { key: 'forced', ok: true, data: data }; },
        function (err) { return { key: 'forced', ok: false, error: err }; }
      )
    ]).then(function (results) {
      var errors = [];
      results.forEach(function (result) {
        if (!result.ok) {
          errors.push(result.key);
          return;
        }
        if (result.key === 'settings') {
          applySettingsData(result.data);
        } else if (result.key === 'sticky') {
          state.sticky.items = Array.isArray(result.data.items) ? result.data.items : [];
          state.sticky.loaded = true;
          renderStickyTable();
        } else if (result.key === 'acl') {
          state.acl.items = Array.isArray(result.data.items) ? result.data.items : [];
          state.acl.loaded = true;
          state.acl.defaultAction = result.data.default_action || '';
          renderACLTable();
        } else if (result.key === 'forced') {
          state.aclForced.items = Array.isArray(result.data.items) ? result.data.items : [];
          state.aclForced.loaded = true;
          renderForcedACL();
        }
      });
      if (errors.length) {
        var labels = { settings: '运行设置', sticky: '粘性黑名单', acl: 'ACL', forced: '强制默认拒绝清单' };
        toast('部分规则数据加载失败：' + errors.map(function (k) { return labels[k] || k; }).join('、'), 'warn', 6000);
      }
    });
  }

  function renderStickyTable() {
    var tbody = $('sticky-tbody');
    if (!tbody) return;
    if (!state.sticky.items.length) {
      emptyRow(tbody, 8, '还没有粘性黑名单规则。');
      return;
    }
    var frag = document.createDocumentFragment();
    state.sticky.items.forEach(function (rule) {
      var tr = el('tr');
      var tdEnabled = el('td');
      tdEnabled.append(rule.enabled ? badge('启用', 'enabled') : badge('禁用', 'disabled'));
      tr.append(tdEnabled);
      tr.append(el('td', 'col-name', rule.note || '—'));
      var target = rule.target || {};
      var tdCIDR = el('td');
      var cidrWrap = el('span', 'cell-chips');
      (target.cidrs || []).forEach(function (c) { cidrWrap.append(el('span', 'tag', c)); });
      tdCIDR.append((target.cidrs || []).length ? cidrWrap : el('span', 'cell-sub', '—'));
      tr.append(tdCIDR);
      var tdDomains = el('td');
      var domainWrap = el('span', 'cell-chips');
      (target.domains || []).forEach(function (d) { domainWrap.append(el('span', 'tag', d)); });
      tdDomains.append((target.domains || []).length ? domainWrap : el('span', 'cell-sub', '—'));
      tr.append(tdDomains);
      var tdGroups = el('td');
      var groupWrap = el('span', 'cell-chips');
      groupNames(rule.node_groups || []).forEach(function (g) { groupWrap.append(el('span', 'tag', g)); });
      tdGroups.append((rule.node_groups || []).length ? groupWrap : el('span', 'cell-sub', '—'));
      tr.append(tdGroups);
      tr.append(el('td', 'cell-code', (rule.node_ids || []).join(', ') || '—'));
      tr.append(el('td', null, fmtRelative(rule.updated_at)));
      var tdActions = el('td', 'col-actions');
      var actions = el('span', 'row-actions');
      actions.append(btn('编辑', { small: true, action: 'sticky-edit', id: rule.id }));
      actions.append(btn('删除', { small: true, variant: 'btn-danger-ghost', action: 'sticky-delete', id: rule.id }));
      tdActions.append(actions);
      tr.append(tdActions);
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
  }

  function findSticky(id) {
    for (var i = 0; i < state.sticky.items.length; i++) {
      if (state.sticky.items[i] && state.sticky.items[i].id === id) return state.sticky.items[i];
    }
    return null;
  }

  function openStickyForm(rule) {
    var isEdit = !!rule;
    var current = rule || { enabled: true, target: {} };
    var target = current.target || {};
    var enabled = checkField({ label: '启用该规则', name: 'enabled', value: current.enabled !== false });
    var note = field({ label: '备注', name: 'note', value: current.note || '', placeholder: '可选，如「银行相关目标不走粘性」' });
    var cidrs = field({
      label: '目标 CIDR', name: 'cidrs', type: 'textarea', rows: 3,
      value: joinList(target.cidrs, '\n'),
      hint: '逗号/换行分隔，如 10.0.0.0/8、203.0.113.7/32'
    });
    var domains = field({
      label: '目标域名', name: 'domains', type: 'textarea', rows: 3,
      value: joinList(target.domains, '\n'),
      hint: '精确域名、*.bank.example 后缀或通配'
    });
    var nodeGroups = checkGroupField({
      label: '节点组（命中其中任一组则生效）',
      name: 'node_groups',
      options: state.groups.items.map(function (group) { return { value: group.id, label: group.name || group.id }; }),
      value: current.node_groups || []
    });
    var nodeIDs = field({
      label: '节点 ID（命中任一节点则生效）', name: 'node_ids', type: 'textarea', rows: 2,
      value: joinList(current.node_ids, '\n'),
      hint: '节点 ID，逗号/换行分隔'
    });

    formModal({
      title: isEdit ? '编辑粘性黑名单规则' : '新建粘性黑名单规则',
      note: '目标维度（CIDR/域名）与节点维度（节点组/节点 ID）任一命中，即在该请求上禁用会话粘性。',
      fields: [enabled, note, cidrs, domains, nodeGroups, nodeIDs],
      submitText: isEdit ? '保存' : '创建',
      onSubmit: function () {
        var payload = {
          enabled: enabled.checked,
          note: note.value.trim(),
          target: {
            cidrs: splitList(cidrs.value),
            domains: splitList(domains.value)
          },
          node_groups: nodeGroups.getValues(),
          node_ids: splitList(nodeIDs.value)
        };
        var request = isEdit
          ? api('/rules/sticky/' + enc(current.id), { method: 'PATCH', body: payload })
          : api('/rules/sticky', { method: 'POST', body: payload });
        return request.then(function () {
          closeModal();
          toast(isEdit ? '粘性黑名单已更新' : '粘性黑名单已创建', 'success');
          return loadRules();
        });
      }
    });
  }

  function deleteSticky(rule) {
    confirmDialog({
      title: '删除粘性黑名单规则',
      message: '确定删除该粘性黑名单规则吗？',
      note: rule.note ? '备注：' + rule.note : '',
      confirmText: '删除',
      danger: true,
      onConfirm: function () {
        return api('/rules/sticky/' + enc(rule.id), { method: 'DELETE' }).then(function () {
          toast('粘性黑名单已删除', 'success');
          return loadRules();
        });
      }
    });
  }

  function onStickyPreviewSubmit(ev) {
    ev.preventDefault();
    var resultEl = $('sticky-preview-result');
    if (!resultEl) return;
    var payload = {};
    var host = ($('sticky-preview-host').value || '').trim();
    var ip = ($('sticky-preview-ip').value || '').trim();
    var port = ($('sticky-preview-port').value || '').trim();
    var nodeID = ($('sticky-preview-node').value || '').trim();
    var groups = splitList($('sticky-preview-groups').value);
    if (host) payload.host = host;
    if (ip) payload.ip = ip;
    if (port) payload.port = toInt(port, 0);
    if (nodeID) payload.node_id = nodeID;
    if (groups.length) payload.groups = groups;
    resultEl.hidden = false;
    clear(resultEl);
    resultEl.append(el('p', 'muted small', '试算中…'));
    api('/rules/sticky/preview', { method: 'POST', body: payload }).then(function (data) {
      clear(resultEl);
      var head = el('div', 'hit-row');
      head.append(el('strong', null, '试算结果 '));
      head.append(data && data.hit ? badge('命中黑名单', 'warn') : badge('未命中', 'ok'));
      resultEl.append(head);
      var dl = el('dl', 'result-grid');
      kvRow(dl, '命中', data && data.hit ? '是' : '否');
      if (data && data.rule_id) kvRow(dl, '规则 ID', data.rule_id);
      if (data && data.reason) kvRow(dl, '原因', data.reason);
      if (data && data.forced_node_id) kvRow(dl, '强制节点 ID', data.forced_node_id);
      if (!data || !data.hit) {
        kvRow(dl, '说明', '该目标/节点不会因黑名单规则禁用粘性。');
      }
      resultEl.append(dl);
    }).catch(function (err) {
      clear(resultEl);
      resultEl.append(el('p', 'form-alert', '试算失败：' + ((err && err.message) || '未知错误')));
      showApiError(err);
    });
  }

  function renderACLTable() {
    var tbody = $('acl-tbody');
    if (!tbody) return;
    var items = state.acl.items.slice().sort(function (a, b) {
      if ((a.order || 0) !== (b.order || 0)) return (a.order || 0) - (b.order || 0);
      return String(a.id || '').localeCompare(String(b.id || ''));
    });
    var summary = $('acl-summary');
    if (summary) {
      var allowCount = items.filter(function (r) { return r.action === 'allow'; }).length;
      var denyCount = items.filter(function (r) { return r.action === 'deny'; }).length;
      var defaultAction = state.acl.defaultAction ||
        (state.settings && state.settings.current && state.settings.current.default_acl_action) || 'allow';
      summary.replaceChildren(
        summaryChip('规则数', items.length),
        summaryChip('allow', allowCount),
        summaryChip('deny', denyCount),
        summaryChip('默认动作', defaultAction === 'deny' ? 'deny（拒绝）' : 'allow（放行）')
      );
    }
    if (!items.length) {
      emptyRow(tbody, 8, '还没有 ACL 规则。未命中任何规则时按默认动作处理。');
      return;
    }
    var frag = document.createDocumentFragment();
    items.forEach(function (rule) {
      var tr = el('tr');
      tr.append(el('td', 'col-num', rule.order === undefined ? '—' : String(rule.order)));
      tr.append(el('td', 'cell-code', (rule.src_cidrs || []).join(', ') || '—'));
      tr.append(el('td', 'cell-code', (rule.domains || []).join(', ') || '—'));
      tr.append(el('td', 'cell-code', (rule.ports || []).join(', ') || '—'));
      var protocols = el('td');
      var wrap = el('span', 'cell-chips');
      (rule.protocols || []).forEach(function (p) { wrap.append(el('span', 'tag', p)); });
      protocols.append((rule.protocols || []).length ? wrap : el('span', 'cell-sub', '—'));
      tr.append(protocols);
      var action = el('td');
      action.append(rule.action === 'deny' ? badge('deny', 'deny') : badge('allow', 'allow'));
      tr.append(action);
      tr.append(el('td', 'col-name', rule.note || '—'));
      var tdActions = el('td', 'col-actions');
      var actions = el('span', 'row-actions');
      actions.append(btn('编辑', { small: true, action: 'acl-edit', id: rule.id }));
      actions.append(btn('删除', { small: true, variant: 'btn-danger-ghost', action: 'acl-delete', id: rule.id }));
      tdActions.append(actions);
      tr.append(tdActions);
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
  }

  function findACL(id) {
    for (var i = 0; i < state.acl.items.length; i++) {
      if (state.acl.items[i] && state.acl.items[i].id === id) return state.acl.items[i];
    }
    return null;
  }

  function openACLForm(rule) {
    var isEdit = !!rule;
    var maxOrder = state.acl.items.reduce(function (max, item) {
      return Math.max(max, Number(item.order) || 0);
    }, 0);
    var current = rule || { order: maxOrder + 10, action: 'allow', protocols: [] };
    var order = field({ label: 'Order（升序匹配）', name: 'order', type: 'number', value: current.order === undefined ? 0 : current.order });
    var srcCIDRs = field({
      label: '来源 CIDR', name: 'src_cidrs', type: 'textarea', rows: 2,
      value: joinList(current.src_cidrs, '\n'), hint: '逗号/换行分隔；留空 = 任意来源'
    });
    var domains = field({
      label: '目标域名', name: 'domains', type: 'textarea', rows: 2,
      value: joinList(current.domains, '\n'), hint: '精确/后缀/通配；留空 = 任意域名'
    });
    var ports = field({
      label: '端口', name: 'ports', type: 'textarea', rows: 2,
      value: joinList(current.ports, '\n'), hint: '如 443, 8000-9000；留空 = 任意端口'
    });
    var protocols = checkGroupField({
      label: '协议', name: 'protocols', options: ACL_PROTOCOL_OPTIONS,
      value: current.protocols || [], hint: '不选 = 任意协议'
    });
    var action = field({
      label: '动作', name: 'action', type: 'select', value: current.action || 'allow',
      options: [{ value: 'allow', label: 'allow（放行）' }, { value: 'deny', label: 'deny（拒绝）' }]
    });
    var note = field({ label: '备注', name: 'note', value: current.note || '', placeholder: '可选' });

    formModal({
      title: isEdit ? '编辑 ACL 规则' : '新建 ACL 规则',
      note: '规则按 order 从小到大匹配，首条命中生效。强制默认拒绝清单不可关闭，只能追加规则。',
      fields: [order, action, srcCIDRs, domains, ports, protocols, note],
      submitText: isEdit ? '保存' : '创建',
      onSubmit: function () {
        var payload = {
          order: toInt(order.value, 0),
          src_cidrs: splitList(srcCIDRs.value),
          domains: splitList(domains.value),
          ports: splitList(ports.value),
          protocols: protocols.getValues(),
          action: action.value,
          note: note.value.trim()
        };
        var request = isEdit
          ? api('/rules/acl/' + enc(current.id), { method: 'PATCH', body: payload })
          : api('/rules/acl', { method: 'POST', body: payload });
        return request.then(function () {
          closeModal();
          toast(isEdit ? 'ACL 规则已更新' : 'ACL 规则已创建', 'success');
          return loadRules();
        });
      }
    });
  }

  function deleteACL(rule) {
    confirmDialog({
      title: '删除 ACL 规则',
      message: '确定删除 order=' + (rule.order === undefined ? '?' : rule.order) + ' 的 ACL 规则吗？',
      note: rule.note ? '备注：' + rule.note : '',
      confirmText: '删除',
      danger: true,
      onConfirm: function () {
        return api('/rules/acl/' + enc(rule.id), { method: 'DELETE' }).then(function () {
          toast('ACL 规则已删除', 'success');
          return loadRules();
        });
      }
    });
  }

  function renderForcedACL() {
    var container = $('acl-forced');
    if (!container) return;
    clear(container);
    if (!state.aclForced.loaded) {
      container.append(el('p', 'muted small', '正在加载强制默认拒绝清单…'));
      return;
    }
    if (!state.aclForced.items.length) {
      container.append(el('p', 'muted small', '未返回强制默认拒绝清单（服务端应始终提供）。'));
      return;
    }
    state.aclForced.items.forEach(function (item) {
      var row = el('div', 'forced-item');
      if (Array.isArray(item)) {
        var name = el('span', 'forced-name', item[0] || '强制规则');
        var detailParts = item.slice(1).map(function (v) {
          if (Array.isArray(v)) return v.join(', ');
          return String(v === undefined || v === null ? '' : v);
        }).filter(Boolean);
        row.append(name, el('span', 'forced-detail', detailParts.join(' · ')));
      } else {
        row.append(el('span', 'forced-name', item.name || '强制规则'));
        var parts = [];
        if (item.cidrs && item.cidrs.length) parts.push('CIDR：' + item.cidrs.join(', '));
        if (item.ports && item.ports.length) parts.push('端口：' + item.ports.join(', '));
        if (item.reason) parts.push('原因：' + item.reason);
        row.append(el('span', 'forced-detail', parts.join(' · ') || '—'));
      }
      container.append(row);
    });
  }

  /* ================================================================== 审计页 */

  function readAuditFilters() {
    return {
      since: fromLocalInput($('audit-since') ? $('audit-since').value : ''),
      until: fromLocalInput($('audit-until') ? $('audit-until').value : ''),
      action: ($('audit-action') ? $('audit-action').value : '').trim(),
      actor: ($('audit-actor') ? $('audit-actor').value : '').trim(),
      limit: toInt($('audit-limit') ? $('audit-limit').value : '200', 200)
    };
  }

  function buildAuditQuery(filters, append) {
    var params = new URLSearchParams();
    if (append && state.audit.oldest) {
      params.set('until', new Date(state.audit.oldest - 1000).toISOString());
    } else {
      if (filters.since) params.set('since', filters.since);
      if (filters.until) params.set('until', filters.until);
    }
    if (filters.action) params.set('action', filters.action);
    if (filters.actor) params.set('actor', filters.actor);
    params.set('limit', String(filters.limit));
    return params.toString();
  }

  function loadAudit(options) {
    options = options || {};
    var append = !!options.append;
    var tbody = $('audit-tbody');
    if (!tbody) return Promise.resolve();
    if (state.audit.loading) return Promise.resolve();
    state.audit.loading = true;
    var filters = readAuditFilters();
    if (!append) {
      state.audit.expanded.clear();
      state.audit.oldest = null;
      tableMessage(tbody, 7, '正在加载审计记录…', { loading: true });
    }
    var loadMoreBtn = qs('[data-action="audit-load-more"]');
    if (loadMoreBtn) loadMoreBtn.disabled = true;
    return api('/audit?' + buildAuditQuery(filters, append)).then(function (data) {
      var items = Array.isArray(data && data.items) ? data.items : [];
      if (append) state.audit.items = state.audit.items.concat(items);
      else state.audit.items = items;
      var last = items.length ? items[items.length - 1] : null;
      var lastDate = last ? toDate(last.time) : null;
      if (lastDate) state.audit.oldest = lastDate.getTime();
      state.audit.canMore = items.length >= filters.limit;
      state.audit.loaded = true;
      renderAudit();
      updateAuditActionList();
    }).catch(function (err) {
      if (!append) tableMessage(tbody, 7, '审计加载失败：' + ((err && err.message) || '未知错误'), {
        actionLabel: '重试',
        onAction: function () { loadAudit(); }
      });
      showApiError(err);
    }).then(function () {
      state.audit.loading = false;
      updateAuditFooter();
    });
  }

  function updateAuditActionList() {
    var list = $('audit-action-list');
    if (!list) return;
    var seen = {};
    var frag = document.createDocumentFragment();
    var reset = el('option');
    reset.value = '';
    reset.label = '全部动作';
    frag.append(reset);
    state.audit.items.forEach(function (item) {
      if (!item || !item.action || seen[item.action]) return;
      seen[item.action] = true;
      var option = el('option');
      option.value = item.action;
      option.label = actionLabel(item.action);
      frag.append(option);
    });
    list.replaceChildren(frag);
  }

  function updateAuditFooter() {
    setText('audit-count', '已加载 ' + state.audit.items.length + ' 条' +
      (state.audit.canMore ? '（还有更多，可继续加载）' : ''));
    var loadMoreBtn = qs('[data-action="audit-load-more"]');
    if (loadMoreBtn) loadMoreBtn.disabled = !state.audit.canMore || state.audit.loading;
  }

  function renderAudit() {
    var tbody = $('audit-tbody');
    if (!tbody) return;
    if (!state.audit.items.length) {
      emptyRow(tbody, 7, '没有匹配的审计记录。可调整时间范围 / 动作 / 操作者后重试。');
      updateAuditFooter();
      return;
    }
    var frag = document.createDocumentFragment();
    state.audit.items.forEach(function (item) {
      var tr = el('tr');
      tr.append(el('td', null, fmtDateTime(item.time)));
      tr.append(el('td', null, item.actor || '—'));
      tr.append(el('td', 'cell-code', item.source_ip || '—'));
      var tdAction = el('td');
      tdAction.append(el('span', 'cell-main', actionLabel(item.action)));
      tdAction.append(el('span', 'cell-sub', item.action || ''));
      tr.append(tdAction);
      var tdObject = el('td', 'col-name');
      tdObject.append(el('span', 'cell-code', item.object || '—'));
      tr.append(tdObject);
      var tdResult = el('td');
      tdResult.append(resultBadge(item.result));
      tr.append(tdResult);
      var tdActions = el('td', 'col-actions');
      var detailBtn = btn(state.audit.expanded.has(item.id) ? '收起' : '详情', { small: true });
      detailBtn.dataset.action = 'audit-detail';
      detailBtn.dataset.id = item.id;
      var actions = el('span', 'detail-actions');
      actions.append(detailBtn);
      tdActions.append(actions);
      tr.append(tdActions);
      frag.append(tr);
      if (state.audit.expanded.has(item.id)) {
        var detailTr = el('tr', 'detail-row');
        var detailTd = el('td');
        detailTd.colSpan = 7;
        var pre = el('pre', 'code-block json-detail');
        var detail = item.detail === undefined ? {} : item.detail;
        try {
          pre.textContent = JSON.stringify(detail, null, 2);
        } catch (e) {
          pre.textContent = String(detail);
        }
        detailTd.append(pre);
        detailTr.append(detailTd);
        frag.append(detailTr);
      }
    });
    tbody.replaceChildren(frag);
    updateAuditFooter();
  }

  function toggleAuditDetail(id) {
    if (state.audit.expanded.has(id)) state.audit.expanded.delete(id);
    else state.audit.expanded.add(id);
    renderAudit();
  }

  function clearAuditFilters() {
    ['audit-since', 'audit-until', 'audit-action', 'audit-actor'].forEach(function (id) {
      var node = $(id);
      if (node) node.value = '';
    });
    var limit = $('audit-limit');
    if (limit) limit.value = '200';
    loadAudit();
  }

  /* ================================================================== 证书页 */

  function loadCert() {
    return api('/cert').then(function (data) {
      state.cert = data;
      renderCert(data);
    }).catch(function (err) {
      showApiError(err);
      var mode = $('cert-mode');
      if (mode) mode.replaceChildren(el('p', 'form-alert', '证书信息加载失败：' + ((err && err.message) || '未知错误')));
    });
  }

  function renderCert(cert) {
    if (!cert) cert = {};
    var mode = modeLabel(cert.mode);
    var modeContainer = $('cert-mode');
    if (modeContainer) {
      modeContainer.replaceChildren();
      modeContainer.append(badge(mode.label, mode.variant));
      modeContainer.append(el('span', 'mode-desc', mode.desc || ''));
    }
    setText('cert-cert-path', cert.cert_path || '（自签证书，使用默认路径或 tls.dir）');
    setText('cert-key-path', cert.key_path || '（默认路径，权限 0600）');
    setText('cert-pin-value', cert.pin || '未提供');
    setText('cert-pin-next-value', cert.pin_next || '未配置（当前无需轮换）');
    var expiryContainer = $('cert-not-after');
    if (expiryContainer) {
      clear(expiryContainer);
      var expiry = certExpiryInfo(cert.not_after);
      expiryContainer.append(el('div', 'expiry-date', expiry.text));
      var row = el('div', 'hit-row');
      row.append(badge(expiry.label, expiry.variant));
      if (expiry.days !== null) {
        row.append(el('span', 'muted small', '剩余 ' + expiry.days + ' 天（按本地时间计算）'));
      }
      expiryContainer.append(row);
      if (expiry.days !== null && expiry.days <= 30) {
        expiryContainer.append(el('p', 'warn-text',
          expiry.days < 0 ? '证书已过期，请立即更换并重载。' : '证书将在 30 天内到期，请提前更换并重载。'));
      }
    }
    setText('cert-last-reload', cert.last_reload ? fmtDateTime(cert.last_reload) + '（' + fmtRelative(cert.last_reload) + '）' : '—');
    var errorEl = $('cert-last-error');
    if (errorEl) {
      errorEl.textContent = cert.last_error || '无';
      errorEl.className = cert.last_error ? 'result-error' : '';
    }
  }

  function rotateCertPin() {
    var button = qs('[data-action="cert-rotate"]');
    setBusy(button, true, '生成中…');
    api('/cert/rotate-pin', { method: 'POST' })
      .then(function (data) {
        showRotatePinModal(data || {});
        return loadCert();
      })
      .catch(function (err) {
        showApiError(err);
      })
      .then(function () {
        setBusy(button, false);
      });
  }

  function showRotatePinModal(data) {
    var body = el('div');
    body.append(el('p', 'confirm-text', '已生成新的密钥对与 SPKI pin（尚未切换证书）。轮换流程如下：'));
    var steps = el('ol', 'confirm-text');
    ['把新 pin 加入节点配置 tls.pins（与当前 pin 同时接受），并逐步下发到全部节点。',
      '确认所有节点同时接受新旧两枚 pin 后，在服务端切换证书/密钥或启用 pin_next。',
      '验证节点全部重连成功后，移除节点配置中的旧 pin。'].forEach(function (text) {
      steps.append(el('li', null, text));
    });
    body.append(steps);
    if (data.message) body.append(el('p', 'muted small', data.message));
    body.append(el('div', 'result-section-title', '新 pin'));
    var pinLine = el('div', 'copy-row');
    var pinCode = el('pre', 'code-block code-inline', data.pin || '—');
    pinLine.append(pinCode);
    var copyBtn = btn('复制', { small: true });
    copyBtn.addEventListener('click', function () { copyText(data.pin || ''); });
    pinLine.append(copyBtn);
    body.append(pinLine);
    body.append(el('p', 'warn-text', '注意：生成新 pin 不会自动切换证书；请在维护窗口按上述流程操作。'));
    var done = btn('知道了', {});
    done.addEventListener('click', closeModal);
    openModal({ title: '生成下一枚 pin', body: body, footer: [done], size: 'md' });
  }

  function reloadCert() {
    var button = qs('[data-action="cert-reload"]');
    setBusy(button, true, '重载中…');
    api('/cert/reload', { method: 'POST' })
      .then(function () {
        toast('证书已触发重载（ca 模式下新连接使用新证书）', 'success');
        return loadCert();
      })
      .catch(function (err) {
        showApiError(err);
      })
      .then(function () {
        setBusy(button, false);
      });
  }

  function openInstallTemplateModal() {
    var body = el('div');
    body.append(el('p', 'muted small', '正在加载安装模板…'));
    openModal({ title: '生成节点安装命令', body: body, size: 'lg' });
    return Promise.all([
      api('/cert').then(function (value) { return { ok: true, value: value }; }, function (err) { return { ok: false, error: err }; }),
      api('/nodes/install-template').then(function (value) { return { ok: true, value: value }; }, function (err) { return { ok: false, error: err }; })
    ]).then(function (results) {
      clear(body);
      var cert = results[0].ok ? results[0].value : (state.cert || {});
      var template = results[1].ok ? results[1].value : null;
      var pin = cert.pin || '';
      if (!results[0].ok) body.append(el('p', 'form-alert', '证书信息获取失败，pin 可能为空。'));
      if (!template) body.append(el('p', 'form-alert', '安装模板获取失败，已使用内置示例命令。'));
      var linux = fillPinPlaceholders(template && template.linux, pin) || fallbackLinux(pin);
      var windows = fillPinPlaceholders(template && template.windows, pin) || fallbackWindows(pin);
      body.append(el('p', 'muted small', templateNote(linux, pin)));
      body.append(buildCodeTabs([
        { id: 'linux', label: 'Linux', content: linux },
        { id: 'windows', label: 'Windows', content: windows }
      ]));
      body.append(el('p', 'muted small',
        '接入令牌为占位符；服务端首次启动会打印令牌，也可通过 config.server.yaml 的 nodes.tokens 配置静态令牌。'));
    });
  }

  /* ================================================================== 归属地 provider 页 */

  function loadGeo() {
    return api('/geo/providers').then(function (data) {
      state.geo.items = Array.isArray(data.items) ? data.items : [];
      state.geo.loaded = true;
      renderGeo();
    }).catch(function (err) {
      var tbody = $('geo-tbody');
      if (tbody) {
        tableMessage(tbody, 9, '归属地 provider 加载失败：' + ((err && err.message) || '未知错误'), {
          actionLabel: '重试',
          onAction: loadGeo
        });
      }
      showApiError(err);
    });
  }

  function findGeo(name) {
    for (var i = 0; i < state.geo.items.length; i++) {
      if (state.geo.items[i] && state.geo.items[i].name === name) return state.geo.items[i];
    }
    return null;
  }

  function providerTypeLabel(type) {
    var map = { preset: 'preset', template: 'template', schema: 'schema', mmdb: 'MMDB' };
    return map[String(type || '').toLowerCase()] || (type || '—');
  }

  function renderGeo() {
    var tbody = $('geo-tbody');
    if (!tbody) return;
    setText('geo-count', '共 ' + state.geo.items.length + ' 个 provider');
    if (!state.geo.items.length) {
      emptyRow(tbody, 9, '服务端未配置归属地 provider（或 geo.enabled=false）。');
      return;
    }
    var frag = document.createDocumentFragment();
    state.geo.items.forEach(function (item) {
      var tr = el('tr');
      tr.append(el('td', 'col-name', item.name || '—'));
      tr.append(el('td', null, providerTypeLabel(item.type)));
      tr.append(el('td', 'cell-code', item.preset || '—'));
      var tdEnabled = el('td');
      var toggle = el('input');
      toggle.type = 'checkbox';
      toggle.checked = !!item.enabled;
      toggle.title = item.enabled ? '点击禁用该 provider' : '点击启用该 provider';
      toggle.addEventListener('change', function () {
        toggleProvider(item, toggle);
      });
      tdEnabled.append(toggle);
      tr.append(tdEnabled);
      var tdHealthy = el('td');
      if (!item.enabled) tdHealthy.append(badge('未启用', 'muted'));
      else tdHealthy.append(item.healthy ? badge('健康', 'healthy') : badge('异常', 'warn'));
      tr.append(tdHealthy);
      tr.append(el('td', 'col-num', fmtNum(item.failures)));
      var tdError = el('td');
      var errorText = item.last_error || '—';
      tdError.append(el('span', 'cell-sub', errorText));
      tdError.title = errorText;
      tr.append(tdError);
      tr.append(el('td', 'col-num', item.priority === undefined ? '—' : String(item.priority)));
      var tdActions = el('td', 'col-actions');
      var actions = el('span', 'row-actions');
      actions.append(btn('测试', { small: true, action: 'geo-test', name: item.name }));
      tdActions.append(actions);
      tr.append(tdActions);
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
  }

  function toggleProvider(provider, checkbox) {
    checkbox.disabled = true;
    var next = checkbox.checked;
    api('/geo/providers/' + enc(provider.name), { method: 'PATCH', body: { enabled: next } })
      .then(function () {
        provider.enabled = next;
        toast('provider「' + provider.name + '」已' + (next ? '启用' : '禁用'), 'success');
        renderGeo();
      })
      .catch(function (err) {
        checkbox.checked = !next;
        checkbox.disabled = false;
        showApiError(err);
      });
  }

  function openGeoTestModal(provider) {
    var ipField = field({
      label: '测试 IP（可选）', name: 'ip', value: '',
      placeholder: '如 8.8.8.8；留空则使用服务端出口 IP',
      hint: '测试会按 provider 配置发起一次真实查询。'
    });
    var results = el('div');
    results.hidden = true;
    var form = el('form', 'form-grid');
    form.append(ipField.wrap);
    var notice = el('p', 'form-note span-2',
      '注意：启用远程 provider 需要服务端 geo.remote_consent=true，节点/测试 IP 会发送给第三方。');
    var runBtn = btn('执行测试', { variant: 'btn-primary' });
    runBtn.type = 'button';
    var closeBtn = btn('关闭', {});
    closeBtn.addEventListener('click', closeModal);
    var body = el('div');
    body.append(form, results, notice);
    openModal({
      title: 'Provider 测试 · ' + provider.name,
      body: body,
      footer: [closeBtn, runBtn],
      size: 'lg'
    });
    function runGeoTest() {
      if (form.dataset.busy === '1') return;
      form.dataset.busy = '1';
      setBusy(runBtn, true, '测试中…');
      results.hidden = false;
      clear(results);
      results.append(el('p', 'muted small', '正在调用 provider…'));
      var payload = {};
      var ip = ipField.value.trim();
      if (ip) payload.ip = ip;
      api('/geo/providers/' + enc(provider.name) + '/test', { method: 'POST', body: payload })
        .then(function (data) {
          renderGeoTestResult(results, data || {});
        })
        .catch(function (err) {
          clear(results);
          results.append(el('p', 'form-alert', '测试失败：' + ((err && err.message) || '未知错误')));
          showApiError(err);
        })
        .then(function () {
          form.dataset.busy = '0';
          setBusy(runBtn, false);
        });
    }
    wireFormSubmit(form, runBtn, runGeoTest);
  }

  function renderGeoTestResult(container, data) {
    clear(container);
    var head = el('div', 'result-head');
    head.append(el('strong', null, '测试结果 '));
    head.append(badge(data.error ? '失败' : '成功', data.error ? 'fail' : 'ok'));
    if (data.duration_ms !== undefined && data.duration_ms !== null) {
      head.append(el('span', 'muted small', '耗时 ' + Number(data.duration_ms).toFixed(1) + ' ms'));
    }
    container.append(head);
    var dl = el('dl', 'result-grid');
    kvRow(dl, 'provider', data.provider || '—');
    kvRow(dl, 'IP', data.ip || '—');
    if (data.error) kvRow(dl, '错误', data.error, 'result-error');
    container.append(dl);
    var result = data.result || {};
    var resultKeys = ['country', 'region', 'city', 'asn', 'asn_org', 'isp', 'provider'];
    var hasResult = resultKeys.some(function (key) {
      return result[key] !== undefined && result[key] !== null && result[key] !== '';
    });
    if (hasResult) {
      container.append(el('div', 'result-section-title', '提取结果'));
      var resultDl = el('dl', 'result-grid');
      resultKeys.forEach(function (key) {
        if (result[key] === undefined || result[key] === null || result[key] === '') return;
        kvRow(resultDl, key, String(result[key]));
      });
      container.append(resultDl);
    }
    if (data.hit_paths && typeof data.hit_paths === 'object') {
      var hitKeys = Object.keys(data.hit_paths);
      if (hitKeys.length) {
        container.append(el('div', 'result-section-title', '命中路径'));
        var hitDl = el('dl', 'result-grid');
        hitKeys.forEach(function (key) { kvRow(hitDl, key, String(data.hit_paths[key])); });
        container.append(hitDl);
      }
    }
    if (data.raw_snippet) {
      container.append(el('div', 'result-section-title', '原始响应片段'));
      var pre = el('pre', 'code-block');
      pre.textContent = String(data.raw_snippet);
      container.append(pre);
    }
  }

  /* ================================================================== 接入页 */

  function loadAccess() {
    return Promise.all([
      api('/cert').then(function (value) { return { ok: true, value: value }; }, function (err) { return { ok: false, error: err }; }),
      api('/nodes/install-template').then(function (value) { return { ok: true, value: value }; }, function (err) { return { ok: false, error: err }; }),
      api('/nodes/tokens').then(function (value) { return { ok: true, value: value }; }, function (err) { return { ok: false, error: err }; })
    ]).then(function (results) {
      var cert = results[0].ok ? results[0].value : (state.cert || {});
      var template = results[1].ok ? results[1].value : null;
      var pin = cert.pin || '';
      if (results[0].ok) state.cert = cert;
      setText('access-pin-value', pin || '未获取到 pin，请在证书页查看');
      var linux = fillPinPlaceholders(template && template.linux, pin) || fallbackLinux(pin);
      var windows = fillPinPlaceholders(template && template.windows, pin) || fallbackWindows(pin);
      setText('access-linux-code', linux);
      setText('access-windows-code', windows);
      var note = template ? templateNote(linux, pin) : '';
      if (!results[1].ok) note = '安装模板接口不可用（' + ((results[1].error && results[1].error.message) || '未知错误') + '），以下为内置示例命令。';
      setText('access-template-note', note);
      renderAccessTokenNote();
      renderNodeTokens(results[2]);
      if (!results[0].ok && results[1].ok) {
        toast('证书信息获取失败，pin 可能未自动填入', 'warn');
      }
    });
  }

  function renderAccessTokenNote() {
    var container = $('access-token-note');
    if (!container) return;
    clear(container);
    var list = el('ul');
    [
      '一节点一令牌；面板签发后令牌只显示一次，请立即保存。',
      '共享令牌在首个节点认证后会绑定该节点，不能再给其它节点使用。',
      '启用 mTLS（nodes.mtls=true 且 tls.client_auth=require）时，节点可使用客户端证书接入而无需令牌。',
      '可在下方「节点令牌管理」中签发、查看状态或吊销令牌。'
    ].forEach(function (text) {
      list.append(el('li', null, text));
    });
    container.append(list);
  }

  function loadNodeTokens() {
    var tbody = $('token-tbody');
    if (!tbody) return Promise.resolve();
    return api('/nodes/tokens').then(function (data) {
      renderNodeTokens({ ok: true, value: data });
    }, function (err) {
      renderNodeTokens({ ok: false, error: err });
    });
  }

  function renderNodeTokens(result) {
    var tbody = $('token-tbody');
    if (!tbody) return;
    if (!result || !result.ok) {
      emptyRow(tbody, 5, '节点令牌接口不可用：' + ((result && result.error && result.error.message) || '未知错误'));
      return;
    }
    var items = (result.value && result.value.items) || [];
    if (!items.length) {
      emptyRow(tbody, 5, '尚未签发节点令牌。');
      return;
    }
    var frag = document.createDocumentFragment();
    items.forEach(function (item) {
      var tr = el('tr');
      tr.append(el('td', null, item.node_id || '—'));
      tr.append(el('td', null, item.note || '—'));
      var tdStatus = el('td');
      tdStatus.append(badge(item.revoked ? '已吊销' : '有效', item.revoked ? 'fail' : 'ok'));
      tr.append(tdStatus);
      tr.append(el('td', null, fmtDateTime(item.created_at)));
      var tdActions = el('td', 'col-actions');
      if (!item.revoked) {
        var btn = el('button', 'btn btn-danger-ghost btn-sm', '吊销');
        btn.type = 'button';
        btn.dataset.action = 'token-revoke';
        btn.dataset.nodeId = item.node_id;
        tdActions.append(btn);
      } else {
        tdActions.append(document.createTextNode('—'));
      }
      tr.append(tdActions);
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
  }

  function issueNodeToken() {
    var nodeIDEl = $('token-node-id');
    var noteEl = $('token-note');
    var nodeID = ((nodeIDEl && nodeIDEl.value) || '').trim();
    var note = ((noteEl && noteEl.value) || '').trim();
    if (!nodeID) {
      toast('请填写节点 ID', 'warn');
      return;
    }
    var button = qs('[data-action="token-issue"]');
    setBusy(button, true, '签发中…');
    api('/nodes/tokens', { method: 'POST', body: { node_id: nodeID, note: note } })
      .then(function (data) {
        var wrap = $('access-issued-token-wrap');
        setText('access-issued-token', data && data.token ? data.token : '');
        if (wrap) wrap.hidden = false;
        if (noteEl) noteEl.value = '';
        toast('节点令牌已签发（只显示一次）', 'success');
        return loadNodeTokens();
      })
      .catch(showApiError)
      .then(function () {
        setBusy(button, false);
      });
  }

  function revokeNodeToken(nodeID) {
    if (!nodeID) return;
    confirmDialog({
      title: '吊销节点令牌',
      message: '确定吊销节点「' + nodeID + '」的所有令牌吗？',
      note: '该节点会被立即踢下线，之后必须使用新令牌才能重新接入。',
      confirmText: '吊销',
      danger: true,
      onConfirm: function () {
        return api('/nodes/tokens/' + enc(nodeID), { method: 'DELETE' }).then(function () {
          toast('节点令牌已吊销', 'success');
          return loadNodeTokens();
        });
      }
    });
  }

  function groupField(options) {
    options = options || {};
    return field({
      label: options.label,
      name: options.name,
      type: 'textarea',
      rows: 2,
      value: options.value,
      hint: options.hint,
      placeholder: options.placeholder
    });
  }

  /* ================================================================== 事件委托 / 动作表 */

  var ACTIONS = {
    nav: function (target) { go(target.dataset.page); },
    'toggle-nav': function () {
      var open = document.body.classList.toggle('app-nav-open');
      var toggle = qs('[data-action="toggle-nav"]');
      if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    },
    'refresh-page': function () { refreshCurrentPage(); },
    'token-refresh': function () { loadNodeTokens(); },
    'token-issue': function () { issueNodeToken(); },
    'token-revoke': function (target) { revokeNodeToken(target.dataset.nodeId); },
    logout: function () { logout(); },
    'banner-retry': function () {
      setBanner('network', null);
      setBanner('server', null);
      if (state.session) {
        refreshCurrentPage();
        if (!state.sse.connected) connectSSE();
      } else {
        bootSession();
      }
    },
    'copy-el': function (target) {
      var id = target.dataset.target;
      var node = id ? $(id) : null;
      copyText(node ? node.textContent : '');
    },
    'nodes-refresh': function () { loadNodes(); },
    'nodes-prev': function () {
      if (state.nodes.page > 1) {
        state.nodes.page--;
        loadNodes();
      }
    },
    'nodes-next': function () {
      if (state.nodes.page * state.nodes.size < state.nodes.total) {
        state.nodes.page++;
        loadNodes();
      }
    },
    'nodes-edit': function (target) { openNodeEdit(target.dataset.id); },
    'nodes-kick': function (target) { openNodeKick(target.dataset.id); },
    'nodes-probe': function (target) { openNodeProbe(target.dataset.id); },
    'nodes-install': function (target) { openNodeInstall(target.dataset.id); },
    'nodes-update': function (target) { openNodeUpdate(target.dataset.id); },
    'nodes-update-all': function () { updateAllNodes(); },
    'nodes-columns-toggle': function () { toggleNodeColumnsMenu(); },
    'groups-new': function () { openGroupForm(null); },
    'groups-edit': function (target) {
      var group = findGroup(target.dataset.id);
      if (group) openGroupForm(group);
    },
    'groups-members': function (target) {
      var group = findGroup(target.dataset.id);
      if (group) openGroupMembers(group);
    },
    'groups-delete': function (target) {
      var group = findGroup(target.dataset.id);
      if (group) deleteGroup(group);
    },
    'credentials-new': function () {
      ensureGroups().then(function () { openCredentialForm(null); });
    },
    'credentials-edit': function (target) {
      var cred = findCredential(target.dataset.id);
      if (cred) openCredentialForm(cred);
    },
    'credentials-kick': function (target) {
      var cred = findCredential(target.dataset.id);
      if (cred) kickCredentialSessions(cred);
    },
    'credentials-usage': function (target) {
      var cred = findCredential(target.dataset.id);
      if (cred) openCredentialUsage(cred);
    },
    'credentials-visible': function (target) {
      var cred = findCredential(target.dataset.id);
      if (cred) openCredentialVisibleNodes(cred);
    },
    'credentials-delete': function (target) {
      var cred = findCredential(target.dataset.id);
      if (cred) deleteCredential(cred);
    },
    'sticky-new': function () {
      ensureGroups().then(function () { openStickyForm(null); });
    },
    'sticky-edit': function (target) {
      var rule = findSticky(target.dataset.id);
      if (rule) openStickyForm(rule);
    },
    'sticky-delete': function (target) {
      var rule = findSticky(target.dataset.id);
      if (rule) deleteSticky(rule);
    },
    'acl-new': function () { openACLForm(null); },
    'acl-edit': function (target) {
      var rule = findACL(target.dataset.id);
      if (rule) openACLForm(rule);
    },
    'acl-delete': function (target) {
      var rule = findACL(target.dataset.id);
      if (rule) deleteACL(rule);
    },
    'audit-detail': function (target) { toggleAuditDetail(target.dataset.id); },
    'audit-load-more': function () { loadAudit({ append: true }); },
    'audit-clear': function () { clearAuditFilters(); },
    'settings-save': function () { saveSettings(); },
    'settings-undo': function () { settingsAction('undo'); },
    'settings-reset': function () { settingsAction('reset'); },
    'cert-rotate': function () { rotateCertPin(); },
    'cert-reload': function () { reloadCert(); },
    'cert-install': function () { openInstallTemplateModal(); },
    'geo-test': function (target) {
      var provider = findGeo(target.dataset.name);
      if (provider) openGeoTestModal(provider);
    }
  };

  function onDelegatedClick(ev) {
    var target = ev.target;
    if (!target || !target.closest) return;
    var actionEl = target.closest('[data-action]');
    if (!actionEl || actionEl.disabled) return;
    var handler = ACTIONS[actionEl.dataset.action];
    if (!handler) return;
    ev.preventDefault();
    try {
      var result = handler(actionEl, ev);
      if (result && typeof result.catch === 'function') result.catch(showApiError);
    } catch (err) {
      showApiError(err);
    }
  }

  function onGlobalKeydown(ev) {
    if (ev.key === 'Escape') {
      if (modalState.current) {
        closeModal();
        return;
      }
      var columnsPopover = $('nodes-columns-popover');
      if (columnsPopover && !columnsPopover.hidden) {
        closeNodeColumnsMenu();
        return;
      }
      if (document.body.classList.contains('app-nav-open')) {
        document.body.classList.remove('app-nav-open');
        var toggle = qs('[data-action="toggle-nav"]');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
      }
    }
  }

  function bindStaticEvents() {
    var loginForm = $('login-form');
    if (loginForm) loginForm.addEventListener('submit', onLoginSubmit);

    var nodesFilters = $('nodes-filters');
    if (nodesFilters) {
      nodesFilters.addEventListener('submit', function (ev) {
        ev.preventDefault();
        state.nodes.page = 1;
        loadNodes();
      });
      nodesFilters.addEventListener('reset', function () {
        setTimeout(function () {
          state.nodes.page = 1;
          loadNodes();
        }, 0);
      });
    }

    var stickyPreview = $('sticky-preview-form');
    if (stickyPreview) stickyPreview.addEventListener('submit', onStickyPreviewSubmit);

    var tokenIssue = $('token-issue-form');
    if (tokenIssue) tokenIssue.addEventListener('submit', function (ev) {
      ev.preventDefault();
      issueNodeToken();
    });

    var auditFilters = $('audit-filters');
    if (auditFilters) auditFilters.addEventListener('submit', function (ev) {
      ev.preventDefault();
      loadAudit();
    });

    document.addEventListener('click', onDelegatedClick);
    document.addEventListener('click', function (ev) {
      var picker = $('nodes-column-picker');
      var popover = $('nodes-columns-popover');
      if (!picker || !popover || popover.hidden) return;
      if (!picker.contains(ev.target)) setNodeColumnsMenuOpen(false);
    });
    document.addEventListener('keydown', onGlobalKeydown);
    window.addEventListener('hashchange', onRouteChange);
    window.addEventListener('resize', syncNodesViewportOffset);
    document.addEventListener('visibilitychange', onVisibilityChange);
  }

  /* ================================================================== 页面加载器 */

  var LOADERS = {
    overview: loadOverview,
    nodes: loadNodes,
    groups: loadGroups,
    credentials: loadCredentials,
    rules: loadRules,
    settings: loadSettings,
    audit: loadAudit,
    cert: loadCert,
    geo: loadGeo,
    access: loadAccess
  };

  /* ================================================================== 启动 */

  function bootSession() {
    var boot = $('boot-screen');
    if (boot) boot.hidden = false;
    var login = $('login-view');
    if (login) login.hidden = true;
    var app = $('app-view');
    if (app) app.hidden = true;
    return api('/session').then(function (session) {
      state.session = session;
      state.csrf = (session && session.csrf) || '';
      enterApp();
    }).catch(function () {
      showLogin();
    }).then(function () {
      if (boot) boot.hidden = true;
    });
  }

  function init() {
    bindStaticEvents();
    renderAccessTokenNote();
    applyNodeColumnVisibility();
    syncNodesViewportOffset();
    bootSession();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
