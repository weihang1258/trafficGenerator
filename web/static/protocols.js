// 协议配置功能模块
// 包含TCP、UDP、HTTP协议的配置渲染和策略行渲染

// 协议配置渲染
function renderProtoConfig(idx) {
  var st = state.subtasks[idx];
  var t = st.type || 'tcp';
  var html = '';
  
  // 基本信息组
  html += '<div class="form-group">' +
    '<div class="form-control">' +
    '<label>类型</label>' +
    '<select onchange="onChange(' + idx + ',\'type\', this.value)">' +
    '<option ' + (t === 'tcp' ? 'selected' : '') + ' value="tcp">TCP</option>' +
    '<option ' + (t === 'udp' ? 'selected' : '') + ' value="udp">UDP</option>' +
    '<option ' + (t === 'http' ? 'selected' : '') + ' value="http">HTTP</option>' +
    '</select>' +
    '</div>' +
    
    '<div class="form-control">' +
    '<label>bps</label>' +
    '<input value="' + (st.bps || '0') + '" onchange="onChange(' + idx + ',\'bps\', this.value)"/>' +
    '</div>' +
    
    '<div class="form-control">' +
    '<label>每秒流数量</label>' +
    '<input type="number" value="' + (st.rate_limit_fps || 0) + '" onchange="onChange(' + idx + ',\'rate_limit_fps\', parseInt(this.value||0))"/>' +
    '</div>' +
    '</div>';
  
  // IP和端口策略行
  html += renderStrategyRow(idx, 'ip_src', '源IP');
  html += renderStrategyRow(idx, 'ip_dst', '目的IP');
  html += renderStrategyRow(idx, 'sport', '源端口');
  html += renderStrategyRow(idx, 'dport', '目的端口');
  
  // 协议特定配置
  if (t === 'tcp') {
    var c = st.tcp || {};
    if (!c.uplink) c.uplink = {};
    if (!c.downlink) c.downlink = {};
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>TCP</label>' +
      '</div>' +
      '</div>';
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>握手</label>' +
      '<input type="checkbox" ' + (c.handshake !== false ? 'checked' : '') + ' onchange="onChange(' + idx + ',\'tcp.handshake\', this.checked)"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>挥手</label>' +
      '<input type="checkbox" ' + (c.termination !== false ? 'checked' : '') + ' onchange="onChange(' + idx + ',\'tcp.termination\', this.checked)"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>MSS</label>' +
      '<input type="number" value="' + (c.mss || 1460) + '" onchange="onChange(' + idx + ',\'tcp.mss\', parseInt(this.value||0))"/>' +
      '</div>' +
      '</div>';
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>上行负载长度</label>' +
      '<input type="number" value="' + ((c.uplink && c.uplink.payload_length) || 128) + '" onchange="onChange(' + idx + ',\'tcp.uplink.payload_length\', parseInt(this.value||0))"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>下行负载长度</label>' +
      '<input type="number" value="' + ((c.downlink && c.downlink.payload_length) || 64) + '" onchange="onChange(' + idx + ',\'tcp.downlink.payload_length\', parseInt(this.value||0))"/>' +
      '</div>' +
      '</div>';
    
  } else if (t === 'udp') {
    var u = st.udp || {};
    if (!u.uplink) u.uplink = {};
    if (!u.downlink) u.downlink = {};
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>UDP</label>' +
      '</div>' +
      '</div>';
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>上行负载长度</label>' +
      '<input type="number" value="' + ((u.uplink && u.uplink.payload_length) || 48) + '" onchange="onChange(' + idx + ',\'udp.uplink.payload_length\', parseInt(this.value||0))"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>下行负载长度</label>' +
      '<input type="number" value="' + ((u.downlink && u.downlink.payload_length) || 48) + '" onchange="onChange(' + idx + ',\'udp.downlink.payload_length\', parseInt(this.value||0))"/>' +
      '</div>' +
      '</div>';
    
  } else {
    var h = st.http || {
      handshake: true,
      termination: true,
      directionless: true,
      uplink: { dport: 80 },
      sessions_per_flow: { range: [1, 2] },
      methods: ['GET', 'POST'],
      domains: { strategy: 'rand', list: ['www.example.com'] },
      uris: { strategy: 'inc', pattern: '/p{n}.html', n_range: [1, 100] },
      body: { length_range: [0, 256] }
    };
    st.http = h;
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>HTTP</label>' +
      '</div>' +
      '</div>';
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>握手</label>' +
      '<input type="checkbox" ' + (h.handshake !== false ? 'checked' : '') + ' onchange="onChange(' + idx + ',\'http.handshake\', this.checked)"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>挥手</label>' +
      '<input type="checkbox" ' + (h.termination !== false ? 'checked' : '') + ' onchange="onChange(' + idx + ',\'http.termination\', this.checked)"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>目的端口</label>' +
      '<input type="number" value="' + ((h.uplink && h.uplink.dport) || 80) + '" onchange="onChange(' + idx + ',\'http.uplink.dport\', parseInt(this.value||80))"/>' +
      '</div>' +
      '</div>';
    
    html += '<div class="form-group">' +
      '<div class="form-control">' +
      '<label>每流会话数</label>' +
      '<input value="' + ((h.sessions_per_flow && h.sessions_per_flow.range) ? (h.sessions_per_flow.range[0] + "," + h.sessions_per_flow.range[1]) : '1,2') + '" onchange="(function(v){ var a=v.split(\',\'); onChange(' + idx + ',\'http.sessions_per_flow\',{range:[parseInt(a[0]||1),parseInt(a[1]||2)]}) })(this.value)"/>' +
      '</div>' +
      
      '<div class="form-control">' +
      '<label>Body长度范围</label>' +
      '<input value="' + ((h.body && h.body.length_range) ? (h.body.length_range[0] + "," + h.body.length_range[1]) : '0,256') + '" onchange="(function(v){ var a=v.split(\',\'); var b={length_range:[parseInt(a[0]||0),parseInt(a[1]||256)]}; onChange(' + idx + ',\'http.body\', b) })(this.value)"/>' +
      '</div>' +
      '</div>';
  }
  
  return html;
}

// 策略行渲染
function renderStrategyRow(idx, field, label) {
  var cfg = (state.subtasks[idx].tuples[field] || {});
  var html = '';
  
  html += '<div class="form-group">' +
    '<div class="form-control">' +
    '<label>' + label + '策略</label>' +
    '<select onchange="onChange(' + idx + ',\'tuples.' + field + '.strategy\', this.value)">' +
    '<option ' + (cfg.strategy === 'inc' ? 'selected' : '') + ' value="inc">递增</option>' +
    '<option ' + (cfg.strategy === 'rand' ? 'selected' : '') + ' value="rand">随机</option>' +
    '<option ' + (cfg.strategy === 'fixed' ? 'selected' : '') + ' value="fixed">固定</option>' +
    '</select>' +
    '</div>';
  
  if (cfg.strategy === 'inc') {
    if (field === 'ip_src' || field === 'ip_dst') {
      html += '<div class="form-control">' +
        '<label>范围</label><input value="' + (cfg.range || '10.0.0.1-10.0.0.254') + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.range\', this.value)"/>' +
        '</div>' +
        '<div class="form-control">' +
        '<label>步长</label><input type="number" value="' + (cfg.step || 1) + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.step\', parseInt(this.value||1))"/>' +
        '</div>';
    } else {
      var r = cfg.range || [10000, 10010];
      html += '<div class="form-control">' +
        '<label>范围</label><input value="' + r[0] + ',' + r[1] + '" onchange="(function(v){ var a=v.split(\',\'); onChange(' + idx + ',\'tuples.' + field + '.range\',[parseInt(a[0]||0),parseInt(a[1]||0)]) })(this.value)"/>' +
        '</div>' +
        '<div class="form-control">' +
        '<label>步长</label><input type="number" value="' + (cfg.step || 1) + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.step\', parseInt(this.value||1))"/>' +
        '</div>';
    }
  } else if (cfg.strategy === 'rand') {
    if (field === 'ip_src' || field === 'ip_dst') {
      html += '<div class="form-control">' +
        '<label>范围/CIDR</label><input value="' + (cfg.range || '192.168.1.0/24') + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.range\', this.value)"/>' +
        '</div>' +
        '<div class="form-control">' +
        '<label>种子</label><input type="number" value="' + (cfg.seed || 0) + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.seed\', parseInt(this.value||0))"/>' +
        '</div>';
    } else {
      var rr = cfg.range || [1024, 65535];
      html += '<div class="form-control">' +
        '<label>范围</label><input value="' + rr[0] + ',' + rr[1] + '" onchange="(function(v){ var a=v.split(\',\'); onChange(' + idx + ',\'tuples.' + field + '.range\',[parseInt(a[0]||0),parseInt(a[1]||0)]) })(this.value)"/>' +
        '</div>' +
        '<div class="form-control">' +
        '<label>种子</label><input type="number" value="' + (cfg.seed || 0) + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.seed\', parseInt(this.value||0))"/>' +
        '</div>';
    }
  } else {
    html += '<div class="form-control">' +
      '<label>值</label><input value="' + (cfg.value || (field === 'dport' ? 80 : '192.168.1.1')) + '" onchange="onChange(' + idx + ',\'tuples.' + field + '.value\', this.value)"/>' +
      '</div>';
  }
  
  html += '</div>';
  return html;
}

// 摘要函数
function summarizeIp(spec) {
  if (!spec) return '-';
  var s = spec.strategy || 'inc';
  var txt = '-';
  if (s === 'fixed') {
    txt = String(spec.value || '-');
  } else if (s === 'inc') {
    txt = String(spec.range || '-');
  } else if (s === 'rand') {
    txt = String(spec.range || '-');
  }
  return '<span class="mono-badge">' + txt + '</span>';
}

function summarizePort(spec) {
  if (!spec) return '-';
  var s = spec.strategy || 'inc';
  var txt = '-';
  if (s === 'fixed') {
    txt = String(spec.value || '-');
  } else if (s === 'inc' || s === 'rand') {
    if (Array.isArray(spec.range)) {
      txt = String(spec.range[0]) + '-' + String(spec.range[1]);
    } else {
      txt = String(spec.range || '-');
    }
  }
  return '<span class="mono-badge">' + txt + '</span>';
}

// 导出到全局作用域
window.renderProtoConfig = renderProtoConfig;
window.renderStrategyRow = renderStrategyRow;
window.summarizeIp = summarizeIp;
window.summarizePort = summarizePort;
