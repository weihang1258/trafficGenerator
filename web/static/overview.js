// 概览页面功能模块

// 图表数据系列
var bufSeries = [], upSeries = [], downSeries = [], qcSeries = [], qpSeries = [], timeSeries = [];

// 初始化图表
function initCharts() {
  if (state.charts.buf && state.charts.q) return;
  
  state.charts.buf = echarts.init(getElement("chart_buffer"));
  state.charts.q = echarts.init(getElement("chart_queue"));
  
  // 缓冲区大小图表
  state.charts.buf.setOption({
    title: { text: '缓冲区大小' },
    tooltip: {},
    legend: { data: ['合并', '上行', '下行'] },
    xAxis: { type: 'category', data: [] },
    yAxis: { type: 'value' },
    series: [
      { name: '合并', type: 'line', data: [] },
      { name: '上行', type: 'line', data: [] },
      { name: '下行', type: 'line', data: [] }
    ]
  });
  
  // 队列深度图表
  state.charts.q.setOption({
    title: { text: '队列深度' },
    tooltip: {},
    legend: { data: ['配置队列', '报文队列'] },
    xAxis: { type: 'category', data: [] },
    yAxis: { type: 'value' },
    series: [
      { name: '配置队列', type: 'line', data: [] },
      { name: '报文队列', type: 'line', data: [] }
    ]
  });
}

// 推送指标数据到图表
function pushMetrics(s) {
  var ts = new Date().toLocaleTimeString();
  timeSeries.push(ts);
  bufSeries.push(s.current_size || 0);
  upSeries.push(s.current_size_up || 0);
  downSeries.push(s.current_size_down || 0);
  qcSeries.push(s.config_queue_depth || 0);
  qpSeries.push(s.packet_queue_depth || 0);
  
  // 保持最近100个数据点
  if (timeSeries.length > 100) {
    timeSeries.shift();
    bufSeries.shift();
    upSeries.shift();
    downSeries.shift();
    qcSeries.shift();
    qpSeries.shift();
  }
  
  // 更新图表
  state.charts.buf.setOption({
    xAxis: { data: timeSeries },
    series: [
      { name: '合并', data: bufSeries },
      { name: '上行', data: upSeries },
      { name: '下行', data: downSeries }
    ]
  });
  
  state.charts.q.setOption({
    xAxis: { data: timeSeries },
    series: [
      { name: '配置队列', data: qcSeries },
      { name: '报文队列', data: qpSeries }
    ]
  });
}

// 确保WebSocket连接
function ensureWS() {
  if (state.ws) return;
  
  try {
    var t = encodeURIComponent(getElement('token').value || '');
    var qs = t ? ('?token=' + t) : '';
    state.ws = new WebSocket((location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/api/hptg/stream' + qs);
    
    state.ws.onmessage = function(ev) {
      try {
        var j = JSON.parse(ev.data);
        getElement('status').innerText = JSON.stringify(j, null, 2);
        if (j && j.running) {
          pushMetrics(j);
        }
      } catch (e) {
        console.warn('解析WebSocket消息失败:', e);
      }
      
      try {
        state.ws.send('ping');
      } catch (e) {
        console.warn('发送ping失败:', e);
      }
    };
    
    state.ws.onclose = function() {
      state.ws = null;
      setTimeout(function() {
        if (!state.ws && state.page === 'overview') {
          ensureWS();
        }
      }, 3000);
    };
    
    state.ws.onerror = function(error) {
      console.error('WebSocket连接错误:', error);
      state.ws = null;
    };
    
  } catch (e) {
    console.error('创建WebSocket连接失败:', e);
  }
}

// 刷新状态
async function refreshStatus() {
  try {
    var r = await fetch('/api/hptg/status', { headers: authHeaders() });
    var s = await r.json();
    getElement('status').innerText = JSON.stringify(s, null, 2);
  } catch (e) {
    console.error('获取状态失败:', e);
    getElement('status').innerText = '获取状态失败: ' + e.message;
  }
}

// 启动生成器
async function startGen() {
  try {
    var cp = parseInt(getElement('cfg_cp').value || '1');
    var pp = parseInt(getElement('cfg_pp').value || '1');
    var buf = parseInt(getElement('cfg_buf').value || '4096');
    var qc = parseInt(getElement('cfg_qc').value || '2000');
    var qp = parseInt(getElement('cfg_qp').value || '2000');
    
    var r = await fetch('/api/hptg/start', {
      method: 'POST',
      headers: Object.assign({'Content-Type': 'application/json'}, authHeaders()),
      body: JSON.stringify({
        config_processes: cp,
        packet_processes: pp,
        local_buffer_size: buf,
        config_queue_capacity: qc,
        packet_queue_capacity: qp
      })
    });
    
    if (r.ok) {
      showToast('生成器已启动', true);
      refreshStatus();
    } else {
      showToast('启动失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('启动出错: ' + e.message, false);
  }
}

// 停止生成器
async function stopGen() {
  try {
    var r = await fetch('/api/hptg/stop', {
      method: 'POST',
      headers: authHeaders()
    });
    
    if (r.ok) {
      showToast('生成器已停止', true);
      refreshStatus();
    } else {
      showToast('停止失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('停止出错: ' + e.message, false);
  }
}

// 窗口大小变化时重新调整图表
window.addEventListener('resize', function() {
  if (state.charts.buf) {
    state.charts.buf.resize();
  }
  if (state.charts.q) {
    state.charts.q.resize();
  }
});

// 加载概览页面内容
function loadOverviewContent(container) {
  container.innerHTML = `
    <div class="card">
      <h3>概览</h3>
      <div class="row">
        <label>Token</label>
        <input id="token" placeholder="可选：后端设置 HPTG_TOKEN 后填写" class="control-lg" style="min-width:280px;"/>
        <button class="btn" onclick="saveToken()">保存</button>
      </div>
      <div class="row">
        <label>配置进程数</label>
        <input id="cfg_cp" type="number" value="1" class="control-lg"/>
        <label style="margin-left:12px;">数据包进程数</label>
        <input id="cfg_pp" type="number" value="1" class="control-lg"/>
      </div>
      <div class="row">
        <label>本地缓冲大小</label>
        <input id="cfg_buf" type="number" value="4096" class="control-lg"/>
        <label style="margin-left:12px;">配置队列</label>
        <input id="cfg_qc" type="number" value="2000" class="control-lg"/>
        <label style="margin-left:12px;">报文队列</label>
        <input id="cfg_qp" type="number" value="2000" class="control-lg"/>
      </div>
      <div class="row">
        <button class="btn primary" onclick="startGen()">启动生成器</button>
        <button class="btn danger" onclick="stopGen()">停止生成器</button>
      </div>
      <div class="row">
        <div class="status" id="status">{}</div>
      </div>
      <div class="grid">
        <div id="chart_buffer" style="height:240px;"></div>
        <div id="chart_queue" style="height:240px;"></div>
      </div>
    </div>
  `;
  
  // 加载保存的Token
  var savedToken = localStorage.getItem('HPTG_TOKEN');
  if (savedToken) {
    getElement('token').value = savedToken;
  }
  
  // 初始化图表
  setTimeout(() => {
    initCharts();
    refreshStatus();
    ensureWS();
  }, 100);
}
