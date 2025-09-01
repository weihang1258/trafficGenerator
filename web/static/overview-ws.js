// 概览页面WebSocket功能模块
// 包含WebSocket连接管理和消息处理

// WebSocket连接管理
var wsReconnectTimer = null;
var wsReconnectAttempts = 0;
var maxReconnectAttempts = 5;

// 确保WebSocket连接
function ensureWS() {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    return;
  }
  
  try {
    var token = getElement('token').value || '';
    var wsUrl = 'ws://localhost:8080/ws';
    if (token) {
      wsUrl += '?token=' + encodeURIComponent(token);
    }
    
    state.ws = new WebSocket(wsUrl);
    
    state.ws.onopen = function() {
      console.log('WebSocket连接已建立');
      wsReconnectAttempts = 0;
      showToast('实时连接已建立', true);
    };
    
    state.ws.onmessage = function(event) {
      try {
        var data = JSON.parse(event.data);
        handleWSMessage(data);
      } catch (e) {
        console.warn('WebSocket消息解析失败:', e);
      }
    };
    
    state.ws.onclose = function() {
      console.log('WebSocket连接已关闭');
      scheduleReconnect();
    };
    
    state.ws.onerror = function(error) {
      console.error('WebSocket错误:', error);
    };
    
  } catch (e) {
    console.error('WebSocket连接失败:', e);
    scheduleReconnect();
  }
}

// 安排重连
function scheduleReconnect() {
  if (wsReconnectAttempts >= maxReconnectAttempts) {
    showToast('WebSocket重连失败，请检查服务器状态', false);
    return;
  }
  
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
  }
  
  var delay = Math.min(1000 * Math.pow(2, wsReconnectAttempts), 30000);
  wsReconnectAttempts++;
  
  console.log('安排WebSocket重连，延迟:', delay, 'ms，尝试次数:', wsReconnectAttempts);
  
  wsReconnectTimer = setTimeout(function() {
    ensureWS();
  }, delay);
}

// 处理WebSocket消息
function handleWSMessage(data) {
  if (data.type === 'status') {
    updateStatus(data.data);
  } else if (data.type === 'metrics') {
    updateMetrics(data.data);
  } else if (data.type === 'error') {
    showToast('服务器错误: ' + data.message, false);
  }
}

// 更新状态信息
function updateStatus(statusData) {
  var statusElement = getElement('status_info');
  if (!statusElement) return;
  
  var statusText = '未知';
  var statusClass = 'unknown';
  
  if (statusData.running) {
    statusText = '运行中';
    statusClass = 'running';
  } else if (statusData.stopped) {
    statusText = '已停止';
    statusClass = 'stopped';
  } else if (statusData.error) {
    statusText = '错误: ' + statusData.error;
    statusClass = 'error';
  }
  
  statusElement.textContent = statusText;
  statusElement.className = 'status-badge ' + statusClass;
}

// 更新指标数据
function updateMetrics(metricsData) {
  // 更新流量统计
  if (metricsData.bytes_sent !== undefined) {
    var bytesElement = getElement('bytes_sent');
    if (bytesElement) {
      bytesElement.textContent = formatBytes(metricsData.bytes_sent);
    }
  }
  
  if (metricsData.packets_sent !== undefined) {
    var packetsElement = getElement('packets_sent');
    if (packetsElement) {
      packetsElement.textContent = metricsData.packets_sent.toLocaleString();
    }
  }
  
  if (metricsData.flows_active !== undefined) {
    var flowsElement = getElement('flows_active');
    if (flowsElement) {
      flowsElement.textContent = metricsData.flows_active.toLocaleString();
    }
  }
  
  // 更新图表数据
  if (state.charts && state.charts.buf) {
    updateChartData(metricsData);
  }
}

// 导出到全局作用域
window.ensureWS = ensureWS;
window.handleWSMessage = handleWSMessage;
window.updateStatus = updateStatus;
window.updateMetrics = updateMetrics;
