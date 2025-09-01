// 历史页面功能模块

// 加载最近历史
function loadRecent() {
  showToast('正在加载历史记录...', true);
  
  // 模拟加载历史数据
  setTimeout(function() {
    var historyData = [
      {
        id: 'config_001',
        name: 'Web服务器压力测试',
        timestamp: Date.now() - 86400000,
        type: 'tcp',
        status: 'completed'
      },
      {
        id: 'config_002',
        name: 'API接口性能测试',
        timestamp: Date.now() - 172800000,
        type: 'http',
        status: 'completed'
      },
      {
        id: 'config_003',
        name: '网络延迟测试',
        timestamp: Date.now() - 259200000,
        type: 'udp',
        status: 'failed'
      }
    ];
    
    renderHistoryList(historyData);
    showToast('历史记录加载完成', true);
  }, 1000);
}

// 渲染历史列表
function renderHistoryList(historyData) {
  var container = getElement('history_list');
  if (!container) return;
  
  if (historyData.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:40px;color:#64748b;">暂无历史记录</div>';
    return;
  }
  
  var html = '';
  historyData.forEach(function(item) {
    html += `
      <div class="history-item" onclick="loadHistoryConfig('${item.id}')">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <h4 style="margin:0 0 8px 0;color:#1e293b;">${item.name}</h4>
            <p style="margin:0;color:#64748b;font-size:13px;">
              <span class="badge badge-${item.type}">${item.type.toUpperCase()}</span>
              <span class="badge badge-${item.status}">${getHistoryStatusText(item.status)}</span>
            </p>
          </div>
          <div style="text-align:right;color:#64748b;font-size:12px;">
            ${formatTime(item.timestamp)}
          </div>
        </div>
      </div>
    `;
  });
  
  container.innerHTML = html;
}

// 获取历史状态文本
function getHistoryStatusText(status) {
  var statusMap = {
    'completed': '已完成',
    'failed': '失败',
    'running': '运行中',
    'stopped': '已停止'
  };
  return statusMap[status] || status;
}

// 加载历史配置
function loadHistoryConfig(configId) {
  showToast('正在加载配置: ' + configId, true);
  
  // TODO: 实现历史配置加载逻辑
  setTimeout(function() {
    showToast('配置加载完成', true);
    // 这里可以切换到任务页面并加载配置
    switchPage('tasks');
  }, 1000);
}

// 清空历史
function clearHistory() {
  confirmAction('确定要清空所有历史记录吗？此操作不可恢复。', function() {
    getElement('history_list').innerHTML = '<div style="text-align:center;padding:40px;color:#64748b;">历史记录已清空</div>';
    showToast('历史记录已清空', true);
  });
}

// 加载历史页面内容
function loadHistoryContent(container) {
  container.innerHTML = `
    <div class="card">
      <h3>历史配置</h3>
      <div class="row">
        <button class="btn" onclick="loadRecent()">刷新历史</button>
        <button class="btn ghost" onclick="clearHistory()">清空历史</button>
      </div>
      <div id="history_list" class="history-list"></div>
    </div>
  `;
  
  // 自动加载历史记录
  setTimeout(() => {
    loadRecent();
  }, 100);
}
