// 概览页面图表功能模块
// 包含图表初始化和数据更新

// 初始化图表
function initCharts() {
  try {
    // 初始化缓冲区图表
    if (typeof Chart !== 'undefined') {
      var ctxBuf = document.getElementById('chart_buf');
      if (ctxBuf) {
        state.charts.buf = new Chart(ctxBuf, {
          type: 'line',
          data: {
            labels: [],
            datasets: [{
              label: '缓冲区使用率',
              data: [],
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              tension: 0.4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true,
                max: 100
              }
            }
          }
        });
      }
      
      // 初始化队列图表
      var ctxQ = document.getElementById('chart_q');
      if (ctxQ) {
        state.charts.q = new Chart(ctxQ, {
          type: 'line',
          data: {
            labels: [],
            datasets: [{
              label: '队列长度',
              data: [],
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              tension: 0.4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true
              }
            }
          }
        });
      }
    }
  } catch (e) {
    console.warn('图表初始化失败:', e);
  }
}

// 更新图表数据
function updateChartData(metricsData) {
  if (!state.charts) return;
  
  var now = new Date();
  var timeLabel = now.toLocaleTimeString();
  
  // 更新缓冲区图表
  if (state.charts.buf && metricsData.buffer_usage !== undefined) {
    var bufChart = state.charts.buf;
    bufChart.data.labels.push(timeLabel);
    bufChart.data.datasets[0].data.push(metricsData.buffer_usage);
    
    // 保持最近20个数据点
    if (bufChart.data.labels.length > 20) {
      bufChart.data.labels.shift();
      bufChart.data.datasets[0].data.shift();
    }
    
    bufChart.update('none');
  }
  
  // 更新队列图表
  if (state.charts.q && metricsData.queue_length !== undefined) {
    var qChart = state.charts.q;
    qChart.data.labels.push(timeLabel);
    qChart.data.datasets[0].data.push(metricsData.queue_length);
    
    // 保持最近20个数据点
    if (qChart.data.labels.length > 20) {
      qChart.data.labels.shift();
      qChart.data.datasets[0].data.shift();
    }
    
    qChart.update('none');
  }
}

// 刷新状态
function refreshStatus() {
  try {
    fetch('/api/hptg/status', {
      headers: authHeaders()
    })
    .then(function(response) {
      if (response.ok) {
        return response.json();
      }
      throw new Error('状态获取失败');
    })
    .then(function(data) {
      updateStatus(data);
    })
    .catch(function(error) {
      console.warn('状态刷新失败:', error);
    });
  } catch (e) {
    console.warn('状态刷新出错:', e);
  }
}

// 格式化字节数
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  var k = 1024;
  var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  var i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 导出到全局作用域
window.initCharts = initCharts;
window.updateChartData = updateChartData;
window.refreshStatus = refreshStatus;
window.formatBytes = formatBytes;
