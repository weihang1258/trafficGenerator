// PCAP 页面功能模块

// 浏览PCAP文件
function browsePcap() {
  // 创建文件输入元素
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = '.pcap,.pcapng';
  input.onchange = function(e) {
    var file = e.target.files[0];
    if (file) {
      getElement('pcap_path').value = file.name;
      showToast('已选择文件: ' + file.name, true);
    }
  };
  input.click();
}

// 加载PCAP文件
function loadPcap() {
  var path = getElement('pcap_path').value;
  if (!path) {
    showToast('请先选择PCAP文件', false);
    return;
  }
  
  showToast('正在加载PCAP文件...', true);
  // TODO: 实现PCAP文件加载逻辑
  setTimeout(function() {
    showToast('PCAP文件加载完成', true);
    getElement('pcap_info').innerHTML = `
      <h4>文件信息</h4>
      <p><strong>文件名:</strong> ${path}</p>
      <p><strong>大小:</strong> 1.2 MB</p>
      <p><strong>数据包数:</strong> 15,432</p>
      <p><strong>时间范围:</strong> 2024-01-01 10:00:00 - 10:05:00</p>
    `;
  }, 1000);
}

// 分析PCAP流量
function analyzePcap() {
  var path = getElement('pcap_path').value;
  if (!path) {
    showToast('请先选择PCAP文件', false);
    return;
  }
  
  showToast('正在分析流量...', true);
  // TODO: 实现流量分析逻辑
  setTimeout(function() {
    showToast('流量分析完成', true);
    getElement('pcap_info').innerHTML += `
      <h4>流量统计</h4>
      <p><strong>TCP连接:</strong> 2,145</p>
      <p><strong>UDP数据包:</strong> 8,234</p>
      <p><strong>HTTP请求:</strong> 1,567</p>
      <p><strong>平均包大小:</strong> 512 bytes</p>
    `;
  }, 2000);
}

// 加载PCAP页面内容
function loadPCAPContent(container) {
  container.innerHTML = `
    <div class="card">
      <h3>PCAP 文件管理</h3>
      <div class="row">
        <label>PCAP 文件路径</label>
        <input id="pcap_path" type="text" placeholder="输入PCAP文件路径" class="control-lg" style="flex:1;"/>
        <button class="btn" onclick="browsePcap()">浏览</button>
      </div>
      <div class="row">
        <button class="btn primary" onclick="loadPcap()">加载PCAP</button>
        <button class="btn" onclick="analyzePcap()">分析流量</button>
      </div>
      <div id="pcap_info" class="info-box"></div>
    </div>
  `;
}
