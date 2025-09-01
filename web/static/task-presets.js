// 预设任务配置模块
// 包含预设任务的定义和添加功能

// 预设模型添加
function onPresetAdd(select) {
  var value = select.value;
  if (!value) return;
  
  var preset = getPresetConfig(value);
  if (preset) {
    addSubtask(preset);
    select.value = '';
    showToast('已添加预设任务: ' + value, true);
  }
}

// 获取预设配置
function getPresetConfig(presetName) {
  var presets = {
    'tcp_web': {
      id: generateUniqueId('tcp_web'),
      type: 'tcp',
      bps: '100k',
      rate_limit_fps: 100,
      tuples: {
        ip_src: { strategy: 'inc', range: '10.0.1.1-10.0.1.10', step: 1 },
        ip_dst: { strategy: 'fixed', value: '192.168.1.100' },
        sport: { strategy: 'rand', range: [1024, 65535] },
        dport: { strategy: 'fixed', value: 80 }
      },
      tcp: {
        handshake: true,
        termination: true,
        mss: 1460,
        directionless: false,
        uplink: { payload_length: 256 },
        downlink: { payload_length: 128 }
      },
      status: 'idle'
    },
    'udp_ping': {
      id: generateUniqueId('udp_ping'),
      type: 'udp',
      bps: '50k',
      rate_limit_fps: 50,
      tuples: {
        ip_src: { strategy: 'inc', range: '10.0.2.1-10.0.2.5', step: 1 },
        ip_dst: { strategy: 'fixed', value: '192.168.2.1' },
        sport: { strategy: 'rand', range: [1024, 65535] },
        dport: { strategy: 'fixed', value: 53 }
      },
      udp: {
        payload_length: 64
      },
      status: 'idle'
    },
    'http_api': {
      id: generateUniqueId('http_api'),
      type: 'http',
      bps: '200k',
      rate_limit_fps: 200,
      tuples: {
        ip_src: { strategy: 'inc', range: '10.0.3.1-10.0.3.20', step: 1 },
        ip_dst: { strategy: 'fixed', value: '192.168.3.1' },
        sport: { strategy: 'rand', range: [1024, 65535] },
        dport: { strategy: 'fixed', value: 8080 }
      },
      http: {
        method: 'POST',
        path: '/api/data',
        headers: { 'Content-Type': 'application/json' },
        payload: '{"test": "data"}'
      },
      status: 'idle'
    }
  };
  
  return presets[presetName];
}

// 导出到全局作用域
window.onPresetAdd = onPresetAdd;
window.getPresetConfig = getPresetConfig;
