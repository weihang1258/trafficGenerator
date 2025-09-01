// 预设模板功能模块
// 包含TCP Web、UDP Ping、HTTP API等预设模板

// 预设模板选择处理
function onPresetAdd(sel) {
  var v = sel.value || '';
  if (!v) return;
  
  if (v === 'tcp_web') {
    addSubtask({
      id: generateUniqueId('tcp_web'),
      type: 'tcp',
      bps: '50k',
      rate_limit_fps: 5,
      tuples: {
        ip_src: { strategy: 'inc', range: '10.0.2.1-10.0.2.10', step: 1 },
        ip_dst: { strategy: 'fixed', value: '192.168.1.1' },
        sport: { strategy: 'inc', range: [20000, 20050], step: 1 },
        dport: { strategy: 'fixed', value: 80 }
      },
      tcp: {
        handshake: true,
        termination: true,
        mss: 1460,
        directionless: true,
        uplink: { payload_length: 256 },
        downlink: { payload_length: 128 }
      },
      status: 'idle'
    });
  } else if (v === 'udp_ping') {
    addSubtask({
      id: generateUniqueId('udp_ping'),
      type: 'udp',
      bps: '0',
      rate_limit_fps: 20,
      tuples: {
        ip_src: { strategy: 'inc', range: '10.0.3.1-10.0.3.5', step: 1 },
        ip_dst: { strategy: 'fixed', value: '192.168.1.2' },
        sport: { strategy: 'fixed', value: 33434 },
        dport: { strategy: 'fixed', value: 33434 }
      },
      udp: {
        uplink: { payload_length: 48 },
        downlink: { payload_length: 48 }
      },
      status: 'idle'
    });
  } else if (v === 'http_api') {
    addSubtask({
      id: generateUniqueId('http_api'),
      type: 'http',
      bps: '100k',
      rate_limit_fps: 10,
      tuples: {
        ip_src: { strategy: 'rand', range: '172.16.0.0/16', seed: 42 },
        ip_dst: { strategy: 'fixed', value: '192.168.1.10' },
        sport: { strategy: 'inc', range: [30000, 30100], step: 1 },
        dport: { strategy: 'fixed', value: 80 }
      },
      http: {
        handshake: true,
        termination: true,
        directionless: true,
        uplink: { dport: 80 },
        sessions_per_flow: { range: [1, 3] },
        methods: ['GET', 'POST'],
        domains: { strategy: 'list', list: ['api.example.com'] },
        uris: { strategy: 'inc', pattern: '/users/{n}', n_range: [1, 1000] },
        body: { length_range: [0, 256] }
      },
      status: 'idle'
    });
  }
  
  sel.value = '';
}

// 载入示例到任务
function loadExamplesToTasks() {
  // 清空现有任务
  state.subtasks = [];
  
  // 添加TCP Web示例
  addSubtask({
    id: generateUniqueId('tcp_web'),
    type: 'tcp',
    bps: '100k',
    rate_limit_fps: 10,
    tuples: {
      ip_src: { strategy: 'inc', range: '10.0.1.1-10.0.1.50', step: 1 },
      ip_dst: { strategy: 'fixed', value: '192.168.1.100' },
      sport: { strategy: 'inc', range: [20000, 20099], step: 1 },
      dport: { strategy: 'fixed', value: 80 }
    },
    tcp: {
      handshake: true,
      termination: true,
      mss: 1460,
      directionless: true,
      uplink: {
        strategy: 'random',
        length: 512
      },
      downlink: {
        strategy: 'random',
        length: 256
      }
    },
    status: 'idle'
  });
  
  // 添加UDP Ping示例
  addSubtask({
    id: generateUniqueId('udp_ping'),
    type: 'udp',
    bps: '0',
    rate_limit_fps: 50,
    tuples: {
      ip_src: { strategy: 'inc', range: '10.0.2.1-10.0.2.20', step: 1 },
      ip_dst: { strategy: 'fixed', value: '192.168.1.200' },
      sport: { strategy: 'fixed', value: 33434 },
      dport: { strategy: 'fixed', value: 33434 }
    },
    udp: {
      uplink: {
        strategy: 'fixed',
        content: 'ping'
      },
      downlink: {
        strategy: 'fixed',
        content: 'pong'
      }
    },
    status: 'idle'
  });
  
  // 添加HTTP API示例
  addSubtask({
    id: generateUniqueId('http_api'),
    type: 'http',
    bps: '200k',
    rate_limit_fps: 20,
    tuples: {
      ip_src: { strategy: 'rand', range: '172.16.0.0/16', seed: 123 },
      ip_dst: { strategy: 'fixed', value: '192.168.1.50' },
      sport: { strategy: 'inc', range: [30000, 30099], step: 1 },
      dport: { strategy: 'fixed', value: 443 }
    },
    http: {
      handshake: true,
      termination: true,
      directionless: true,
      uplink: { dport: 443 },
      sessions_per_flow: { range: [1, 5] },
      methods: ['GET', 'POST', 'PUT'],
      domains: { strategy: 'list', list: ['api.example.com', 'v1.api.example.com'] },
      uris: { strategy: 'inc', pattern: '/users/{n}', n_range: [1, 1000] },
      body: { length_range: [0, 1024] },
      uplink: {
        strategy: 'increment',
        pattern: 'POST /api/users/{n}',
        start: 1,
        step: 1
      },
      downlink: {
        strategy: 'random',
        length: 256
      }
    },
    status: 'idle'
  });
  
  // 设置总流数量
  var flowsCountEl = getElement('flows_count');
  if (flowsCountEl) {
    flowsCountEl.value = '100';
  }
  
  showToast('已载入示例任务', true);
}

// 导出到全局作用域
window.onPresetAdd = onPresetAdd;
window.loadExamplesToTasks = loadExamplesToTasks;
