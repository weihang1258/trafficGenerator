// 通用核心功能模块
// 包含全局状态和基础工具函数

// 全局状态管理
var state = {
  page: 'overview',
  ws: null,
  charts: {},
  subtasks: [],
  searchFilters: {
    id: '',
    type: '',
    status: ''
  },
  selected: {},
  currentSort: null,
  colWidths: (function() {
    try {
      var s = localStorage.getItem('HPTG_COLWIDTHS');
      if (s) {
        return JSON.parse(s);
      }
    } catch (e) {}
    return ["40px", "1fr", "100px", "100px", "100px", "2fr", "1.2fr", "120px", "220px"];
  })(),
  pagination: {
    currentPage: 1,
    pageSize: 10,
    totalItems: 0,
    totalPages: 1
  }
};

// 通用工具函数
function getElement(id) {
  return document.getElementById(id);
}

// 页面切换函数
function switchPage(p) {
  // 检查当前是否在高性能流量生成器系统下
  var currentSystem = getCurrentSystem();
  if (currentSystem !== 'hptg') {
    showToast('请先切换到高性能流量生成器系统', false);
    return;
  }
  
  state.page = p;
  var secs = ['overview', 'tasks', 'pcap', 'history', 'settings'];
  
  for (var i = 0; i < secs.length; i++) {
    var k = secs[i];
    var el = getElement("sec_" + k);
    if (el) {
      el.className = 'card' + (k === p ? '' : ' hidden');
    }
    var nav = getElement("nav_" + k);
    if (nav) {
      if (k === p) {
        nav.className = 'active';
      } else {
        nav.className = '';
      }
    }
  }
  
  // 页面特定的初始化
  if (p === 'overview') {
    if (typeof ensureWS === 'function') ensureWS();
    if (typeof initCharts === 'function') initCharts();
    if (typeof refreshStatus === 'function') refreshStatus();
  } else if (p === 'history') {
    if (typeof loadRecent === 'function') loadRecent();
  } else if (p === 'tasks') {
    if (typeof renderHeader === 'function') renderHeader();
    if (typeof renderSubtasks === 'function') renderSubtasks();
    if (typeof updateTasksStatusBar === 'function') updateTasksStatusBar();
  }
}

// 获取当前选中的系统
function getCurrentSystem() {
  var topNavs = ['hptg', 'pcap_analyzer', 'common'];
  for (var i = 0; i < topNavs.length; i++) {
    var nav = getElement('nav_' + topNavs[i]);
    if (nav && nav.className === 'active') {
      return topNavs[i];
    }
  }
  return 'hptg'; // 默认返回高性能流量生成器
}

// Toast 提示系统
function showToast(message, isSuccess = true) {
  var toast = getElement('toast');
  if (!toast) return;
  
  toast.textContent = message;
  toast.className = 'toast ' + (isSuccess ? 'success' : 'error') + ' show';
  
  setTimeout(function() {
    toast.className = 'toast';
  }, 3000);
}

// 认证头部
function authHeaders() {
  var token = getElement('token').value || '';
  return token ? { 'Authorization': 'Bearer ' + token } : {};
}

// Token 保存
function saveToken() {
  try {
    localStorage.setItem('HPTG_TOKEN', getElement('token').value || '');
    showToast('Token已保存', true);
  } catch (e) {
    showToast('保存失败: ' + e.message, false);
  }
}

// 数据持久化
function persistDraft() {
  try {
    var flowsElement = getElement('flows_count');
    var flows = flowsElement ? flowsElement.value : '4';
    localStorage.setItem('HPTG_TASKS_DRAFT', JSON.stringify({
      subtasks: state.subtasks,
      flows: flows
    }));
  } catch (e) {}
}

function restoreDraft() {
  try {
    var t = localStorage.getItem('HPTG_TOKEN');
    if (t) getElement('token').value = t;
    
    var d = localStorage.getItem('HPTG_TASKS_DRAFT');
    if (d) {
      var j = JSON.parse(d);
      state.subtasks = j.subtasks || [];
      var flowsElement = getElement('flows_count');
      if (flowsElement) flowsElement.value = j.flows || '4';
    }
  } catch (e) {}
}

// 列宽管理
function gridColsFromState() {
  return state.colWidths.join(' ');
}

function applyGridWidths(recalc) {
  var cols = gridColsFromState();
  var headerEl = getElement("grid_hd");
  if (headerEl) {
    headerEl.style.gridTemplateColumns = cols;
  }
  
  var rows = document.querySelectorAll('.list-row');
  for (var i = 0; i < rows.length; i++) {
    rows[i].style.gridTemplateColumns = cols;
  }
}

function resetColWidths() {
  var defaultColWidths = ["40px", "1fr", "100px", "100px", "100px", "2fr", "1.2fr", "120px", "220px"];
  state.colWidths = defaultColWidths.slice();
  applyGridWidths(true);
  try {
    localStorage.setItem('HPTG_COLWIDTHS', JSON.stringify(state.colWidths));
  } catch (e) {}
}

// 初始化函数
function initializeCore() {
  restoreDraft();
  
  // 如果没有任务数据，添加默认示例
  if (state.subtasks.length === 0) {
    // 添加一个默认的TCP任务
    if (typeof addSubtask === 'function') {
      addSubtask({
        id: 'default_tcp_task',
        type: 'tcp',
        bps: '100k',
        rate_limit_fps: 10,
        tuples: {
          ip_src: { strategy: 'inc', range: '10.0.1.1-10.0.1.10', step: 1 },
          ip_dst: { strategy: 'fixed', value: '192.168.1.100' },
          sport: { strategy: 'inc', range: [10000, 10009], step: 1 },
          dport: { strategy: 'fixed', value: 80 }
        },
        tcp: {
          handshake: true,
          termination: true,
          mss: 1460,
          directionless: true,
          uplink: { payload_length: 128 },
          downlink: { payload_length: 64 }
        },
        status: 'idle'
      });
    }
  }
  
  switchPage('overview');
}

// 系统切换函数
function switchSystem(system) {
  // 更新顶级菜单状态
  var topNavs = ['hptg', 'pcap_analyzer', 'common'];
  topNavs.forEach(function(nav) {
    var navEl = getElement('nav_' + nav);
    if (navEl) {
      navEl.className = nav === system ? 'active' : '';
    }
  });
  
  // 更新二级菜单显示
  var subNavs = ['sub_nav_hptg', 'sub_nav_pcap_analyzer', 'sub_nav_common'];
  subNavs.forEach(function(subNav) {
    var subNavEl = getElement(subNav);
    if (subNavEl) {
      subNavEl.className = subNav === 'sub_nav_' + system ? 'sub-nav' : 'sub-nav hidden';
    }
  });
  
  // 重置二级菜单状态
  if (system === 'hptg') {
    // 高性能流量生成器：显示所有功能页面
    switchPage('overview');
  } else {
    // 其他系统：隐藏所有功能页面，显示"即将推出"提示
    hideAllPages();
    showComingSoonPage(system);
  }
}

// 隐藏所有功能页面
function hideAllPages() {
  var secs = ['overview', 'tasks', 'pcap', 'history', 'settings'];
  secs.forEach(function(sec) {
    var el = getElement("sec_" + sec);
    if (el) {
      el.className = 'card hidden';
    }
  });
}

// 显示"即将推出"页面
function showComingSoonPage(system) {
  var systemNames = {
    'pcap_analyzer': '报文分析器',
    'common': '常用功能'
  };
  
  var name = systemNames[system] || system;
  
  // 创建或更新即将推出页面
  var comingSoonEl = getElement('sec_coming_soon');
  if (!comingSoonEl) {
    comingSoonEl = document.createElement('div');
    comingSoonEl.id = 'sec_coming_soon';
    comingSoonEl.className = 'card';
    document.querySelector('.main').appendChild(comingSoonEl);
  }
  
  comingSoonEl.innerHTML = `
    <h3>${name} - 即将推出</h3>
    <div style="text-align: center; padding: 60px 20px; color: #64748b;">
      <div style="font-size: 48px; margin-bottom: 20px;">🚧</div>
      <div style="font-size: 18px; margin-bottom: 10px;">功能开发中</div>
      <div style="font-size: 14px;">该功能模块正在开发中，敬请期待...</div>
    </div>
  `;
  
  comingSoonEl.className = 'card';
}

// 显示"即将推出"提示
function showComingSoon(system) {
  showToast(system + '功能即将推出，敬请期待！', true);
}

// 导出到全局作用域
window.state = state;
window.getElement = getElement;
window.switchPage = switchPage;
window.showToast = showToast;
window.authHeaders = authHeaders;
window.saveToken = saveToken;
window.persistDraft = persistDraft;
window.restoreDraft = restoreDraft;
window.resetColWidths = resetColWidths;
window.initializeCore = initializeCore;
window.switchSystem = switchSystem;
window.showComingSoon = showComingSoon;
window.getCurrentSystem = getCurrentSystem;
