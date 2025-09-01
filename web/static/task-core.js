// 任务核心功能模块
// 包含任务的增删改查和状态管理

// 生成唯一ID
function generateUniqueId(baseName) {
  var counter = 1;
  var id = baseName;
  while (state.subtasks.some(function(st) { return st.id === id; })) {
    id = baseName + '_' + counter;
    counter++;
  }
  return id;
}

// 添加子任务
function addSubtask(prefill) {
  var st = prefill || {
    id: generateUniqueId('task'),
    type: 'tcp',
    bps: '50k',
    rate_limit_fps: 2,
    tuples: {
      ip_src: { strategy: 'inc', range: '10.0.1.1-10.0.1.3', step: 1 },
      ip_dst: { strategy: 'fixed', value: '192.168.1.1' },
      sport: { strategy: 'inc', range: [10000, 10002], step: 1 },
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
  };
  
  state.subtasks.push(st);
  
  // 重置分页到第一页
  if (typeof resetPagination === 'function') {
    resetPagination();
  }
  
  renderSubtasks();
  persistDraft();
  showToast('已添加任务', true);
}

// 删除子任务
function removeSubtask(idx) {
  var st = state.subtasks[idx];
  if (st && st.status === 'running') {
    showToast('执行中的任务不能删除', false);
    return;
  }
  state.subtasks.splice(idx, 1);
  
  // 检查是否需要调整分页
  if (typeof updatePagination === 'function') {
    updatePagination();
  }
  
  renderSubtasks();
  persistDraft();
}

// 任务配置变更处理
function onChange(idx, path, val) {
  var parts = path.split('.');
  var obj = state.subtasks[idx];
  
  for (var i = 0; i < parts.length - 1; i++) {
    var p = parts[i];
    if (!obj[p]) obj[p] = {};
    obj = obj[p];
  }
  
  obj[parts[parts.length - 1]] = val;
  
  // 只更新当前行的编辑界面，不重新渲染整个列表
  var editDiv = getElement('subtask_bd_' + idx);
  if (editDiv && !editDiv.classList.contains('hidden')) {
    editDiv.innerHTML = renderProtoConfig(idx);
  }
  
  persistDraft();
}

// 切换任务编辑界面
function toggleSubtaskBody(i) {
  var el = getElement('subtask_bd_' + i);
  if (!el) return;
  el.className = (el.className.indexOf('hidden') > -1) ? 'subtask-bd' : 'subtask-bd hidden';
}

// 提交任务
function submitTasks() {
  var selectedIds = getSelectedTaskIds();
  if (selectedIds.length === 0) {
    showToast('请先选择要提交的任务', false);
    return;
  }
  
  // 这里可以添加任务提交的逻辑
  // 比如发送到后端API或执行其他操作
  showToast(`已提交 ${selectedIds.length} 个任务`, true);
  
  // 清空选择
  selectAll(false);
}

// 导出到全局作用域
window.generateUniqueId = generateUniqueId;
window.addSubtask = addSubtask;
window.removeSubtask = removeSubtask;
window.onChange = onChange;
window.toggleSubtaskBody = toggleSubtaskBody;
window.submitTasks = submitTasks;

// 加载任务页面内容
function loadTasksContent(container) {
  // 重置分页状态到第一页
  if (state.pagination) {
    state.pagination.currentPage = 1;
  }
  
  container.innerHTML = `
    <div class="card">
      <div class="tasks-header">
        <div class="search-row">
          <div class="left-search">
            <div class="search-group">
              <label>任务ID</label>
              <input id="search_id" type="text" placeholder="搜索任务ID" oninput="onSearchChange()"/>
            </div>
            <div class="search-group">
              <label>类型</label>
              <select id="search_type" onchange="onSearchChange()">
                <option value="">全部类型</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
              </select>
            </div>
            <div class="search-group">
              <label>状态</label>
              <select id="search_status" onchange="onSearchChange()">
                <option value="">全部状态</option>
                <option value="idle">空闲</option>
                <option value="running">运行中</option>
                <option value="stopped">已停止</option>
              </select>
            </div>
          </div>
          
          <div class="right-controls">
            <button class="btn ghost" onclick="clearSearch()">清空搜索</button>
          </div>
        </div>
        
        <div class="control-row">
          <div class="left-controls">
            <button class="btn primary" onclick="addSubtask()">➕ 新增任务</button>
            <div class="preset-group">
              <label>预设模型</label>
              <select id="preset_sel" onchange="onPresetAdd(this)">
                <option value="">选择预设...</option>
                <option value="tcp_web">TCP Web 小流量</option>
                <option value="udp_ping">UDP Ping 模拟</option>
                <option value="http_api">HTTP API 混合</option>
              </select>
            </div>
            <button class="btn danger" onclick="deleteSelected()">🗑️ 删除</button>
            <button class="btn ghost" onclick="resetColWidths()">🔄 重置列宽</button>
          </div>
          <div class="right-controls">
            <button class="btn success" onclick="submitTasks()">✅ 提交</button>
          </div>
        </div>
      </div>
      
      <div class="tasks-content">
        <div id="subtasks" class="subtasks"></div>
        
        <!-- 分页控件 -->
        <div id="pagination-container" class="pagination-container"></div>
      </div>
    </div>
  `;
  
  // 初始化任务页面
  setTimeout(() => {
    // 初始化分页
    if (typeof initPagination === 'function') {
      initPagination();
    }
    
    if (typeof renderSubtasks === 'function') {
      renderSubtasks();
    }
    if (typeof renderPagination === 'function') {
      renderPagination();
    }
    
    // 加载保存的任务数据
    if (typeof loadDraft === 'function') {
      loadDraft();
      // 重新渲染以显示加载的数据
      if (typeof renderSubtasks === 'function') {
        renderSubtasks();
      }
      if (typeof renderPagination === 'function') {
        renderPagination();
      }
    }
  }, 100);
}
