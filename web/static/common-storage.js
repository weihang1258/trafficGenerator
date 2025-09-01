// 通用存储功能模块
// 包含数据持久化和草稿管理

// 数据持久化
function persistDraft() {
  try {
    var data = {
      subtasks: state.subtasks,
      timestamp: Date.now()
    };
    localStorage.setItem('HPTG_DRAFT', JSON.stringify(data));
  } catch (e) {
    console.warn('保存草稿失败:', e);
  }
}

function loadDraft() {
  try {
    var data = localStorage.getItem('HPTG_DRAFT');
    if (data) {
      var parsed = JSON.parse(data);
      if (parsed.subtasks && Array.isArray(parsed.subtasks)) {
        state.subtasks = parsed.subtasks;
        return true;
      }
    }
  } catch (e) {
    console.warn('加载草稿失败:', e);
  }
  return false;
}

// 任务状态栏更新
function updateTasksStatusBar() {
  var statusBar = getElement('tasks_status_bar');
  if (!statusBar) return;
  
  var total = state.subtasks.length;
  var running = state.subtasks.filter(function(st) { return st.status === 'running'; }).length;
  var idle = state.subtasks.filter(function(st) { return st.status === 'idle'; }).length;
  var stopped = state.subtasks.filter(function(st) { return st.status === 'stopped'; }).length;
  
  statusBar.innerHTML = 
    '<span>总任务: ' + total + '</span>' +
    '<span>运行中: ' + running + '</span>' +
    '<span>空闲: ' + idle + '</span>' +
    '<span>已停止: ' + stopped + '</span>';
}

// 搜索过滤
function applySearchFilters() {
  var idFilter = getElement('search_id').value.toLowerCase();
  var typeFilter = getElement('search_type').value;
  var statusFilter = getElement('search_status').value;
  
  state.searchFilters.id = idFilter;
  state.searchFilters.type = typeFilter;
  state.searchFilters.status = statusFilter;
  
  // 搜索时重置分页到第一页
  if (typeof resetPagination === 'function') {
    resetPagination();
  }
  
  if (typeof renderSubtasks === 'function') {
    renderSubtasks();
  }
}

// 清除搜索
function clearSearchFilters() {
  getElement('search_id').value = '';
  getElement('search_type').value = '';
  getElement('search_status').value = '';
  
  state.searchFilters.id = '';
  state.searchFilters.type = '';
  state.searchFilters.status = '';
  
  // 清除搜索时重置分页到第一页
  if (typeof resetPagination === 'function') {
    resetPagination();
  }
  
  if (typeof renderSubtasks === 'function') {
    renderSubtasks();
  }
}

// 获取过滤后的任务
function getFilteredTasks() {
  var tasks = state.subtasks;
  var filters = state.searchFilters;
  
  return tasks.filter(function(task) {
    var matchId = !filters.id || (task.id && task.id.toLowerCase().includes(filters.id));
    var matchType = !filters.type || task.type === filters.type;
    var matchStatus = !filters.status || task.status === filters.status;
    
    return matchId && matchType && matchStatus;
  });
}

// 导出到全局作用域
window.persistDraft = persistDraft;
window.loadDraft = loadDraft;
window.updateTasksStatusBar = updateTasksStatusBar;
window.applySearchFilters = applySearchFilters;
window.clearSearchFilters = clearSearchFilters;
window.getFilteredTasks = getFilteredTasks;

// 搜索变化处理函数
function onSearchChange() {
  applySearchFilters();
}

// 清空搜索处理函数
function clearSearch() {
  clearSearchFilters();
}

// 导出搜索处理函数
window.onSearchChange = onSearchChange;
window.clearSearch = clearSearch;
