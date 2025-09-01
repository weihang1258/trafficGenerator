// 任务表格渲染模块
// 包含任务表格的创建、渲染和格式化功能

// 渲染任务头部 - 已删除，使用renderSubtasks中的表头

// 渲染子任务列表
function renderSubtasks() {
  var container = getElement('subtasks');
  if (!container) return;
  
  var filteredTasks = filterTasks();
  
  if (filteredTasks.length === 0) {
    container.innerHTML = '<div class="empty-state">暂无任务，点击"新增任务"开始创建</div>';
    // 清空分页
    if (typeof renderPagination === 'function') {
      renderPagination();
    }
    return;
  }
  
  // 更新分页信息
  if (typeof updatePagination === 'function') {
    updatePagination();
  }
  
  // 获取当前页的任务
  var currentPageTasks = [];
  if (typeof getCurrentPageItems === 'function') {
    currentPageTasks = getCurrentPageItems();
  } else {
    currentPageTasks = filteredTasks;
  }
  
  // 创建表格容器，支持固定表头
  var tableContainer = document.createElement('div');
  tableContainer.className = 'table-container';
  
  var table = document.createElement('table');
  table.className = 'subtasks-table';
  
  // 表头
  var thead = document.createElement('thead');
  var headerRow = document.createElement('tr');
  
  // 定义列配置
  var columns = [
    { key: 'checkbox', title: '<input type="checkbox" id="chk_all" onclick="toggleAll(this)"/>', width: '50px', sortable: false },
    { key: 'id', title: '任务ID', width: '120px', sortable: true },
    { key: 'type', title: '类型', width: '80px', sortable: true },
    { key: 'bps', title: 'bps', width: '80px', sortable: true },
    { key: 'fps', title: '每秒流', width: '80px', sortable: true },
    { key: 'ip', title: 'IP(源→目的)', width: '200px', sortable: false },
    { key: 'port', title: '端口(源→目的)', width: '150px', sortable: false },
    { key: 'status', title: '状态', width: '80px', sortable: true },
    { key: 'actions', title: '操作', width: '120px', sortable: false }
  ];
  
  for (var i = 0; i < columns.length; i++) {
    var col = columns[i];
    var th = document.createElement('th');
    th.className = 'sortable-header';
    th.style.width = col.width;
    th.setAttribute('data-key', col.key);
    
    if (col.sortable) {
      th.innerHTML = col.title + '<span class="sort-icon">↕</span>';
      th.onclick = function() { sortTable(this.getAttribute('data-key')); };
    } else {
      th.innerHTML = col.title;
    }
    
    // 添加拖拽调整列宽功能
    if (i < columns.length - 1) { // 最后一列不添加拖拽
      var dragHandle = document.createElement('div');
      dragHandle.className = 'column-resize-handle';
      dragHandle.onmousedown = function(e) { startResize(e, th); };
      th.appendChild(dragHandle);
    }
    
    headerRow.appendChild(th);
  }
  
  thead.appendChild(headerRow);
  table.appendChild(thead);
  
  // 表体
  var tbody = document.createElement('tbody');
  for (var j = 0; j < currentPageTasks.length; j++) {
    var row = createTaskRow(currentPageTasks[j]);
    tbody.appendChild(row);
  }
  
  table.appendChild(tbody);
  tableContainer.appendChild(table);
  container.innerHTML = '';
  container.appendChild(tableContainer);
  
  // 为每个任务创建编辑界面区域
  // 先移除所有已存在的编辑区域
  var existingEditors = document.querySelectorAll('.subtask-bd');
  for (var i = 0; i < existingEditors.length; i++) {
    existingEditors[i].remove();
  }
  
  // 创建任务ID到索引的映射
  var tasksMap = {};
  for (var k = 0; k < state.subtasks.length; k++) {
    tasksMap[state.subtasks[k].id] = k;
  }
  
  // 获取表格容器
  var table = document.querySelector('.subtasks-table');
  if (!table) return;
  
  // 创建一个包装器来容纳任务行和编辑区域
  var wrapper = document.createElement('div');
  wrapper.className = 'task-items-wrapper';
  
  // 移动表格内容到包装器
  var tbody = table.querySelector('tbody');
  if (tbody) {
    var rows = Array.from(tbody.querySelectorAll('.task-row'));
    tbody.innerHTML = '';
    
    // 为每个任务行创建包含编辑区域的行组
    for (var m = 0; m < rows.length; m++) {
      var taskRow = rows[m];
      var taskId = taskRow.getAttribute('data-task-id');
      var taskIndex = tasksMap[taskId];
      
      if (taskIndex !== undefined) {
          // 创建行组结构
          // 1. 原始任务行
          tbody.appendChild(taskRow);
          
          // 2. 编辑区域行（作为单独的行显示）
          var editRow = document.createElement('tr');
          editRow.className = 'edit-row';
          var editCell = document.createElement('td');
          editCell.colSpan = 9; // 匹配表格列数
          
          // 创建编辑区域div
          var editDiv = document.createElement('div');
          editDiv.className = 'subtask-bd hidden';
          editDiv.id = 'subtask_bd_' + taskIndex;
          editDiv.innerHTML = renderProtoConfig(taskIndex);
          
          editCell.appendChild(editDiv);
          editRow.appendChild(editCell);
          tbody.appendChild(editRow);
        } else {
        // 如果找不到索引，直接添加行
        tbody.appendChild(taskRow);
      }
    }
  }
  
  updateTasksStatusBar();
  
  // 渲染分页控件
  if (typeof renderPagination === 'function') {
    renderPagination();
  }
}

// 创建任务行
function createTaskRow(task) {
  var row = document.createElement('tr');
  row.className = 'task-row';
  row.setAttribute('data-task-id', task.id);
  
  // 添加行点击选中功能
  row.onclick = function(e) {
    // 如果点击的是复选框或按钮，不处理行选中
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.closest('button')) {
      return;
    }
    toggleRowSelection(this);
  };
  
  row.innerHTML = 
    '<td><input type="checkbox" class="task-checkbox" value="' + task.id + '" onclick="event.stopPropagation()"/></td>' +
    '<td>' + task.id + '</td>' +
    '<td><span class="badge badge-' + task.type + '">' + task.type.toUpperCase() + '</span></td>' +
    '<td>' + task.bps + '</td>' +
    '<td>' + (task.rate_limit_fps || '-') + '</td>' +
    '<td>' + formatIPRange(task.tuples.ip_src) + ' → ' + formatIPRange(task.tuples.ip_dst) + '</td>' +
    '<td>' + formatPortRange(task.tuples.sport) + ' → ' + formatPortRange(task.tuples.dport) + '</td>' +
    '<td><span class="badge badge-' + task.status + '">' + getStatusText(task.status) + '</span></td>' +
    '<td>' +
      '<button class="btn btn-sm" onclick="editTask(\'' + task.id + '\'); event.stopPropagation();">编辑</button> ' +
      '<button class="btn btn-sm danger" onclick="deleteTask(\'' + task.id + '\'); event.stopPropagation();">删除</button>' +
    '</td>';
  return row;
}

// 格式化IP范围
function formatIPRange(ipSpec) {
  if (!ipSpec) return '-';
  var s = ipSpec.strategy || 'inc';
  var txt = '-';
  
  if (s === 'fixed') {
    txt = String(ipSpec.value || '-');
  } else if (s === 'inc') {
    txt = String(ipSpec.range || '-');
  } else if (s === 'rand') {
    txt = String(ipSpec.range || '-');
  }
  
  return '<span class="mono-badge">' + txt + '</span>';
}

// 格式化端口范围
function formatPortRange(portSpec) {
  if (!portSpec) return '-';
  var s = portSpec.strategy || 'inc';
  var txt = '-';
  
  if (s === 'inc' || s === 'rand') {
    if (Array.isArray(portSpec.range)) {
      txt = String(portSpec.range[0]) + '-' + String(portSpec.range[1]);
    } else {
      txt = String(portSpec.range || '-');
    }
  } else {
    txt = String(portSpec.value || '-');
  }
  
  return '<span class="mono-badge">' + txt + '</span>';
}

// 获取状态文本
function getStatusText(status) {
  var statusMap = {
    'idle': '空闲',
    'running': '运行中',
    'stopped': '已停止'
  };
  return statusMap[status] || status;
}

// 更新任务状态栏
function updateTasksStatusBar() {
  var total = state.subtasks.length;
  var running = 0, idle = 0, stopped = 0;
  
  for (var i = 0; i < state.subtasks.length; i++) {
    var task = state.subtasks[i];
    if (task.status === 'running') running++;
    else if (task.status === 'idle') idle++;
    else if (task.status === 'stopped') stopped++;
  }
  
  var totalElement = getElement('total_count');
  var runningElement = getElement('running_count');
  var idleElement = getElement('idle_count');
  var stoppedElement = getElement('stopped_count');
  
  if (totalElement) totalElement.textContent = total;
  if (runningElement) runningElement.textContent = running;
  if (idleElement) idleElement.textContent = idle;
  if (stoppedElement) stoppedElement.textContent = stopped;
}

// 过滤任务
function filterTasks() {
  var filters = state.searchFilters;
  var result = [];
  
  for (var i = 0; i < state.subtasks.length; i++) {
    var task = state.subtasks[i];
    var include = true;
    
    if (filters.id && task.id.toLowerCase().indexOf(filters.id.toLowerCase()) === -1) {
      include = false;
    }
    if (filters.type && task.type !== filters.type) {
      include = false;
    }
    if (filters.status && task.status !== filters.status) {
      include = false;
    }
    
    if (include) {
      result.push(task);
    }
  }
  
  // 应用排序
  result = getSortedTasks(result);
  
  return result;
}

// 搜索变化处理
function onSearchChange() {
  var searchId = getElement('search_id');
  var searchType = getElement('search_type');
  var searchStatus = getElement('search_status');
  
  if (searchId) state.searchFilters.id = searchId.value || '';
  if (searchType) state.searchFilters.type = searchType.value || '';
  if (searchStatus) state.searchFilters.status = searchStatus.value || '';
  
  // 搜索后重置分页到第一页
  if (typeof resetPagination === 'function') {
    resetPagination();
  }
  
  renderSubtasks();
}

// 清空搜索
function clearSearch() {
  var searchId = getElement('search_id');
  var searchType = getElement('search_type');
  var searchStatus = getElement('search_status');
  
  if (searchId) searchId.value = '';
  if (searchType) searchType.value = '';
  if (searchStatus) searchType.value = '';
  
  state.searchFilters = { id: '', type: '', status: '' };
  
  // 清空搜索后重置分页到第一页
  if (typeof resetPagination === 'function') {
    resetPagination();
  }
  
  renderSubtasks();
}

// 切换全选
function toggleAll(checkbox) {
  var taskCheckboxes = document.querySelectorAll('.task-checkbox');
  for (var i = 0; i < taskCheckboxes.length; i++) {
    taskCheckboxes[i].checked = checkbox.checked;
    var row = taskCheckboxes[i].closest('.task-row');
    if (row) {
      updateRowSelectionStyle(row, checkbox.checked);
    }
  }
}

// 获取选中的任务ID
function getSelectedTaskIds() {
  var checkboxes = document.querySelectorAll('.task-checkbox:checked');
  var result = [];
  for (var i = 0; i < checkboxes.length; i++) {
    result.push(checkboxes[i].value);
  }
  return result;
}

// 重置列宽
function resetColWidths() {
  // 重置所有列宽到默认值
  var headers = document.querySelectorAll('.subtasks-table th');
  var defaultWidths = ['50px', '120px', '80px', '80px', '80px', '200px', '150px', '80px', '120px'];
  
  for (var i = 0; i < headers.length && i < defaultWidths.length; i++) {
    headers[i].style.width = defaultWidths[i];
  }
  
  showToast('列宽已重置', true);
}

// 行选中功能
function toggleRowSelection(row) {
  var checkbox = row.querySelector('.task-checkbox');
  if (checkbox) {
    checkbox.checked = !checkbox.checked;
    updateRowSelectionStyle(row, checkbox.checked);
  }
}

// 更新行选中样式
function updateRowSelectionStyle(row, isSelected) {
  if (isSelected) {
    row.classList.add('row-selected');
  } else {
    row.classList.remove('row-selected');
  }
}

// 列排序功能
function sortTable(key) {
  var currentSort = state.currentSort || {};
  var sortDirection = currentSort.key === key ? (currentSort.direction === 'asc' ? 'desc' : 'asc') : 'asc';
  
  // 更新排序状态
  state.currentSort = { key: key, direction: sortDirection };
  
  // 更新排序图标
  updateSortIcons(key, sortDirection);
  
  // 重新渲染表格
  renderSubtasks();
}

// 更新排序图标
function updateSortIcons(key, direction) {
  var headers = document.querySelectorAll('.sortable-header');
  for (var i = 0; i < headers.length; i++) {
    var header = headers[i];
    var icon = header.querySelector('.sort-icon');
    var headerKey = header.getAttribute('data-key');
    
    // 移除所有排序状态类
    header.classList.remove('sort-asc', 'sort-desc');
    
    if (headerKey === key) {
      // 设置当前排序列的图标和状态
      icon.textContent = direction === 'asc' ? '↑' : '↓';
      header.classList.add(direction === 'asc' ? 'sort-asc' : 'sort-desc');
    } else {
      // 重置其他列的图标
      icon.textContent = '↕';
    }
  }
}

// 列宽拖拽调整
function startResize(e, header) {
  e.preventDefault();
  
  var startX = e.clientX;
  var startWidth = header.offsetWidth;
  
  function onMouseMove(e) {
    var newWidth = startWidth + (e.clientX - startX);
    if (newWidth > 50) { // 最小宽度限制
      header.style.width = newWidth + 'px';
    }
  }
  
  function onMouseUp() {
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  }
  
  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
}

// 获取排序后的任务列表
function getSortedTasks(tasks) {
  var sortConfig = state.currentSort;
  if (!sortConfig || !sortConfig.key) {
    return tasks;
  }
  
  var sortedTasks = tasks.slice().sort(function(a, b) {
    var aVal = getTaskValue(a, sortConfig.key);
    var bVal = getTaskValue(b, sortConfig.key);
    
    if (sortConfig.direction === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });
  
  return sortedTasks;
}

// 获取任务字段值
function getTaskValue(task, key) {
  switch (key) {
    case 'id': return task.id;
    case 'type': return task.type;
    case 'bps': return parseBps(task.bps);
    case 'fps': return task.rate_limit_fps || 0;
    case 'status': return task.status;
    default: return '';
  }
}

// 解析bps值用于排序
function parseBps(bps) {
  if (!bps) return 0;
  var num = parseFloat(bps);
  if (bps.includes('k')) num *= 1000;
  if (bps.includes('m')) num *= 1000000;
  if (bps.includes('g')) num *= 1000000000;
  return num;
}

// 导出到全局作用域
window.renderSubtasks = renderSubtasks;
window.createTaskRow = createTaskRow;
window.formatIPRange = formatIPRange;
window.formatPortRange = formatPortRange;
window.getStatusText = getStatusText;
window.updateTasksStatusBar = updateTasksStatusBar;
window.filterTasks = filterTasks;
window.onSearchChange = onSearchChange;
window.clearSearch = clearSearch;
window.toggleAll = toggleAll;
window.getSelectedTaskIds = getSelectedTaskIds;
window.resetColWidths = resetColWidths;
window.toggleRowSelection = toggleRowSelection;
window.sortTable = sortTable;
window.startResize = startResize;
