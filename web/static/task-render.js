// 任务渲染功能模块
// 包含任务表格渲染和选择管理

// 渲染任务头部
function renderHeader() {
  var hd = getElement("grid_hd");
  if (!hd) return;
  
  var cols = gridColsFromState();
  hd.style.gridTemplateColumns = cols;
  
  var labels = [
    "<input type='checkbox' id='chk_all' onclick='toggleAll(this)'/>",
    "任务ID",
    "类型",
    "bps",
    "每秒流",
    "IP(源→目的)",
    "端口(源→目的)",
    "状态",
    "操作"
  ];
  
  hd.innerHTML = '';
  for (var i = 0; i < labels.length; i++) {
    var div = document.createElement('div');
    div.className = 'th';
    div.innerHTML = labels[i];
    if (i === 0) {
      div.innerHTML += '<div class="drag" onmousedown="startDrag(event, ' + i + ')"></div>';
    }
    hd.appendChild(div);
  }
}

// 渲染任务列表 - 已移至task-table.js，避免重复
// 此函数已被删除，使用task-table.js中的renderSubtasks函数

// 行点击处理
function rowClickHandler(evt, id) {
  var tag = (evt.target && evt.target.tagName) || '';
  if (tag === 'INPUT' || tag === 'BUTTON' || tag === 'SELECT' || tag === 'TEXTAREA') return;
  
  var on = !state.selected[id];
  toggleSelect(id, on);
  renderSubtasks();
}

// 选择相关函数
function selectAll(on) {
  state.selected = {};
  if (on) {
    for (var i = 0; i < state.subtasks.length; i++) {
      var id = state.subtasks[i].id || ('task_' + (i + 1));
      state.selected[id] = true;
    }
  }
  renderHeader();
  renderSubtasks();
  var chk = getElement('chk_all');
  if (chk) chk.checked = on;
}

function toggleAll(el) {
  if (!el) return;
  selectAll(el.checked);
}

function toggleSelect(id, on) {
  if (on) {
    state.selected[id] = true;
  } else {
    delete state.selected[id];
  }
  
  var allSel = Object.keys(state.selected).length === state.subtasks.length && state.subtasks.length > 0;
  var chk = getElement('chk_all');
  if (chk) chk.checked = allSel;
}

// 导出到全局作用域
window.renderHeader = renderHeader;
window.rowClickHandler = rowClickHandler;
window.selectAll = selectAll;
window.toggleAll = toggleAll;
window.toggleSelect = toggleSelect;
