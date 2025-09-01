// 任务操作模块
// 包含任务的启动、停止、删除等操作功能

// 启动选中任务
function startSelected() {
  var selectedIds = getSelectedTaskIds();
  if (selectedIds.length === 0) {
    showToast('请先选择要启动的任务', false);
    return;
  }
  
  for (var i = 0; i < selectedIds.length; i++) {
    startTask(selectedIds[i]);
  }
}

// 停止选中任务
function stopSelected() {
  var selectedIds = getSelectedTaskIds();
  if (selectedIds.length === 0) {
    showToast('请先选择要停止的任务', false);
    return;
  }
  
  for (var i = 0; i < selectedIds.length; i++) {
    stopTask(selectedIds[i]);
  }
}

// 删除选中任务
function deleteSelected() {
  var selectedIds = getSelectedTaskIds();
  if (selectedIds.length === 0) {
    showToast('请先选择要删除的任务', false);
    return;
  }
  
  confirmAction('确定要删除选中的任务吗？此操作不可恢复。', function() {
    for (var i = 0; i < selectedIds.length; i++) {
      deleteTask(selectedIds[i]);
    }
    showToast('已删除选中任务', true);
  });
}

// 编辑任务
function editTask(id) {
  // 找到对应ID的任务索引
  for (var i = 0; i < state.subtasks.length; i++) {
    if (state.subtasks[i].id === id) {
      // 切换显示该任务的编辑界面
      toggleSubtaskBody(i);
      // 滚动到该任务行
      var taskRow = document.querySelector('[data-task-id="' + id + '"]');
      if (taskRow) {
        taskRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      break;
    }
  }
}

// 启动任务
function startTask(id) {
  for (var i = 0; i < state.subtasks.length; i++) {
    if (state.subtasks[i].id === id) {
      state.subtasks[i].status = 'running';
      renderSubtasks();
      persistDraft();
      showToast('任务已启动: ' + id, true);
      break;
    }
  }
}

// 停止任务
function stopTask(id) {
  for (var i = 0; i < state.subtasks.length; i++) {
    if (state.subtasks[i].id === id) {
      state.subtasks[i].status = 'stopped';
      renderSubtasks();
      persistDraft();
      showToast('任务已停止: ' + id, true);
      break;
    }
  }
}

// 删除任务
function deleteTask(id) {
  for (var i = 0; i < state.subtasks.length; i++) {
    if (state.subtasks[i].id === id) {
      state.subtasks.splice(i, 1);
      renderSubtasks();
      persistDraft();
      showToast('任务已删除: ' + id, true);
      break;
    }
  }
}

// 确认操作
function confirmAction(message, callback) {
  if (confirm(message)) {
    callback();
  }
}

// 导出到全局作用域
window.startSelected = startSelected;
window.stopSelected = stopSelected;
window.deleteSelected = deleteSelected;
window.editTask = editTask;
window.startTask = startTask;
window.stopTask = stopTask;
window.deleteTask = deleteTask;
window.confirmAction = confirmAction;
