// 任务启动停止功能模块
// 包含任务的启动、停止等操作

// 转换为批处理规格
function toBatchSpec() {
  var classes = [];
  for (var i = 0; i < state.subtasks.length; i++) {
    var st = state.subtasks[i];
    var cls = {
      id: st.id || ('task_' + (i + 1)),
      type: st.type || 'tcp',
      bps: st.bps || '0',
      tuples: st.tuples || {},
      rate_limit_fps: parseInt(st.rate_limit_fps || 0)
    };
    
    if (cls.type === 'tcp') {
      cls.tcp = st.tcp || {};
    } else if (cls.type === 'udp') {
      cls.udp = st.udp || {};
    } else if (cls.type === 'http') {
      cls.http = st.http || {};
    }
    
    classes.push(cls);
  }
  
  var flowsCount = parseInt(getElement('flows_count').value || '0');
  return {
    classes: classes,
    flows: {
      count: flowsCount > 0 ? flowsCount : 0
    }
  };
}

// 启动所有任务
async function startTasks() {
  var bs = toBatchSpec();
  if (!validateSpec(bs)) return;
  
  try {
    var r = await fetch('/api/hptg/batch/start', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ batch_spec: bs })
    });
    
    if (r.ok) {
      showToast('任务已启动', true);
      // 更新所有任务状态为运行中
      for (var i = 0; i < state.subtasks.length; i++) {
        state.subtasks[i].status = 'running';
      }
      renderSubtasks();
    } else {
      showToast('启动失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('启动出错: ' + e.message, false);
  }
}

// 启动选中的任务
async function startSelected() {
  var classes = [];
  var map = state.selected || {};
  
  for (var i = 0; i < state.subtasks.length; i++) {
    var st = state.subtasks[i];
    var id = st.id || ('task_' + (i + 1));
    if (map[id]) {
      var cls = {
        id: id,
        type: (st.type || 'tcp'),
        bps: st.bps,
        tuples: st.tuples,
        rate_limit_fps: parseInt(st.rate_limit_fps || 0)
      };
      
      if (cls.type === 'tcp') cls.tcp = st.tcp;
      else if (cls.type === 'udp') cls.udp = st.udp;
      else cls.http = st.http;
      
      classes.push(cls);
    }
  }
  
  if (classes.length === 0) {
    showToast('请先勾选要启动的任务', false);
    return;
  }
  
  var flowsCount = parseInt((getElement('flows_count').value || '0'));
  var bsSel = {
    classes: classes,
    flows: { count: flowsCount > 0 ? flowsCount : 0 }
  };
  
  if (!validateSpec(bsSel)) return;
  
  try {
    var r = await fetch('/api/hptg/batch/start', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ batch_spec: bsSel })
    });
    
    if (r.ok) {
      // 更新选中任务状态为运行中
      for (var j = 0; j < state.subtasks.length; j++) {
        var s = state.subtasks[j];
        if (state.selected[s.id]) s.status = 'running';
      }
      renderSubtasks();
      showToast('选中任务已启动', true);
    } else {
      showToast('启动失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('启动出错: ' + e.message, false);
  }
}

// 停止所有任务
async function stopTasks() {
  try {
    var r = await fetch('/api/hptg/batch/stop', {
      method: 'POST',
      headers: authHeaders()
    });
    
    if (r.ok) {
      showToast('任务已停止', true);
      // 更新所有任务状态为已停止
      for (var i = 0; i < state.subtasks.length; i++) {
        state.subtasks[i].status = 'stopped';
      }
      renderSubtasks();
    } else {
      showToast('停止失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('停止出错: ' + e.message, false);
  }
}

// 停止选中的任务
async function stopSelected() {
  if (Object.keys(state.selected || {}).length === 0) {
    showToast('请先勾选要停止的任务', false);
    return;
  }
  
  try {
    var r = await fetch('/api/hptg/batch/stop', {
      method: 'POST',
      headers: authHeaders()
    });
    
    if (r.ok) {
      // 更新选中任务状态为已停止
      for (var i = 0; i < state.subtasks.length; i++) {
        var st = state.subtasks[i];
        if (state.selected[st.id]) st.status = 'stopped';
      }
      renderSubtasks();
      showToast('任务已停止（当前后端为全局停止）', true);
    } else {
      showToast('停止失败: ' + r.status, false);
    }
  } catch (e) {
    showToast('停止出错: ' + e.message, false);
  }
}

// 导出到全局作用域
window.toBatchSpec = toBatchSpec;
window.startTasks = startTasks;
window.startSelected = startSelected;
window.stopTasks = stopTasks;
window.stopSelected = stopSelected;
