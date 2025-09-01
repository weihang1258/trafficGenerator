// 任务工具函数模块
// 包含删除、验证等辅助功能

// 删除选中的任务
async function deleteSelected() {
  if (Object.keys(state.selected || {}).length === 0) {
    showToast('请先勾选要删除的任务', false);
    return;
  }
  
  if (!confirm('确定要删除选中的任务吗？此操作不可恢复。')) {
    return;
  }
  
  // 从后往前删除，避免索引变化
  var toDelete = [];
  for (var i = 0; i < state.subtasks.length; i++) {
    var st = state.subtasks[i];
    if (state.selected[st.id]) {
      toDelete.push(i);
    }
  }
  
  // 从大到小排序，从后往前删除
  toDelete.sort((a, b) => b - a);
  for (var idx of toDelete) {
    state.subtasks.splice(idx, 1);
  }
  
  // 清空选中状态
  state.selected = {};
  renderSubtasks();
  persistDraft();
  showToast('已删除选中任务', true);
}

// 验证规格
function validateSpec(bs) {
  try {
    var classes = bs.classes || [];
    if (classes.length === 0) {
      showToast('请至少添加一个子任务', false);
      return false;
    }
    
    for (var i = 0; i < classes.length; i++) {
      var c = classes[i];
      if (!c.id) {
        showToast('子任务缺少 ID', false);
        return false;
      }
      
      var t = c.tuples || {};
      if (t.ip_src) {
        if (t.ip_src.strategy === 'inc' || t.ip_src.strategy === 'rand') {
          if (!isValidIpRange(t.ip_src.range)) {
            showToast('源IP范围无效: ' + t.ip_src.range, false);
            return false;
          }
        }
      }
      
      if (t.ip_dst) {
        if (t.ip_dst.strategy === 'inc' || t.ip_dst.strategy === 'rand') {
          if (!isValidIpRange(t.ip_dst.range)) {
            showToast('目的IP范围无效: ' + t.ip_dst.range, false);
            return false;
          }
        }
      }
      
      if (t.sport && t.sport.range) {
        if (t.sport.range.length === 2 && (t.sport.range[0] > t.sport.range[1])) {
          showToast('源端口范围非法', false);
          return false;
        }
      }
      
      if (t.dport && t.dport.range) {
        if (t.dport.range.length === 2 && (t.dport.range[0] > t.dport.range[1])) {
          showToast('目的端口范围非法', false);
          return false;
        }
      }
    }
    
    return true;
  } catch (e) {
    return true;
  }
}

// IP范围验证
function isValidIpRange(s) {
  if (!s || typeof s !== 'string') return false;
  if (s.indexOf('/') > 0) return true;
  if (s.indexOf('-') > 0) {
    var a = s.split('-');
    return a.length === 2;
  }
  return (/^\d+\.\d+\.\d+\.\d+$/).test(s);
}

// 导出到全局作用域
window.deleteSelected = deleteSelected;
window.validateSpec = validateSpec;
window.isValidIpRange = isValidIpRange;
