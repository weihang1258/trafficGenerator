// 设置页面功能模块

// 保存默认Token
function saveDefaultToken() {
  var token = getElement('default_token').value;
  if (!token) {
    showToast('请输入要保存的Token', false);
    return;
  }
  
  try {
    localStorage.setItem('HPTG_DEFAULT_TOKEN', token);
    showToast('默认Token已保存', true);
  } catch (e) {
    showToast('保存失败: ' + e.message, false);
  }
}

// 导出配置
function exportConfig() {
  try {
    var config = {
      subtasks: state.subtasks,
      settings: {
        default_token: localStorage.getItem('HPTG_DEFAULT_TOKEN') || '',
        auto_save_interval: getElement('auto_save_interval').value || 30
      },
      export_time: new Date().toISOString(),
      version: '1.0.0'
    };
    
    var dataStr = JSON.stringify(config, null, 2);
    var dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    var link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = 'hptg_config_' + new Date().toISOString().slice(0, 10) + '.json';
    link.click();
    
    showToast('配置导出成功', true);
  } catch (e) {
    showToast('导出失败: ' + e.message, false);
  }
}

// 导入配置
function importConfig() {
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = function(e) {
    var file = e.target.files[0];
    if (file) {
      var reader = new FileReader();
      reader.onload = function(e) {
        try {
          var config = JSON.parse(e.target.result);
          
          if (config.subtasks && Array.isArray(config.subtasks)) {
            state.subtasks = config.subtasks;
            showToast('任务配置导入成功', true);
          }
          
          if (config.settings) {
            if (config.settings.default_token) {
              localStorage.setItem('HPTG_DEFAULT_TOKEN', config.settings.default_token);
              getElement('default_token').value = config.settings.default_token;
            }
            
            if (config.settings.auto_save_interval) {
              getElement('auto_save_interval').value = config.settings.auto_save_interval;
            }
          }
          
          showToast('配置导入完成', true);
          
          // 如果当前在任务页面，刷新显示
          if (state.page === 'tasks') {
            renderSubtasks();
          }
          
        } catch (e) {
          showToast('配置文件格式错误: ' + e.message, false);
        }
      };
      reader.readAsText(file);
    }
  };
  input.click();
}

// 加载设置
function loadSettings() {
  try {
    var defaultToken = localStorage.getItem('HPTG_DEFAULT_TOKEN');
    if (defaultToken) {
      getElement('default_token').value = defaultToken;
    }
    
    var autoSaveInterval = localStorage.getItem('HPTG_AUTO_SAVE_INTERVAL');
    if (autoSaveInterval) {
      getElement('auto_save_interval').value = autoSaveInterval;
    }
  } catch (e) {
    console.warn('加载设置失败:', e);
  }
}

// 保存设置
function saveSettings() {
  try {
    var autoSaveInterval = getElement('auto_save_interval').value;
    localStorage.setItem('HPTG_AUTO_SAVE_INTERVAL', autoSaveInterval);
    showToast('设置已保存', true);
  } catch (e) {
    showToast('保存设置失败: ' + e.message, false);
  }
}

// 重置设置
function resetSettings() {
  confirmAction('确定要重置所有设置吗？此操作不可恢复。', function() {
    try {
      localStorage.removeItem('HPTG_DEFAULT_TOKEN');
      localStorage.removeItem('HPTG_AUTO_SAVE_INTERVAL');
      
      getElement('default_token').value = '';
      getElement('auto_save_interval').value = '30';
      
      showToast('设置已重置', true);
    } catch (e) {
      showToast('重置设置失败: ' + e.message, false);
    }
  });
}

// 初始化设置页面
document.addEventListener('DOMContentLoaded', function() {
  // 延迟加载设置，确保DOM元素已创建
  setTimeout(loadSettings, 100);
  
  // 监听设置变化
  var autoSaveInput = getElement('auto_save_interval');
  if (autoSaveInput) {
    autoSaveInput.addEventListener('change', saveSettings);
  }
});

// 加载设置页面内容
function loadSettingsContent(container) {
  container.innerHTML = `
    <div class="card">
      <h3>系统设置</h3>
      <div class="row">
        <label>默认Token</label>
        <input id="default_token" type="text" placeholder="设置默认Token" class="control-lg"/>
        <button class="btn" onclick="saveDefaultToken()">保存</button>
      </div>
      <div class="row">
        <label>自动保存间隔(秒)</label>
        <input id="auto_save_interval" type="number" value="30" min="10" max="300" class="control-lg"/>
      </div>
      <div class="row">
        <button class="btn" onclick="exportConfig()">导出配置</button>
        <button class="btn" onclick="importConfig()">导入配置</button>
        <button class="btn ghost" onclick="resetSettings()">重置设置</button>
      </div>
    </div>
  `;
  
  // 加载设置
  setTimeout(() => {
    loadSettings();
  }, 100);
}
