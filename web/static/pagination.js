// 分页功能模块
// 包含分页逻辑、分页控件渲染和分页状态管理

// 初始化分页状态
function initPagination() {
  if (!state.pagination) {
    state.pagination = {
      currentPage: 1,
      pageSize: 10,
      totalItems: 0,
      totalPages: 1
    };
  }
  
  // 从localStorage加载分页设置
  try {
    var savedPageSize = localStorage.getItem('HPTG_PAGE_SIZE');
    if (savedPageSize) {
      state.pagination.pageSize = parseInt(savedPageSize);
    }
  } catch (e) {
    console.warn('加载分页设置失败:', e);
  }
  
  updatePagination();
}

// 更新分页信息
function updatePagination() {
  if (!state.pagination) return;
  
  var filteredTasks = getFilteredTasks();
  state.pagination.totalItems = filteredTasks.length;
  state.pagination.totalPages = Math.ceil(state.pagination.totalItems / state.pagination.pageSize);
  
  // 确保当前页不超出范围
  if (state.pagination.currentPage > state.pagination.totalPages) {
    state.pagination.currentPage = Math.max(1, state.pagination.totalPages);
  }
  
  console.log('分页状态更新:', state.pagination);
}

// 获取当前页的任务
function getCurrentPageItems() {
  if (!state.pagination) {
    initPagination();
  }
  
  var filteredTasks = getFilteredTasks();
  var startIndex = (state.pagination.currentPage - 1) * state.pagination.pageSize;
  var endIndex = startIndex + state.pagination.pageSize;
  
  return filteredTasks.slice(startIndex, endIndex);
}

// 跳转到指定页
function goToPage(page) {
  if (!state.pagination || page < 1 || page > state.pagination.totalPages) {
    return;
  }
  
  state.pagination.currentPage = page;
  console.log('跳转到第', page, '页');
  
  if (typeof renderSubtasks === 'function') {
    renderSubtasks();
  }
  
  if (typeof renderPagination === 'function') {
    renderPagination();
  }
}

// 改变每页显示条数
function changePageSize(newSize) {
  if (!state.pagination) return;
  
  var newPageSize = parseInt(newSize);
  if (newPageSize < 1 || newPageSize > 100) return;
  
  state.pagination.pageSize = newPageSize;
  state.pagination.currentPage = 1; // 重置到第一页
  
  // 保存到localStorage
  try {
    localStorage.setItem('HPTG_PAGE_SIZE', newPageSize.toString());
  } catch (e) {
    console.warn('保存分页设置失败:', e);
  }
  
  updatePagination();
  
  if (typeof renderSubtasks === 'function') {
    renderSubtasks();
  }
  
  if (typeof renderPagination === 'function') {
    renderPagination();
  }
  
  console.log('每页显示条数改为:', newPageSize);
}

// 渲染分页控件
function renderPagination() {
  var container = getElement('pagination-container');
  if (!container) return;
  
  if (!state.pagination) {
    initPagination();
  }
  
  var pagination = state.pagination;
  
  // 如果没有数据，隐藏分页控件
  if (pagination.totalItems === 0) {
    container.innerHTML = '';
    return;
  }
  
  var html = `
    <div class="pagination-left">
      <span>每页显示:</span>
      <select class="pagination-select" onchange="changePageSize(this.value)">
        <option value="5" ${pagination.pageSize === 5 ? 'selected' : ''}>5条</option>
        <option value="10" ${pagination.pageSize === 10 ? 'selected' : ''}>10条</option>
        <option value="20" ${pagination.pageSize === 20 ? 'selected' : ''}>20条</option>
        <option value="50" ${pagination.pageSize === 50 ? 'selected' : ''}>50条</option>
      </select>
      <span>共 <span class="total-count">${pagination.totalItems}</span> 条记录</span>
    </div>
    
    <div class="pagination-right">
      ${pagination.totalPages > 1 ? `
        <button class="pagination-btn" onclick="goToPage(1)" ${pagination.currentPage === 1 ? 'disabled' : ''}>
          首页
        </button>
        <button class="pagination-btn" onclick="goToPage(${pagination.currentPage - 1})" ${pagination.currentPage === 1 ? 'disabled' : ''}>
          上一页
        </button>
        
        <span class="page-info">第 ${pagination.currentPage} 页 / 共 ${pagination.totalPages} 页</span>
        
        <button class="pagination-btn" onclick="goToPage(${pagination.currentPage + 1})" ${pagination.currentPage === pagination.totalPages ? 'disabled' : ''}>
          下一页
        </button>
        <button class="pagination-btn" onclick="goToPage(${pagination.totalPages})" ${pagination.currentPage === pagination.totalPages ? 'disabled' : ''}>
          末页
        </button>
      ` : `
        <span class="page-info">共 ${pagination.totalItems} 条记录</span>
      `}
    </div>
  `;
  
  container.innerHTML = html;
}

// 重置分页到第一页
function resetPagination() {
  if (state.pagination) {
    state.pagination.currentPage = 1;
    updatePagination();
    
    if (typeof renderPagination === 'function') {
      renderPagination();
    }
  }
}

// 导出到全局作用域
window.initPagination = initPagination;
window.updatePagination = updatePagination;
window.getCurrentPageItems = getCurrentPageItems;
window.goToPage = goToPage;
window.changePageSize = changePageSize;
window.renderPagination = renderPagination;
window.resetPagination = resetPagination;
