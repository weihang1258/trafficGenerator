<template>
  <div class="task-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('task.title') }}</span>
          <div class="header-actions">
            <template v-if="selectedTasks.length === 0">
              <el-button aria-label="Column settings" @click="proTableRef?.openColumnSettings()" circle size="small">
                <el-icon><Setting /></el-icon>
              </el-button>
              <el-button aria-label="Refresh" @click="loadTasks" circle size="small">
                <el-icon><RefreshRight /></el-icon>
              </el-button>
              <el-button type="primary" @click="$router.push('/tasks/create')">
                <el-icon><Plus /></el-icon>
                {{ t('task.createTask') }}
              </el-button>
            </template>
            <template v-else>
              <span class="batch-info">{{ t('task.selectedCount', { count: selectedTasks.length }) }}</span>
              <el-button type="danger" size="small" @click="handleBatchDelete">{{ t('task.batchDelete') }}</el-button>
              <el-button size="small" @click="handleBatchStop">{{ t('task.batchStop') }}</el-button>
              <el-button size="small" link type="primary" @click="clearSelection">{{ t('common.reset') }}</el-button>
            </template>
          </div>
        </div>
      </template>

      <!-- Filter bar -->
      <div class="filter-bar">
        <el-input
          v-model="filters.keyword"
          :placeholder="t('task.searchPlaceholder')"
          clearable
          style="width: 240px"
          @keyup.enter="loadTasks"
          @clear="loadTasks"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-select v-model="filters.protocol" :placeholder="t('task.protocol')" clearable style="width: 140px" @change="loadTasks">
          <el-option label="TCP" value="tcp" />
          <el-option label="UDP" value="udp" />
          <el-option label="HTTP" value="http" />
          <el-option label="DNS" value="dns" />
          <el-option label="ICMP" value="icmp" />
          <el-option label="ARP" value="arp" />
        </el-select>
        <el-select v-model="filters.status" :placeholder="t('task.status')" clearable style="width: 140px" @change="loadTasks">
          <el-option :label="t('task.running')" value="running" />
          <el-option :label="t('task.pending')" value="pending" />
          <el-option :label="t('task.completed')" value="completed" />
          <el-option :label="t('task.failed')" value="failed" />
          <el-option :label="t('task.stopped')" value="stopped" />
        </el-select>
        <el-button link type="primary" @click="resetFilters">{{ t('common.reset') }}</el-button>
      </div>

      <!-- Active filter tags -->
      <div v-if="hasActiveFilters" class="active-filters">
        <el-tag v-if="filters.keyword" closable @close="filters.keyword = ''; loadTasks()">
          {{ filters.keyword }}
        </el-tag>
        <el-tag v-if="filters.protocol" closable @close="filters.protocol = ''; loadTasks()">
          {{ filters.protocol.toUpperCase() }}
        </el-tag>
        <el-tag v-if="filters.status" closable @close="filters.status = ''; loadTasks()">
          {{ getStatusText(filters.status) }}
        </el-tag>
        <el-button link type="primary" size="small" @click="resetFilters">{{ t('common.reset') }}</el-button>
      </div>

      <ProTable
        ref="proTableRef"
        table-id="task-list"
        :columns="columns"
        :data="tasks"
        :loading="loading"
        :default-sort="{ prop: 'created_at', order: 'descending' }"
        :pagination="{ total: pagination.total }"
        :empty-text="t('task.noTasks')"
        @selection-change="handleSelectionChange"
        @sort-change="handleSortChange"
        @page-change="handlePageChange"
      >
        <template #toolbar>
          <span></span>
        </template>
        <template #name="{ row }">
          <router-link :to="`/tasks/${row.id}`" class="task-name-link">
            {{ row.name }}
          </router-link>
        </template>
        <template #protocol="{ row }">
          <el-tag size="small">{{ (row.protocol || 'N/A').toUpperCase() }}</el-tag>
        </template>
        <template #status="{ row }">
          <el-tooltip v-if="row.error_message" :content="row.error_message" placement="top">
            <task-status-tag :status="row.status" />
          </el-tooltip>
          <task-status-tag v-else :status="row.status" />
        </template>
        <template #error_message="{ row }">
          <el-tooltip v-if="row.error_message" :content="row.error_message" placement="top">
            <el-tag type="danger" size="small" effect="light" class="error-tag">
              {{ row.error_message.length > 20 ? row.error_message.slice(0, 20) + '...' : row.error_message }}
            </el-tag>
          </el-tooltip>
          <span v-else style="color: var(--tg-text-secondary, #94a3b8);">-</span>
        </template>
        <template #progress="{ row }">
          <el-progress
            :percentage="row.progress || 0"
            :status="getProgressStatus(row.status)"
            :stroke-width="6"
          />
        </template>
        <template #output_type="{ row }">
          {{ row.output_type === 'port_group' ? t('taskCreate.portGroup') : t('taskCreate.pcap') }}
        </template>
        <template #stats.packets_sent="{ row }">
          {{ formatNumber(row.stats?.packets_sent || 0) }}
        </template>
        <template #created_at="{ row }">
          {{ formatTimestamp(row.created_at) }}
        </template>
        <template #updated_at="{ row }">
          {{ formatTimestamp(row.updated_at) }}
        </template>
        <template #actions="{ row }">
          <div class="action-buttons">
            <el-button
              size="small"
              link
              @click="router.push(`/tasks/${row.id}`)"
            >
              {{ t('task.viewDetail') }}
            </el-button>
            <el-button
              v-if="row.status !== 'running'"
              type="primary"
              size="small"
              link
              @click="handleStart(row)"
            >
              {{ t('task.start') }}
            </el-button>
            <el-button
              v-if="row.status === 'running'"
              type="danger"
              size="small"
              link
              @click="handleStop(row)"
            >
              {{ t('task.stop') }}
            </el-button>
            <el-button
              type="danger"
              size="small"
              link
              @click="handleDelete(row)"
            >
              {{ t('task.delete') }}
            </el-button>
          </div>
        </template>
        <template #empty>
          <el-empty :description="t('task.noTasks')">
            <el-button type="primary" @click="$router.push('/tasks/create')">
              {{ t('task.createTask') }}
            </el-button>
          </el-empty>
        </template>
      </ProTable>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Search, Setting, RefreshRight } from '@element-plus/icons-vue'
import { taskApi, type Task } from '@/api'
import TaskStatusTag from '@/components/TaskStatusTag.vue'
import ProTable from '@/components/ProTable/index.vue'
import { formatNumber, formatTimestamp } from '@/utils/format'

const { t } = useI18n()
const router = useRouter()

const loading = ref(false)
const tasks = ref<Task[]>([])
const selectedTasks = ref<Task[]>([])
const proTableRef = ref()
let refreshTimer: number | null = null
let loadErrorShown = false

const columns = computed(() => [
  { prop: 'selection', label: '', type: 'selection', width: 45, fixed: 'left' },
  { prop: 'name', label: t('task.taskName'), minWidth: 180, sortable: 'custom', required: true },
  { prop: 'protocol', label: t('task.protocol'), width: 90, sortable: 'custom' },
  { prop: 'status', label: t('task.status'), width: 100, sortable: 'custom' },
  { prop: 'error_message', label: t('task.errorLog'), width: 160, sortable: 'custom' },
  { prop: 'progress', label: t('task.progress'), width: 120, sortable: 'custom' },
  { prop: 'output_type', label: t('task.outputType'), width: 90, sortable: 'custom' },
  { prop: 'stats.packets_sent', label: t('task.packets'), width: 90, sortable: 'custom' },
  { prop: 'created_at', label: t('task.createdAt'), width: 170, sortable: 'custom' },
  { prop: 'updated_at', label: t('common.updatedAt'), width: 170, sortable: 'custom' },
  { prop: 'actions', label: t('task.actions'), width: 180, fixed: 'right', required: true }
])

const filters = reactive({
  keyword: '',
  protocol: '',
  status: ''
})

const pagination = reactive({
  page: 1,
  pageSize: 20,
  total: 0
})

const sortState = reactive({
  prop: 'created_at',
  order: 'descending'
})

const hasActiveFilters = computed(() =>
  filters.keyword || filters.protocol || filters.status
)

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    running: t('task.running'),
    pending: t('task.pending'),
    completed: t('task.completed'),
    failed: t('task.failed'),
    stopped: t('task.stopped')
  }
  return map[status] || status
}


function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'exception'
  if (status === 'stopped') return 'warning'
  return ''
}

function resetFilters() {
  filters.keyword = ''
  filters.protocol = ''
  filters.status = ''
  pagination.page = 1
  loadTasks()
}

function handleSelectionChange(selection: Task[]) {
  selectedTasks.value = selection
}

function clearSelection() {
  selectedTasks.value = []
  proTableRef.value?.tableRef?.clearSelection()
}

function handleSortChange({ prop, order }: { prop: string; order: string }) {
  sortState.prop = prop
  sortState.order = order
  loadTasks()
}

function handlePageChange(page: number, pageSize: number) {
  pagination.page = page
  pagination.pageSize = pageSize
  loadTasks()
}

async function loadTasks() {
  loading.value = true
  try {
    const res = await taskApi.list({
      page: pagination.page,
      size: pagination.pageSize,
      status: filters.status || undefined,
      sort_by: sortState.prop || undefined,
      sort_order: sortState.order || undefined,
    })
    if (res.data) {
      const data = res.data as any
      tasks.value = data.items || []
      pagination.total = data.total || 0
      loadErrorShown = false
    }
  } catch (error) {
    console.error('Failed to load tasks:', error)
    if (!loadErrorShown) {
      ElMessage.error(t('task.loadFailed'))
      loadErrorShown = true
    }
  } finally {
    loading.value = false
  }
}


async function handleStart(task: Task) {
  try {
    await taskApi.start(task.id)
    ElMessage.success(t('task.startSuccess'))
  } catch {
    // Error toast already shown by axios interceptor
  }
  loadTasks()
}

async function handleStop(task: Task) {
  try {
    await ElMessageBox.confirm(
      t('task.stopConfirm'),
      t('task.stop'),
      { type: 'warning' }
    )
    await taskApi.stop(task.id)
    ElMessage.success(t('task.stopSuccess'))
    loadTasks()
  } catch (error: any) {
    if (error !== 'cancel') {
      const msg = error?.response?.data?.message || t('task.stopFailed')
      ElMessage.error(msg)
    }
  }
}

async function handleDelete(task: Task) {
  try {
    await ElMessageBox.confirm(
      t('task.deleteConfirm', { name: task.name }),
      t('task.delete'),
      { type: 'warning' }
    )
    await taskApi.delete(task.id)
    ElMessage.success(t('task.deleteSuccess'))
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete task:', error)
    }
  }
}


async function handleBatchDelete() {
  if (selectedTasks.value.length === 0) return
  try {
    await ElMessageBox.confirm(
      t('task.batchDeleteConfirm', { count: selectedTasks.value.length }),
      t('task.batchDelete'),
      { type: 'warning' }
    )
    const results = await Promise.allSettled(
      selectedTasks.value.map(task => taskApi.delete(task.id))
    )
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('task.bulkDeleted', { count: succeeded }))
    }
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete tasks:', error)
    }
  }
}

async function handleBatchStop() {
  if (selectedTasks.value.length === 0) return
  try {
    await ElMessageBox.confirm(
      t('task.batchStopConfirm', { count: selectedTasks.value.length }),
      t('task.batchStop'),
      { type: 'warning' }
    )
    const runningTasks = selectedTasks.value.filter(t => t.status === 'running')
    const results = await Promise.allSettled(
      runningTasks.map(task => taskApi.stop(task.id))
    )
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('task.bulkStopped', { count: succeeded }))
    }
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to stop tasks:', error)
    }
  }
}

onMounted(() => {
  loadTasks()
  refreshTimer = window.setInterval(() => {
    if (tasks.value.some(t => t.status === 'running')) {
      loadTasks()
    }
  }, 10000)
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  min-height: 32px;
}

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
  gap: 12px;
  flex-wrap: wrap;
}

.active-filters {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.batch-info {
  font-size: 13px;
  color: var(--tg-text-secondary, #606266);
}

.task-name-link {
  color: var(--tg-primary, #409eff);
  text-decoration: none;
  font-weight: 500;
}

.task-name-link:hover {
  text-decoration: underline;
}

.action-buttons {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.error-tag {
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (max-width: 768px) {
  .filter-bar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>