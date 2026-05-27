<template>
  <div class="task-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('task.title') }}</span>
          <el-button type="primary" @click="$router.push('/tasks/create')">
            <el-icon><Plus /></el-icon>
            {{ t('task.createTask') }}
          </el-button>
        </div>
      </template>

      <!-- Modern single-line filter bar -->
      <div class="filter-bar">
        <el-input
          v-model="filters.search"
          :placeholder="t('task.searchPlaceholder')"
          clearable
          style="width: 300px"
          @keyup.enter="loadTasks"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>

        <el-select
          v-model="filters.status"
          :placeholder="t('task.status')"
          multiple
          collapse-tags
          collapse-tags-tooltip
          clearable
          style="width: 200px"
          @change="loadTasks"
        >
          <el-option :label="t('task.pending')" value="pending" />
          <el-option :label="t('task.running')" value="running" />
          <el-option :label="t('task.completed')" value="completed" />
          <el-option :label="t('task.failed')" value="error" />
          <el-option :label="t('task.stopped')" value="stopped" />
        </el-select>

        <el-select
          v-model="filters.protocol"
          :placeholder="t('task.protocol')"
          multiple
          collapse-tags
          collapse-tags-tooltip
          clearable
          style="width: 200px"
          @change="loadTasks"
        >
          <el-option :label="t('protocol.tcp')" value="tcp" />
          <el-option :label="t('protocol.udp')" value="udp" />
          <el-option :label="t('protocol.http')" value="http" />
          <el-option :label="t('protocol.dns')" value="dns" />
          <el-option :label="t('protocol.icmp')" value="icmp" />
        </el-select>

        <el-button link type="primary" @click="resetFilters">
          {{ t('common.reset') }}
        </el-button>
      </div>

      <!-- Bulk Actions Toolbar -->
      <div v-if="selectedTasks.length > 0" class="bulk-toolbar">
        <el-space>
          <span class="bulk-text">
            {{ t('common.selected') }} {{ selectedTasks.length }} {{ t('task.tasks') }}
          </span>
          <el-button size="small" type="success" @click="handleBulkStart">
            {{ t('task.bulkStart') }}
          </el-button>
          <el-button size="small" type="warning" @click="handleBulkStop">
            {{ t('task.bulkStop') }}
          </el-button>
          <el-button size="small" type="danger" @click="handleBulkDelete">
            {{ t('task.bulkDelete') }}
          </el-button>
        </el-space>
      </div>

      <!-- Task Table -->
      <el-empty
        v-if="tasks.length === 0 && !loading"
        :description="t('task.noTasks')"
      >
        <el-button type="primary" @click="$router.push('/tasks/create')">
          {{ t('task.createFirst') }}
        </el-button>
      </el-empty>

      <el-table v-else :data="tasks" v-loading="loading" stripe @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="55" />
        <el-table-column prop="name" :label="t('common.name')" min-width="150" show-overflow-tooltip />
        <el-table-column prop="strategy_ids" :label="t('task.strategies')" min-width="180">
          <template #default="{ row }">
            <div class="strategy-tags">
              <el-tag v-for="id in row.strategy_ids?.slice(0, 2)" :key="id" size="small" style="margin: 2px">
                {{ id.substring(0, 8) }}
              </el-tag>
              <el-tag v-if="row.strategy_ids?.length > 2" size="small" type="info">
                +{{ row.strategy_ids.length - 2 }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="output_type" :label="t('task.output')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.output_type === 'pcap' ? 'warning' : 'success'" size="small">
              {{ row.output_type?.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('task.status')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)" size="small">{{ getStatusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" :label="t('task.progress')" width="140">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" :status="getProgressStatus(row.status)" :stroke-width="6" />
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('task.createdAt')" width="160">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="220" fixed="right">
          <template #default="{ row }">
            <el-space>
              <el-button size="small" @click="openDrawer(row)">
                {{ t('task.viewDetail') }}
              </el-button>
              <el-button
                size="small"
                type="success"
                :disabled="row.status !== 'pending' && row.status !== 'stopped'"
                @click="startTask(row.id)"
              >
                {{ t('task.start') }}
              </el-button>
              <el-button
                size="small"
                type="warning"
                :disabled="row.status !== 'running'"
                @click="stopTask(row.id)"
              >
                {{ t('task.stop') }}
              </el-button>
              <el-button
                size="small"
                type="danger"
                @click="deleteTask(row.id)"
              >
                {{ t('common.delete') }}
              </el-button>
            </el-space>
          </template>
        </el-table-column>
      </el-table>

      <!-- Pagination -->
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        style="margin-top: 20px; justify-content: flex-end;"
        @size-change="loadTasks"
        @current-change="loadTasks"
      />
    </el-card>

    <!-- Task Detail Drawer -->
    <el-drawer
      v-model="drawerVisible"
      :title="selectedTask?.name || t('task.taskDetail')"
      size="60%"
      direction="rtl"
    >
      <div v-if="selectedTask" v-loading="drawerLoading">
        <el-descriptions :column="2" border>
          <el-descriptions-item :label="t('task.taskName')">{{ selectedTask.id }}</el-descriptions-item>
          <el-descriptions-item :label="t('common.name')">{{ selectedTask.name }}</el-descriptions-item>
          <el-descriptions-item :label="t('taskCreate.outputType')">
            <el-tag :type="selectedTask.output_type === 'pcap' ? 'warning' : 'success'">
              {{ selectedTask.output_type?.toUpperCase() }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('task.status')">
            <el-tag :type="getStatusTagType(selectedTask.status)">{{ getStatusText(selectedTask.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('task.createdAt')">{{ formatDate(selectedTask.created_at) }}</el-descriptions-item>
          <el-descriptions-item :label="t('task.startedAt')">{{ formatDate(selectedTask.started_at) }}</el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">{{ t('task.strategies') }}</el-divider>
        <el-table :data="selectedTask.strategy_ids" size="small">
          <el-table-column prop="id" :label="t('strategy.strategyId')">
            <template #default="{ row }">
              {{ row }}
            </template>
          </el-table-column>
        </el-table>

        <el-divider content-position="left">{{ t('task.progress') }}</el-divider>

        <el-progress
          :percentage="selectedTask.progress || 0"
          :status="getProgressStatus(selectedTask.status)"
          :stroke-width="20"
          style="margin-bottom: 20px;"
        />

        <el-divider content-position="left">{{ t('task.statistics') }}</el-divider>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-statistic :title="t('dashboard.packetsSent')" :value="selectedTask.stats?.packets_sent || 0" />
          </el-col>
          <el-col :span="12">
            <el-statistic :title="t('task.bytes')" :value="selectedTask.stats?.bytes_sent || 0" />
          </el-col>
        </el-row>

        <el-divider content-position="left">{{ t('common.action') }}</el-divider>

        <el-space>
          <el-button
            type="success"
            :disabled="selectedTask.status !== 'pending' && selectedTask.status !== 'stopped'"
            @click="handleDrawerStart"
          >
            {{ t('task.start') }}
          </el-button>
          <el-button
            type="warning"
            :disabled="selectedTask.status !== 'running'"
            @click="handleDrawerStop"
          >
            {{ t('task.stop') }}
          </el-button>
          <el-button type="danger" @click="handleDrawerDelete">
            {{ t('common.delete') }}
          </el-button>
        </el-space>

        <el-divider content-position="left">{{ t('common.error') }}</el-divider>

        <el-alert
          v-if="selectedTask.error_message"
          :title="selectedTask.error_message"
          type="error"
          show-icon
          :closable="false"
        />
        <el-empty v-else :description="t('common.noData')" :image-size="60" />
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { taskApi, type Task } from '@/api'
import { useTaskWebSocket } from '@/composables/useTaskWebSocket'
import dayjs from 'dayjs'

const TASK_LIST_STORAGE_KEY = 'task-list-state'

const { t } = useI18n()

const loading = ref(false)
const tasks = ref<Task[]>([])
const selectedTasks = ref<Task[]>([])
const drawerVisible = ref(false)
const drawerLoading = ref(false)
const selectedTask = ref<Task | null>(null)

// WebSocket for real-time updates
const { taskStatus, connect: connectWs, disconnect: disconnectWs, subscribeTask, unsubscribeTask } = useTaskWebSocket()

function loadTaskListState() {
  try {
    const raw = localStorage.getItem(TASK_LIST_STORAGE_KEY)
    if (raw) return JSON.parse(raw)
  } catch {}
  return null
}

const savedTaskState = loadTaskListState()

const filters = reactive({
  status: savedTaskState?.filters?.status || [] as string[],
  protocol: savedTaskState?.filters?.protocol || [] as string[],
  search: savedTaskState?.filters?.search || ''
})

const pagination = reactive({
  page: savedTaskState?.pagination?.page || 1,
  size: savedTaskState?.pagination?.size || 20,
  total: 0
})

watch([() => ({ ...filters }), () => ({ ...pagination })], () => {
  localStorage.setItem(TASK_LIST_STORAGE_KEY, JSON.stringify({
    filters: { status: filters.status, protocol: filters.protocol, search: filters.search },
    pagination: { page: pagination.page, size: pagination.size }
  }))
}, { deep: true })

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(2) + 'K'
  return num.toString()
}

function formatDate(timestamp?: number): string {
  if (!timestamp) return '-'
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    pending: t('task.pending'),
    running: t('task.running'),
    stopped: t('task.stopped'),
    completed: t('task.completed'),
    error: t('task.failed')
  }
  return map[status] || status
}

function getStatusTagType(status: string): string {
  const map: Record<string, string> = {
    pending: 'info',
    running: 'success',
    stopped: 'warning',
    completed: '',
    error: 'danger'
  }
  return map[status] || 'info'
}

function getProtocolTagType(protocol: string): string {
  const map: Record<string, string> = {
    tcp: 'primary',
    udp: 'success',
    http: 'warning',
    dns: 'info',
    icmp: 'danger'
  }
  return map[protocol] || ''
}

function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'error') return 'exception'
  if (status === 'stopped') return 'warning'
  return ''
}

async function loadTasks() {
  loading.value = true
  try {
    const data = await taskApi.list({
      status: filters.status?.join(','),
      protocol: filters.protocol?.join(',')
    })
    if (data) {
      let taskList = data

      // Client-side search filter
      if (filters.search) {
        const searchLower = filters.search.toLowerCase()
        taskList = taskList.filter(task =>
          task.id.toLowerCase().includes(searchLower) ||
          task.name?.toLowerCase().includes(searchLower)
        )
      }

      tasks.value = taskList
      pagination.total = taskList.length
    }
  } catch (error) {
    console.error('Failed to load tasks:', error)
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.status = []
  filters.protocol = []
  filters.search = ''
  loadTasks()
}

async function startTask(id: string) {
  try {
    await taskApi.start(id)
    ElMessage.success(t('task.startSuccess'))
    loadTasks()
  } catch (error) {
    console.error('Failed to start task:', error)
  }
}

async function stopTask(id: string) {
  try {
    await taskApi.stop(id)
    ElMessage.success(t('task.stopSuccess'))
    loadTasks()
  } catch (error) {
    console.error('Failed to stop task:', error)
  }
}

async function deleteTask(id: string) {
  try {
    await ElMessageBox.confirm(t('task.confirmDelete'), t('common.confirm'), {
      type: 'warning'
    })
    await taskApi.delete(id)
    ElMessage.success(t('task.deleteSuccess'))
    loadTasks()
  } catch (error) {
    // Cancelled or error
  }
}

function handleSelectionChange(selection: Task[]) {
  selectedTasks.value = selection
}

async function handleBulkStart() {
  try {
    const results = await Promise.allSettled(selectedTasks.value.map(task => taskApi.start(task.id)))
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('task.bulkStarted', { count: succeeded }))
    }
    selectedTasks.value = []
    loadTasks()
  } catch (error) {
    console.error('Failed to bulk start tasks:', error)
  }
}

async function handleBulkStop() {
  try {
    const results = await Promise.allSettled(selectedTasks.value.map(task => taskApi.stop(task.id)))
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('task.bulkStopped', { count: succeeded }))
    }
    selectedTasks.value = []
    loadTasks()
  } catch (error) {
    console.error('Failed to bulk stop tasks:', error)
  }
}

async function handleBulkDelete() {
  try {
    await ElMessageBox.confirm(
      t('task.confirmBulkDelete', { count: selectedTasks.value.length }),
      t('common.confirm'),
      { type: 'warning' }
    )
    const results = await Promise.allSettled(selectedTasks.value.map(task => taskApi.delete(task.id)))
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('task.bulkDeleted', { count: succeeded }))
    }
    selectedTasks.value = []
    loadTasks()
  } catch (error) {
    // Cancelled or error
  }
}

async function openDrawer(task: Task) {
  selectedTask.value = task
  drawerVisible.value = true
  await loadDrawerTask()

  // Connect WebSocket and subscribe to task updates
  await connectWs()
  subscribeTask(task.id)
}

async function loadDrawerTask() {
  if (!selectedTask.value) return
  drawerLoading.value = true
  try {
    const res = await taskApi.get(selectedTask.value.id)
    if (res.data) {
      selectedTask.value = res.data
    }
  } catch (error) {
    console.error('Failed to load task detail:', error)
  } finally {
    drawerLoading.value = false
  }
}

async function handleDrawerStart() {
  if (!selectedTask.value) return
  try {
    await taskApi.start(selectedTask.value.id)
    ElMessage.success(t('task.startSuccess'))
    await loadDrawerTask()
    loadTasks()
  } catch (error) {
    console.error('Failed to start task:', error)
    ElMessage.error(t('task.startFailed'))
  }
}

async function handleDrawerStop() {
  if (!selectedTask.value) return
  try {
    await taskApi.stop(selectedTask.value.id)
    ElMessage.success(t('task.stopSuccess'))
    await loadDrawerTask()
    loadTasks()
  } catch (error) {
    console.error('Failed to stop task:', error)
    ElMessage.error(t('task.stopFailed'))
  }
}

async function handleDrawerDelete() {
  if (!selectedTask.value) return
  try {
    await ElMessageBox.confirm(t('task.confirmDelete'), t('common.confirm'), {
      type: 'warning'
    })
    await taskApi.delete(selectedTask.value.id)
    ElMessage.success(t('task.deleteSuccess'))
    drawerVisible.value = false
    loadTasks()
  } catch (error) {
    // Cancelled or error
  }
}

onMounted(() => {
  loadTasks()
})

onUnmounted(() => {
  disconnectWs()
})

// Watch drawer close to unsubscribe and disconnect
watch(drawerVisible, (newVal) => {
  if (!newVal && selectedTask.value) {
    unsubscribeTask(selectedTask.value.id)
    disconnectWs()
  }
})

// Watch WebSocket task status updates
watch(taskStatus, (newStatus) => {
  if (newStatus && selectedTask.value && newStatus.id === selectedTask.value.id) {
    selectedTask.value = newStatus
  }
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}

.bulk-toolbar {
  margin-bottom: 16px;
  padding: 12px 16px;
  background: #f4f4f5;
  border-radius: 4px;
}

.bulk-text {
  color: #606266;
  font-size: 14px;
}

.strategy-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
</style>
