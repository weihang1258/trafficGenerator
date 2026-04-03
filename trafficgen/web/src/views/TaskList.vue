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

      <!-- Search and Filter -->
      <el-collapse v-model="activeFilters" class="filter-collapse">
        <el-collapse-item :title="t('task.advancedFilters')" name="filters">
          <el-form :inline="true" class="search-form">
            <el-form-item :label="t('task.status')">
              <el-select
                v-model="filters.status"
                :placeholder="t('common.select')"
                multiple
                clearable
                @change="loadTasks"
              >
                <el-option :label="t('task.running')" value="running" />
                <el-option :label="t('task.completed')" value="completed" />
                <el-option :label="t('task.failed')" value="failed" />
                <el-option :label="t('task.stopped')" value="paused" />
              </el-select>
            </el-form-item>
            <el-form-item :label="t('task.protocol')">
              <el-select
                v-model="filters.protocol"
                :placeholder="t('common.select')"
                multiple
                clearable
                @change="loadTasks"
              >
                <el-option label="TCP" value="tcp" />
                <el-option label="UDP" value="udp" />
                <el-option label="HTTP" value="http" />
                <el-option label="DNS" value="dns" />
                <el-option label="ICMP" value="icmp" />
              </el-select>
            </el-form-item>
            <el-form-item :label="t('common.search')">
              <el-input
                v-model="filters.search"
                :placeholder="t('task.searchPlaceholder')"
                clearable
                @clear="loadTasks"
                @keyup.enter="loadTasks"
              >
                <template #append>
                  <el-button :icon="Search" @click="loadTasks" />
                </template>
              </el-input>
            </el-form-item>
            <el-form-item>
              <el-button @click="resetFilters">
                {{ t('common.reset') }}
              </el-button>
            </el-form-item>
          </el-form>
        </el-collapse-item>
      </el-collapse>

      <!-- Bulk Actions Toolbar -->
      <div v-if="selectedTasks.length > 0" class="bulk-actions">
        <el-alert
          :title="`${t('common.selected')} ${selectedTasks.length} ${t('task.tasks')}`"
          type="info"
          :closable="false"
        >
          <template #default>
            <el-button-group>
              <el-button size="small" type="success" @click="handleBulkStart">
                {{ t('task.bulkStart') }}
              </el-button>
              <el-button size="small" type="warning" @click="handleBulkStop">
                {{ t('task.bulkStop') }}
              </el-button>
              <el-button size="small" type="danger" @click="handleBulkDelete">
                {{ t('task.bulkDelete') }}
              </el-button>
            </el-button-group>
          </template>
        </el-alert>
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
        <el-table-column prop="id" :label="t('task.taskName')" width="180" />
        <el-table-column prop="name" :label="t('common.name')" min-width="150" />
        <el-table-column prop="protocol" :label="t('task.protocol')" width="100">
          <template #default="{ row }">
            <el-tag :type="getProtocolTagType(row.protocol)">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('task.status')" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)">{{ getStatusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" :label="t('task.progress')" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" :status="getProgressStatus(row.status)" />
          </template>
        </el-table-column>
        <el-table-column prop="stats.packets_sent" :label="t('task.packets')" width="120">
          <template #default="{ row }">
            {{ formatNumber(row.stats?.packets_sent || 0) }}
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('task.createdAt')" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="200" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button size="small" @click="openDrawer(row)">
                {{ t('task.viewDetail') }}
              </el-button>
              <el-button
                size="small"
                type="success"
                :disabled="row.status !== 'created' && row.status !== 'paused'"
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
            </el-button-group>
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
          <el-descriptions-item :label="t('task.protocol')">
            <el-tag :type="getProtocolTagType(selectedTask.protocol)">{{ selectedTask.protocol?.toUpperCase() }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('task.status')">
            <el-tag :type="getStatusTagType(selectedTask.status)">{{ getStatusText(selectedTask.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('task.createdAt')">{{ formatDate(selectedTask.created_at) }}</el-descriptions-item>
          <el-descriptions-item :label="t('task.startedAt')">{{ formatDate(selectedTask.started_at) }}</el-descriptions-item>
        </el-descriptions>

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
            :disabled="selectedTask.status !== 'created' && selectedTask.status !== 'paused'"
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
          v-if="selectedTask.error"
          :title="selectedTask.error"
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

const { t } = useI18n()

const loading = ref(false)
const tasks = ref<Task[]>([])
const selectedTasks = ref<Task[]>([])
const activeFilters = ref<string[]>(['filters'])
const drawerVisible = ref(false)
const drawerLoading = ref(false)
const selectedTask = ref<Task | null>(null)

// WebSocket for real-time updates
const { taskStatus, connect: connectWs, disconnect: disconnectWs, subscribeTask, unsubscribeTask } = useTaskWebSocket()

const filters = reactive({
  status: [] as string[],
  protocol: [] as string[],
  search: ''
})

const pagination = reactive({
  page: 1,
  size: 20,
  total: 0
})

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(2) + 'K'
  return num.toString()
}

function formatDate(timestamp: number): string {
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    created: t('task.pending'),
    running: t('task.running'),
    paused: t('task.stopped'),
    completed: t('task.completed'),
    failed: t('task.failed')
  }
  return map[status] || status
}

function getStatusTagType(status: string): string {
  const map: Record<string, string> = {
    created: 'info',
    running: 'success',
    paused: 'warning',
    completed: '',
    failed: 'danger'
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
  if (status === 'failed') return 'exception'
  if (status === 'paused') return 'warning'
  return ''
}

async function loadTasks() {
  loading.value = true
  try {
    const res = await taskApi.list({
      page: pagination.page,
      size: pagination.size,
      status: Array.isArray(filters.status) ? filters.status.join(',') : filters.status,
      protocol: Array.isArray(filters.protocol) ? filters.protocol.join(',') : filters.protocol
    })
    if (res.data) {
      let taskList = res.data.tasks

      // Client-side search filter
      if (filters.search) {
        const searchLower = filters.search.toLowerCase()
        taskList = taskList.filter(task =>
          task.id.toLowerCase().includes(searchLower) ||
          task.name?.toLowerCase().includes(searchLower)
        )
      }

      tasks.value = taskList
      pagination.total = res.data.total
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
    await Promise.all(selectedTasks.value.map(task => taskApi.start(task.id)))
    ElMessage.success(t('task.bulkStarted', { count: selectedTasks.value.length }))
    selectedTasks.value = []
    loadTasks()
  } catch (error) {
    console.error('Failed to bulk start tasks:', error)
    ElMessage.error(t('task.startFailed'))
  }
}

async function handleBulkStop() {
  try {
    await Promise.all(selectedTasks.value.map(task => taskApi.stop(task.id)))
    ElMessage.success(t('task.bulkStopped', { count: selectedTasks.value.length }))
    selectedTasks.value = []
    loadTasks()
  } catch (error) {
    console.error('Failed to bulk stop tasks:', error)
    ElMessage.error(t('task.stopFailed'))
  }
}

async function handleBulkDelete() {
  try {
    await ElMessageBox.confirm(
      t('task.confirmBulkDelete', { count: selectedTasks.value.length }),
      t('common.confirm'),
      { type: 'warning' }
    )
    await Promise.all(selectedTasks.value.map(task => taskApi.delete(task.id)))
    ElMessage.success(t('task.bulkDeleted', { count: selectedTasks.value.length }))
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

.filter-collapse {
  margin-bottom: 20px;
}

.search-form {
  margin-top: 10px;
}

.bulk-actions {
  margin-bottom: 20px;
}

.bulk-actions :deep(.el-alert__content) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
}
</style>
