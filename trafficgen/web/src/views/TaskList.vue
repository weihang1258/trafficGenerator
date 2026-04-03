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
      <el-form :inline="true" class="search-form">
        <el-form-item :label="t('task.status')">
          <el-select v-model="filters.status" :placeholder="t('common.select')" clearable @change="loadTasks">
            <el-option :label="t('task.running')" value="running" />
            <el-option :label="t('task.completed')" value="completed" />
            <el-option :label="t('task.failed')" value="failed" />
            <el-option :label="t('task.stopped')" value="paused" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('task.protocol')">
          <el-select v-model="filters.protocol" :placeholder="t('common.select')" clearable @change="loadTasks">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
            <el-option label="HTTP" value="http" />
            <el-option label="DNS" value="dns" />
            <el-option label="ICMP" value="icmp" />
          </el-select>
        </el-form-item>
      </el-form>

      <!-- Task Table -->
      <el-table :data="tasks" v-loading="loading" stripe>
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
              <el-button size="small" @click="$router.push(`/tasks/${row.id}`)">
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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { taskApi, type Task } from '@/api'
import dayjs from 'dayjs'

const { t } = useI18n()

const loading = ref(false)
const tasks = ref<Task[]>([])

const filters = reactive({
  status: '',
  protocol: ''
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
      status: filters.status,
      protocol: filters.protocol
    })
    if (res.data) {
      tasks.value = res.data.tasks
      pagination.total = res.data.total
    }
  } catch (error) {
    console.error('Failed to load tasks:', error)
  } finally {
    loading.value = false
  }
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

onMounted(() => {
  loadTasks()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-form {
  margin-bottom: 20px;
}
</style>
