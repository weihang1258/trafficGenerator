<template>
  <div class="task-detail">
    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <div class="title">
            <el-button link @click="$router.back()">
              <el-icon><ArrowLeft /></el-icon>
            </el-button>
            <span>{{ task?.name || t('task.taskDetail') }}</span>
            <el-tag :type="getStatusTagType(task?.status || '')">{{ getStatusText(task?.status || '') }}</el-tag>
          </div>
          <div class="actions">
            <el-button
              type="success"
              :disabled="task?.status !== 'pending' && task?.status !== 'stopped'"
              @click="startTask"
            >
              {{ t('task.start') }}
            </el-button>
            <el-button
              type="warning"
              :disabled="task?.status !== 'running'"
              @click="stopTask"
            >
              {{ t('task.stop') }}
            </el-button>
            <el-button type="danger" @click="deleteTask">{{ t('common.delete') }}</el-button>
          </div>
        </div>
      </template>

      <el-descriptions :column="3" border>
        <el-descriptions-item :label="t('task.taskName')">{{ task?.name }}</el-descriptions-item>
        <el-descriptions-item :label="t('task.protocol')">
          <el-tag :type="getProtocolTagType(task?.protocol || '')">{{ task?.protocol?.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="t('task.status')">
          <el-tag :type="getStatusTagType(task?.status || '')">{{ getStatusText(task?.status || '') }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="t('task.createdAt')">{{ formatDate(task?.created_at) }}</el-descriptions-item>
        <el-descriptions-item :label="t('task.startedAt')">{{ formatDate(task?.started_at) }}</el-descriptions-item>
        <el-descriptions-item :label="t('task.completedAt')">{{ formatDate(task?.completed_at) }}</el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">{{ t('task.progress') }}</el-divider>

      <el-progress
        :percentage="task?.progress || 0"
        :status="getProgressStatus(task?.status || '')"
        :stroke-width="20"
        style="margin-bottom: 20px;"
      />

      <el-divider content-position="left">{{ t('task.statistics') }}</el-divider>

      <el-row :gutter="20">
        <el-col :span="6">
          <el-statistic :title="t('dashboard.packetsSent')" :value="task?.stats?.packets_sent || 0" />
        </el-col>
        <el-col :span="6">
          <el-statistic :title="t('task.bytes')" :value="task?.stats?.bytes_sent || 0" />
        </el-col>
        <el-col :span="6">
          <el-statistic :title="t('dashboard.pps')" :value="task?.stats?.current_pps || 0" :precision="2" />
        </el-col>
        <el-col :span="6">
          <el-statistic :title="t('dashboard.bps')" :value="task?.stats?.current_bps || 0" :precision="2" />
        </el-col>
      </el-row>

      <el-divider content-position="left">{{ t('common.error') }}</el-divider>

      <el-alert
        v-if="task?.error_message"
        :title="task.error_message"
        type="error"
        show-icon
        :closable="false"
      />
      <el-empty v-else :description="t('common.noData')" :image-size="60" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { taskApi, type Task } from '@/api'
import dayjs from 'dayjs'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const loading = ref(false)
const task = ref<Task | null>(null)
let refreshTimer: number | null = null

const taskId = route.params.id as string

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

async function loadTask() {
  try {
    const res = await taskApi.get(taskId)
    if (res.data) {
      task.value = res.data
    }
  } catch (error) {
    console.error('Failed to load task:', error)
  }
}

async function startTask() {
  try {
    await taskApi.start(taskId)
    ElMessage.success(t('task.startSuccess'))
    loadTask()
  } catch (error) {
    console.error('Failed to start task:', error)
  }
}

async function stopTask() {
  try {
    await taskApi.stop(taskId)
    ElMessage.success(t('task.stopSuccess'))
    loadTask()
  } catch (error) {
    console.error('Failed to stop task:', error)
  }
}

async function deleteTask() {
  try {
    await ElMessageBox.confirm(t('task.confirmDelete'), t('common.confirm'), { type: 'warning' })
    await taskApi.delete(taskId)
    ElMessage.success(t('task.deleteSuccess'))
    router.push('/tasks')
  } catch (error) {
    // Cancelled
  }
}

onMounted(() => {
  loadTask()
  refreshTimer = window.setInterval(loadTask, 3000)
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

.title {
  display: flex;
  align-items: center;
  gap: 10px;
}

.actions {
  display: flex;
  gap: 10px;
}
</style>
