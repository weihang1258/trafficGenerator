<template>
  <div class="task-detail">
    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <div class="title">
            <el-button link @click="$router.back()">
              <el-icon><ArrowLeft /></el-icon>
            </el-button>
            <span>{{ task?.name || '任务详情' }}</span>
            <el-tag :type="getStatusTagType(task?.status || '')">{{ getStatusText(task?.status || '') }}</el-tag>
          </div>
          <div class="actions">
            <el-button
              type="success"
              :disabled="task?.status !== 'created' && task?.status !== 'paused'"
              @click="startTask"
            >
              启动
            </el-button>
            <el-button
              type="warning"
              :disabled="task?.status !== 'running'"
              @click="stopTask"
            >
              停止
            </el-button>
            <el-button type="danger" @click="deleteTask">删除</el-button>
          </div>
        </div>
      </template>

      <el-descriptions :column="3" border>
        <el-descriptions-item label="任务ID">{{ task?.id }}</el-descriptions-item>
        <el-descriptions-item label="协议">
          <el-tag :type="getProtocolTagType(task?.protocol || '')">{{ task?.protocol?.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusTagType(task?.status || '')">{{ getStatusText(task?.status || '') }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ formatDate(task?.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="开始时间">{{ formatDate(task?.started_at) }}</el-descriptions-item>
        <el-descriptions-item label="完成时间">{{ formatDate(task?.completed_at) }}</el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">进度</el-divider>

      <el-progress
        :percentage="task?.progress || 0"
        :status="getProgressStatus(task?.status || '')"
        :stroke-width="20"
        style="margin-bottom: 20px;"
      />

      <el-divider content-position="left">统计信息</el-divider>

      <el-row :gutter="20">
        <el-col :span="6">
          <el-statistic title="已发送报文" :value="task?.stats?.packets_sent || 0" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="已发送字节" :value="task?.stats?.bytes_sent || 0" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="当前PPS" :value="task?.stats?.current_pps || 0" :precision="2" />
        </el-col>
        <el-col :span="6">
          <el-statistic title="当前BPS" :value="task?.stats?.current_bps || 0" :precision="2" />
        </el-col>
      </el-row>

      <el-divider content-position="left">错误信息</el-divider>

      <el-alert
        v-if="task?.error"
        :title="task.error"
        type="error"
        show-icon
        :closable="false"
      />
      <el-empty v-else description="无错误" :image-size="60" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { taskApi, type Task } from '@/api'
import dayjs from 'dayjs'

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
    created: '已创建',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    failed: '失败'
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
    ElMessage.success('任务已启动')
    loadTask()
  } catch (error) {
    console.error('Failed to start task:', error)
  }
}

async function stopTask() {
  try {
    await taskApi.stop(taskId)
    ElMessage.success('任务已停止')
    loadTask()
  } catch (error) {
    console.error('Failed to stop task:', error)
  }
}

async function deleteTask() {
  try {
    await ElMessageBox.confirm('确定要删除此任务吗？', '确认删除', { type: 'warning' })
    await taskApi.delete(taskId)
    ElMessage.success('任务已删除')
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
