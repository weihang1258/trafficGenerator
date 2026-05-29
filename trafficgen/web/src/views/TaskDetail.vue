<template>
  <div class="task-detail">
    <!-- Back button + title -->
    <div class="page-header">
      <el-button link @click="$router.back()">
        <el-icon><ArrowLeft /></el-icon>
        {{ t('common.back') }}
      </el-button>
      <span class="page-title">{{ task.name || t('task.detail') }}</span>
    </div>

    <!-- Status banner -->
    <el-card class="status-card">
      <div class="status-row">
        <div class="status-main">
          <task-status-tag :status="task.status" size="large" />
          <span class="task-id">ID: {{ task.id }}</span>
        </div>
        <div class="status-meta">
          <span class="meta-item">
            <el-icon><Connection /></el-icon>
            {{ (task.protocol || 'N/A').toUpperCase() }}
          </span>
          <span class="meta-item">
            <el-icon><Clock /></el-icon>
            {{ formatDate(task.created_at) }}
          </span>
          <span v-if="task.started_at" class="meta-item">
            <el-icon><Timer /></el-icon>
            {{ formatDuration(task.started_at, task.completed_at) }}
          </span>
        </div>
      </div>

      <!-- Progress bar -->
      <el-progress
        v-if="task.status === 'running' || task.status === 'completed'"
        :percentage="task.progress || 0"
        :status="getProgressStatus(task.status)"
        :stroke-width="10"
        style="margin-top: 16px;"
      />
    </el-card>

    <!-- Stats cards -->
    <el-row :gutter="16" class="stats-row">
      <el-col :xs="12" :sm="6">
        <div class="mini-stat">
          <div class="mini-stat-value">{{ formatNumber(task.stats?.packets_sent || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.packets') }}</div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="6">
        <div class="mini-stat">
          <div class="mini-stat-value">{{ formatBytes(task.stats?.bytes_sent || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.bytes') }}</div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="6">
        <div class="mini-stat">
          <div class="mini-stat-value">{{ formatThroughput(task.stats?.current_pps || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.pps') || 'PPS' }}</div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="6">
        <div class="mini-stat">
          <div class="mini-stat-value">{{ formatThroughputBps(task.stats?.current_bps || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.bps') || 'BPS' }}</div>
        </div>
      </el-col>
    </el-row>

    <!-- Charts -->
    <el-row :gutter="16" class="charts-row">
      <el-col :span="24">
        <el-card>
          <template #header>
            <span>{{ t('task.throughputTrend') }}</span>
          </template>
          <div ref="chartRef" class="chart-container" />
        </el-card>
      </el-col>
    </el-row>

    <!-- Strategy configuration -->
    <el-card class="strategy-card">
      <template #header>
        <span>{{ t('task.strategyConfig') }}</span>
      </template>
      <el-descriptions :column="2" border>
        <el-descriptions-item :label="t('task.outputType')">
          {{ task.output_type === 'port_group' ? t('taskCreate.portGroup') : 'PCAP' }}
        </el-descriptions-item>
        <el-descriptions-item v-if="task.output_type === 'pcap'" :label="t('taskCreate.pcapPath')">
          {{ task.output_config?.pcap_path || '-' }}
        </el-descriptions-item>
        <el-descriptions-item v-if="task.output_type === 'port_group'" :label="t('taskCreate.portGroupID')">
          {{ task.output_config?.port_group_id || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('taskCreate.flowControl')">
          <span v-if="task.flow_control">{{ task.flow_control.type }}: {{ task.flow_control.value }}</span>
          <span v-else>-</span>
        </el-descriptions-item>
      </el-descriptions>

      <!-- Strategy list -->
      <div v-if="task.strategies && task.strategies.length > 0" style="margin-top: 16px;">
        <el-table :data="task.strategies" stripe size="small">
          <el-table-column prop="name" :label="t('common.name')" min-width="150" />
          <el-table-column prop="protocol" :label="t('task.protocol')" width="100">
            <template #default="{ row }">
              <el-tag size="small">{{ (row.protocol || '').toUpperCase() }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('strategy.flowControl')" min-width="120">
            <template #default="{ row }">
              <span v-if="row.flow_control">{{ row.flow_control.type }}: {{ row.flow_control.value }}</span>
              <span v-else>-</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <!-- Error log -->
    <el-card v-if="task.error_message" class="error-card">
      <template #header>
        <span style="color: var(--tg-danger, #f56c6c);">{{ t('task.errorLog') }}</span>
      </template>
      <pre class="error-log">{{ task.error_message }}</pre>
    </el-card>

    <!-- Action buttons -->
    <div class="action-bar">
      <el-button
        v-if="task.status === 'pending'"
        type="primary"
        @click="handleStart"
      >
        {{ t('task.start') }}
      </el-button>
      <el-button
        v-if="task.status === 'running'"
        type="warning"
        @click="handleStop"
      >
        {{ t('task.stop') }}
      </el-button>
      <el-button
        v-if="task.status === 'completed' || task.status === 'failed' || task.status === 'stopped'"
        type="primary"
        @click="handleRestart"
      >
        {{ t('task.start') }}
      </el-button>
      <el-button
        type="danger"
        @click="handleDelete"
      >
        {{ t('task.delete') }}
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft, Connection, Clock, Timer } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { taskApi, type Task } from '@/api'
import TaskStatusTag from '@/components/TaskStatusTag.vue'
import dayjs from 'dayjs'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null
let refreshTimer: number | null = null

const task = ref<Task>({} as Task)

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return bytes + ' B'
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(2) + 'K'
  return num.toString()
}

function formatThroughput(pps: number): string {
  if (pps >= 1000000) return (pps / 1000000).toFixed(2) + 'M'
  if (pps >= 1000) return (pps / 1000).toFixed(2) + 'K'
  return pps.toString()
}

function formatThroughputBps(bps: number): string {
  if (bps >= 1000000000) return (bps / 1000000000).toFixed(2) + ' Gbps'
  if (bps >= 1000000) return (bps / 1000000).toFixed(2) + ' Mbps'
  if (bps >= 1000) return (bps / 1000).toFixed(2) + ' Kbps'
  return bps + ' bps'
}

function formatDate(timestamp?: number): string {
  if (!timestamp) return '-'
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

function formatDuration(start?: number, end?: number): string {
  if (!start) return '-'
  const endTime = end || Math.floor(Date.now() / 1000)
  const seconds = Math.floor(endTime - start)
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
  if (minutes > 0) return `${minutes}m ${secs}s`
  return `${secs}s`
}

function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'exception'
  if (status === 'stopped') return 'warning'
  return ''
}

function initChart() {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 60, right: 20, top: 20, bottom: 30 },
    xAxis: { type: 'category', data: [], boundaryGap: false },
    yAxis: { type: 'value' },
    series: [{
      type: 'line',
      smooth: true,
      areaStyle: { opacity: 0.15 },
      lineStyle: { width: 2 },
      itemStyle: { color: getComputedStyle(document.documentElement).getPropertyValue('--tg-primary').trim() || '#2563EB' },
      data: []
    }]
  })
}

async function loadTask() {
  try {
    const id = route.params.id as string
    const res = await taskApi.get(id)
    if (res.data) {
      task.value = res.data as Task
    }
  } catch (error) {
    console.error('Failed to load task:', error)
  }
}

async function handleStart() {
  try {
    await taskApi.start(task.value.id)
    ElMessage.success(t('task.startSuccess'))
    loadTask()
  } catch (error) {
    console.error('Failed to start task:', error)
  }
}

async function handleRestart() {
  try {
    await taskApi.start(task.value.id)
    ElMessage.success(t('task.startSuccess'))
    loadTask()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || t('task.startFailed'))
  }
}

async function handleStop() {
  try {
    await ElMessageBox.confirm(t('task.stopConfirm'), t('task.stop'), { type: 'warning' })
    await taskApi.stop(task.value.id)
    ElMessage.success(t('task.stopSuccess'))
    loadTask()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to stop task:', error)
    }
  }
}

async function handleDelete() {
  try {
    await ElMessageBox.confirm(
      t('task.deleteConfirm', { name: task.value.name }),
      t('task.delete'),
      { type: 'warning' }
    )
    await taskApi.delete(task.value.id)
    ElMessage.success(t('task.deleteSuccess'))
    router.push('/tasks')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete task:', error)
    }
  }
}

function handleResize() {
  chart?.resize()
}

onMounted(async () => {
  await loadTask()
  await nextTick()
  initChart()
  refreshTimer = window.setInterval(() => {
    if (task.value.status === 'running') {
      loadTask()
    }
  }, 5000)
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
  chart?.dispose()
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
.task-detail {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.page-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
}

.page-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--tg-text-primary, #0F172A);
}

.status-card {
  border-left: 4px solid var(--tg-primary, #2563EB);
}

.status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.status-main {
  display: flex;
  align-items: center;
  gap: 12px;
}

.task-id {
  font-size: 12px;
  color: var(--tg-text-secondary, #64748B);
  font-family: monospace;
}

.status-meta {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: var(--tg-text-body, #606266);
}

.stats-row {
  margin-bottom: 0;
}

.mini-stat {
  background: var(--tg-bg-card, #FFFFFF);
  border-radius: var(--tg-radius-card, 12px);
  padding: 16px;
  text-align: center;
  box-shadow: var(--tg-shadow-sm, 0 1px 3px rgba(0,0,0,0.1));
}

.mini-stat-value {
  font-size: 20px;
  font-weight: 600;
  color: var(--tg-text-primary, #0F172A);
}

.mini-stat-label {
  font-size: 12px;
  color: var(--tg-text-secondary, #64748B);
  margin-top: 4px;
}

.chart-container {
  height: 250px;
}

.error-card {
  border-left: 4px solid var(--tg-danger, #f56c6c);
}

.error-log {
  background: #fef0f0;
  padding: 12px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--tg-danger, #f56c6c);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

.action-bar {
  display: flex;
  gap: 8px;
  padding-top: 8px;
}

@media (max-width: 768px) {
  .status-row {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
