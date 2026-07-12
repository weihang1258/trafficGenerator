<template>
  <div class="task-detail" v-loading="loading && !task.id">
    <!-- Loading state -->
    <div v-if="loading && !task.id" class="loading-state" v-loading="true"></div>

    <!-- Error state -->
    <el-result
      v-else-if="errorState"
      icon="error"
      :title="errorState"
    >
      <template #extra>
        <el-button type="primary" @click="loadTask">{{ t('common.retry') }}</el-button>
        <el-button @click="$router.back()">{{ t('common.back') }}</el-button>
      </template>
    </el-result>

    <!-- Content -->
    <template v-else>
    <!-- Back button + title -->
    <div class="page-header">
      <el-button link @click="$router.back()">
        <el-icon><ArrowLeft /></el-icon>
        {{ t('common.back') }}
      </el-button>
      <span class="page-title">{{ task.name || t('task.detail') }}</span>
    </div>

    <!-- Status banner -->
    <el-card class="status-card" :class="`status-${task.status}`">
      <div class="status-row">
        <div class="status-main">
          <task-status-tag :status="task.status" size="large" />
          <span class="task-id">ID: {{ task.id }}</span>
          <ConnectionIndicator v-if="task.status === 'running'" :connected="wsConnected" :error="wsError" />
        </div>
        <div class="status-meta">
          <span class="meta-item">
            <el-icon><Connection /></el-icon>
            {{ (task.protocol || 'N/A').toUpperCase() }}
          </span>
          <span class="meta-item">
            <el-icon><Clock /></el-icon>
            {{ formatTimestamp(task.created_at) }}
          </span>
          <span v-if="task.started_at" class="meta-item">
            <el-icon><Timer /></el-icon>
            {{ formatTaskDuration(task.started_at, task.completed_at) }}
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
          <div class="mini-stat-value">{{ formatPps(task.stats?.current_pps || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.pps') }}</div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="6">
        <div class="mini-stat">
          <div class="mini-stat-value">{{ formatBps(task.stats?.current_bps || 0) }}</div>
          <div class="mini-stat-label">{{ t('task.bps') }}</div>
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
          <div ref="chartRef" class="chart-container" style="position: relative;">
            <div v-if="throughputHistory.length === 0 && !loading" class="chart-empty-overlay">
              <el-empty :description="t('common.noData')" :image-size="60" />
            </div>
          </div>
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
          {{ task.output_type === 'port_group' ? t('taskCreate.portGroup') : t('taskCreate.pcap') }}
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
        v-if="task.status !== 'running'"
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
        type="danger"
        @click="handleDelete"
      >
        {{ t('task.delete') }}
      </el-button>
    </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onBeforeUnmount, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft, Connection, Clock, Timer } from '@element-plus/icons-vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])
import { taskApi, type Task } from '@/api'
import TaskStatusTag from '@/components/TaskStatusTag.vue'
import ConnectionIndicator from '@/components/ConnectionIndicator.vue'
import { useTaskWebSocket } from '@/composables/useTaskWebSocket'
import { useServerList } from '@/composables/useServerList'
import { getProgressStatus } from '@/constants/status'
import { formatBytes, formatNumber, formatPps, formatBps, formatTaskDuration, formatTimestamp } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()

const chartRef = ref<HTMLElement>()
let refreshTimer: number | null = null

// WebSocket for real-time updates
const { connected: wsConnected, progress: wsProgress, stats: wsStats, error: wsError, connect: wsConnect, subscribeTask: wsSubscribe, disconnect: wsDisconnect } = useTaskWebSocket()

const taskId = route.params.id as string

// Server list composable for task data (single item list)
const { loading, data: taskList, refresh } = useServerList<Task>({
  fetchFn: async () => {
    const res = await taskApi.get(taskId)
    return { items: res.data ? [res.data] : [], total: res.data ? 1 : 0 }
  },
  defaultPageSize: 1
})

// Use reactive object instead of computed so WebSocket updates can merge in
const task = reactive<Record<string, any>>({})

// When useServerList data loads, merge it into task
watch(() => taskList.value[0], (apiTask) => {
  if (apiTask) {
    Object.assign(task, apiTask)
  }
}, { immediate: true })

const throughputHistory = ref<Array<{ time: string; pps: number; bps: number }>>([])
const errorState = ref<string | null>(null)
const chartInstance = ref<echarts.ECharts | null>(null)


function initChart() {
  if (!chartRef.value) return
  chartInstance.value = echarts.init(chartRef.value)
  chartInstance.value.setOption({
    tooltip: { trigger: 'axis' },
    legend: { data: ['PPS', 'Mbps'] },
    grid: { left: 60, right: 20, top: 40, bottom: 30 },
    xAxis: { type: 'category', data: [], boundaryGap: false },
    yAxis: { type: 'value' },
    series: [{
      name: 'PPS',
      type: 'line',
      smooth: true,
      areaStyle: { opacity: 0.15 },
      lineStyle: { width: 2 },
      itemStyle: { color: getComputedStyle(document.documentElement).getPropertyValue('--tg-primary').trim() || '#2563EB' },
      data: []
    }, {
      name: 'Mbps',
      type: 'line',
      smooth: true,
      areaStyle: { opacity: 0.15 },
      lineStyle: { width: 2 },
      itemStyle: { color: getComputedStyle(document.documentElement).getPropertyValue('--tg-success').trim() || '#10B981' },
      data: []
    }]
  })
}

function updateChart() {
  if (!chartInstance.value) return
  const history = throughputHistory.value
  chartInstance.value.setOption({
    xAxis: { data: history.map(h => h.time) },
    series: [
      { data: history.map(h => h.pps) },
      { data: history.map(h => Number((h.bps / 1024 / 1024).toFixed(2))) }
    ]
  })
}

async function loadTaskData(showLoading = true) {
  if (disposed) return
  await refresh()
  if (disposed) return
  // task is a reactive object, access directly
  if (task.stats?.current_pps || task.stats?.current_bps) {
    throughputHistory.value.push({
      time: new Date().toLocaleTimeString(),
      pps: task.stats.current_pps || 0,
      bps: task.stats.current_bps || 0
    })
    if (throughputHistory.value.length > 30) {
      throughputHistory.value = throughputHistory.value.slice(-30)
    }
    updateChart()
  }
}

async function loadTask(showLoading = true) {
  errorState.value = null
  try {
    await loadTaskData(showLoading)
  } catch (error: any) {
    if (disposed) return
    console.error('Failed to load task:', error)
    if (error?.response?.status === 404) {
      errorState.value = t('error.notFound')
    } else {
      errorState.value = t('error.networkError')
    }
  }
}

async function handleStart() {
  try {
    await taskApi.start(task.id)
    ElMessage.success(t('task.startSuccess'))
    loadTask()
    scheduleRefresh()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || t('task.startFailed'))
  }
}

async function handleStop() {
  try {
    await ElMessageBox.confirm(t('task.stopConfirm'), t('task.stop'), { type: 'warning' })
    await taskApi.stop(task.id)
    ElMessage.success(t('task.stopSuccess'))
    loadTask()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to stop task:', error)
      ElMessage.error(t('task.stopFailed'))
    }
  }
}

async function handleDelete() {
  try {
    await ElMessageBox.confirm(
      t('task.deleteConfirm', { name: task.name }),
      t('task.delete'),
      { type: 'warning' }
    )
    await taskApi.delete(task.id)
    ElMessage.success(t('task.deleteSuccess'))
    router.push('/tasks')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete task:', error)
    }
  }
}

function handleResize() {
  chartInstance.value?.resize()
}

let disposed = false

function scheduleRefresh() {
  if (disposed) return
  const terminalStatuses = ['completed', 'stopped', 'failed', 'error']
  if (terminalStatuses.includes(task.status)) return
  refreshTimer = window.setTimeout(async () => {
    if (disposed) return
    if (task.status === 'running') {
      await loadTask(false)
    }
    scheduleRefresh()
  }, 5000)
}

// Merge WebSocket real-time data into task (reactive object allows mutation)
watch(wsProgress, (val) => {
  if (val > 0 && task.status === 'running') {
    task.progress = val
  }
})

watch(wsStats, (val) => {
  if (val && task.status === 'running') {
    task.stats = { ...task.stats, ...val }
    // Append to throughput history
    throughputHistory.value.push({
      time: new Date().toLocaleTimeString(),
      pps: val.current_pps || 0,
      bps: val.current_bps || 0
    })
    if (throughputHistory.value.length > 30) {
      throughputHistory.value = throughputHistory.value.slice(-30)
    }
    updateChart()
  }
})

onMounted(async () => {
  await loadTask()
  if (disposed) return
  await nextTick()
  initChart()
  // Try WebSocket for real-time updates
  try {
    await wsConnect()
    wsSubscribe(route.params.id as string)
  } catch {
    // WebSocket failed, HTTP polling will continue
  }
  scheduleRefresh()
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  disposed = true
  wsDisconnect()
  if (refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = null
  chartInstance.value?.dispose()
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

.status-card.status-running {
  border-left-color: var(--tg-warning, #F59E0B);
}

.status-card.status-completed {
  border-left-color: var(--tg-success, #10B981);
}

.status-card.status-failed,
.status-card.status-error {
  border-left-color: var(--tg-danger, #EF4444);
}

.status-card.status-stopped {
  border-left-color: var(--tg-text-disabled, #94A3B8);
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

.loading-state {
  min-height: 400px;
}

.chart-empty-overlay {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--tg-bg-card, #fff);
  z-index: 1;
}

.error-card {
  border-left: 4px solid var(--tg-danger, #f56c6c);
}

.error-log {
  background: var(--tg-danger-light);
  padding: 12px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--tg-danger);
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
