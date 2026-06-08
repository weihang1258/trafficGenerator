<template>
  <div class="dashboard" v-loading="initialLoading">
    <!-- Header -->
    <div class="dashboard-header">
      <h2 class="dashboard-title">{{ t('dashboard.title') }}</h2>
      <el-button :loading="refreshing" @click="handleRefresh" circle size="small" aria-label="Refresh dashboard">
        <el-icon><Refresh /></el-icon>
      </el-button>
    </div>

    <!-- Section 1: Overview Stats -->
    <div class="section-title">{{ t('dashboard.sectionStats') }}</div>
    <el-row :gutter="12" class="stats-row">
      <el-col :xs="12" :sm="8" :md="4" :lg="4">
        <div class="stat-card" @click="$router.push('/tasks')">
          <div class="stat-icon stat-icon--primary">
            <el-icon :size="20"><List /></el-icon>
          </div>
          <div class="stat-body">
            <div class="stat-value">{{ stats.activeTasks != null ? stats.activeTasks : '--' }}</div>
            <div class="stat-label">{{ t('dashboard.activeTasks') }}</div>
          </div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="8" :md="4" :lg="4">
        <div class="stat-card">
          <div class="stat-icon stat-icon--success">
            <el-icon :size="20"><MessageBox /></el-icon>
          </div>
          <div class="stat-body">
            <div class="stat-value">{{ stats.packetsSent != null ? formatNumber(stats.packetsSent) : '--' }}</div>
            <div class="stat-label">{{ t('dashboard.packetsSent') }}</div>
          </div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="8" :md="4" :lg="4">
        <div class="stat-card">
          <div class="stat-icon stat-icon--warning">
            <el-icon :size="20"><TrendCharts /></el-icon>
          </div>
          <div class="stat-body">
            <div class="stat-value">{{ stats.throughputBps != null ? formatBps(stats.throughputBps) : '--' }}</div>
            <div class="stat-label">{{ t('dashboard.throughput') }}</div>
          </div>
        </div>
      </el-col>
      <el-col :xs="12" :sm="8" :md="4" :lg="4">
        <div class="stat-card">
          <div class="stat-icon stat-icon--info">
            <el-icon :size="20"><Odometer /></el-icon>
          </div>
          <div class="stat-body">
            <div class="stat-value">{{ stats.currentPps != null ? formatNumber(stats.currentPps) + '/s' : '--' }}</div>
            <div class="stat-label">{{ t('dashboard.packetRate') }}</div>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- Section 2: Hardware Resources + Charts -->
    <div class="section-title">
      {{ t('dashboard.sectionResources') }}
      <span v-if="resources.uptime" class="uptime-badge">
        {{ t('dashboard.uptime') }}: {{ formatUptime(resources.uptime) }}
      </span>
    </div>
    <el-row :gutter="12" class="resources-row">
      <!-- Left: Resource Gauges -->
      <el-col :xs="24" :lg="8">
        <el-card class="resource-card" shadow="never">
          <div class="resource-list">
            <div class="resource-item">
              <div class="resource-header">
                <span class="resource-name">CPU</span>
                <span class="resource-value">{{ resources.cpu }}%</span>
              </div>
              <el-progress :percentage="resources.cpu || 0" :stroke-width="8" :show-text="false" :color="getProgressColor(resources.cpu || 0)" />
            </div>
            <div class="resource-item">
              <div class="resource-header">
                <span class="resource-name">{{ t('dashboard.memory') }}</span>
                <span class="resource-value">{{ resources.memoryMb > 0 ? resources.memoryMb.toFixed(1) + ' MB' : '--' }}</span>
              </div>
              <el-progress :percentage="memoryPercent || 0" :stroke-width="8" :show-text="false" :color="getProgressColor(memoryPercent || 0)" />
            </div>
            <div class="resource-item">
              <div class="resource-header">
                <span class="resource-name">{{ t('dashboard.bufferUsage') }}</span>
                <span class="resource-value">{{ bufferPercent > 0 ? bufferPercent.toFixed(2) + '%' : '--' }}</span>
              </div>
              <el-progress :percentage="bufferPercent || 0" :stroke-width="8" :show-text="false" :color="getProgressColor(bufferPercent || 0)" />
            </div>
          </div>
        </el-card>
      </el-col>
      <!-- Right: Charts -->
      <el-col :xs="24" :lg="16">
        <el-row :gutter="12">
          <el-col :xs="24" :sm="14">
            <el-card class="chart-card" shadow="never">
              <template #header>
                <ProCardHeader :title="t('dashboard.throughputTrend')" />
              </template>
              <div class="chart-container-sm chart-with-overlay">
                <div ref="throughputChartRef" class="chart-canvas" />
                <div v-if="throughputHistory.length === 0" class="chart-empty-overlay">
                  <el-empty :image-size="48" :description="t('common.noData')" />
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :xs="24" :sm="10">
            <el-card class="chart-card" shadow="never">
              <template #header>
                <ProCardHeader :title="t('dashboard.protocolDistribution')" />
              </template>
              <div class="chart-container-sm chart-with-overlay">
                <div ref="protocolChartRef" class="chart-canvas" />
                <div v-if="protocolDataEmpty" class="chart-empty-overlay">
                  <el-empty :image-size="48" :description="t('common.noData')" />
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </el-col>
    </el-row>

    <!-- Section 3: Task Execution Details -->
    <div class="section-title">
      {{ t('dashboard.sectionTasks') }}
      <el-button link type="primary" size="small" @click="$router.push('/tasks')">
        {{ t('dashboard.viewAll') }} <el-icon><ArrowRight /></el-icon>
      </el-button>
    </div>
    <el-card class="task-card" shadow="never">
      <el-table :data="displayTasks" stripe size="small" v-loading="tasksLoading" :max-height="taskTableHeight">
        <el-table-column prop="name" :label="t('task.taskName')" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <router-link :to="`/tasks/${row.id}`" class="task-link">{{ row.name }}</router-link>
          </template>
        </el-table-column>
        <el-table-column :label="t('task.protocol')" width="80">
          <template #default="{ row }">
            <el-tag size="small">{{ getProtocol(row).toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('task.status')" width="100">
          <template #default="{ row }">
            <task-status-tag :status="row.status" size="small" />
          </template>
        </el-table-column>
        <el-table-column :label="t('dashboard.packetsSent')" width="100">
          <template #default="{ row }">
            {{ row.stats?.packets_sent != null ? formatNumber(row.stats.packets_sent) : '--' }}
          </template>
        </el-table-column>
        <el-table-column :label="t('dashboard.throughput')" width="120">
          <template #default="{ row }">
            {{ row.stats?.current_bps != null ? formatBps(row.stats.current_bps) : '--' }}
          </template>
        </el-table-column>
        <el-table-column :label="t('task.progress')" width="110">
          <template #default="{ row }">
            <el-progress :percentage="Number(row.progress) || 0" :stroke-width="5" :status="getProgressStatus(row.status)" />
          </template>
        </el-table-column>
        <el-table-column :label="t('dashboard.runningTime')" width="100">
          <template #default="{ row }">
            {{ getDuration(row) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="80" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'pending'"
              type="primary"
              size="small"
              link
              @click="handleStartTask(row)"
            >
              {{ t('task.start') }}
            </el-button>
            <el-button
              v-if="row.status === 'running'"
              type="danger"
              size="small"
              link
              @click="handleStopTask(row)"
            >
              {{ t('task.stop') }}
            </el-button>
            <span v-if="!['pending', 'running'].includes(row.status)" class="text-muted">--</span>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="displayTasks.length === 0 && !tasksLoading" :description="t('task.noTasks')" :image-size="60" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  List, MessageBox, TrendCharts, Odometer, Refresh, ArrowRight
} from '@element-plus/icons-vue'
import * as echarts from 'echarts/core'
import { PieChart, LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([PieChart, LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])
import { taskApi, systemApi, strategyApi, type Task } from '@/api'
import TaskStatusTag from '@/components/TaskStatusTag.vue'
import { formatNumber, formatBps, formatUptime, formatDuration } from '@/utils/format'
import { getProgressStatus } from '@/constants/status'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import { useDarkMode } from '@/composables/useDarkMode'

const { t } = useI18n()
const { isDark } = useDarkMode()

const throughputChartRef = ref<HTMLElement>()
const protocolChartRef = ref<HTMLElement>()
let throughputChart: echarts.ECharts | null = null
let protocolChart: echarts.ECharts | null = null
let refreshTimer: number | null = null
let visibilityHandler: (() => void) | null = null

// Error spam prevention: only show error once until next successful load
let dashboardErrorShown = false
let tasksErrorShown = false

const refreshing = ref(false)
const initialLoading = ref(true)
const tasksLoading = ref(false)
const allTasks = ref<Task[]>([])
const strategyMap = ref<Map<string, string>>(new Map())

const stats = reactive({
  activeTasks: 0,
  packetsSent: 0,
  throughputBps: 0,
  currentPps: 0
})

const resources = reactive({
  cpu: 0,
  memoryMb: 0,
  memoryTotalMb: 0,
  bufferBytes: 0,
  bufferMaxBytes: 0,
  uptime: 0
})

const throughputHistory = ref<{ time: string; value: number }[]>([])
const protocolDataEmpty = ref(true)
const bufferPercent = computed(() => {
  if (!resources.bufferMaxBytes) return 0
  const v = (resources.bufferBytes / resources.bufferMaxBytes) * 100
  return Number.isFinite(v) ? v : 0
})

// Try API value first, then navigator.deviceMemory, fallback 8GB
const memoryTotalMb = computed(() => {
  if (resources.memoryTotalMb) return resources.memoryTotalMb
  if ((navigator as any).deviceMemory) return (navigator as any).deviceMemory * 1024
  return 8192
})

const memoryPercent = computed(() => {
  if (!resources.memoryMb) return 0
  const total = memoryTotalMb.value
  if (!total) return 0
  const v = Math.min((resources.memoryMb / total) * 100, 100)
  return Number.isFinite(v) ? v : 0
})

const taskTableHeight = ref(400)

const displayTasks = computed(() => {
  const order: Record<string, number> = { running: 0, pending: 1, stopped: 2, completed: 3, error: 4 }
  return [...allTasks.value]
    .sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9))
    .slice(0, 10)
})

function getCssVar(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

function getProgressColor(value: number): string {
  if (value >= 90) return getCssVar('--tg-danger', '#EF4444')
  if (value >= 70) return getCssVar('--tg-warning', '#F59E0B')
  return getCssVar('--tg-success', '#10B981')
}

function getProtocol(task: Task): string {
  if (task.protocol) return task.protocol
  const sid = task.strategy_ids?.[0]
  if (sid && strategyMap.value.has(sid)) return strategyMap.value.get(sid)!
  return 'N/A'
}

function getDuration(task: Task): string {
  if (!task.started_at) return '--'
  const end = task.completed_at || Math.floor(Date.now() / 1000)
  return formatDuration(end - task.started_at)
}

function recordThroughput(bps: number) {
  const now = new Date()
  const time = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`
  throughputHistory.value.push({ time, value: bps })
  if (throughputHistory.value.length > 30) throughputHistory.value.shift()
}

function getChartTheme(): string | undefined {
  return isDark.value ? 'dark' : undefined
}

function initCharts() {
  const theme = getChartTheme()
  const primaryColor = getCssVar('--tg-primary', '#2563EB')
  const cardBgColor = getCssVar('--tg-bg-card', '#fff')
  if (throughputChartRef.value) {
    throughputChart = echarts.init(throughputChartRef.value, theme)
    throughputChart.setOption({
      tooltip: { trigger: 'axis', formatter: (p: any) => p[0] ? `${p[0].name}<br/>${formatBps(p[0].value)}` : '' },
      grid: { left: 50, right: 12, top: 12, bottom: 24 },
      xAxis: { type: 'category', data: [], boundaryGap: false, axisLabel: { fontSize: 11 } },
      yAxis: { type: 'value', axisLabel: { fontSize: 11, formatter: (v: number) => formatBps(v) }, splitLine: { lineStyle: { type: 'dashed' } } },
      series: [{
        type: 'line', smooth: true, symbol: 'none',
        areaStyle: { opacity: 0.12 },
        lineStyle: { width: 2, color: primaryColor },
        itemStyle: { color: primaryColor },
        data: []
      }]
    })
  }

  if (protocolChartRef.value) {
    protocolChart = echarts.init(protocolChartRef.value, theme)
    protocolChart.setOption({
      tooltip: { trigger: 'item' },
      legend: { bottom: 0, type: 'scroll', textStyle: { fontSize: 11 } },
      series: [{
        type: 'pie', radius: ['35%', '60%'],
        avoidLabelOverlap: false,
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 12, fontWeight: 'bold' } },
        labelLine: { show: false },
        data: [],
        itemStyle: { borderColor: cardBgColor, borderWidth: 2 }
      }]
    })
  }
}

function updateCharts() {
  if (throughputChart) {
    throughputChart.setOption({
      xAxis: { data: throughputHistory.value.map(p => p.time) },
      series: [{ data: throughputHistory.value.map(p => p.value) }]
    })
  }
}

async function loadDashboardData() {
  try {
    const [statusRes, statsRes] = await Promise.all([
      systemApi.getStatus(),
      systemApi.getStats()
    ])

    if (statusRes.data) {
      const d = statusRes.data as any
      stats.activeTasks = d.active_tasks ?? 0
      resources.cpu = Math.round(Number(d.cpu_usage) || 0)
      resources.memoryMb = Number(d.memory_mb) || 0
      resources.memoryTotalMb = Number(d.memory_total_mb) || 0
      resources.uptime = Number(d.uptime) || 0
      if (d.buffer_status?.combined) {
        resources.bufferBytes = d.buffer_status.combined.bytes || 0
        resources.bufferMaxBytes = d.buffer_status.combined.max_bytes || 1
      }
    }

    if (statsRes.data) {
      const d = statsRes.data as any
      stats.packetsSent = d.packets_sent ?? 0
      stats.throughputBps = d.current_bps ?? 0
      stats.currentPps = d.current_pps ?? 0

      recordThroughput(d.current_bps || 0)
      updateCharts()

      if (protocolChart) {
        if (d.protocols && Object.keys(d.protocols).length > 0) {
          protocolDataEmpty.value = false
          const pieData = Object.entries(d.protocols).map(([name, value]) => ({
            name: name.toUpperCase(),
            value
          }))
          protocolChart.setOption({ series: [{ data: pieData }] })
        } else {
          protocolDataEmpty.value = true
          protocolChart.setOption({ series: [{ data: [] }] })
        }
      }
    }

    // Success — reset error flag so next failure can show again
    dashboardErrorShown = false
  } catch (error) {
    console.error('Failed to load dashboard data:', error)
    if (!dashboardErrorShown) {
      ElMessage.error(t('dashboard.loadFailed'))
      dashboardErrorShown = true
    }
  }
}

async function loadTasks() {
  if (tasksLoading.value) return
  tasksLoading.value = true
  try {
    const res = await taskApi.list()
    if (res.data) {
      const data = res.data as any
      allTasks.value = Array.isArray(data) ? data : (data.items || [])
    }
    // Success — reset error flag so next failure can show again
    tasksErrorShown = false
  } catch (error) {
    console.error('Failed to load tasks:', error)
    if (!tasksErrorShown) {
      ElMessage.error(t('task.loadFailed'))
      tasksErrorShown = true
    }
  } finally {
    tasksLoading.value = false
  }
}

async function loadStrategies() {
  try {
    const res = await strategyApi.list()
    if (res.data) {
      const data = res.data as any
      const strategies = Array.isArray(data) ? data : (data.items || [])
      strategyMap.value = new Map(strategies.map((s: any) => [s.id, s.protocol]))
    }
  } catch (error) {
    console.error('Failed to load strategies:', error)
  }
}

async function handleStartTask(task: Task) {
  try {
    await taskApi.start(task.id)
    ElMessage.success(t('task.startSuccess'))
    loadTasks()
  } catch (error) {
    console.error('Failed to start task:', error)
    ElMessage.error(t('task.startFailed'))
  }
}

async function handleStopTask(task: Task) {
  try {
    await ElMessageBox.confirm(t('task.stopConfirm'), t('task.stop'), { type: 'warning' })
    await taskApi.stop(task.id)
    ElMessage.success(t('task.stopSuccess'))
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to stop task:', error)
    }
  }
}

function handleResize() {
  throughputChart?.resize()
  protocolChart?.resize()
}

function scheduleRefresh() {
  refreshTimer = window.setTimeout(async () => {
    await Promise.all([loadDashboardData(), loadTasks()])
    scheduleRefresh()
  }, 10000)
}

async function handleRefresh() {
  refreshing.value = true
  try {
    await Promise.all([loadDashboardData(), loadTasks()])
  } finally {
    refreshing.value = false
  }
}

function stopPolling() {
  if (refreshTimer) {
    clearTimeout(refreshTimer)
    refreshTimer = null
  }
}

onMounted(async () => {
  await nextTick()
  initCharts()
  await Promise.all([loadStrategies(), loadDashboardData(), loadTasks()])
  initialLoading.value = false
  scheduleRefresh()
  window.addEventListener('resize', handleResize)

  // Pause polling when tab is hidden, resume when visible
  visibilityHandler = () => {
    if (document.hidden) {
      stopPolling()
    } else {
      // Immediately poll and resume interval
      handleRefresh()
      scheduleRefresh()
    }
  }
  document.addEventListener('visibilitychange', visibilityHandler)
})

onUnmounted(() => {
  stopPolling()
  if (visibilityHandler) {
    document.removeEventListener('visibilitychange', visibilityHandler)
  }
  throughputChart?.dispose()
  protocolChart?.dispose()
  window.removeEventListener('resize', handleResize)
})

// Re-init charts when dark mode toggles
watch(isDark, () => {
  // Dispose existing charts and re-create with new theme
  throughputChart?.dispose()
  throughputChart = null
  protocolChart?.dispose()
  protocolChart = null
  nextTick(() => {
    initCharts()
    updateCharts()
    // Re-render protocol data if available
    if (protocolChart && !protocolDataEmpty.value) {
      // Protocol data will be refreshed on next poll cycle
    }
  })
})
</script>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 12px;
  height: 100%;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}

.dashboard-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--tg-text-primary, #0F172A);
  margin: 0;
}

.section-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--tg-text-body, #334155);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}

.uptime-badge {
  font-size: 12px;
  font-weight: 400;
  color: var(--tg-text-secondary, #64748B);
  background: var(--tg-bg-hover, #F1F5F9);
  padding: 2px 8px;
  border-radius: 4px;
}

/* Section 1: Stats Cards */
.stats-row {
  flex-shrink: 0;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  background: var(--tg-bg-card, #FFFFFF);
  border-radius: var(--tg-radius-card, 12px);
  box-shadow: var(--tg-shadow-sm, 0 1px 2px 0 rgba(0, 0, 0, 0.05));
  cursor: default;
  transition: box-shadow 0.2s;
}

.stat-card:hover {
  box-shadow: var(--tg-shadow-md, 0 2px 8px rgba(0, 0, 0, 0.08));
}

.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 10px;
  flex-shrink: 0;
}

.stat-icon--primary { background: var(--tg-primary-light, rgba(37, 99, 235, 0.1)); color: var(--tg-primary, #2563EB); }
.stat-icon--success { background: var(--tg-success-light, rgba(16, 185, 129, 0.1)); color: var(--tg-success, #10B981); }
.stat-icon--warning { background: var(--tg-warning-light, rgba(245, 158, 11, 0.1)); color: var(--tg-warning, #F59E0B); }
.stat-icon--info { background: var(--tg-info-light, rgba(59, 130, 246, 0.1)); color: var(--tg-info, #3B82F6); }

.stat-body {
  flex: 1;
  min-width: 0;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--tg-text-primary, #0F172A);
  line-height: 1.2;
}

.stat-label {
  font-size: 12px;
  color: var(--tg-text-secondary, #64748B);
  margin-top: 2px;
}

/* Section 2: Resources */
.resources-row {
  flex-shrink: 0;
}

.resource-card {
  height: 100%;
}

.resource-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.resource-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
}

.resource-name {
  font-size: 13px;
  color: var(--tg-text-body, #334155);
}

.resource-value {
  font-size: 13px;
  font-weight: 600;
  color: var(--tg-text-primary, #0F172A);
}

.chart-card {
  height: 100%;
}

.chart-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--tg-text-body, #334155);
}

.chart-container-sm {
  height: 160px;
}

.chart-with-overlay {
  position: relative;
}

.chart-canvas {
  height: 100%;
}

.chart-empty-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--tg-bg-card, #FFFFFF);
  z-index: 1;
}

/* Section 3: Tasks */
.task-card {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.task-card :deep(.el-card__body) {
  flex: 1;
  padding: 0;
  overflow: hidden;
}

.task-link {
  color: var(--tg-primary, #2563EB);
  text-decoration: none;
  font-weight: 500;
}

.task-link:hover {
  text-decoration: underline;
}

.text-muted {
  color: var(--tg-text-disabled, #94A3B8);
}

@media (max-width: 768px) {
  .stat-card {
    padding: 10px 12px;
  }
  .stat-value {
    font-size: 16px;
  }
  .chart-container-sm {
    height: 120px;
  }
}
</style>
