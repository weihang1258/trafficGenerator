<template>
  <div class="dashboard" :class="{ 'is-fullscreen': isFullscreen }">
    <!-- Dashboard header with fullscreen toggle -->
    <div class="dashboard-header">
      <span class="dashboard-title">{{ t('dashboard.title') }}</span>
      <el-button size="small" @click="toggleFullscreen">
        <el-icon><FullScreen /></el-icon>
        {{ isFullscreen ? t('dashboard.restore') : t('dashboard.zoom') }}
      </el-button>
    </div>
    <el-row :gutter="20">
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card clickable" @click="navigateToTasks">
          <div class="stat-icon running">
            <el-icon :size="32"><VideoPlay /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ status.active_tasks }}</div>
            <div class="stat-label">{{ t('dashboard.activeTasks') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card clickable" @click="navigateToTasks">
          <div class="stat-icon packets">
            <el-icon :size="32"><Promotion /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatNumber(stats.packets_sent || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.packetsSent') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon bytes">
            <el-icon :size="32"><Coin /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatBytes(stats.bytes_sent || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.throughput') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon speed">
            <el-icon :size="32"><Odometer /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatBps(stats.current_bps || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.currentRate') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card clickable" @click="navigateToErrorTasks">
          <div class="stat-icon error">
            <el-icon :size="32"><Warning /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatPercent(stats.error_rate || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.errorRate') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card clickable" @click="navigateToLostPackets">
          <div class="stat-icon loss">
            <el-icon :size="32"><CircleClose /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatPercent(stats.packet_loss_rate || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.packetLossRate') }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col :span="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>{{ t('dashboard.throughput') }}</span>
              <div class="header-actions">
                <el-button-group size="small">
                  <el-button :type="timeRange === '1m' ? 'primary' : ''" @click="changeTimeRange('1m')">
                    {{ t('dashboard.timeRange1m') }}
                  </el-button>
                  <el-button :type="timeRange === '5m' ? 'primary' : ''" @click="changeTimeRange('5m')">
                    {{ t('dashboard.timeRange5m') }}
                  </el-button>
                  <el-button :type="timeRange === '15m' ? 'primary' : ''" @click="changeTimeRange('15m')">
                    {{ t('dashboard.timeRange15m') }}
                  </el-button>
                  <el-button :type="timeRange === '1h' ? 'primary' : ''" @click="changeTimeRange('1h')">
                    {{ t('dashboard.timeRange1h') }}
                  </el-button>
                </el-button-group>
                <el-button size="small" @click="exportChartData">
                  <el-icon><Download /></el-icon>
                  {{ t('dashboard.exportCSV') }}
                </el-button>
              </div>
            </div>
          </template>
          <div ref="chartRef" style="height: 300px;"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>{{ t('dashboard.protocolDistribution') }}</span>
            </div>
          </template>
          <div ref="pieChartRef" style="height: 300px;"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>{{ t('dashboard.systemOverview') }}</span>
              <el-button type="primary" size="small" @click="refreshStatus">
                <el-icon><Refresh /></el-icon>
                {{ t('common.refresh') }}
              </el-button>
            </div>
          </template>
          <el-row :gutter="20">
            <el-col :span="6">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">{{ t('dashboard.cpuUsage') }}</span>
                  <span class="resource-value" :class="{ 'resource-warning': status.cpu_usage > 80, 'resource-danger': status.cpu_usage > 90 }">
                    {{ status.cpu_usage?.toFixed(1) }}%
                  </span>
                </div>
                <el-progress
                  :percentage="status.cpu_usage || 0"
                  :stroke-width="12"
                  :color="getProgressColor(status.cpu_usage || 0)"
                />
              </div>
            </el-col>
            <el-col :span="6">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">{{ t('dashboard.memoryUsage') }}</span>
                  <span class="resource-value" :class="{ 'resource-warning': memoryUsagePercent > 80, 'resource-danger': memoryUsagePercent > 90 }">
                    {{ status.memory_mb?.toFixed(0) }} MB ({{ memoryUsagePercent.toFixed(1) }}%)
                  </span>
                </div>
                <el-progress
                  :percentage="memoryUsagePercent"
                  :stroke-width="12"
                  :color="getProgressColor(memoryUsagePercent)"
                />
              </div>
            </el-col>
            <el-col :span="6">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">{{ t('dashboard.bufferUsage') }}</span>
                  <span class="resource-value" :class="{ 'resource-warning': bufferUsagePercent > 80, 'resource-danger': bufferUsagePercent > 90 }">
                    {{ bufferUsagePercent.toFixed(1) }}%
                  </span>
                </div>
                <el-progress
                  :percentage="bufferUsagePercent"
                  :stroke-width="12"
                  :color="getProgressColor(bufferUsagePercent)"
                />
              </div>
            </el-col>
            <el-col :span="6">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">{{ t('task.duration') }}</span>
                  <span class="resource-value">{{ formatUptime(status.uptime) }}</span>
                </div>
                <el-descriptions :column="1" border size="small">
                  <el-descriptions-item :label="t('dashboard.systemOverview')">
                    <el-tag :type="status.running ? 'success' : 'danger'">
                      {{ status.running ? t('task.running') : t('task.stopped') }}
                    </el-tag>
                  </el-descriptions-item>
                </el-descriptions>
              </div>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>

    <!-- 告警通知区域 -->
    <el-row v-if="alerts.length > 0" :gutter="20" style="margin-top: 20px;">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>
                <el-icon style="color: #e6a23c; margin-right: 6px;"><Warning /></el-icon>
                {{ t('dashboard.alerts') }}
              </span>
              <el-button size="small" link type="primary" @click="clearAlerts">
                {{ t('dashboard.clearAlerts') }}
              </el-button>
            </div>
          </template>
          <div class="alert-list">
            <div v-for="(alert, index) in alerts" :key="index" class="alert-item" :class="`alert-${alert.level}`">
              <el-icon class="alert-icon">
                <Warning v-if="alert.level === 'warning'" />
                <CircleClose v-else />
              </el-icon>
              <span class="alert-message">{{ alert.message }}</span>
              <span class="alert-time">{{ alert.time }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { systemApi, type SystemStatus } from '@/api'
import { Warning, CircleClose, Download, FullScreen } from '@element-plus/icons-vue'

const { t, locale } = useI18n()
const router = useRouter()

const chartRef = ref<HTMLElement>()
const pieChartRef = ref<HTMLElement>()
let lineChart: echarts.ECharts | null = null
let pieChart: echarts.ECharts | null = null
let refreshTimer: number | null = null

const timeRange = ref<'1m' | '5m' | '15m' | '1h'>('1m')
const refreshInterval = computed(() => {
  switch (timeRange.value) {
    case '1m': return 5000
    case '5m': return 10000
    case '15m': return 15000
    case '1h': return 30000
    default: return 5000
  }
})

const historyLength = computed(() => {
  switch (timeRange.value) {
    case '1m': return 12  // 12 * 5秒 = 1分钟
    case '5m': return 30  // 30 * 10秒 = 5分钟
    case '15m': return 60 // 60 * 15秒 = 15分钟
    case '1h': return 120 // 120 * 30秒 = 1小时
    default: return 30
  }
})

const status = ref<SystemStatus>({
  running: false,
  cpu_usage: 0,
  memory_mb: 0,
  active_tasks: 0,
  buffer_status: {},
  uptime: 0
})

const stats = ref({
  packets_sent: 0,
  bytes_sent: 0,
  current_pps: 0,
  current_bps: 0,
  error_rate: 0,
  packet_loss_rate: 0
})

function formatNumber(num: number): string {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(2) + 'M'
  } else if (num >= 1000) {
    return (num / 1000).toFixed(2) + 'K'
  }
  return num.toString()
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
  } else if (bytes >= 1024 * 1024) {
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  } else if (bytes >= 1024) {
    return (bytes / 1024).toFixed(2) + ' KB'
  }
  return bytes + ' B'
}

function formatBps(bps: number): string {
  if (bps >= 1000000000) {
    return (bps / 1000000000).toFixed(2) + ' Gbps'
  } else if (bps >= 1000000) {
    return (bps / 1000000).toFixed(2) + ' Mbps'
  } else if (bps >= 1000) {
    return (bps / 1000).toFixed(2) + ' Kbps'
  }
  return bps.toFixed(0) + ' bps'
}

function formatPercent(value: number): string {
  return value.toFixed(2) + '%'
}

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}${t('unit.hours')}${minutes}${t('unit.minutes')}`
}

const statsHistory = ref<number[]>([])
const protocolStats = ref<{ name: string; value: number }[]>([])
const timeLabels = ref<string[]>([])

function changeTimeRange(range: '1m' | '5m' | '15m' | '1h') {
  timeRange.value = range
  statsHistory.value = Array(historyLength.value).fill(0)
  generateTimeLabels()
  initCharts()

  // 重置定时器
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = window.setInterval(refreshStatus, refreshInterval.value)
  }
}

function generateTimeLabels() {
  const labels: string[] = []
  const now = Date.now()
  const intervalMs = refreshInterval.value

  for (let i = historyLength.value - 1; i >= 0; i--) {
    const time = new Date(now - i * intervalMs)
    if (timeRange.value === '1h') {
      labels.push(time.toLocaleTimeString(locale.value, { hour: '2-digit', minute: '2-digit' }))
    } else {
      labels.push(time.toLocaleTimeString(locale.value, { minute: '2-digit', second: '2-digit' }))
    }
  }
  timeLabels.value = labels
}

function exportChartData() {
  const csvRows = [
    ['Time', 'Throughput (Mbps)'],
    ...timeLabels.value.map((time, idx) => [time, statsHistory.value[idx].toString()])
  ]

  const csvContent = csvRows.map(row => row.join(',')).join('\n')
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `dashboard-throughput-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

async function refreshStatus() {
  try {
    const [statusRes, statsRes] = await Promise.all([
      systemApi.getStatus(),
      systemApi.getStats()
    ])
    if (statusRes.data) {
      status.value = statusRes.data
    }
    if (statsRes.data) {
      const data = statsRes.data as any
      stats.value = {
        packets_sent: data.packets_sent || 0,
        bytes_sent: data.bytes_sent || 0,
        current_pps: data.current_pps || 0,
        current_bps: data.current_bps || 0,
        error_rate: data.error_rate || 0,
        packet_loss_rate: data.packet_loss_rate || 0
      }

      // 更新吞吐量历史数据
      if (statsHistory.value.length >= historyLength.value) {
        statsHistory.value.shift()
      }
      statsHistory.value.push(data.current_bps ? data.current_bps / 1000000 : 0)

      // 更新时间标签
      generateTimeLabels()

      updateLineChart()

      // 更新协议分布数据
      if (data.protocols) {
        protocolStats.value = Object.entries(data.protocols).map(([proto, count]) => ({
          name: t(`protocol.${proto}`),
          value: count as number
        }))
        updatePieChart()
      }

      // 检查告警
      checkAlerts()
    }
  } catch (error) {
    console.error('Failed to refresh status:', error)
  }
}

function initCharts() {
  if (chartRef.value) {
    lineChart = echarts.init(chartRef.value)
    lineChart.setOption({
      tooltip: {
        trigger: 'axis',
        formatter: (params: any) => {
          const data = params[0]
          return `${data.name}<br/>${data.seriesName}: ${data.value?.toFixed(2)} Mbps`
        }
      },
      toolbox: {
        feature: {
          dataZoom: {
            yAxisIndex: false,
            title: {
              zoom: t('dashboard.zoom'),
              back: t('dashboard.zoomBack')
            }
          },
          restore: {
            title: t('dashboard.restore')
          }
        }
      },
      dataZoom: [
        {
          type: 'inside',
          xAxisIndex: 0,
          filterMode: 'none'
        },
        {
          type: 'slider',
          xAxisIndex: 0,
          filterMode: 'none',
          height: 20,
          bottom: 10,
          start: 0,
          end: 100
        }
      ],
      xAxis: {
        type: 'category',
        data: timeLabels.value,
        axisLabel: {
          rotate: timeRange.value === '1h' ? 0 : 30
        }
      },
      yAxis: {
        type: 'value',
        name: 'Mbps',
        splitLine: {
          lineStyle: {
            type: 'dashed'
          }
        }
      },
      series: [{
        name: t('dashboard.throughput'),
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        itemStyle: {
          color: '#4facfe'
        },
        areaStyle: {
          opacity: 0.3,
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(79, 172, 254, 0.5)' },
            { offset: 1, color: 'rgba(79, 172, 254, 0.1)' }
          ])
        },
        data: statsHistory.value
      }],
      grid: {
        bottom: 80
      }
    })
  }

  if (pieChartRef.value) {
    pieChart = echarts.init(pieChartRef.value)
    pieChart.setOption({
      tooltip: { trigger: 'item' },
      legend: { bottom: 0 },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        data: protocolStats.value.length > 0 ? protocolStats.value : [
          { value: 0, name: t('protocol.tcp') },
          { value: 0, name: t('protocol.udp') },
          { value: 0, name: t('protocol.http') }
        ]
      }]
    })
  }
}

function updateLineChart() {
  if (lineChart) {
    lineChart.setOption({
      xAxis: { data: timeLabels.value },
      series: [{ data: statsHistory.value }]
    })
  }
}

function updatePieChart() {
  if (pieChart && protocolStats.value.length > 0) {
    pieChart.setOption({
      series: [{ data: protocolStats.value }]
    })
  }
}

function navigateToTasks() {
  router.push('/tasks')
}

function navigateToErrorTasks() {
  router.push({ path: '/tasks', query: { status: 'error' } })
}

function navigateToLostPackets() {
  router.push('/history')
}

// 告警系统
interface Alert {
  level: 'warning' | 'danger'
  message: string
  time: string
}

const alerts = ref<Alert[]>([])
const isFullscreen = ref(false)
const CPU_THRESHOLD_WARNING = 80
const CPU_THRESHOLD_DANGER = 90
const MEMORY_THRESHOLD_WARNING = 80
const MEMORY_THRESHOLD_DANGER = 90
const BUFFER_THRESHOLD_WARNING = 80
const BUFFER_THRESHOLD_DANGER = 90

const memoryUsagePercent = computed(() => {
  // 假设系统总内存约8GB，按比例计算
  const totalMemoryMB = 8192
  return Math.min(((status.value.memory_mb || 0) / totalMemoryMB) * 100, 100)
})

const bufferUsagePercent = computed(() => {
  const bufferStatus = status.value.buffer_status as any
  if (!bufferStatus) return 0
  // 计算所有缓冲区的平均使用率
  const buffers = Object.values(bufferStatus)
  if (buffers.length === 0) return 0
  const totalUsage = buffers.reduce((sum: number, buf: any) => {
    return sum + (buf.usage_percent || buf.usage || 0)
  }, 0)
  return Math.min(totalUsage / buffers.length, 100)
})

function getProgressColor(percentage: number): string {
  if (percentage > CPU_THRESHOLD_DANGER) return '#f56c6c'
  if (percentage > CPU_THRESHOLD_WARNING) return '#e6a23c'
  return '#67c23a'
}

function checkAlerts() {
  const newAlerts: Alert[] = []
  const now = new Date().toLocaleTimeString()

  // CPU告警
  if (status.value.cpu_usage > CPU_THRESHOLD_DANGER) {
    newAlerts.push({
      level: 'danger',
      message: t('dashboard.alertCpuDanger', { value: status.value.cpu_usage?.toFixed(1) }),
      time: now
    })
  } else if (status.value.cpu_usage > CPU_THRESHOLD_WARNING) {
    newAlerts.push({
      level: 'warning',
      message: t('dashboard.alertCpuWarning', { value: status.value.cpu_usage?.toFixed(1) }),
      time: now
    })
  }

  // 内存告警
  if (memoryUsagePercent.value > MEMORY_THRESHOLD_DANGER) {
    newAlerts.push({
      level: 'danger',
      message: t('dashboard.alertMemoryDanger', { value: memoryUsagePercent.value.toFixed(1) }),
      time: now
    })
  } else if (memoryUsagePercent.value > MEMORY_THRESHOLD_WARNING) {
    newAlerts.push({
      level: 'warning',
      message: t('dashboard.alertMemoryWarning', { value: memoryUsagePercent.value.toFixed(1) }),
      time: now
    })
  }

  // 缓冲区告警
  if (bufferUsagePercent.value > BUFFER_THRESHOLD_DANGER) {
    newAlerts.push({
      level: 'danger',
      message: t('dashboard.alertBufferDanger', { value: bufferUsagePercent.value.toFixed(1) }),
      time: now
    })
  } else if (bufferUsagePercent.value > BUFFER_THRESHOLD_WARNING) {
    newAlerts.push({
      level: 'warning',
      message: t('dashboard.alertBufferWarning', { value: bufferUsagePercent.value.toFixed(1) }),
      time: now
    })
  }

  // 错误率告警
  if (stats.value.error_rate > 5) {
    newAlerts.push({
      level: 'danger',
      message: t('dashboard.alertErrorRate', { value: stats.value.error_rate.toFixed(2) }),
      time: now
    })
  } else if (stats.value.error_rate > 1) {
    newAlerts.push({
      level: 'warning',
      message: t('dashboard.alertErrorRate', { value: stats.value.error_rate.toFixed(2) }),
      time: now
    })
  }

  alerts.value = newAlerts
}

function clearAlerts() {
  alerts.value = []
}

function toggleFullscreen() {
  const el = document.querySelector('.dashboard') as HTMLElement
  if (!el) return
  if (!document.fullscreenElement) {
    el.requestFullscreen().then(() => { isFullscreen.value = true })
  } else {
    document.exitFullscreen().then(() => { isFullscreen.value = false })
  }
}

function onFullscreenChange() {
  isFullscreen.value = !!document.fullscreenElement
}

function handleResize() {
  lineChart?.resize()
  pieChart?.resize()
}

onMounted(() => {
  document.addEventListener('fullscreenchange', onFullscreenChange)
  window.addEventListener('resize', handleResize)
  statsHistory.value = Array(historyLength.value).fill(0)
  generateTimeLabels()
  refreshStatus()
  initCharts()
  refreshTimer = window.setInterval(refreshStatus, refreshInterval.value)
})

onUnmounted(() => {
  document.removeEventListener('fullscreenchange', onFullscreenChange)
  window.removeEventListener('resize', handleResize)
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
  lineChart?.dispose()
  pieChart?.dispose()
})
</script>

<style scoped>
.dashboard {
  padding: 0;
}

.dashboard.is-fullscreen {
  padding: 20px;
  background: #f5f7fa;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.dashboard-title {
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}

.stat-card {
  display: flex;
  align-items: center;
  padding: 20px;
}

.stat-card :deep(.el-card__body) {
  display: flex;
  align-items: center;
  width: 100%;
  padding: 20px;
}

.stat-icon {
  width: 64px;
  height: 64px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  margin-right: 16px;
}

.stat-icon.running { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.stat-icon.packets { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
.stat-icon.bytes { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
.stat-icon.speed { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
.stat-icon.error { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
.stat-icon.loss { background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); }

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #303133;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 4px;
}

.stat-card.clickable {
  cursor: pointer;
  transition: all 0.3s ease;
}

.stat-card.clickable:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.resource-item {
  padding: 8px 0;
}

.resource-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.resource-label {
  font-size: 14px;
  color: #606266;
}

.resource-value {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
}

.resource-warning {
  color: #e6a23c;
}

.resource-danger {
  color: #f56c6c;
}

.alert-list {
  max-height: 200px;
  overflow-y: auto;
}

.alert-item {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  margin-bottom: 6px;
  border-radius: 4px;
  font-size: 14px;
}

.alert-warning {
  background: #fdf6ec;
  border-left: 3px solid #e6a23c;
}

.alert-danger {
  background: #fef0f0;
  border-left: 3px solid #f56c6c;
}

.alert-icon {
  margin-right: 8px;
  flex-shrink: 0;
}

.alert-warning .alert-icon {
  color: #e6a23c;
}

.alert-danger .alert-icon {
  color: #f56c6c;
}

.alert-message {
  flex: 1;
  color: #303133;
}

.alert-time {
  color: #909399;
  font-size: 12px;
  margin-left: 12px;
  flex-shrink: 0;
}
</style>
