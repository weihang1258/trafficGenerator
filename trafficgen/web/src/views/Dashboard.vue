<template>
  <div class="dashboard">
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon running">
            <el-icon :size="32"><VideoPlay /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ status.active_tasks }}</div>
            <div class="stat-label">{{ t('dashboard.activeTasks') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon packets">
            <el-icon :size="32"><Promotion /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatNumber(stats.packets_sent || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.packetsSent') }}</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
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
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon speed">
            <el-icon :size="32"><Odometer /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatBps(stats.current_bps || 0) }}</div>
            <div class="stat-label">{{ t('dashboard.throughput') }}</div>
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
          <el-descriptions :column="4" border>
            <el-descriptions-item :label="t('dashboard.systemOverview')">
              <el-tag :type="status.running ? 'success' : 'danger'">
                {{ status.running ? t('task.running') : t('task.stopped') }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="CPU">{{ status.cpu_usage?.toFixed(1) }}%</el-descriptions-item>
            <el-descriptions-item label="Memory">{{ status.memory_mb?.toFixed(0) }} MB</el-descriptions-item>
            <el-descriptions-item :label="t('task.duration')">{{ formatUptime(status.uptime) }}</el-descriptions-item>
          </el-descriptions>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import * as echarts from 'echarts'
import { systemApi, type SystemStatus } from '@/api'

const { t } = useI18n()

const chartRef = ref<HTMLElement>()
const pieChartRef = ref<HTMLElement>()
let lineChart: echarts.ECharts | null = null
let pieChart: echarts.ECharts | null = null
let refreshTimer: number | null = null

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
  current_bps: 0
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

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}${t('unit.hours')}${minutes}${t('unit.minutes')}`
}

async function refreshStatus() {
  try {
    const res = await systemApi.getStatus()
    if (res.data) {
      status.value = res.data
    }
  } catch (error) {
    console.error('Failed to refresh status:', error)
  }
}

function initCharts() {
  if (chartRef.value) {
    lineChart = echarts.init(chartRef.value)
    lineChart.setOption({
      tooltip: { trigger: 'axis' },
      xAxis: {
        type: 'category',
        data: Array.from({ length: 30 }, (_, i) => `${30 - i}${t('unit.seconds')}`)
      },
      yAxis: { type: 'value', name: 'Mbps' },
      series: [{
        name: t('dashboard.throughput'),
        type: 'line',
        smooth: true,
        areaStyle: { opacity: 0.3 },
        data: Array.from({ length: 30 }, () => Math.random() * 100)
      }]
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
        data: [
          { value: 40, name: t('protocol.tcp') },
          { value: 30, name: t('protocol.udp') },
          { value: 20, name: t('protocol.http') },
          { value: 10, name: t('protocol.dns') }
        ]
      }]
    })
  }
}

onMounted(() => {
  refreshStatus()
  initCharts()
  refreshTimer = window.setInterval(refreshStatus, 5000)
})

onUnmounted(() => {
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

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
