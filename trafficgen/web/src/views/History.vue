<template>
  <div class="history">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('history.title') }}</span>
          <div class="header-actions">
            <el-button @click="loadHistory">
              <el-icon><Refresh /></el-icon>
              {{ t('common.refresh') }}
            </el-button>
            <el-button @click="exportHistoryCSV" :disabled="records.length === 0">
              <el-icon><Download /></el-icon>
              {{ t('history.export') }}
            </el-button>
          </div>
        </div>
      </template>

      <!-- Quick time filters + date range picker -->
      <div class="filter-bar">
        <el-button-group size="small">
          <el-button :type="quickRange === 'today' ? 'primary' : ''" @click="setQuickRange('today')">
            {{ t('history.today') }}
          </el-button>
          <el-button :type="quickRange === 'yesterday' ? 'primary' : ''" @click="setQuickRange('yesterday')">
            {{ t('history.yesterday') }}
          </el-button>
          <el-button :type="quickRange === '7d' ? 'primary' : ''" @click="setQuickRange('7d')">
            {{ t('history.last7Days') }}
          </el-button>
          <el-button :type="quickRange === '30d' ? 'primary' : ''" @click="setQuickRange('30d')">
            {{ t('history.last30Days') }}
          </el-button>
          <el-button :type="quickRange === 'custom' ? 'primary' : ''" @click="setQuickRange('custom')">
            {{ t('history.custom') }}
          </el-button>
        </el-button-group>
        <el-date-picker
          v-if="quickRange === 'custom'"
          v-model="dateRange"
          type="datetimerange"
          :range-separator="t('history.to')"
          :start-placeholder="t('history.startTime')"
          :end-placeholder="t('history.endTime')"
          value-format="X"
          style="margin-left: 12px;"
        />
        <el-button type="primary" size="small" @click="loadHistory" style="margin-left: 12px;">
          {{ t('common.search') }}
        </el-button>
      </div>

      <el-table :data="records" v-loading="loading" stripe>
        <el-table-column prop="name" :label="t('task.taskName')" min-width="150" />
        <el-table-column prop="protocol" :label="t('task.protocol')" width="100">
          <template #default="{ row }">
            <el-tag>{{ row.protocol?.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('task.status')" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">{{ getStatusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" :label="t('task.progress')" width="120">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" :status="getProgressStatus(row.status)" />
          </template>
        </el-table-column>
        <el-table-column prop="duration" :label="t('task.duration')" width="120">
          <template #default="{ row }">
            {{ formatDuration(row.started_at, row.completed_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="stats.packets_sent" :label="t('task.packets')" width="120">
          <template #default="{ row }">
            {{ formatNumber(row.stats?.packets_sent || 0) }}
          </template>
        </el-table-column>
        <el-table-column prop="stats.bytes_sent" :label="t('task.bytes')" width="120">
          <template #default="{ row }">
            {{ formatBytes(row.stats?.bytes_sent || 0) }}
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('task.createdAt')" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="completed_at" :label="t('task.completedAt')" width="180">
          <template #default="{ row }">
            {{ formatDate(row.completed_at) }}
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="records.length === 0 && !loading" :description="t('history.noRecords')" />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Refresh, Download } from '@element-plus/icons-vue'
import { historyApi } from '@/api'
import dayjs from 'dayjs'

const { t } = useI18n()

const loading = ref(false)
const records = ref<any[]>([])
const dateRange = ref<[string, string] | null>(null)
const quickRange = ref<'today' | 'yesterday' | '7d' | '30d' | 'custom' | ''>('7d')

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

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(2) + 'K'
  return num.toString()
}

function formatDuration(start?: number, end?: number): string {
  if (!start || !end) return '-'
  const seconds = Math.floor(end - start)
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`
  } else {
    return `${secs}s`
  }
}

function formatDate(timestamp?: number): string {
  if (!timestamp) return '-'
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

function getStatusType(status: string): string {
  const map: Record<string, string> = {
    completed: '',
    failed: 'danger',
    error: 'danger',
    stopped: 'warning'
  }
  return map[status] || 'info'
}

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    completed: t('task.completed'),
    failed: t('task.failed'),
    error: t('task.failed'),
    stopped: t('task.stopped')
  }
  return map[status] || status
}

function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'failed' || status === 'error') return 'exception'
  if (status === 'stopped') return 'warning'
  return ''
}

function getQuickRangeTimestamps(range: string): { start: number; end: number } {
  const now = dayjs()
  switch (range) {
    case 'today':
      return { start: now.startOf('day').unix(), end: now.unix() }
    case 'yesterday':
      return { start: now.subtract(1, 'day').startOf('day').unix(), end: now.subtract(1, 'day').endOf('day').unix() }
    case '7d':
      return { start: now.subtract(7, 'day').unix(), end: now.unix() }
    case '30d':
      return { start: now.subtract(30, 'day').unix(), end: now.unix() }
    default:
      return { start: 0, end: 0 }
  }
}

function setQuickRange(range: 'today' | 'yesterday' | '7d' | '30d' | 'custom') {
  quickRange.value = range
  if (range !== 'custom') {
    dateRange.value = null
    loadHistory()
  }
}

function exportHistoryCSV() {
  if (records.value.length === 0) return
  const header = [
    t('history.taskName'),
    t('history.protocol'),
    t('history.status'),
    t('history.startTime'),
    t('history.endTime'),
    t('history.duration'),
    t('history.packets'),
    t('history.bytes')
  ].join(',')
  const rows = records.value.map(r => [
    `"${r.name || r.id || ''}"`,
    r.protocol || '',
    r.status || '',
    r.started_at ? dayjs(r.started_at * 1000).format('YYYY-MM-DD HH:mm:ss') : '',
    r.completed_at ? dayjs(r.completed_at * 1000).format('YYYY-MM-DD HH:mm:ss') : '',
    formatDuration(r.started_at, r.completed_at),
    r.stats?.packets_sent || 0,
    r.stats?.bytes_sent || 0
  ].join(','))
  const csv = '﻿' + header + '\n' + rows.join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `history_${dayjs().format('YYYYMMDD_HHmmss')}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

async function loadHistory() {
  loading.value = true
  try {
    const params: any = {}
    if (quickRange.value && quickRange.value !== 'custom') {
      const { start, end } = getQuickRangeTimestamps(quickRange.value)
      params.start_time = start
      params.end_time = end
    } else if (dateRange.value) {
      params.start_time = Number(dateRange.value[0])
      params.end_time = Number(dateRange.value[1])
    }
    const res = await historyApi.list(params)
    if (res.data) {
      records.value = res.data as any[]
    }
  } catch (error) {
    console.error('Failed to load history:', error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadHistory()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
}
</style>
