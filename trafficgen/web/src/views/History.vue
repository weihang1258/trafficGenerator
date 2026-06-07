<template>
  <div class="history">
    <el-card>
      <template #header>
        <ProCardHeader :title="t('history.title')">
          <el-button aria-label="Column settings" @click="proTableRef?.openColumnSettings()" circle size="small">
            <el-icon><Setting /></el-icon>
          </el-button>
          <el-button aria-label="Refresh" @click="refresh" circle size="small">
            <el-icon><Refresh /></el-icon>
          </el-button>
          <el-button @click="exportHistoryCSV" :disabled="historyRecords.length === 0">
            <el-icon><Download /></el-icon>
            {{ t('history.export') }}
          </el-button>
        </ProCardHeader>
      </template>

      <!-- Quick time filters + date range picker -->
      <ProFilterBar
        :filters="filters"
        :field-defs="filterFieldDefs"
        @reset="resetFilters"
      >
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
        <el-select v-model="statusFilter" :placeholder="t('task.status')" clearable style="width: 130px; margin-left: 12px;" @change="refresh">
          <el-option :label="t('task.completed')" value="completed" />
          <el-option :label="t('task.failed')" value="failed" />
          <el-option :label="t('task.stopped')" value="stopped" />
          <el-option :label="t('task.error')" value="error" />
        </el-select>
        <el-button type="primary" size="small" @click="refresh" style="margin-left: 12px;">
          {{ t('common.search') }}
        </el-button>
      </ProFilterBar>

      <ProTable
        ref="proTableRef"
        table-id="history-list"
        :columns="columns"
        :data="historyRecords"
        :loading="loading"
        :default-sort="{ prop: 'completed_at', order: 'descending' }"
        :pagination="{ total: pagination.total }"
        :empty-text="t('history.noRecords')"
        @sort-change="handleSortChange"
        @page-change="handlePageChange"
      >
        <template #protocol="{ row }">
          <el-tag size="small">{{ (row.protocol || 'N/A').toUpperCase() }}</el-tag>
        </template>
        <template #status="{ row }">
          <el-tag :type="TASK_STATUS_TYPE[row.status] || 'info'" size="small">{{ getStatusText(row.status) }}</el-tag>
        </template>
        <template #progress="{ row }">
          <el-progress :percentage="row.progress" :status="getProgressStatus(row.status)" :stroke-width="6" />
        </template>
        <template #duration="{ row }">
          {{ formatTaskDuration(row.started_at, row.completed_at) }}
        </template>
        <template #stats.packets_sent="{ row }">
          {{ formatNumber(row.stats?.packets_sent || 0) }}
        </template>
        <template #stats.bytes_sent="{ row }">
          {{ formatBytes(row.stats?.bytes_sent || 0) }}
        </template>
        <template #created_at="{ row }">
          {{ formatTimestamp(row.created_at) }}
        </template>
        <template #completed_at="{ row }">
          {{ formatTimestamp(row.completed_at) }}
        </template>
        <template #empty>
          <el-empty :description="t('history.noRecords')" />
        </template>
      </ProTable>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Refresh, Download, Setting } from '@element-plus/icons-vue'
import { historyApi } from '@/api'
import ProTable from '@/components/ProTable/index.vue'
import dayjs from 'dayjs'
import { useServerList } from '@/composables/useServerList'
import { TASK_STATUS_TYPE, getProgressStatus } from '@/constants/status'
import { formatBytes, formatNumber, formatTaskDuration, formatTimestamp } from '@/utils/format'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import ProFilterBar from '@/components/ProFilterBar/index.vue'

const { t } = useI18n()

const proTableRef = ref()
const dateRange = ref<[string, string] | null>(null)
const quickRange = ref<'today' | 'yesterday' | '7d' | '30d' | 'custom' | ''>('7d')
const statusFilter = ref('')

const filters = computed(() => ({
  quickRange: quickRange.value,
  status: statusFilter.value
}))

const filterFieldDefs = [
  { key: 'quickRange', label: t('history.range'), emptyValue: '' },
  { key: 'status', label: t('task.status'), emptyValue: '' }
]

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    completed: t('task.completed'),
    failed: t('task.failed'),
    error: t('task.error'),
    stopped: t('task.stopped')
  }
  return map[status] || status
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

function getRangeLabel(range: string): string {
  const labels: Record<string, string> = {
    today: t('history.today'),
    yesterday: t('history.yesterday'),
    '7d': t('history.last7Days'),
    '30d': t('history.last30Days'),
    custom: t('history.custom')
  }
  return labels[range] || range
}

function setQuickRange(range: 'today' | 'yesterday' | '7d' | '30d' | 'custom') {
  quickRange.value = range
  if (range !== 'custom') {
    dateRange.value = null
    refresh()
  }
}

function escapeCsv(value: string | number): string {
  const str = String(value)
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"'
  }
  return str
}

function exportHistoryCSV() {
  if (historyRecords.value.length === 0) return
  const header = [
    t('history.taskName'),
    t('history.protocol'),
    t('history.status'),
    t('history.startTime'),
    t('history.endTime'),
    t('history.duration'),
    t('history.packets'),
    t('history.bytes')
  ].map(escapeCsv).join(',')
  const rows = historyRecords.value.map(r => [
    escapeCsv(r.name || r.id || ''),
    escapeCsv(r.protocol || ''),
    escapeCsv(r.status || ''),
    escapeCsv(r.started_at ? dayjs(r.started_at * 1000).format('YYYY-MM-DD HH:mm:ss') : ''),
    escapeCsv(r.completed_at ? dayjs(r.completed_at * 1000).format('YYYY-MM-DD HH:mm:ss') : ''),
    escapeCsv(formatTaskDuration(r.started_at, r.completed_at)),
    escapeCsv(r.stats?.packets_sent || 0),
    escapeCsv(r.stats?.bytes_sent || 0)
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

function resetFilters() {
  quickRange.value = '7d'
  dateRange.value = null
  statusFilter.value = ''
  refresh()
}

const columns = computed(() => [
  { prop: 'name', label: t('task.taskName'), minWidth: 150, required: true, sortable: 'custom' },
  { prop: 'protocol', label: t('task.protocol'), width: 100, sortable: 'custom' },
  { prop: 'status', label: t('task.status'), width: 120, sortable: 'custom' },
  { prop: 'progress', label: t('task.progress'), width: 120, sortable: 'custom' },
  { prop: 'duration', label: t('task.duration'), width: 120, sortable: 'custom' },
  { prop: 'stats.packets_sent', label: t('task.packets'), width: 120, sortable: 'custom' },
  { prop: 'stats.bytes_sent', label: t('task.bytes'), width: 120, sortable: 'custom' },
  { prop: 'created_at', label: t('task.createdAt'), width: 180, sortable: 'custom' },
  { prop: 'completed_at', label: t('task.completedAt'), width: 180, sortable: 'custom' }
])

const { loading, data: historyRecords, pagination, sortState, refresh, handleSortChange, handlePageChange } = useServerList({
  fetchFn: async (params) => {
    const extra: Record<string, any> = {}
    if (quickRange.value && quickRange.value !== 'custom') {
      const { start, end } = getQuickRangeTimestamps(quickRange.value)
      extra.start_time = start
      extra.end_time = end
    } else if (dateRange.value) {
      extra.start_time = Number(dateRange.value[0])
      extra.end_time = Number(dateRange.value[1])
    }
    if (statusFilter.value) {
      extra.status = statusFilter.value
    }
    const res = await historyApi.list({ ...params, ...extra })
    const data = res.data as any
    return { items: data.items || [], total: data.total || 0 }
  },
  defaultPageSize: 20,
  defaultSort: { prop: 'completed_at', order: 'descending' }
})

onMounted(() => {
  refresh()
})
</script>

<style scoped>
.history {
  padding: 20px;
}
</style>
