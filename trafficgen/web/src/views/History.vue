<template>
  <div class="history">
    <el-card>
      <template #header>
        <span>{{ t('history.title') }}</span>
      </template>

      <el-form :inline="true" class="search-form">
        <el-form-item :label="t('history.timeRange')">
          <el-date-picker
            v-model="dateRange"
            type="datetimerange"
            range-separator="-"
            :start-placeholder="t('history.startTime')"
            :end-placeholder="t('history.endTime')"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="loadHistory">{{ t('common.search') }}</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="histories" v-loading="loading" stripe>
        <el-table-column prop="task_id" :label="t('task.taskName')" width="180" />
        <el-table-column prop="name" :label="t('history.taskName')" min-width="150" />
        <el-table-column prop="protocol" :label="t('task.protocol')" width="100">
          <template #default="{ row }">
            <el-tag>{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('task.status')" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'completed' ? 'success' : 'danger'">
              {{ row.status === 'completed' ? t('task.completed') : t('task.failed') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="packets_sent" :label="t('history.packets')" width="120">
          <template #default="{ row }">
            {{ formatNumber(row.packets_sent) }}
          </template>
        </el-table-column>
        <el-table-column prop="bytes_sent" :label="t('history.bytes')" width="120">
          <template #default="{ row }">
            {{ formatBytes(row.bytes_sent) }}
          </template>
        </el-table-column>
        <el-table-column prop="duration" :label="t('history.duration')" width="100">
          <template #default="{ row }">
            {{ row.duration }}s
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('task.createdAt')" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        layout="total, prev, pager, next"
        style="margin-top: 20px; justify-content: flex-end;"
        @current-change="loadHistory"
      />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import dayjs from 'dayjs'

const { t } = useI18n()

const loading = ref(false)
const histories = ref<any[]>([])
const dateRange = ref<[Date, Date] | null>(null)

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

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return bytes + ' B'
}

function formatDate(timestamp: number): string {
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

async function loadHistory() {
  loading.value = true
  try {
    // TODO: Implement history API
    histories.value = []
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
.search-form {
  margin-bottom: 20px;
}
</style>
