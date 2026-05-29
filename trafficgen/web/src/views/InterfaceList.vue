<template>
  <div class="interface-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('interface.title') }}</span>
          <div class="header-actions">
            <el-button @click="proTableRef?.openColumnSettings()" circle size="small">
              <el-icon><Setting /></el-icon>
            </el-button>
            <el-button @click="loadInterfaces" circle size="small">
              <el-icon><Refresh /></el-icon>
            </el-button>
            <el-button type="primary" @click="discoverInterfaces">
              <el-icon><Refresh /></el-icon>
              {{ t('interface.discover') }}
            </el-button>
          </div>
        </div>
      </template>

      <!-- Filter bar -->
      <div class="filter-bar">
        <el-input
          v-model="searchQuery"
          :placeholder="t('interface.interfaceName')"
          clearable
          style="width: 240px"
          @keyup.enter="handleSearch"
          @clear="handleSearch"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-select v-model="filterStatus" :placeholder="t('interface.status')" clearable style="width: 140px" @change="handleSearch">
          <el-option :label="t('interface.up')" value="up" />
          <el-option :label="t('interface.down')" value="down" />
        </el-select>
        <el-button link type="primary" @click="handleReset">{{ t('common.reset') }}</el-button>
      </div>

      <!-- Active filter tags -->
      <div v-if="searchQuery || filterStatus" class="active-filters">
        <el-tag v-if="searchQuery" closable @close="searchQuery = ''; handleSearch()">
          {{ searchQuery }}
        </el-tag>
        <el-tag v-if="filterStatus" closable @close="filterStatus = ''; handleSearch()">
          {{ filterStatus === 'up' ? t('interface.up') : t('interface.down') }}
        </el-tag>
        <el-button link type="primary" size="small" @click="handleReset">{{ t('common.reset') }}</el-button>
      </div>

      <ProTable
        ref="proTableRef"
        table-id="interface-list"
        :columns="columns"
        :data="filteredInterfaces"
        :loading="loading"
        :empty-text="t('interface.noInterfaces')"
      >
        <template #name="{ row }">
          <span class="interface-name">{{ row.name }}</span>
        </template>
        <template #is_up="{ row }">
          <el-tag :type="row.is_up ? 'success' : 'danger'" size="small">
            {{ row.is_up ? t('interface.up') : t('interface.down') }}
          </el-tag>
        </template>
        <template #link_up="{ row }">
          <el-tag :type="row.link_up ? 'success' : 'warning'" size="small">
            {{ row.link_up ? t('interface.linkUp') : t('interface.linkDown') }}
          </el-tag>
        </template>
        <template #in_use="{ row }">
          <el-tag v-if="row.in_use" type="warning" size="small">
            {{ t('interface.inUse') }}
          </el-tag>
          <el-tag v-else type="info" size="small">
            {{ t('interface.idle') }}
          </el-tag>
        </template>
        <template #traffic="{ row }">
          <span v-if="row.stats" class="traffic-compact">
            <span class="traffic-tx">↑{{ formatBytes(row.stats.tx_bytes || 0) }}</span>
            <span class="traffic-rx">↓{{ formatBytes(row.stats.rx_bytes || 0) }}</span>
          </span>
          <span v-else>-</span>
        </template>
        <template #empty>
          <el-empty :description="t('interface.noInterfaces')">
            <el-button type="primary" @click="discoverInterfaces">
              {{ t('interface.discover') }}
            </el-button>
          </el-empty>
        </template>
      </ProTable>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh, Setting, Search } from '@element-plus/icons-vue'
import { interfaceApi, type NetworkInterface } from '@/api'
import ProTable from '@/components/ProTable/index.vue'

const { t } = useI18n()

const loading = ref(false)
const interfaces = ref<NetworkInterface[]>([])
const proTableRef = ref()
let refreshTimer: number | null = null
const searchQuery = ref('')
const filterStatus = ref('')

const filteredInterfaces = computed(() => {
  let result = interfaces.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(item =>
      item.name?.toLowerCase().includes(q) ||
      item.ip?.toLowerCase().includes(q) ||
      item.mac?.toLowerCase().includes(q)
    )
  }
  if (filterStatus.value) {
    result = result.filter(item =>
      filterStatus.value === 'up' ? item.is_up : !item.is_up
    )
  }
  return result
})

const columns = computed(() => [
  { prop: 'name', label: t('interface.interfaceName'), width: 150, required: true },
  { prop: 'mac', label: t('interface.macAddress'), width: 180 },
  { prop: 'ip', label: t('interface.ipAddress'), width: 150 },
  { prop: 'mtu', label: t('interface.mtu'), width: 80, align: 'center' as const },
  { prop: 'is_up', label: t('interface.adminStatus'), width: 90, align: 'center' as const },
  { prop: 'link_up', label: t('interface.linkStatus'), width: 90, align: 'center' as const },
  { prop: 'in_use', label: t('interface.usageStatus'), width: 110, align: 'center' as const },
  { prop: 'traffic', label: t('interface.traffic'), width: 150 },
  { prop: 'description', label: t('common.description'), minWidth: 150 }
])

function handleSearch() {
  // filteredInterfaces is reactive via computed
}

function handleReset() {
  searchQuery.value = ''
  filterStatus.value = ''
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return bytes + ' B'
}

function formatRate(bps: number): string {
  if (bps >= 1000000000) return (bps / 1000000000).toFixed(1) + ' Gbps'
  if (bps >= 1000000) return (bps / 1000000).toFixed(1) + ' Mbps'
  if (bps >= 1000) return (bps / 1000).toFixed(1) + ' Kbps'
  return bps + ' bps'
}

async function loadInterfaces() {
  loading.value = true
  try {
    const res = await interfaceApi.list()
    if (res.data) {
      interfaces.value = res.data
    }
  } catch (error) {
    console.error('Failed to load interfaces:', error)
  } finally {
    loading.value = false
  }
}

async function discoverInterfaces() {
  try {
    await interfaceApi.discover()
    ElMessage.success(t('interface.refreshSuccess'))
    loadInterfaces()
  } catch (error) {
    console.error('Failed to discover interfaces:', error)
    ElMessage.error(t('interface.refreshFailed'))
  }
}

onMounted(() => {
  loadInterfaces()
  refreshTimer = window.setInterval(loadInterfaces, 10000)
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

.header-actions {
  display: flex;
  gap: 8px;
}

.interface-name {
  font-weight: 500;
}

.traffic-compact {
  display: inline-flex;
  gap: 8px;
  font-size: 13px;
  white-space: nowrap;
}

.traffic-tx {
  color: var(--tg-primary, #409eff);
}

.traffic-rx {
  color: var(--tg-success, #67c23a);
}
</style>