<template>
  <div class="interface-list">
    <el-card>
      <template #header>
        <ProCardHeader :title="t('interface.title')">
          <el-button
            @click="proTableRef?.openColumnSettings()"
            circle
            size="small"
            :title="t('common.detail')"
            :aria-label="t('common.detail')"
          >
            <el-icon><Setting /></el-icon>
          </el-button>
          <el-button
            @click="refresh"
            circle
            size="small"
            :title="t('interface.refresh')"
            :aria-label="t('interface.refresh')"
          >
            <el-icon><RefreshRight /></el-icon>
          </el-button>
          <el-button
            type="primary"
            @click="discoverInterfaces"
            :loading="scanning"
            :disabled="scanning"
          >
            <el-icon v-if="!scanning"><Refresh /></el-icon>
            {{ scanning ? t('interface.scanning') : t('interface.scan') }}
          </el-button>
        </ProCardHeader>
      </template>

      <ProFilterBar>
        <el-input
          v-model="searchQuery"
          :placeholder="t('interface.searchPlaceholder')"
          clearable
          style="width: 240px"
          @clear="searchQuery = ''"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-select
          v-model="filterAdminStatus"
          :placeholder="t('interface.filterByStatus')"
          clearable
          style="width: 130px"
        >
          <el-option :label="t('interface.allStatus')" value="" />
          <el-option :label="t('interface.up')" value="up" />
          <el-option :label="t('interface.down')" value="down" />
        </el-select>
        <el-select
          v-model="filterLinkStatus"
          :placeholder="t('interface.filterByLink')"
          clearable
          style="width: 130px"
        >
          <el-option :label="t('interface.allStatus')" value="" />
          <el-option :label="t('interface.linked')" value="up" />
          <el-option :label="t('interface.unlinked')" value="down" />
        </el-select>
        <el-select
          v-model="filterUsage"
          :placeholder="t('interface.filterByUsage')"
          clearable
          style="width: 120px"
        >
          <el-option :label="t('interface.allStatus')" value="" />
          <el-option :label="t('interface.inUse')" value="in_use" />
          <el-option :label="t('interface.idle')" value="idle" />
        </el-select>
        <el-button link type="primary" @click="handleReset">{{ t('common.reset') }}</el-button>
        <template #append>
          <el-switch
            v-model="showVirtual"
            :active-text="t('interface.showVirtual')"
            :inactive-text="t('interface.hideVirtual')"
            inline-prompt
            style="--el-switch-on-color: var(--tg-text-secondary, #909399)"
          />
        </template>
      </ProFilterBar>

      <!-- Active filter tags -->
      <div v-if="searchQuery || filterAdminStatus || filterLinkStatus || filterUsage" class="active-filters">
        <el-tag v-if="searchQuery" closable @close="searchQuery = ''">
          {{ searchQuery }}
        </el-tag>
        <el-tag v-if="filterAdminStatus" closable @close="filterAdminStatus = ''">
          {{ filterAdminStatus === 'up' ? t('interface.up') : t('interface.down') }}
        </el-tag>
        <el-tag v-if="filterLinkStatus" closable @close="filterLinkStatus = ''">
          {{ filterLinkStatus === 'up' ? t('interface.linked') : t('interface.unlinked') }}
        </el-tag>
        <el-tag v-if="filterUsage" closable @close="filterUsage = ''">
          {{ filterUsage === 'in_use' ? t('interface.inUse') : t('interface.idle') }}
        </el-tag>
      </div>

      <ProTable
        ref="proTableRef"
        table-id="interface-list"
        :columns="columns"
        :data="filteredInterfaces"
        :loading="loading"
        :default-sort="{ prop: 'is_up', order: 'descending' }"
        :empty-text="t('interface.noInterfaces')"
        :row-class-name="rowClassName"
        @sort-change="handleSortChange"
      >
        <template #name="{ row }">
          <div class="interface-name-cell">
            <el-icon v-if="row.is_virtual" class="virtual-icon" :title="t('interface.virtual')">
              <Monitor />
            </el-icon>
            <el-icon v-else class="physical-icon" :title="t('interface.physical')">
              <Connection />
            </el-icon>
            <span class="interface-name">{{ row.name }}</span>
          </div>
        </template>
        <template #ips="{ row }">
          <div v-if="row.ips && row.ips.length > 0" class="ip-cell">
            <span class="ip-primary">{{ row.ips[0] }}</span>
            <el-tag v-if="row.ips.length > 1" size="small" type="info" class="ip-count">
              +{{ row.ips.length - 1 }}
            </el-tag>
          </div>
          <span v-else class="text-muted">-</span>
        </template>
        <template #mtu="{ row }">
          <span>{{ row.mtu > 0 ? row.mtu : '-' }}</span>
        </template>
        <template #is_up="{ row }">
          <el-tag :type="row.is_up ? 'success' : 'danger'" size="small" :effect="row.is_up ? 'light' : 'plain'">
            {{ row.is_up ? t('interface.up') : t('interface.down') }}
          </el-tag>
        </template>
        <template #link_up="{ row }">
          <el-tag :type="row.link_up ? 'success' : 'info'" size="small" :effect="row.link_up ? 'light' : 'plain'">
            {{ row.link_up ? t('interface.linkUp') : t('interface.linkDown') }}
          </el-tag>
        </template>
        <template #in_use="{ row }">
          <el-tag v-if="row.in_use" type="warning" size="small" effect="light">
            {{ t('interface.inUse') }}
          </el-tag>
          <el-tag v-else type="success" size="small" effect="plain">
            {{ t('interface.idle') }}
          </el-tag>
        </template>
        <template #actions="{ row }">
          <el-button size="small" link type="primary" @click="showDetail(row)">
            {{ t('common.detail') }}
          </el-button>
        </template>
        <template #empty>
          <el-empty :description="t('interface.noInterfaces')">
            <el-button type="primary" @click="discoverInterfaces" :loading="scanning">
              {{ t('interface.scan') }}
            </el-button>
          </el-empty>
        </template>
      </ProTable>
    </el-card>

    <!-- Interface Detail Drawer -->
    <ProDrawer
      :visible="detailVisible"
      :title="detailInterface?.name || ''"
      size="420px"
      @update:visible="closeDetail"
    >
      <template v-if="detailInterface">
        <el-descriptions :column="1" border>
          <el-descriptions-item :label="t('interface.interfaceName')">
            <div class="detail-name">
              <el-icon v-if="detailInterface.is_virtual" class="virtual-icon">
                <Monitor />
              </el-icon>
              <el-icon v-else class="physical-icon">
                <Connection />
              </el-icon>
              <span>{{ detailInterface.name }}</span>
              <el-tag size="small" :type="detailInterface.is_virtual ? 'info' : 'success'" effect="plain">
                {{ detailInterface.is_virtual ? t('interface.virtual') : t('interface.physical') }}
              </el-tag>
            </div>
          </el-descriptions-item>
          <el-descriptions-item
            v-if="detailInterface.description"
            :label="t('interface.description')"
          >
            {{ detailInterface.description }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.macAddress')">
            {{ detailInterface.mac || '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.allIPs')">
            <div v-if="detailInterface.ips && detailInterface.ips.length > 0" class="ip-list">
              <el-tag
                v-for="(ip, idx) in detailInterface.ips"
                :key="idx"
                size="small"
                :type="ip.includes(':') ? 'info' : ''"
                class="ip-tag"
              >
                {{ ip }}
              </el-tag>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.mtu')">
            {{ detailInterface.mtu > 0 ? detailInterface.mtu : '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.adminStatus')">
            <el-tag :type="detailInterface.is_up ? 'success' : 'danger'" size="small">
              {{ detailInterface.is_up ? t('interface.up') : t('interface.down') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.linkStatus')">
            <el-tag :type="detailInterface.link_up ? 'success' : 'info'" size="small">
              {{ detailInterface.link_up ? t('interface.linkUp') : t('interface.linkDown') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="t('interface.usageStatus')">
            <div v-if="detailInterface.in_use">
              <el-tag type="warning" size="small">{{ t('interface.inUse') }}</el-tag>
              <div v-if="detailInterface.allocations && detailInterface.allocations.length" class="allocation-list">
                <div v-for="(alloc, idx) in detailInterface.allocations" :key="idx" class="allocation-item">
                  <span class="allocation-label">{{ t('interface.taskUsing') }}:</span>
                  <code class="allocation-task">{{ alloc.task_id }}</code>
                </div>
              </div>
            </div>
            <el-tag v-else type="success" size="small">{{ t('interface.idle') }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </ProDrawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Refresh, RefreshRight, Setting, Search, Connection, Monitor } from '@element-plus/icons-vue'
import { interfaceApi, type NetworkInterface } from '@/api'
import ProTable from '@/components/ProTable/index.vue'
import { useClientList } from '@/composables/useClientList'
import { formatTimestamp } from '@/utils/format'
import { createClientSort } from '@/utils/sort'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import ProFilterBar from '@/components/ProFilterBar/index.vue'
import ProDrawer from '@/components/ProDrawer/index.vue'

const { t } = useI18n()

const scanning = ref(false)
const proTableRef = ref()
let refreshTimer: number | null = null
let visibilityHandler: (() => void) | null = null

const searchQuery = ref('')
const filterAdminStatus = ref('')
const filterLinkStatus = ref('')
const filterUsage = ref('')
const showVirtual = ref(false)

const detailVisible = ref(false)
const detailInterface = ref<NetworkInterface | null>(null)

const { loading, data: interfaces, sortState, refresh, handleSortChange } = useClientList({
  fetchFn: async () => {
    const res = await interfaceApi.list()
    return Array.isArray(res.data) ? res.data : (res.data as any).items || []
  },
  clientSort: (items, sort) => {
    if (!sort.prop || !sort.order) return items
    return [...items].sort(createClientSort(sort.prop as keyof NetworkInterface, sort.order))
  },
  defaultSort: { prop: 'name', order: 'ascending' }
})

const filteredInterfaces = computed(() => {
  let result = interfaces.value

  // Filter virtual interfaces
  if (!showVirtual.value) {
    result = result.filter(item => !item.is_virtual)
  }

  // Search filter
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(item =>
      item.name?.toLowerCase().includes(q) ||
      item.ips?.some(ip => ip.toLowerCase().includes(q)) ||
      item.mac?.toLowerCase().includes(q)
    )
  }

  // Admin status filter
  if (filterAdminStatus.value) {
    result = result.filter(item =>
      filterAdminStatus.value === 'up' ? item.is_up : !item.is_up
    )
  }

  // Link status filter
  if (filterLinkStatus.value) {
    result = result.filter(item =>
      filterLinkStatus.value === 'up' ? item.link_up : !item.link_up
    )
  }

  // Usage filter
  if (filterUsage.value) {
    result = result.filter(item =>
      filterUsage.value === 'in_use' ? item.in_use : !item.in_use
    )
  }

  return result
})

const columns = computed(() => [
  { prop: 'name', label: t('interface.interfaceName'), minWidth: 160, fixed: 'left', required: true, sortable: 'custom' },
  { prop: 'mac', label: t('interface.macAddress'), width: 180, sortable: 'custom' },
  { prop: 'ips', label: t('interface.ipAddress'), minWidth: 200, sortable: false },
  { prop: 'mtu', label: t('interface.mtu'), width: 80, align: 'center' as const, sortable: 'custom' },
  { prop: 'is_up', label: t('interface.adminStatus'), width: 90, align: 'center' as const, sortable: 'custom' },
  { prop: 'link_up', label: t('interface.linkStatus'), width: 90, align: 'center' as const, sortable: 'custom' },
  { prop: 'in_use', label: t('interface.usageStatus'), width: 100, align: 'center' as const, sortable: 'custom' },
  { prop: 'actions', label: t('common.action'), width: 80, fixed: 'right', required: true }
])

function rowClassName({ row }: { row: NetworkInterface }): string {
  if (row.is_virtual) return 'row-virtual'
  if (row.in_use) return 'row-in-use'
  if (row.is_up && row.link_up && !row.in_use) return 'row-available'
  return ''
}

function showDetail(row: NetworkInterface) {
  detailInterface.value = row
  detailVisible.value = true
}

function closeDetail() {
  detailVisible.value = false
}

function handleReset() {
  searchQuery.value = ''
  filterAdminStatus.value = ''
  filterLinkStatus.value = ''
  filterUsage.value = ''
}

async function discoverInterfaces() {
  scanning.value = true
  try {
    const res = await interfaceApi.discover()
    const count = (res.data as any)?.count ?? 0
    ElMessage.success(t('interface.scanSuccess').replace('{count}', String(count)))
    await refresh()
  } catch (error) {
    console.error('Failed to discover interfaces:', error)
    ElMessage.error(t('interface.refreshFailed'))
  } finally {
    scanning.value = false
  }
}

function startPolling() {
  stopPolling()
  refreshTimer = window.setInterval(refresh, 30000)
}

function stopPolling() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

onMounted(() => {
  refresh()
  startPolling()

  // Pause polling when tab is hidden, resume when visible
  visibilityHandler = () => {
    if (document.hidden) {
      stopPolling()
    } else {
      refresh()
      startPolling()
    }
  }
  document.addEventListener('visibilitychange', visibilityHandler)
})

onUnmounted(() => {
  stopPolling()
  if (visibilityHandler) {
    document.removeEventListener('visibilitychange', visibilityHandler)
  }
})
</script>

<style scoped>
.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.active-filters {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.interface-name-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.interface-name {
  font-weight: 500;
}

.physical-icon {
  color: var(--tg-success, #67c23a);
  font-size: 16px;
}

.virtual-icon {
  color: var(--tg-text-secondary, #909399);
  font-size: 16px;
}

.ip-cell {
  display: flex;
  align-items: center;
  gap: 4px;
}

.ip-primary {
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 13px;
}

.ip-count {
  font-size: 11px;
  cursor: default;
}

.text-muted {
  color: var(--tg-text-disabled, #c0c4cc);
}

/* Detail drawer styles */
.detail-name {
  display: flex;
  align-items: center;
  gap: 8px;
}

.ip-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.ip-tag {
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 12px;
}

.allocation-list {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.allocation-item {
  font-size: 12px;
  color: var(--tg-text-body, #606266);
}

.allocation-label {
  margin-right: 4px;
}

.allocation-task {
  background: var(--tg-bg-hover, #f5f7fa);
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 11px;
}

/* Row highlighting */
:deep(.row-available) {
  background-color: var(--tg-success-light, rgba(16, 185, 129, 0.1)) !important;
}

:deep(.row-in-use) {
  background-color: var(--tg-warning-light, rgba(245, 158, 11, 0.1)) !important;
}

:deep(.row-virtual) {
  opacity: 0.7;
}
</style>
