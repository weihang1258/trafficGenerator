<template>
  <div class="port-management">
    <el-card>
      <ProCardHeader :title="t('ports.title')">
        <el-button
          circle
          size="small"
          :aria-label="t('common.refresh')"
          @click="loadData"
        >
          <el-icon><RefreshRight /></el-icon>
        </el-button>
      </ProCardHeader>

      <el-tabs v-model="activeTab">
        <!-- Ports Tab -->
        <el-tab-pane :label="t('ports.portsTab')" name="ports">
          <ProTable
            table-id="port-list"
            :columns="portColumns"
            :data="ports"
            :loading="loading"
            :default-sort="sortState"
            :empty-text="t('ports.noPorts')"
            @sort-change="handleSortChange"
          >
            <template #name="{ row }">
              <div class="port-name-cell">
                <el-icon class="port-icon"><Connection /></el-icon>
                <span class="port-name">{{ row.name }}</span>
              </div>
            </template>
            <template #type="{ row }">
              <el-tag size="small" :type="row.type === 'dpdk' ? 'warning' : 'info'" effect="plain">
                {{ row.type?.toUpperCase() || 'N/A' }}
              </el-tag>
            </template>
            <template #status="{ row }">
              <el-tag
                size="small"
                :type="portStatusType(row.status)"
                :effect="row.status === 'idle' ? 'plain' : 'light'"
              >
                {{ portStatusText(row.status) }}
              </el-tag>
            </template>
            <template #current_task_id="{ row }">
              <router-link
                v-if="row.current_task_id"
                :to="`/tasks/${row.current_task_id}`"
                class="task-link"
              >
                {{ row.current_task_id.substring(0, 8) }}...
              </router-link>
              <span v-else class="text-muted">-</span>
            </template>
            <template #empty>
              <el-empty :description="t('ports.noPortsHint')">
                <el-button type="primary" @click="$router.push('/interfaces')">
                  {{ t('ports.goToInterfaceManagement') }}
                </el-button>
              </el-empty>
            </template>
          </ProTable>
        </el-tab-pane>

        <!-- Port Groups Tab -->
        <el-tab-pane :label="t('ports.portGroupsTab')" name="groups">
          <div class="group-header">
            <el-button
              type="primary"
              size="small"
              :icon="Plus"
              @click="openCreateDialog"
            >
              {{ t('ports.createGroup') }}
            </el-button>
          </div>

          <ProTable
            table-id="port-group-list"
            :columns="groupColumns"
            :data="portGroups"
            :loading="groupsLoading"
            :default-sort="{ prop: 'created_at', order: 'descending' }"
            :empty-text="t('ports.noPortGroups')"
          >
            <template #ports_config="{ row }">
              <div class="member-ports">
                <el-tag
                  v-for="(pc, idx) in row.ports_config"
                  :key="idx"
                  size="small"
                  effect="plain"
                  class="member-tag"
                >
                  {{ pc.interface }}<span v-if="pc.weight > 0" class="weight-label">:{{ pc.weight }}</span>
                </el-tag>
              </div>
            </template>
            <template #ports_count="{ row }">
              <el-tag size="small" effect="plain">{{ row.ports_config?.length || 0 }}</el-tag>
            </template>
            <template #created_at="{ row }">
              {{ formatTimestamp(row.created_at) }}
            </template>
            <template #actions="{ row }">
              <el-button
                type="danger"
                link
                size="small"
                @click="handleDeleteGroup(row)"
              >
                {{ t('common.delete') }}
              </el-button>
            </template>
            <template #empty>
              <el-empty :description="t('ports.noPortGroups')">
                <el-button type="primary" @click="openCreateDialog">
                  {{ t('ports.createGroup') }}
                </el-button>
              </el-empty>
            </template>
          </ProTable>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- Create Port Group Dialog -->
    <el-dialog
      v-model="createDialogVisible"
      :title="t('ports.createGroup')"
      width="600px"
      :close-on-click-modal="false"
      destroy-on-close
    >
      <el-alert
        v-if="ports.length === 0"
        :title="t('ports.noPortsAvailable')"
        type="warning"
        show-icon
        :closable="false"
        style="margin-bottom: 16px;"
      />
      <el-table
        v-else
        :data="ports"
        size="small"
        max-height="400"
        @selection-change="handlePortSelection"
      >
        <el-table-column type="selection" width="45" />
        <el-table-column prop="name" :label="t('ports.name')" min-width="150" />
        <el-table-column prop="type" :label="t('ports.type')" width="100">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.type?.toUpperCase() || 'N/A' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('ports.status')" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="portStatusType(row.status)">
              {{ portStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('ports.portWeight')" width="120">
          <template #default="{ row }">
            <el-input-number
              v-model="portWeights[row.name]"
              :min="0"
              :max="100"
              size="small"
              controls-position="right"
              style="width: 100px;"
            />
          </template>
        </el-table-column>
      </el-table>

      <template #footer>
        <el-button @click="createDialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button
          type="primary"
          :loading="createLoading"
          :disabled="selectedPorts.length === 0"
          @click="handleCreateGroup"
        >
          {{ t('common.create') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshRight, Plus, Connection } from '@element-plus/icons-vue'
import { portApi, portGroupApi, type Port, type PortGroup } from '@/api'
import ProTable from '@/components/ProTable/index.vue'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import { formatTimestamp } from '@/utils/format'
import { createClientSort } from '@/utils/sort'
import { useClientList } from '@/composables/useClientList'

const { t } = useI18n()

const activeTab = ref('ports')
const portGroups = ref<PortGroup[]>([])
const groupsLoading = ref(false)

const { loading, data: ports, sortState, refresh, handleSortChange } = useClientList<Port>({
  fetchFn: async () => {
    const res = await portApi.list()
    return Array.isArray(res.data) ? res.data : (res.data as any).items || []
  },
  clientSort: (items, sort) => {
    if (!sort.prop || !sort.order) return items
    return [...items].sort(createClientSort(sort.prop as keyof Port, sort.order))
  },
  defaultSort: { prop: 'port_number', order: 'ascending' }
})

// Create dialog state
const createDialogVisible = ref(false)
const createLoading = ref(false)
const selectedPorts = ref<Port[]>([])
const portWeights = reactive<Record<string, number>>({})

const portColumns = computed(() => [
  { prop: 'name', label: t('ports.name'), minWidth: 160, fixed: 'left' as const, required: true, sortable: 'custom' },
  { prop: 'type', label: t('ports.type'), width: 100, sortable: 'custom' },
  { prop: 'pci_address', label: t('ports.pciAddress'), width: 160 },
  { prop: 'status', label: t('ports.status'), width: 100, align: 'center' as const, sortable: 'custom' },
  { prop: 'current_task_id', label: t('ports.currentTask'), width: 140 }
])

const groupColumns = computed(() => [
  { prop: 'name', label: t('common.name'), minWidth: 180, required: true, sortable: 'custom' },
  { prop: 'ports_count', label: t('ports.portsCount'), width: 90, align: 'center' as const },
  { prop: 'ports_config', label: t('ports.memberPorts'), minWidth: 250 },
  { prop: 'created_at', label: t('common.createdAt'), width: 170, sortable: 'custom' },
  { prop: 'actions', label: t('common.action'), width: 80, fixed: 'right' as const, required: true }
])

function portStatusType(status: string): 'success' | 'warning' | 'info' {
  if (status === 'idle') return 'success'
  if (status === 'using') return 'warning'
  return 'info'
}

function portStatusText(status: string): string {
  if (status === 'idle') return t('ports.idle')
  if (status === 'using') return t('ports.using')
  if (status === 'maintenance') return t('ports.maintenance')
  return status || '-'
}

async function loadPortGroups() {
  groupsLoading.value = true
  try {
    const res = await portGroupApi.list()
    if (res.data) {
      portGroups.value = (Array.isArray(res.data) ? res.data : []) as PortGroup[]
    }
  } catch (error) {
    console.error('Failed to load port groups:', error)
    ElMessage.error(t('ports.loadFailed'))
  } finally {
    groupsLoading.value = false
  }
}

function loadData() {
  refresh()
  loadPortGroups()
}

// Create dialog
function openCreateDialog() {
  selectedPorts.value = []
  // Reset weights
  for (const key of Object.keys(portWeights)) {
    delete portWeights[key]
  }
  // Initialize weights for all ports
  for (const p of ports.value) {
    portWeights[p.name] = 1
  }
  createDialogVisible.value = true
}

function handlePortSelection(selection: Port[]) {
  selectedPorts.value = selection
}

async function handleCreateGroup() {
  if (selectedPorts.value.length === 0) return
  createLoading.value = true
  try {
    const portsConfig = selectedPorts.value.map(p => ({
      interface: p.name,
      weight: portWeights[p.name] || 1
    }))
    const res = await portGroupApi.create({ ports: portsConfig })
    if (res.data) {
      ElMessage.success(t('ports.createSuccess'))
      createDialogVisible.value = false
      loadPortGroups()
    }
  } catch (error: any) {
    const msg = error?.response?.data?.message || t('ports.createFailed')
    ElMessage.error(msg)
  } finally {
    createLoading.value = false
  }
}

async function handleDeleteGroup(group: PortGroup) {
  try {
    await ElMessageBox.confirm(
      t('ports.confirmDeleteGroup'),
      t('common.delete'),
      { type: 'warning' }
    )
    await portGroupApi.delete(group.id)
    ElMessage.success(t('ports.deleteSuccess'))
    loadPortGroups()
  } catch (error: any) {
    if (error === 'cancel') return
    const msg = error?.response?.data?.message || t('ports.deleteFailed')
    if (msg.includes('used by') || msg.includes('任务')) {
      ElMessage.error(t('ports.groupInUse'))
    } else {
      ElMessage.error(msg)
    }
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.group-header {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 12px;
}

.port-name-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.port-icon {
  color: var(--tg-success, #67c23a);
  font-size: 16px;
}

.port-name {
  font-weight: 500;
}

.member-ports {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.member-tag {
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 12px;
}

.weight-label {
  color: var(--tg-text-secondary, #909399);
  font-size: 11px;
}

.task-link {
  color: var(--tg-primary, #409eff);
  text-decoration: none;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 12px;
}

.task-link:hover {
  text-decoration: underline;
}

.text-muted {
  color: var(--tg-text-secondary, #c0c4cc);
}
</style>
