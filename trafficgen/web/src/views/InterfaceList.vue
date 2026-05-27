<template>
  <div class="interface-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('interface.title') }}</span>
          <div class="header-actions">
            <el-button @click="loadInterfaces">
              <el-icon><Refresh /></el-icon>
              {{ t('common.refresh') }}
            </el-button>
            <el-button type="primary" @click="discoverInterfaces">
              <el-icon><Refresh /></el-icon>
              {{ t('interface.discover') }}
            </el-button>
          </div>
        </div>
      </template>

      <el-empty v-if="interfaces.length === 0 && !loading" :description="t('interface.noInterfaces')" />

      <el-table v-else :data="interfaces" v-loading="loading" stripe>
        <el-table-column prop="name" :label="t('interface.interfaceName')" width="150" />
        <el-table-column prop="mac" :label="t('interface.macAddress')" width="180" />
        <el-table-column prop="ip" :label="t('interface.ipAddress')" width="150" />
        <el-table-column prop="mtu" :label="t('interface.mtu')" width="80" align="center" />
        <el-table-column prop="is_up" :label="t('interface.adminStatus')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.is_up ? 'success' : 'danger'" size="small">
              {{ row.is_up ? t('interface.up') : t('interface.down') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="link_up" :label="t('interface.linkStatus')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.link_up ? 'success' : 'warning'" size="small">
              {{ row.link_up ? t('interface.linkUp') : t('interface.linkDown') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('interface.usageStatus')" width="110" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.in_use" type="warning" size="small">
              {{ t('interface.inUse') }}
            </el-tag>
            <el-tag v-else type="info" size="small">
              {{ t('interface.idle') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('interface.traffic')" width="180">
          <template #default="{ row }">
            <div v-if="row.stats" class="traffic-stats">
              <span class="traffic-item">
                <span class="traffic-dir">TX</span>
                {{ formatBytes(row.stats.tx_bytes || 0) }}
                ({{ formatRate(row.stats.tx_rate || 0) }})
              </span>
              <span class="traffic-item">
                <span class="traffic-dir">RX</span>
                {{ formatBytes(row.stats.rx_bytes || 0) }}
                ({{ formatRate(row.stats.rx_rate || 0) }})
              </span>
            </div>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="description" :label="t('common.description')" min-width="150" show-overflow-tooltip />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { interfaceApi, type NetworkInterface } from '@/api'

const { t } = useI18n()

const loading = ref(false)
const interfaces = ref<NetworkInterface[]>([])
let refreshTimer: number | null = null

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

.traffic-stats {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 13px;
  line-height: 1.5;
}

.traffic-item {
  color: #606266;
}

.traffic-dir {
  display: inline-block;
  width: 20px;
  font-weight: 600;
  font-size: 12px;
}

.traffic-item .traffic-dir:first-child {
  color: #409eff;
}

.traffic-item:last-child .traffic-dir {
  color: #67c23a;
}
</style>