<template>
  <div class="interface-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>网卡管理</span>
          <el-button type="primary" @click="discoverInterfaces">
            <el-icon><Refresh /></el-icon>
            刷新
          </el-button>
        </div>
      </template>

      <el-table :data="interfaces" v-loading="loading" stripe>
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="mac" label="MAC地址" width="180" />
        <el-table-column prop="ip" label="IP地址" width="150" />
        <el-table-column prop="mtu" label="MTU" width="100" />
        <el-table-column prop="is_up" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.is_up ? 'success' : 'danger'">
              {{ row.is_up ? 'UP' : 'DOWN' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="link_up" label="Link状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.link_up ? 'success' : 'warning'">
              {{ row.link_up ? 'LINK' : 'NO LINK' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="200" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { interfaceApi, type NetworkInterface } from '@/api'

const loading = ref(false)
const interfaces = ref<NetworkInterface[]>([])

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
    ElMessage.success('网卡发现完成')
    loadInterfaces()
  } catch (error) {
    console.error('Failed to discover interfaces:', error)
  }
}

onMounted(() => {
  loadInterfaces()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
