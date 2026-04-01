<template>
  <div class="task-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>任务列表</span>
          <el-button type="primary" @click="$router.push('/tasks/create')">
            <el-icon><Plus /></el-icon>
            创建任务
          </el-button>
        </div>
      </template>

      <!-- Search and Filter -->
      <el-form :inline="true" class="search-form">
        <el-form-item label="状态">
          <el-select v-model="filters.status" placeholder="全部状态" clearable @change="loadTasks">
            <el-option label="运行中" value="running" />
            <el-option label="已完成" value="completed" />
            <el-option label="失败" value="failed" />
            <el-option label="已暂停" value="paused" />
          </el-select>
        </el-form-item>
        <el-form-item label="协议">
          <el-select v-model="filters.protocol" placeholder="全部协议" clearable @change="loadTasks">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
            <el-option label="HTTP" value="http" />
            <el-option label="DNS" value="dns" />
            <el-option label="ICMP" value="icmp" />
          </el-select>
        </el-form-item>
      </el-form>

      <!-- Task Table -->
      <el-table :data="tasks" v-loading="loading" stripe>
        <el-table-column prop="id" label="任务ID" width="180" />
        <el-table-column prop="name" label="任务名称" min-width="150" />
        <el-table-column prop="protocol" label="协议" width="100">
          <template #default="{ row }">
            <el-tag :type="getProtocolTagType(row.protocol)">{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)">{{ getStatusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" :status="getProgressStatus(row.status)" />
          </template>
        </el-table-column>
        <el-table-column prop="stats.packets_sent" label="已发送" width="120">
          <template #default="{ row }">
            {{ formatNumber(row.stats?.packets_sent || 0) }}
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button size="small" @click="$router.push(`/tasks/${row.id}`)">
                查看
              </el-button>
              <el-button
                size="small"
                type="success"
                :disabled="row.status !== 'created' && row.status !== 'paused'"
                @click="startTask(row.id)"
              >
                启动
              </el-button>
              <el-button
                size="small"
                type="warning"
                :disabled="row.status !== 'running'"
                @click="stopTask(row.id)"
              >
                停止
              </el-button>
              <el-button
                size="small"
                type="danger"
                @click="deleteTask(row.id)"
              >
                删除
              </el-button>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>

      <!-- Pagination -->
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        style="margin-top: 20px; justify-content: flex-end;"
        @size-change="loadTasks"
        @current-change="loadTasks"
      />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { taskApi, type Task } from '@/api'
import dayjs from 'dayjs'

const loading = ref(false)
const tasks = ref<Task[]>([])

const filters = reactive({
  status: '',
  protocol: ''
})

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

function formatDate(timestamp: number): string {
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

function getStatusText(status: string): string {
  const map: Record<string, string> = {
    created: '已创建',
    running: '运行中',
    paused: '已暂停',
    completed: '已完成',
    failed: '失败'
  }
  return map[status] || status
}

function getStatusTagType(status: string): string {
  const map: Record<string, string> = {
    created: 'info',
    running: 'success',
    paused: 'warning',
    completed: '',
    failed: 'danger'
  }
  return map[status] || 'info'
}

function getProtocolTagType(protocol: string): string {
  const map: Record<string, string> = {
    tcp: 'primary',
    udp: 'success',
    http: 'warning',
    dns: 'info',
    icmp: 'danger'
  }
  return map[protocol] || ''
}

function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'exception'
  if (status === 'paused') return 'warning'
  return ''
}

async function loadTasks() {
  loading.value = true
  try {
    const res = await taskApi.list({
      page: pagination.page,
      size: pagination.size,
      status: filters.status,
      protocol: filters.protocol
    })
    if (res.data) {
      tasks.value = res.data.tasks
      pagination.total = res.data.total
    }
  } catch (error) {
    console.error('Failed to load tasks:', error)
  } finally {
    loading.value = false
  }
}

async function startTask(id: string) {
  try {
    await taskApi.start(id)
    ElMessage.success('任务已启动')
    loadTasks()
  } catch (error) {
    console.error('Failed to start task:', error)
  }
}

async function stopTask(id: string) {
  try {
    await taskApi.stop(id)
    ElMessage.success('任务已停止')
    loadTasks()
  } catch (error) {
    console.error('Failed to stop task:', error)
  }
}

async function deleteTask(id: string) {
  try {
    await ElMessageBox.confirm('确定要删除此任务吗？', '确认删除', {
      type: 'warning'
    })
    await taskApi.delete(id)
    ElMessage.success('任务已删除')
    loadTasks()
  } catch (error) {
    // Cancelled or error
  }
}

onMounted(() => {
  loadTasks()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-form {
  margin-bottom: 20px;
}
</style>
