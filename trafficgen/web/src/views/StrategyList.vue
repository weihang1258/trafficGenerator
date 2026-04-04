<template>
  <div class="strategy-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('strategy.title') }}</span>
          <el-button type="primary" @click="showCreateDialog">
            <el-icon><Plus /></el-icon>
            {{ t('strategy.createStrategy') }}
          </el-button>
        </div>
      </template>

      <el-table :data="strategies" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="180" />
        <el-table-column prop="name" :label="t('common.name')" min-width="150" />
        <el-table-column prop="protocol" :label="t('task.protocol')" width="100">
          <template #default="{ row }">
            <el-tag>{{ row.protocol.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="flow_control" label="Flow Control" width="150">
          <template #default="{ row }">
            <span v-if="row.flow_control">
              {{ row.flow_control.type }}: {{ row.flow_control.value }}
            </span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('task.createdAt')" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="150" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="editStrategy(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="danger" @click="deleteStrategy(row.id)">{{ t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        layout="total, prev, pager, next"
        style="margin-top: 20px; justify-content: flex-end;"
        @current-change="loadStrategies"
      />
    </el-card>

    <!-- Create/Edit Dialog -->
    <el-dialog v-model="dialogVisible" :title="isEdit ? t('common.edit') : t('strategy.createStrategy')" width="500px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
        <el-form-item :label="t('common.name')" prop="name">
          <el-input v-model="form.name" :placeholder="t('strategy.strategyNamePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('task.protocol')" prop="protocol">
          <el-select v-model="form.protocol" :placeholder="t('taskCreate.selectProtocol')">
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
            <el-option label="HTTP" value="http" />
            <el-option label="DNS" value="dns" />
          </el-select>
        </el-form-item>
        <el-form-item label="Flow Control Type" prop="flow_control.type">
          <el-select v-model="form.flow_control.type" placeholder="Select flow control type">
            <el-option label="Flows (number of flows)" value="flows" />
            <el-option label="CPS (connections per second)" value="cps" />
            <el-option label="BPS (bytes per second)" value="bps" />
            <el-option label="Ratio (percentage)" value="ratio" />
            <el-option label="Time (duration)" value="time" />
          </el-select>
        </el-form-item>
        <el-form-item label="Flow Control Value" prop="flow_control.value">
          <el-input-number v-model="form.flow_control.value" :min="1" :step="1" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { strategyApi, type Strategy } from '@/api'
import dayjs from 'dayjs'

const { t } = useI18n()

const loading = ref(false)
const strategies = ref<Strategy[]>([])
const dialogVisible = ref(false)
const isEdit = ref(false)
const formRef = ref<FormInstance>()

const pagination = reactive({
  page: 1,
  size: 20,
  total: 0
})

const form = reactive({
  id: '',
  name: '',
  protocol: 'tcp',
  config: {} as Record<string, any>,
  flow_control: {
    type: 'flows',
    value: 1
  }
})

const rules: FormRules = {
  name: [{ required: true, message: t('strategy.strategyNamePlaceholder'), trigger: 'blur' }],
  protocol: [{ required: true, message: t('taskCreate.validation.protocolRequired'), trigger: 'change' }]
}

function formatDate(timestamp: number): string {
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

async function loadStrategies() {
  loading.value = true
  try {
    const data = await strategyApi.list()
    if (data) {
      strategies.value = data
      pagination.total = data.length
    }
  } catch (error) {
    console.error('Failed to load strategies:', error)
  } finally {
    loading.value = false
  }
}

function showCreateDialog() {
  isEdit.value = false
  form.id = ''
  form.name = ''
  form.protocol = 'tcp'
  dialogVisible.value = true
}

function editStrategy(strategy: Strategy) {
  isEdit.value = true
  form.id = strategy.id
  form.name = strategy.name
  form.protocol = strategy.protocol
  dialogVisible.value = true
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    if (isEdit.value) {
      await strategyApi.update(form.id, {
        name: form.name,
        protocol: form.protocol,
        config: form.config,
        flow_control: form.flow_control
      })
      ElMessage.success(t('strategy.updateSuccess'))
    } else {
      await strategyApi.create({
        name: form.name,
        protocol: form.protocol,
        config: form.config,
        flow_control: form.flow_control
      })
      ElMessage.success(t('strategy.createSuccess'))
    }
    dialogVisible.value = false
    loadStrategies()
  } catch (error) {
    console.error('Failed to save strategy:', error)
  }
}

async function deleteStrategy(id: string) {
  try {
    await ElMessageBox.confirm(t('strategy.confirmDelete'), t('common.confirm'), { type: 'warning' })
    await strategyApi.delete(id)
    ElMessage.success(t('strategy.deleteSuccess'))
    loadStrategies()
  } catch (error) {
    // Cancelled
  }
}

onMounted(() => {
  loadStrategies()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
