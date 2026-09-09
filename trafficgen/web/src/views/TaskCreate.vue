<template>
  <div class="task-create">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('taskCreate.title') }}</span>
        </div>
      </template>

      <el-steps :active="currentStep" finish-status="success" align-center style="margin-bottom: 30px;">
        <el-step :title="t('task.step.basic')" />
        <el-step :title="t('task.step.strategy')" />
        <el-step :title="t('task.step.output')" />
        <el-step :title="t('task.step.review')" />
      </el-steps>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="120px"
        style="max-width: 800px; margin: 0 auto;"
      >
        <!-- Step 1: Basic Info -->
        <div v-show="currentStep === 0">
          <el-form-item :label="t('taskCreate.taskName')" prop="name">
            <el-input v-model="form.name" :placeholder="t('taskCreate.taskNamePlaceholder')" @input="onTaskNameChange" />
          </el-form-item>

          <!-- Quick create from template -->
          <el-form-item :label="t('strategy.selectTemplate')">
            <el-select v-model="selectedTemplateId" :placeholder="t('strategy.selectTemplate')" clearable style="width: 100%;" @change="handleTemplateSelect">
              <el-option-group :label="t('strategy.builtinTemplates')">
                <el-option v-for="tp in builtinTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()}) - ${tp.description}`" :value="tp.id" />
              </el-option-group>
              <el-option-group v-if="customTemplates.length > 0" :label="t('strategy.customTemplates')">
                <el-option v-for="tp in customTemplates" :key="tp.id" :label="`${tp.name} (${tp.protocol.toUpperCase()}) - ${tp.description}`" :value="tp.id" />
              </el-option-group>
            </el-select>
          </el-form-item>

          <!-- Template preview -->
          <el-descriptions v-if="templatePreview" :column="1" border size="small" style="margin-top: 8px;">
            <el-descriptions-item :label="t('task.protocol')">{{ templatePreview.protocol.toUpperCase() }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.srcIP')">{{ templatePreview.config?.src_ip || '-' }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.dstIP')">{{ templatePreview.config?.dst_ip || '-' }}</el-descriptions-item>
            <el-descriptions-item :label="t('strategy.dstPort')">{{ templatePreview.config?.dst_port || '-' }}</el-descriptions-item>
            <el-descriptions-item v-if="templatePreview.flow_control" :label="t('strategy.flowControl')">
              {{ templatePreview.flow_control.type }}: {{ templatePreview.flow_control.value }}
            </el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- Step 2: Select Strategies -->
        <div v-show="currentStep === 1">
          <el-form-item :label="t('taskCreate.selectStrategy')" prop="strategy_ids">
            <el-select
              v-model="form.strategy_ids"
              multiple
              :placeholder="t('taskCreate.selectStrategy')"
              style="width: 100%;"
              v-loading="strategyLoading"
            >
              <template v-for="group in strategyGroups" :key="group.label">
                <el-option-group :label="group.label">
                  <el-option
                    v-for="s in group.items"
                    :key="s.id"
                    :label="`${s.name} (${s.protocol.toUpperCase()})`"
                    :value="s.id"
                  />
                </el-option-group>
              </template>
            </el-select>
          </el-form-item>

          <el-empty v-if="strategies.length === 0 && !strategyLoading" :description="t('strategy.noStrategies')">
            <el-button type="primary" @click="$router.push('/strategies')">
              {{ t('strategy.createStrategy') }}
            </el-button>
          </el-empty>

          <!-- Show selected strategies detail -->
          <div v-if="selectedStrategyDetails.length > 0" style="margin-top: 20px;">
            <el-divider content-position="left">{{ t('task.step.strategy') }}</el-divider>
            <StrategyConfigPreview
              v-for="s in selectedStrategyDetails"
              :key="s.id"
              :strategy="s"
            />
          </div>
        </div>

        <!-- Step 3: Output Config -->
        <div v-show="currentStep === 2">
          <el-form-item :label="t('taskCreate.outputType')" prop="output_type">
            <el-radio-group v-model="form.output_type">
              <el-radio value="port_group">{{ t('taskCreate.portGroup') }}</el-radio>
              <el-radio value="pcap">{{ t('taskCreate.pcap') }}</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-form-item v-if="form.output_type === 'port_group'" :label="t('taskCreate.portGroupID')" prop="output_config.port_group_id">
            <el-select v-model="form.output_config.port_group_id" :placeholder="t('taskCreate.selectPortGroup')" v-loading="portGroupLoading" style="width: 100%;">
              <el-option v-for="pg in portGroups" :key="pg.id" :label="`${pg.name} (${pg.ports_config.length} ports)`" :value="pg.id" />
            </el-select>
          </el-form-item>

          <el-form-item v-if="form.output_type === 'pcap'" :label="t('taskCreate.pcapPath')" prop="output_config.pcap_path">
            <el-input v-model="form.output_config.pcap_path" :placeholder="t('taskCreate.pcapPathPlaceholder')" >
              <template #prepend>pcap/</template>
            </el-input>
          </el-form-item>

          <el-divider content-position="left">{{ t('taskCreate.flowControl') }}</el-divider>

          <el-form-item :label="t('taskCreate.flowControlType')">
            <el-select v-model="form.flow_control.type" :placeholder="t('strategy.flowControlType')" clearable style="width: 200px;">
              <el-option :label="t('strategy.flows')" value="flows" />
              <el-option :label="t('strategy.bps')" value="bps" />
              <el-option :label="t('strategy.time')" value="time" />
            </el-select>
          </el-form-item>

          <el-form-item v-if="form.flow_control.type" :label="t('taskCreate.flowControlValue')">
            <div style="display: flex; align-items: center; gap: 8px;">
              <el-input-number v-model="form.flow_control.value" :min="flowControlMin" :max="flowControlMax" style="width: 200px;" />
              <span class="flow-control-unit">{{ flowControlUnit }}</span>
            </div>
          </el-form-item>
        </div>

        <!-- Step 4: Review -->
        <div v-show="currentStep === 3">
          <el-divider content-position="left">{{ t('task.step.basic') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('taskCreate.taskName')">{{ form.name }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.outputType')">{{ form.output_type === 'port_group' ? t('taskCreate.portGroup') : t('taskCreate.pcap') }}</el-descriptions-item>
          </el-descriptions>

          <el-divider content-position="left">{{ t('task.step.strategy') }}</el-divider>
          <StrategyConfigPreview
            v-for="s in selectedStrategyDetails"
            :key="s.id"
            :strategy="s"
          />

          <el-divider content-position="left">{{ t('task.step.output') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item v-if="form.output_type === 'port_group'" :label="t('taskCreate.portGroupID')">
              {{ selectedPortGroupName }}
            </el-descriptions-item>
            <el-descriptions-item v-if="form.output_type === 'pcap'" :label="t('taskCreate.pcapPath')">
              {{ form.output_config.pcap_path || '-' }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.flowControl')">
              <span v-if="form.flow_control.type">{{ t('strategy.' + form.flow_control.type) }}: {{ form.flow_control.value }} {{ flowControlUnit }}</span>
              <span v-else>-</span>
            </el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- Step Actions -->
        <el-form-item style="margin-top: 30px;">
          <el-button v-if="currentStep > 0" @click="prevStep">
            {{ t('common.back') }}
          </el-button>
          <el-button v-if="currentStep < 3" type="primary" @click="nextStep">
            {{ t('taskCreate.nextStep') }}
          </el-button>
          <el-button v-if="currentStep === 3" type="primary" :loading="loading" @click="handleSubmit">
            {{ t('taskCreate.create') }}
          </el-button>
          <el-button @click="handleCancel">{{ t('taskCreate.cancel') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { useRouter, onBeforeRouteLeave } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { taskApi, strategyApi, portGroupApi, type Strategy, type PortGroup, type CreateTaskRequest, type FlowControlRequest } from '@/api'
import { useStrategyTemplates } from '@/composables/useStrategyTemplates'
import { useFormDirty } from '@/composables/useFormDirty'
import StrategyConfigPreview from '@/components/StrategyConfigPreview/index.vue'

const { t } = useI18n()
const router = useRouter()
const formRef = ref<FormInstance>()
const loading = ref(false)
const currentStep = ref(0)

const strategies = ref<Strategy[]>([])
const portGroups = ref<PortGroup[]>([])
const strategyLoading = ref(false)
const portGroupLoading = ref(false)

const { allTemplates, customTemplates, getTemplate } = useStrategyTemplates()
const builtinTemplates = computed(() => allTemplates.value.filter(t => t.isBuiltin))
const selectedTemplateId = ref<string>('')
const templatePreview = ref<any>(null)

// Generate default task name with timestamp
function generateTaskName(): string {
  const now = new Date()
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '')
  const timeStr = now.toTimeString().slice(0, 5).replace(':', '')
  return `Task_${dateStr}_${timeStr}`
}

const defaultTaskName = generateTaskName()

const form = reactive<CreateTaskRequest>({
  name: defaultTaskName,
  strategy_ids: [],
  output_type: 'pcap',
  output_config: {
    pcap_path: `${defaultTaskName}.pcap`
  },
  flow_control: {
    type: '',
    value: 1
  }
})

const formDirty = useFormDirty(form)
formDirty.captureSnapshot()

onBeforeRouteLeave(async () => {
  const canLeave = await formDirty.confirmDiscard()
  if (!canLeave) return false
})

// Sync pcap_path when task name changes
function onTaskNameChange(name: string) {
  const oldDefault = form.output_config.pcap_path
  // If pcap_path was auto-generated from old name, sync it
  if (oldDefault && oldDefault.endsWith('.pcap') && !oldDefault.includes('/')) {
    form.output_config.pcap_path = `${name}.pcap`
  }
}

// Strategy grouped by protocol
const strategyGroups = computed(() => {
  const groups: Record<string, Strategy[]> = {}
  for (const s of strategies.value) {
    if (!groups[s.protocol]) groups[s.protocol] = []
    groups[s.protocol].push(s)
  }
  return Object.entries(groups).map(([protocol, items]) => ({
    label: protocol.toUpperCase(),
    items
  })).sort((a, b) => a.label.localeCompare(b.label))
})

const selectedStrategyDetails = computed(() => {
  return strategies.value.filter(s => form.strategy_ids.includes(s.id))
})

const selectedPortGroupName = computed(() => {
  if (form.output_type !== 'port_group' || !form.output_config.port_group_id) return '-'
  const pg = portGroups.value.find(p => p.id === form.output_config.port_group_id)
  return pg ? `${pg.name} (${pg.ports_config.length} ports)` : form.output_config.port_group_id
})

// Dynamic flow control constraints
const flowControlMin = computed(() => {
  if (form.flow_control.type === 'time') return 0
  return 1
})

const flowControlMax = computed(() => {
  return Infinity
})

const flowControlUnit = computed(() => {
  const units: Record<string, string> = {
    flows: t('strategy.unitFlows'),
    bps: t('strategy.unitBps'),

    time: t('strategy.unitTime')
  }
  return units[form.flow_control.type] || ''
})

const rules: FormRules = {
  name: [{ required: true, message: t('taskCreate.validation.taskNameRequired'), trigger: 'blur' }],
  strategy_ids: [{ required: true, type: 'array', min: 1, message: t('taskCreate.validation.strategyRequired'), trigger: 'change' }],
  'output_config.port_group_id': [{ required: true, message: t('taskCreate.validation.portGroupRequired'), trigger: 'change' }],
  'output_config.pcap_path': [{ required: true, message: t('taskCreate.validation.pcapPathRequired'), trigger: 'blur' }]
}

function handleTemplateSelect(templateId: string) {
  if (!templateId) {
    templatePreview.value = null
    return
  }
  templatePreview.value = getTemplate(templateId) || null
}

async function handleCancel() {
  const canLeave = await formDirty.confirmDiscard()
  if (canLeave) {
    router.back()
  }
}

function prevStep() {
  if (currentStep.value > 0) {
    currentStep.value--
  }
}

async function nextStep() {
  if (currentStep.value === 0) {
    try {
      await formRef.value?.validateField(['name'])
      // If template selected, create strategy from template
      if (templatePreview.value && selectedTemplateId.value) {
        try {
          const template = templatePreview.value
          const submitData: any = {
            name: template.name + ' ' + t('strategy.cloneSuffix'),
            protocol: template.protocol,
            config: template.config
          }
          if (template.flow_control) {
            submitData.flow_control = template.flow_control
          }
          const res = await strategyApi.create(submitData)
          if (res.data) {
            form.strategy_ids.push((res.data as any).id)
            ElMessage.success(t('strategy.templateApplied'))
            loadStrategies()
          }
        } catch (error) {
          console.error('Failed to create strategy from template:', error)
          ElMessage.error(t('strategy.createFailed'))
          return
        }
        templatePreview.value = null
        selectedTemplateId.value = ''
      }
      currentStep.value++
    } catch { /* validation failed */ }
  } else if (currentStep.value === 1) {
    try {
      await formRef.value?.validateField(['strategy_ids'])
      currentStep.value++
    } catch { /* validation failed */ }
  } else if (currentStep.value === 2) {
    // Validate output config
    const fieldsToValidate = ['output_type']
    if (form.output_type === 'port_group') {
      fieldsToValidate.push('output_config.port_group_id')
    } else {
      fieldsToValidate.push('output_config.pcap_path')
    }
    try {
      await formRef.value?.validateField(fieldsToValidate)
      currentStep.value++
    } catch { /* validation failed */ }
  } else {
    currentStep.value++
  }
}

async function loadStrategies() {
  strategyLoading.value = true
  try {
    const res = await strategyApi.list()
    if (res.data) {
      strategies.value = res.data as Strategy[]
    }
  } catch (error) {
    console.error('Failed to load strategies:', error)
  } finally {
    strategyLoading.value = false
  }
}

async function loadPortGroups() {
  portGroupLoading.value = true
  try {
    const res = await portGroupApi.list()
    if (res.data) {
      portGroups.value = res.data as PortGroup[]
    }
  } catch (error) {
    console.error('Failed to load port groups:', error)
  } finally {
    portGroupLoading.value = false
  }
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    const submitData: CreateTaskRequest = {
      name: form.name,
      strategy_ids: form.strategy_ids,
      output_type: form.output_type,
      output_config: form.output_config
    }

    if (form.flow_control.type) {
      submitData.flow_control = {
        type: form.flow_control.type,
        value: form.flow_control.value
      } as FlowControlRequest
    }

    const res = await taskApi.create(submitData)
    if (res.data) {
      ElMessage.success(t('task.createSuccess'))
      router.push('/tasks')
    }
  } catch (error) {
    console.error('Failed to create task:', error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadStrategies()
  loadPortGroups()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.flow-control-unit {
  font-size: 12px;
  color: var(--tg-text-secondary, #909399);
}
</style>
