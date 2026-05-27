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
            <el-input v-model="form.name" :placeholder="t('taskCreate.taskNamePlaceholder')" />
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
              <el-option
                v-for="s in strategies"
                :key="s.id"
                :label="`${s.name} (${s.protocol.toUpperCase()})`"
                :value="s.id"
              />
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
            <el-descriptions v-for="s in selectedStrategyDetails" :key="s.id" :column="2" border style="margin-bottom: 10px;">
              <el-descriptions-item :label="t('common.name')">{{ s.name }}</el-descriptions-item>
              <el-descriptions-item :label="t('task.protocol')">{{ s.protocol.toUpperCase() }}</el-descriptions-item>
              <el-descriptions-item :label="t('strategy.flowControl')" :span="2">
                <span v-if="s.flow_control">{{ s.flow_control.type }}: {{ s.flow_control.value }}</span>
                <span v-else>-</span>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </div>

        <!-- Step 3: Output Config -->
        <div v-show="currentStep === 2">
          <el-form-item :label="t('taskCreate.outputType')" prop="output_type">
            <el-radio-group v-model="form.output_type">
              <el-radio label="port_group">{{ t('taskCreate.portGroup') }}</el-radio>
              <el-radio label="pcap">{{ t('taskCreate.pcap') }}</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-form-item v-if="form.output_type === 'port_group'" :label="t('taskCreate.portGroupID')" prop="output_config.port_group_id">
            <el-select v-model="form.output_config.port_group_id" :placeholder="t('taskCreate.selectPortGroup')" v-loading="portGroupLoading">
              <el-option v-for="pg in portGroups" :key="pg.id" :label="`${pg.name} (${pg.ports_config.length} ports)`" :value="pg.id" />
            </el-select>
          </el-form-item>

          <el-form-item v-if="form.output_type === 'pcap'" :label="t('taskCreate.pcapPath')" prop="output_config.pcap_path">
            <el-input v-model="form.output_config.pcap_path" :placeholder="t('taskCreate.pcapPathPlaceholder')" />
          </el-form-item>

          <el-divider content-position="left">{{ t('taskCreate.flowControl') }}</el-divider>

          <el-form-item :label="t('taskCreate.flowControlType')">
            <el-select v-model="form.flow_control.type" :placeholder="t('strategy.flowControlType')" clearable style="width: 200px;">
              <el-option :label="t('strategy.bps')" value="bps" />
              <el-option :label="t('strategy.flows')" value="flows" />
              <el-option :label="t('strategy.cps')" value="cps" />
              <el-option :label="t('strategy.ratio')" value="ratio" />
              <el-option :label="t('strategy.time')" value="time" />
            </el-select>
          </el-form-item>

          <el-form-item v-if="form.flow_control.type" :label="t('taskCreate.flowControlValue')">
            <el-input-number v-model="form.flow_control.value" :min="1" style="width: 200px;" />
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
          <el-descriptions v-for="s in selectedStrategyDetails" :key="s.id" :column="2" border style="margin-bottom: 10px;">
            <el-descriptions-item :label="t('common.name')">{{ s.name }}</el-descriptions-item>
            <el-descriptions-item :label="t('task.protocol')">{{ s.protocol.toUpperCase() }}</el-descriptions-item>
          </el-descriptions>

          <el-divider content-position="left">{{ t('task.step.output') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item v-if="form.output_type === 'port_group'" :label="t('taskCreate.portGroupID')">
              {{ form.output_config.port_group_id || '-' }}
            </el-descriptions-item>
            <el-descriptions-item v-if="form.output_type === 'pcap'" :label="t('taskCreate.pcapPath')">
              {{ form.output_config.pcap_path || '-' }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.flowControl')">
              <span v-if="form.flow_control.type">{{ form.flow_control.type }}: {{ form.flow_control.value }}</span>
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
          <el-button @click="$router.back()">{{ t('taskCreate.cancel') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { taskApi, strategyApi, portGroupApi, type Strategy, type PortGroup, type CreateTaskRequest, type FlowControlRequest, type OutputConfigRequest } from '@/api'
import { useStrategyTemplates } from '@/composables/useStrategyTemplates'

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

const form = reactive<CreateTaskRequest>({
  name: '',
  strategy_ids: [],
  output_type: 'pcap',
  output_config: {
    pcap_path: '/tmp/output.pcap'
  },
  flow_control: {
    type: '',
    value: 1
  }
})

const selectedStrategyDetails = computed(() => {
  return strategies.value.filter(s => form.strategy_ids.includes(s.id))
})

const rules: FormRules = {
  name: [{ required: true, message: t('taskCreate.validation.taskNameRequired'), trigger: 'blur' }],
  strategy_ids: [{ required: true, type: 'array', min: 1, message: t('taskCreate.validation.strategyRequired'), trigger: 'change' }]
}

async function handleTemplateSelect(templateId: string) {
  if (!templateId) return
  const template = getTemplate(templateId)
  if (!template) return

  // Create strategy from template
  try {
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
      currentStep.value++
    } catch { /* validation failed */ }
  } else if (currentStep.value === 1) {
    try {
      await formRef.value?.validateField(['strategy_ids'])
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
</style>
