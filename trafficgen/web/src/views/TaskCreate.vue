<template>
  <div class="task-create">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('taskCreate.title') }}</span>
        </div>
      </template>

      <!-- Steps -->
      <el-steps :active="currentStep" finish-status="success" align-center style="margin-bottom: 30px;">
        <el-step :title="t('task.step.basic')" />
        <el-step :title="t('task.step.protocol')" />
        <el-step :title="t('task.step.advanced')" />
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

          <el-form-item :label="t('common.description')">
            <el-input v-model="form.description" type="textarea" rows="3" :placeholder="t('strategy.descriptionPlaceholder')" />
          </el-form-item>

          <el-form-item :label="t('taskCreate.protocol')" prop="protocol">
            <el-select v-model="form.protocol" :placeholder="t('taskCreate.selectProtocol')" @change="onProtocolChange">
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="HTTP" value="http" />
              <el-option label="DNS" value="dns" />
              <el-option label="ICMP" value="icmp" />
            </el-select>
          </el-form-item>
        </div>

        <!-- Step 2: Protocol Config -->
        <div v-show="currentStep === 1">
          <el-divider content-position="left">{{ t('taskCreate.networkConfig') }}</el-divider>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item :label="t('taskCreate.srcIP')" prop="spec.src_ip">
                <el-input v-model="form.spec.src_ip" :placeholder="t('taskCreate.srcIPPlaceholder')" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('taskCreate.dstIP')" prop="spec.dst_ip">
                <el-input v-model="form.spec.dst_ip" :placeholder="t('taskCreate.dstIPPlaceholder')" />
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item :label="t('taskCreate.srcPort')" prop="spec.src_port">
                <el-input-number v-model="form.spec.src_port" :min="1" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item :label="t('taskCreate.dstPort')" prop="spec.dst_port">
                <el-input-number v-model="form.spec.dst_port" :min="1" :max="65535" style="width: 100%;" />
              </el-form-item>
            </el-col>
          </el-row>

          <!-- TCP specific config -->
          <template v-if="form.protocol === 'tcp'">
            <el-divider content-position="left">TCP {{ t('task.config') }}</el-divider>
            <el-row :gutter="20">
              <el-col :span="8">
                <el-form-item label="三次握手">
                  <el-switch v-model="form.spec.tcp.handshake" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item label="四次挥手">
                  <el-switch v-model="form.spec.tcp.termination" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item label="MSS">
                  <el-input-number v-model="form.spec.tcp.mss" :min="536" :max="65535" />
                </el-form-item>
              </el-col>
            </el-row>
          </template>

          <!-- HTTP specific config -->
          <template v-if="form.protocol === 'http'">
            <el-divider content-position="left">HTTP {{ t('task.config') }}</el-divider>
            <el-row :gutter="20">
              <el-col :span="8">
                <el-form-item label="请求方法">
                  <el-select v-model="form.spec.http.method">
                    <el-option label="GET" value="GET" />
                    <el-option label="POST" value="POST" />
                    <el-option label="PUT" value="PUT" />
                    <el-option label="DELETE" value="DELETE" />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="16">
                <el-form-item label="URI">
                  <el-input v-model="form.spec.http.uri" placeholder="/api/test" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-form-item label="请求体">
              <el-input v-model="form.spec.http.body" type="textarea" rows="3" />
            </el-form-item>
          </template>

          <!-- DNS specific config -->
          <template v-if="form.protocol === 'dns'">
            <el-divider content-position="left">DNS {{ t('task.config') }}</el-divider>
            <el-row :gutter="20">
              <el-col :span="16">
                <el-form-item label="域名">
                  <el-input v-model="form.spec.dns.domain" placeholder="example.com" />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item label="查询类型">
                  <el-select v-model="form.spec.dns.query_type">
                    <el-option label="A" :value="1" />
                    <el-option label="AAAA" :value="28" />
                    <el-option label="CNAME" :value="5" />
                    <el-option label="MX" :value="15" />
                  </el-select>
                </el-form-item>
              </el-col>
            </el-row>
          </template>
        </div>

        <!-- Step 3: Advanced Options -->
        <div v-show="currentStep === 2">
          <el-divider content-position="left">{{ t('taskCreate.outputConfig') }}</el-divider>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="源MAC">
                <el-input v-model="form.spec.src_mac" placeholder="例如: aa:bb:cc:dd:ee:ff" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="目标MAC">
                <el-input v-model="form.spec.dst_mac" placeholder="例如: 11:22:33:44:55:66" />
              </el-form-item>
            </el-col>
          </el-row>

          <el-form-item :label="t('taskCreate.interface')">
            <el-select v-model="form.interface" :placeholder="t('taskCreate.selectInterface')">
              <el-option v-for="iface in interfaces" :key="iface.name" :label="iface.name" :value="iface.name" />
            </el-select>
          </el-form-item>

          <el-form-item :label="t('taskCreate.outputMode')">
            <el-radio-group v-model="form.output_mode">
              <el-radio label="interface">{{ t('outputMode.interface') }}</el-radio>
              <el-radio label="pcap">{{ t('outputMode.pcap') }}</el-radio>
              <el-radio label="both">{{ t('common.both') || '两者都输出' }}</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-form-item v-if="form.output_mode !== 'interface'" :label="t('taskCreate.filename')">
            <el-input v-model="form.pcap_file" :placeholder="t('taskCreate.filenamePlaceholder')" />
          </el-form-item>
        </div>

        <!-- Step 4: Review -->
        <div v-show="currentStep === 3">
          <el-divider content-position="left">{{ t('task.basicInfo') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('taskCreate.taskName')">{{ form.name }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.protocol')">{{ form.protocol.toUpperCase() }}</el-descriptions-item>
            <el-descriptions-item :label="t('common.description')" :span="2">{{ form.description || '-' }}</el-descriptions-item>
          </el-descriptions>

          <el-divider content-position="left">{{ t('taskCreate.networkConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('taskCreate.srcIP')">{{ form.spec.src_ip }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.dstIP')">{{ form.spec.dst_ip }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.srcPort')">{{ form.spec.src_port }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.dstPort')">{{ form.spec.dst_port }}</el-descriptions-item>
          </el-descriptions>

          <el-divider content-position="left">{{ t('taskCreate.outputConfig') }}</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item :label="t('taskCreate.interface')">{{ form.interface || '-' }}</el-descriptions-item>
            <el-descriptions-item :label="t('taskCreate.outputMode')">{{ form.output_mode }}</el-descriptions-item>
            <el-descriptions-item v-if="form.pcap_file" :label="t('taskCreate.filename')" :span="2">{{ form.pcap_file }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- Step Actions -->
        <el-form-item style="margin-top: 30px;">
          <el-button v-if="currentStep > 0" @click="prevStep">
            {{ t('common.back') }}
          </el-button>
          <el-button v-if="currentStep < 3" type="primary" @click="nextStep">
            {{ t('common.submit') }}
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
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { taskApi, interfaceApi, type NetworkInterface, type CreateTaskRequest } from '@/api'

const { t } = useI18n()
const router = useRouter()
const formRef = ref<FormInstance>()
const loading = ref(false)
const interfaces = ref<NetworkInterface[]>([])
const currentStep = ref(0)

const form = reactive<CreateTaskRequest>({
  name: '',
  description: '',
  protocol: 'tcp',
  spec: {
    src_ip: '192.168.1.100',
    dst_ip: '192.168.1.1',
    src_port: 12345,
    dst_port: 80,
    tcp: {
      handshake: true,
      termination: true,
      mss: 1460,
      window_size: 65535
    },
    http: {
      method: 'GET',
      uri: '/',
      headers: {},
      body: '',
      keep_alive: true,
      transactions: 1,
      think_time: 0
    },
    dns: {
      domain: 'example.com',
      query_type: 1,
      response: false
    }
  },
  interface: '',
  output_mode: 'interface'
})

const rules: FormRules = {
  name: [{ required: true, message: t('taskCreate.validation.taskNameRequired'), trigger: 'blur' }],
  protocol: [{ required: true, message: t('taskCreate.validation.protocolRequired'), trigger: 'change' }],
  'spec.src_ip': [{ required: true, message: t('taskCreate.validation.srcIPRequired'), trigger: 'blur' }],
  'spec.dst_ip': [{ required: true, message: t('taskCreate.validation.dstIPRequired'), trigger: 'blur' }],
  'spec.src_port': [{ required: true, message: t('taskCreate.validation.srcPortRequired'), trigger: 'blur' }],
  'spec.dst_port': [{ required: true, message: t('taskCreate.validation.dstPortRequired'), trigger: 'blur' }]
}

function onProtocolChange() {
  // Reset protocol-specific config
}

async function nextStep() {
  // Validate current step fields
  if (currentStep.value === 0) {
    try {
      await formRef.value?.validateField(['name', 'protocol'])
      currentStep.value++
    } catch (error) {
      console.error('Validation failed:', error)
    }
  } else if (currentStep.value === 1) {
    try {
      await formRef.value?.validateField(['spec.src_ip', 'spec.dst_ip', 'spec.src_port', 'spec.dst_port'])
      currentStep.value++
    } catch (error) {
      console.error('Validation failed:', error)
    }
  } else {
    currentStep.value++
  }
}

function prevStep() {
  if (currentStep.value > 0) {
    currentStep.value--
  }
}

async function loadInterfaces() {
  try {
    const res = await interfaceApi.list()
    if (res.data) {
      interfaces.value = res.data
    }
  } catch (error) {
    console.error('Failed to load interfaces:', error)
  }
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    const res = await taskApi.create(form)
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
