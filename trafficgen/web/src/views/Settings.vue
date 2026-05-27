<template>
  <div class="settings">
    <el-card>
      <template #header>
        <span>{{ t('settings.title') }}</span>
      </template>

      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px" style="max-width: 600px;">
        <el-form-item :label="t('settings.language')" prop="language">
          <el-select v-model="currentLocale" @change="handleLanguageChange">
            <el-option :label="t('settings.chinese')" value="zh-CN" />
            <el-option :label="t('settings.english')" value="en-US" />
          </el-select>
        </el-form-item>

        <el-divider />

        <el-form-item :label="t('settings.maxTasks')" prop="max_tasks">
          <el-input-number v-model="form.max_tasks" :min="1" :max="1000" />
        </el-form-item>

        <el-form-item :label="t('settings.bufferSize')" prop="buffer_size">
          <el-input-number v-model="form.buffer_size" :min="1024" :max="65536" :step="1024" />
        </el-form-item>

        <el-form-item :label="t('settings.logLevel')" prop="log_level">
          <el-select v-model="form.log_level">
            <el-option :label="t('settings.debug')" value="debug" />
            <el-option :label="t('settings.info')" value="info" />
            <el-option :label="t('settings.warn')" value="warn" />
            <el-option :label="t('settings.error')" value="error" />
          </el-select>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" :loading="loading" @click="handleSave">
            {{ t('settings.save') }}
          </el-button>
          <el-button @click="loadSettings">{{ t('settings.reset') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { settingsApi, type Settings } from '@/api'
import { setLocale, getLocale } from '@/i18n'

const { t } = useI18n()

const loading = ref(false)
const formRef = ref<FormInstance>()
const currentLocale = ref(getLocale())

const form = reactive<Settings>({
  max_tasks: 100,
  buffer_size: 4096,
  log_level: 'info'
})

const rules: FormRules = {
  max_tasks: [{ required: true, message: t('settings.maxTasks'), trigger: 'blur' }],
  buffer_size: [{ required: true, message: t('settings.bufferSize'), trigger: 'blur' }],
  log_level: [{ required: true, message: t('settings.selectLogLevel'), trigger: 'change' }]
}

async function loadSettings() {
  try {
    const res = await settingsApi.get()
    if (res.data) {
      form.max_tasks = res.data.max_tasks
      form.buffer_size = res.data.buffer_size
      form.log_level = res.data.log_level
    }
  } catch (error) {
    console.error('Failed to load settings:', error)
  }
}

function handleLanguageChange(locale: string) {
  setLocale(locale)
  ElMessage.success(t('settings.saveSuccess'))
}

async function handleSave() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    await settingsApi.update(form)
    ElMessage.success(t('settings.saveSuccess'))
  } catch (error) {
    console.error('Failed to save settings:', error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadSettings()
})
</script>
