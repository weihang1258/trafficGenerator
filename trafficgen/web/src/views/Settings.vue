<template>
  <div class="settings">
    <el-card>
      <template #header>
        <span>系统设置</span>
      </template>

      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px" style="max-width: 600px;">
        <el-form-item label="最大任务数" prop="max_tasks">
          <el-input-number v-model="form.max_tasks" :min="1" :max="1000" />
        </el-form-item>

        <el-form-item label="缓冲区大小" prop="buffer_size">
          <el-input-number v-model="form.buffer_size" :min="1024" :max="65536" :step="1024" />
        </el-form-item>

        <el-form-item label="日志级别" prop="log_level">
          <el-select v-model="form.log_level">
            <el-option label="Debug" value="debug" />
            <el-option label="Info" value="info" />
            <el-option label="Warn" value="warn" />
            <el-option label="Error" value="error" />
          </el-select>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" :loading="loading" @click="handleSave">
            保存设置
          </el-button>
          <el-button @click="loadSettings">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { settingsApi, type Settings } from '@/api'

const loading = ref(false)
const formRef = ref<FormInstance>()

const form = reactive<Settings>({
  max_tasks: 100,
  buffer_size: 4096,
  log_level: 'info'
})

const rules: FormRules = {
  max_tasks: [{ required: true, message: '请输入最大任务数', trigger: 'blur' }],
  buffer_size: [{ required: true, message: '请输入缓冲区大小', trigger: 'blur' }],
  log_level: [{ required: true, message: '请选择日志级别', trigger: 'change' }]
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

async function handleSave() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    await settingsApi.update(form)
    ElMessage.success('设置已保存')
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
