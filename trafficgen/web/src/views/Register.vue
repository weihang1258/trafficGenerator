<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="card-header">
          <el-icon :size="32"><Connection /></el-icon>
          <h2>{{ t('login.registerTitle') }}</h2>
          <p class="subtitle">{{ t('login.registerSubtitle') }}</p>
        </div>
      </template>

      <ProForm
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        label-width="auto"
        @submit.prevent="handleRegister"
      >
        <el-form-item :label="t('login.username')" prop="username">
          <el-input
            v-model="form.username"
            :placeholder="t('login.usernamePlaceholder')"
            prefix-icon="User"
          />
        </el-form-item>

        <el-form-item :label="t('login.email')" prop="email">
          <el-input
            v-model="form.email"
            :placeholder="t('login.emailPlaceholder')"
            prefix-icon="Message"
          />
        </el-form-item>

        <el-form-item :label="t('login.password')" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="t('login.passwordPlaceholder')"
            prefix-icon="Lock"
            show-password
          />
        </el-form-item>

        <el-form-item :label="t('login.confirmPassword')" prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            type="password"
            :placeholder="t('login.confirmPasswordPlaceholder')"
            prefix-icon="Lock"
            show-password
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            :loading="loading"
            style="width: 100%"
            @click="handleRegister"
          >
            {{ t('login.register') }}
          </el-button>
        </el-form-item>

        <div class="login-links">
          <span class="link-text">{{ t('login.alreadyHaveAccount') }}</span>
          <el-button link type="primary" @click="$router.push('/login')">
            {{ t('login.goToLogin') }}
          </el-button>
        </div>
      </ProForm>
    </el-card>
    <p class="version-text">v{{ version }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Connection } from '@element-plus/icons-vue'
import { authApi } from '@/api'
import { version } from '../../package.json'
import ProForm from '@/components/ProForm/index.vue'

const { t } = useI18n()
const router = useRouter()

const formRef = ref<FormInstance>()
const loading = ref(false)

const form = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: ''
})

const validateConfirmPassword = (_rule: any, value: string, callback: (err?: Error) => void) => {
  if (value !== form.password) {
    callback(new Error(t('login.passwordMismatch')))
  } else {
    callback()
  }
}

const rules: FormRules = {
  username: [
    { required: true, message: t('login.pleaseInputUsername'), trigger: 'blur' },
    { min: 3, max: 64, message: t('login.usernameLength'), trigger: 'blur' }
  ],
  email: [
    { required: true, message: t('login.emailInvalid'), trigger: 'blur' },
    { type: 'email', message: t('login.emailInvalid'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('login.pleaseInputPassword'), trigger: 'blur' },
    { min: 8, max: 128, message: t('login.passwordLength'), trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: t('login.confirmPasswordPlaceholder'), trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' }
  ]
}

async function handleRegister() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    await authApi.register({
      username: form.username,
      password: form.password,
      email: form.email
    })
    ElMessage.success(t('login.registerSuccess'))
    router.push('/login?registered=true')
  } catch (error: any) {
    const msg = error?.response?.data?.message || ''
    if (msg.includes('username') || msg.includes('用户名')) {
      ElMessage.error(t('login.usernameExists'))
    } else if (msg.includes('email') || msg.includes('邮箱')) {
      ElMessage.error(t('login.emailExists'))
    } else {
      ElMessage.error(t('login.registerFailed'))
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--tg-primary, #2563EB) 0%, var(--tg-primary-dark, #1D4ED8) 100%);
}

html.dark .login-container {
  background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
}

.login-card {
  max-width: 400px;
  width: 90%;
  border-radius: var(--tg-radius-card, 12px);
  box-shadow: var(--tg-shadow-lg);
  background: var(--tg-bg-card);
}

.login-card :deep(.el-card__header) {
  padding: var(--tg-spacing-lg) var(--tg-spacing-md) var(--tg-spacing-md);
  border-bottom: none;
}

.login-card :deep(.el-card__body) {
  padding: 0 var(--tg-spacing-lg) var(--tg-spacing-lg);
}

.card-header {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--tg-spacing-sm);
}

.card-header h2 {
  margin: 0;
  color: var(--tg-text-primary);
  font-size: var(--tg-font-title);
  font-weight: 600;
}

.subtitle {
  margin: 0;
  font-size: var(--tg-font-body);
  color: var(--tg-text-secondary);
}

.login-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: -8px;
}

.link-text {
  font-size: 13px;
  color: var(--tg-text-secondary, #64748B);
}

.version-text {
  margin-top: var(--tg-spacing-lg);
  color: rgba(255, 255, 255, 0.6);
  font-size: var(--tg-font-small);
}

html.dark .version-text {
  color: rgba(148, 163, 184, 0.6);
}

@media (max-width: 480px) {
  .login-card {
    width: 95%;
  }
}
</style>
