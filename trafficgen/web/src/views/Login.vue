<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="card-header">
          <el-icon :size="32"><Connection /></el-icon>
          <h2>{{ t('login.title') }}</h2>
          <p class="subtitle">{{ t('login.subtitle') }}</p>
        </div>
      </template>

      <ProForm
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        label-width="auto"
        @submit.prevent="handleLogin"
      >
        <el-form-item :label="t('login.username')" prop="username">
          <el-input
            v-model="form.username"
            :placeholder="t('login.usernamePlaceholder')"
            prefix-icon="User"
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

        <el-form-item>
          <div class="login-options">
            <el-checkbox v-model="rememberMe">{{ t('login.rememberMe') }}</el-checkbox>
          </div>
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            :loading="loading"
            style="width: 100%"
            @click="handleLogin"
          >
            {{ t('login.login') }}
          </el-button>
        </el-form-item>

        <div class="login-links">
          <el-button link type="primary" @click="$router.push('/register')">{{ t('login.register') }}</el-button>
          <span class="link-divider">|</span>
          <el-button link @click="forgotPasswordVisible = true">{{ t('login.forgotPassword') }}</el-button>
        </div>
      </ProForm>
    </el-card>

    <!-- Forgot Password Dialog -->
    <el-dialog v-model="forgotPasswordVisible" :title="t('login.forgotPassword')" width="400px" append-to-body>
      <p style="color: var(--tg-text-body, #606266); line-height: 1.8;">{{ t('login.forgotPasswordMessage') }}</p>
      <template #footer>
        <el-button @click="forgotPasswordVisible = false">{{ t('common.close') }}</el-button>
      </template>
    </el-dialog>

    <p class="version-text">v{{ APP_VERSION }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Connection } from '@element-plus/icons-vue'
import { useUserStore } from '@/stores/user'
import { APP_VERSION } from '@/version'
import ProForm from '@/components/ProForm/index.vue'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const userStore = useUserStore()

const formRef = ref<FormInstance>()
const loading = ref(false)
const rememberMe = ref(false)
const forgotPasswordVisible = ref(false)

const form = reactive({
  username: '',
  password: ''
})

const rules: FormRules = {
  username: [
    { required: true, message: t('login.pleaseInputUsername'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('login.pleaseInputPassword'), trigger: 'blur' }
  ]
}

onMounted(() => {
  const saved = localStorage.getItem('remembered_username')
  if (saved) {
    form.username = saved
    rememberMe.value = true
  }
  // Show success message after registration
  if (route.query.registered === 'true') {
    ElMessage.success(t('login.registerSuccess'))
  }
})

async function handleLogin() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  loading.value = true
  try {
    await userStore.login(form.username, form.password)
    if (rememberMe.value) {
      localStorage.setItem('remembered_username', form.username)
    } else {
      localStorage.removeItem('remembered_username')
    }
    ElMessage.success(t('login.loginSuccess'))
    router.push('/')
  } catch (error: any) {
    if (error?.response?.data?.message) {
      ElMessage.error(error.response.data.message)
    } else {
      ElMessage.error(t('login.loginFailed'))
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
  background: linear-gradient(135deg, var(--tg-bg-card, #1E293B) 0%, var(--tg-bg-page, #0F172A) 100%);
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

.login-options {
  display: flex;
  align-items: center;
}

.login-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: -8px;
}

.link-divider {
  color: var(--tg-text-secondary, #94a3b8);
  font-size: 12px;
}

.version-text {
  margin-top: var(--tg-spacing-lg);
  color: var(--tg-text-secondary, rgba(255, 255, 255, 0.6));
  font-size: var(--tg-font-small);
}

html.dark .version-text {
  color: var(--tg-text-secondary, rgba(148, 163, 184, 0.6));
}

@media (max-width: 480px) {
  .login-card {
    width: 95%;
  }
}
</style>