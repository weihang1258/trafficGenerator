<template>
  <div class="user-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('user.title') }}</span>
          <el-button type="primary" @click="handleCreate">
            <el-icon><Plus /></el-icon>
            {{ t('user.createUser') }}
          </el-button>
        </div>
      </template>

      <el-form :inline="true" :model="searchForm" class="search-form">
        <el-form-item :label="t('user.username')">
          <el-input v-model="searchForm.username" :placeholder="t('user.usernamePlaceholder')" clearable />
        </el-form-item>
        <el-form-item :label="t('user.role')">
          <el-select v-model="searchForm.role" :placeholder="t('user.selectRole')" clearable>
            <el-option :label="t('user.admin')" value="admin" />
            <el-option :label="t('user.user')" value="user" />
            <el-option :label="t('user.guest')" value="guest" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">
            <el-icon><Search /></el-icon>
            {{ t('common.search') }}
          </el-button>
          <el-button @click="handleReset">
            <el-icon><Refresh /></el-icon>
            {{ t('common.reset') }}
          </el-button>
        </el-form-item>
      </el-form>

      <el-table :data="users" v-loading="loading" stripe>
        <el-table-column prop="username" :label="t('user.username')" width="150" />
        <el-table-column prop="email" :label="t('user.email')" width="200" />
        <el-table-column prop="role" :label="t('user.role')" width="120">
          <template #default="{ row }">
            <el-tag :type="getRoleType(row.role)">{{ getRoleText(row.role) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('user.status')" width="100">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              :disabled="row.username === 'admin'"
              @change="(val) => handleStatusChange(row, val)"
            />
          </template>
        </el-table-column>
        <el-table-column :label="t('user.createdAt')" width="180">
          <template #default="{ row }">
            {{ row.created_at ? formatDate(row.created_at) : '-' }}
          </template>
        </el-table-column>
        <el-table-column :label="t('user.lastLogin')" width="180">
          <template #default="{ row }">
            {{ row.last_login ? formatDate(row.last_login) : '-' }}
          </template>
        </el-table-column>
        <el-table-column :label="t('common.action')" width="220" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="handleEdit(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="warning" @click="handleResetPassword(row)">{{ t('user.resetPassword') }}</el-button>
            <el-button size="small" type="danger" :disabled="row.role === 'admin'" @click="handleDelete(row)">{{ t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="500px"
      :close-on-click-modal="false"
      @close="handleDialogClose"
    >
      <el-form
        ref="formRef"
        :model="userForm"
        :rules="rules"
        label-width="100px"
      >
        <el-form-item :label="t('user.username')" prop="username">
          <el-input v-model="userForm.username" :placeholder="t('user.usernamePlaceholder')" :disabled="!!userForm.id" />
        </el-form-item>
        <el-form-item :label="t('user.email')" prop="email">
          <el-input v-model="userForm.email" :placeholder="t('user.emailPlaceholder')" />
        </el-form-item>
        <el-form-item v-if="!userForm.id" :label="t('user.password')" prop="password">
          <el-input
            v-model="userForm.password"
            type="password"
            :placeholder="t('user.passwordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item :label="t('user.role')" prop="role">
          <el-select v-model="userForm.role" :placeholder="t('user.selectRole')">
            <el-option :label="t('user.admin')" value="admin" />
            <el-option :label="t('user.user')" value="user" />
            <el-option :label="t('user.guest')" value="guest" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('user.status')">
          <el-switch v-model="userForm.enabled" :active-text="t('user.active')" :inactive-text="t('user.disabled')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Plus, Search, Refresh } from '@element-plus/icons-vue'
import { userApi, authApi, type User } from '@/api'
import dayjs from 'dayjs'

const { t } = useI18n()

const loading = ref(false)
const submitLoading = ref(false)
const users = ref<User[]>([])

const searchForm = reactive({
  username: '',
  role: ''
})

const dialogVisible = ref(false)
const dialogTitle = ref(t('user.createUser'))
const formRef = ref<FormInstance>()

const userForm = reactive({
  id: '',
  username: '',
  email: '',
  password: '',
  role: 'user',
  enabled: true
})

const rules: FormRules = {
  username: [
    { required: true, message: t('user.usernamePlaceholder'), trigger: 'blur' },
    { min: 3, max: 20, message: t('user.usernameLength'), trigger: 'blur' }
  ],
  email: [
    { required: true, message: t('user.emailPlaceholder'), trigger: 'blur' },
    { type: 'email', message: t('user.emailPlaceholder'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('user.passwordPlaceholder'), trigger: 'blur' },
    { min: 6, max: 20, message: t('user.passwordLength'), trigger: 'blur' }
  ],
  role: [
    { required: true, message: t('user.selectRole'), trigger: 'change' }
  ]
}

const getRoleType = (role: string) => {
  const types: Record<string, string> = {
    admin: 'danger',
    user: 'primary',
    guest: 'info'
  }
  return types[role] || 'info'
}

const getRoleText = (role: string) => {
  const texts: Record<string, string> = {
    admin: t('user.admin'),
    user: t('user.user'),
    guest: t('user.guest')
  }
  return texts[role] || role
}

function formatDate(timestamp: number): string {
  if (!timestamp) return '-'
  return dayjs(timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')
}

async function fetchUsers() {
  loading.value = true
  try {
    const res = await userApi.list({
      username: searchForm.username || undefined,
      role: searchForm.role || undefined
    })
    if (res.data) {
      users.value = res.data as User[]
    }
  } catch (error) {
    console.error('Failed to load users:', error)
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  fetchUsers()
}

function handleReset() {
  searchForm.username = ''
  searchForm.role = ''
  fetchUsers()
}

function handleCreate() {
  dialogTitle.value = t('user.createUser')
  userForm.id = ''
  userForm.username = ''
  userForm.email = ''
  userForm.password = ''
  userForm.role = 'user'
  userForm.enabled = true
  dialogVisible.value = true
}

function handleEdit(row: User) {
  dialogTitle.value = t('common.edit')
  userForm.id = row.id
  userForm.username = row.username
  userForm.email = row.email
  userForm.role = row.role
  userForm.enabled = row.enabled
  dialogVisible.value = true
}

async function handleDelete(row: User) {
  try {
    await ElMessageBox.confirm(t('user.confirmDelete'), t('common.confirm'), { type: 'warning' })
    await userApi.delete(row.id)
    ElMessage.success(t('user.deleteSuccess'))
    fetchUsers()
  } catch { /* cancelled */ }
}

async function handleResetPassword(row: User) {
  try {
    await ElMessageBox.confirm(t('user.confirmResetPassword'), t('common.confirm'), { type: 'warning' })
    await userApi.resetPassword(row.id)
    ElMessage.success(t('user.resetPasswordSuccess'))
  } catch { /* cancelled */ }
}

async function handleStatusChange(row: User, enabled: boolean) {
  try {
    await userApi.update(row.id, { enabled })
    ElMessage.success(enabled ? t('user.active') : t('user.disabled'))
  } catch {
    row.enabled = !enabled
  }
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  submitLoading.value = true
  try {
    if (userForm.id) {
      await userApi.update(userForm.id, {
        role: userForm.role,
        enabled: userForm.enabled,
        email: userForm.email
      })
      ElMessage.success(t('user.updateSuccess'))
    } else {
      const res = await authApi.register({
        username: userForm.username,
        password: userForm.password,
        email: userForm.email
      })
      // Set role and enabled status after registration
      const userId = (res.data as any)?.user_id || (res as any)?.data?.user_id
      if (userId && (userForm.role !== 'user' || !userForm.enabled)) {
        await userApi.update(userId, {
          role: userForm.role,
          enabled: userForm.enabled
        })
      }
      ElMessage.success(t('user.createSuccess'))
    }
    dialogVisible.value = false
    fetchUsers()
  } catch (error) {
    console.error('Failed to save user:', error)
  } finally {
    submitLoading.value = false
  }
}

function handleDialogClose() {
  formRef.value?.resetFields()
}

onMounted(() => {
  fetchUsers()
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