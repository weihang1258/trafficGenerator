<template>
  <div class="user-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ t('user.title') }}</span>
          <div class="header-actions">
            <template v-if="selectedUsers.length === 0">
              <el-button aria-label="Column settings" @click="proTableRef?.openColumnSettings()" circle size="small">
                <el-icon><Setting /></el-icon>
              </el-button>
              <el-button aria-label="Refresh" @click="fetchUsers" circle size="small">
                <el-icon><Refresh /></el-icon>
              </el-button>
              <el-button type="primary" @click="handleCreate">
                <el-icon><Plus /></el-icon>
                {{ t('user.createUser') }}
              </el-button>
            </template>
            <template v-else>
              <span class="batch-info">{{ t('common.selected') }} {{ selectedUsers.length }} {{ t('user.title') }}</span>
              <el-button type="danger" size="small" @click="handleBatchDelete">{{ t('common.delete') }}</el-button>
              <el-button size="small" link type="primary" @click="clearSelection">{{ t('common.reset') }}</el-button>
            </template>
          </div>
        </div>
      </template>

      <!-- Filter bar -->
      <div class="filter-bar">
        <el-input
          v-model="searchForm.username"
          :placeholder="t('user.usernamePlaceholder')"
          clearable
          style="width: 240px"
          @keyup.enter="handleSearch"
          @clear="handleSearch"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-select v-model="searchForm.role" :placeholder="t('user.selectRole')" clearable style="width: 140px" @change="handleSearch">
          <el-option :label="t('user.admin')" value="admin" />
          <el-option :label="t('user.user')" value="user" />
          <el-option :label="t('user.guest')" value="guest" />
        </el-select>
        <el-button link type="primary" @click="handleReset">{{ t('common.reset') }}</el-button>
      </div>

      <!-- Active filter tags -->
      <div v-if="hasActiveFilters" class="active-filters">
        <el-tag v-if="searchForm.username" closable @close="searchForm.username = ''; handleSearch()">
          {{ searchForm.username }}
        </el-tag>
        <el-tag v-if="searchForm.role" closable @close="searchForm.role = ''; handleSearch()">
          {{ getRoleText(searchForm.role) }}
        </el-tag>
        <el-button link type="primary" size="small" @click="handleReset">{{ t('common.reset') }}</el-button>
      </div>

      <ProTable
        ref="proTableRef"
        table-id="user-list"
        :columns="columns"
        :data="users"
        :loading="loading"
        :default-sort="{ prop: 'created_at', order: 'descending' }"
        :pagination="{ total: pagination.total }"
        :empty-text="t('user.noUsers')"
        @selection-change="handleSelectionChange"
        @sort-change="handleSortChange"
        @page-change="handlePageChange"
      >
        <template #username="{ row }">
          <span class="user-name">{{ row.username }}</span>
        </template>
        <template #role="{ row }">
          <el-tag :type="getRoleType(row.role)" size="small">{{ getRoleText(row.role) }}</el-tag>
        </template>
        <template #enabled="{ row }">
          <el-switch
            v-model="row.enabled"
            :disabled="row.username === 'admin'"
            @change="(val: boolean) => handleStatusChange(row, val)"
          />
        </template>
        <template #created_at="{ row }">
          {{ row.created_at ? formatTimestamp(row.created_at) : '-' }}
        </template>
        <template #updated_at="{ row }">
          {{ row.updated_at ? formatTimestamp(row.updated_at) : '-' }}
        </template>
        <template #last_login="{ row }">
          {{ row.last_login ? formatTimestamp(row.last_login) : '-' }}
        </template>
        <template #actions="{ row }">
          <div class="action-buttons">
            <el-button size="small" link type="primary" @click="handleEdit(row)">
              {{ t('common.edit') }}
            </el-button>
            <el-dropdown trigger="click" @command="(cmd: string) => handleAction(cmd, row)">
              <el-button size="small" link>
                <el-icon><More /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="resetPassword">{{ t('user.resetPassword') }}</el-dropdown-item>
                  <el-dropdown-item command="delete" :disabled="row.role === 'admin'" style="color: var(--el-color-danger)">{{ t('common.delete') }}</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </template>
        <template #empty>
          <el-empty :description="t('user.noUsers')">
            <el-button type="primary" @click="handleCreate">
              {{ t('user.createUser') }}
            </el-button>
          </el-empty>
        </template>
      </ProTable>
    </el-card>

    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="500px"
      :close-on-click-modal="false"
      :before-close="handleDialogBeforeClose"
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
        <el-form-item v-if="!userForm.id" :label="t('user.confirmPassword')" prop="confirmPassword">
          <el-input
            v-model="userForm.confirmPassword"
            type="password"
            :placeholder="t('user.confirmPasswordPlaceholder')"
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
import { ref, reactive, computed, onMounted, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Plus, Search, Refresh, Setting, More } from '@element-plus/icons-vue'
import { userApi, authApi, type User } from '@/api'
import ProTable from '@/components/ProTable/index.vue'
import { formatTimestamp } from '@/utils/format'

const { t } = useI18n()

const loading = ref(false)
const submitLoading = ref(false)
const users = ref<User[]>([])
const proTableRef = ref()
const selectedUsers = ref<User[]>([])
const formDirty = ref(false)

const searchForm = reactive({
  username: '',
  role: ''
})

const pagination = reactive({
  page: 1,
  size: 20,
  total: 0
})

const sortState = reactive({
  prop: 'created_at',
  order: 'descending'
})

const hasActiveFilters = computed(() =>
  searchForm.username || searchForm.role
)

const columns = computed(() => [
  { type: 'selection' as const, width: 45, fixed: 'left' },
  { prop: 'username', label: t('user.username'), width: 130, required: true, sortable: 'custom' },
  { prop: 'email', label: t('user.email'), minWidth: 180, sortable: 'custom' },
  { prop: 'role', label: t('user.role'), width: 90, sortable: 'custom' },
  { prop: 'enabled', label: t('user.status'), width: 90, sortable: 'custom' },
  { prop: 'created_at', label: t('user.createdAt'), width: 170, sortable: 'custom' },
  { prop: 'updated_at', label: t('common.updatedAt'), width: 170, sortable: 'custom' },
  { prop: 'last_login', label: t('user.lastLogin'), width: 170, sortable: 'custom' },
  { prop: 'actions', label: t('common.action'), width: 120, fixed: 'right', required: true }
])

const dialogVisible = ref(false)
const dialogTitle = ref(t('user.createUser'))
const formRef = ref<FormInstance>()

const userForm = reactive({
  id: '',
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  role: 'user',
  enabled: true
})

const initialFormJson = ref('')

function captureUserFormState() {
  return JSON.stringify({ username: userForm.username, email: userForm.email, password: userForm.password, confirmPassword: userForm.confirmPassword, role: userForm.role, enabled: userForm.enabled })
}

watch(() => captureUserFormState(), (v) => {
  if (dialogVisible.value) {
    formDirty.value = v !== initialFormJson.value
  }
})

const validateConfirmPassword = (_rule: any, value: string, callback: (err?: Error) => void) => {
  if (!value) {
    callback(new Error(t('user.confirmPasswordRequired')))
  } else if (value !== userForm.password) {
    callback(new Error(t('user.passwordMismatch')))
  } else {
    callback()
  }
}

const rules: FormRules = {
  username: [
    { required: true, message: t('user.usernameRequired'), trigger: 'blur' },
    { min: 3, max: 64, message: t('user.usernameLength'), trigger: 'blur' }
  ],
  email: [
    { required: true, message: t('user.emailRequired'), trigger: 'blur' },
    { type: 'email', message: t('user.emailInvalid'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('user.passwordRequired'), trigger: 'blur' },
    { min: 8, max: 128, message: t('user.passwordLength'), trigger: 'blur' }
  ],
  confirmPassword: [
    { validator: validateConfirmPassword, trigger: 'blur' }
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


async function fetchUsers() {
  loading.value = true
  try {
    const params: any = {}
    if (searchForm.username) params.username = searchForm.username
    if (searchForm.role) params.role = searchForm.role
    const res = await userApi.list(params)
    if (res.data) {
      const data = res.data as any
      const items = Array.isArray(data) ? data : (data.items || [])
      users.value = applySort(items)
      pagination.total = items.length
    }
  } catch (error) {
    console.error('Failed to load users:', error)
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  pagination.page = 1
  fetchUsers()
}

function handleReset() {
  searchForm.username = ''
  searchForm.role = ''
  pagination.page = 1
  fetchUsers()
}

function handleSortChange({ prop, order }: { prop: string; order: string }) {
  sortState.prop = prop
  sortState.order = order
  users.value = applySort(users.value)
}

function applySort(data: any[]): any[] {
  if (!sortState.prop || !sortState.order) return data
  const dir = sortState.order === 'ascending' ? 1 : -1
  return [...data].sort((a: any, b: any) => {
    const va = a[sortState.prop!]
    const vb = b[sortState.prop!]
    if (va == null && vb == null) return 0
    if (va == null) return dir
    if (vb == null) return -dir
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir
    if (typeof va === 'boolean' && typeof vb === 'boolean') return (Number(va) - Number(vb)) * dir
    return String(va).localeCompare(String(vb)) * dir
  })
}

function handlePageChange(page: number, pageSize: number) {
  pagination.page = page
  pagination.size = pageSize
  fetchUsers()
}

function handleCreate() {
  dialogTitle.value = t('user.createUser')
  userForm.id = ''
  userForm.username = ''
  userForm.email = ''
  userForm.password = ''
  userForm.confirmPassword = ''
  userForm.role = 'user'
  userForm.enabled = true
  formDirty.value = false
  dialogVisible.value = true
  nextTick(() => { initialFormJson.value = captureUserFormState() })
}

function handleEdit(row: User) {
  dialogTitle.value = t('common.edit')
  userForm.id = row.id
  userForm.username = row.username
  userForm.email = row.email
  userForm.role = row.role
  userForm.enabled = row.enabled
  userForm.confirmPassword = ''
  formDirty.value = false
  dialogVisible.value = true
  nextTick(() => { initialFormJson.value = captureUserFormState() })
}

function handleSelectionChange(selection: User[]) {
  selectedUsers.value = selection
}

function clearSelection() {
  selectedUsers.value = []
  proTableRef.value?.tableRef?.clearSelection()
}

async function handleBatchDelete() {
  if (selectedUsers.value.length === 0) return
  try {
    await ElMessageBox.confirm(
      t('user.batchDeleteConfirm', { count: selectedUsers.value.length }),
      t('common.confirm'),
      { type: 'warning' }
    )
    const results = await Promise.allSettled(
      selectedUsers.value.map(user => userApi.delete(user.id))
    )
    const succeeded = results.filter(r => r.status === 'fulfilled').length
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      ElMessage.warning(t('task.bulkPartial', { succeeded, failed }))
    } else {
      ElMessage.success(t('user.deleteSuccess'))
    }
    selectedUsers.value = []
    fetchUsers()
  } catch {
    // cancelled
  }
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
    const res = await userApi.resetPassword(row.id)
    const newPwd = (res.data as any)?.new_password || (res as any)?.data?.new_password
    if (newPwd) {
      ElMessageBox.alert(
        t('user.newPasswordIs', { password: newPwd }),
        t('user.resetPasswordSuccess'),
        { type: 'success', confirmButtonText: t('common.confirm') }
      )
    } else {
      ElMessage.success(t('user.resetPasswordSuccess'))
    }
  } catch { /* cancelled */ }
}

function handleAction(command: string, user: User) {
  switch (command) {
    case 'resetPassword':
      handleResetPassword(user)
      break
    case 'delete':
      handleDelete(user)
      break
  }
}

async function handleStatusChange(row: User, enabled: boolean) {
  try {
    await ElMessageBox.confirm(
      t('user.confirmToggleStatus'),
      t('common.confirm'),
      { type: 'warning' }
    )
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

function handleDialogBeforeClose(done: () => void) {
  if (formDirty.value) {
    ElMessageBox.confirm(t('common.unsavedChanges'), t('common.warning'), {
      confirmButtonText: t('common.discard'),
      cancelButtonText: t('common.cancel'),
      type: 'warning'
    }).then(() => {
      formDirty.value = false
      done()
    }).catch(() => {})
  } else {
    done()
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

.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  min-height: 32px;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.active-filters {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.batch-info {
  font-size: 13px;
  color: var(--tg-text-secondary, #64748B);
}

.user-name {
  font-weight: 500;
}

.action-buttons {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

@media (max-width: 768px) {
  .filter-bar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
