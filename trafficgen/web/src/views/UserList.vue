<template>
  <div class="user-list">
    <el-card>
      <template #header>
        <ProCardHeader :title="t('user.title')">
          <template v-if="selectedUsers.length === 0">
            <el-button aria-label="Column settings" @click="proTableRef?.openColumnSettings()" circle size="small">
              <el-icon><Setting /></el-icon>
            </el-button>
            <el-button aria-label="Refresh" @click="refresh" circle size="small">
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
            <el-button size="small" link type="primary" @click="clearSelection(proTableRef?.tableRef)">{{ t('common.reset') }}</el-button>
          </template>
        </ProCardHeader>
      </template>

      <ProFilterBar :filters="searchForm" @reset="handleReset">
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
      </ProFilterBar>

      <ProTable
        ref="proTableRef"
        table-id="user-list"
        :columns="columns"
        :data="users"
        :loading="loading"
        :default-sort="{ prop: 'created_at', order: 'descending' }"
        :empty-text="t('user.noUsers')"
        @selection-change="handleSelectionChange"
        @sort-change="handleSortChange"
      >
        <template #username="{ row }">
          <span class="user-name">{{ row.username }}</span>
        </template>
        <template #role="{ row }">
          <el-tag :type="ROLE_TAG_TYPE[row.role] || 'info'" size="small">{{ getRoleText(row.role) }}</el-tag>
        </template>
        <template #enabled="{ row }">
          <div class="status-cell">
            <el-switch
              v-model="row.enabled"
              :disabled="row.username === 'admin'"
              @change="(val: boolean) => handleStatusChange(row, val)"
            />
            <span class="status-label" :class="{ 'status-active': row.enabled, 'status-disabled': !row.enabled }">
              {{ row.enabled ? t('user.active') : t('user.disabled') }}
            </span>
          </div>
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

    <ProDialog
      :visible="dialogVisible"
      :title="dialogTitle"
      width="500px"
      :dirty-guard="formDirty"
      @update:visible="dialogVisible = $event"
      @closed="handleDialogClose"
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
          <el-switch v-model="userForm.enabled" inline-prompt :active-text="t('user.active')" :inactive-text="t('user.disabled')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitLoading" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </ProDialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Plus, Search, Refresh, Setting, More } from '@element-plus/icons-vue'
import { userApi, authApi, type User } from '@/api'
import ProTable from '@/components/ProTable/index.vue'
import { formatTimestamp } from '@/utils/format'
import { createClientSort } from '@/utils/sort'
import { ROLE_TAG_TYPE } from '@/constants/status'
import { useClientList } from '@/composables/useClientList'
import { useSelection } from '@/composables/useSelection'
import { useBatchAction } from '@/composables/useBatchAction'
import { useFormDirty } from '@/composables/useFormDirty'
import ProCardHeader from '@/components/ProCardHeader/index.vue'
import ProFilterBar from '@/components/ProFilterBar/index.vue'
import ProDialog from '@/components/ProDialog/index.vue'

const { t } = useI18n()

const submitLoading = ref(false)
const proTableRef = ref()

const searchForm = reactive({
  username: '',
  role: ''
})

const { loading, data: users, sortState, refresh, handleSortChange } = useClientList({
  fetchFn: async () => {
    const params: any = {}
    if (searchForm.username) params.username = searchForm.username
    if (searchForm.role) params.role = searchForm.role
    const res = await userApi.list(params)
    return Array.isArray(res.data) ? res.data : (res.data as any).items || []
  },
  clientSort: (items, sort) => {
    if (!sort.prop || !sort.order) return items
    return [...items].sort(createClientSort(sort.prop as keyof User, sort.order))
  },
  defaultSort: { prop: 'created_at', order: 'descending' }
})

const { selectedItems: selectedUsers, handleSelectionChange, clearSelection } = useSelection<User>()

const batchDelete = useBatchAction<User>({
  action: (user) => userApi.delete(user.id),
  confirmMessage: (count) => t('user.batchDeleteConfirm', { count }),
  successMessage: (count) => t('user.deleteSuccess'),
  partialMessage: (succeeded, failed) => t('task.bulkPartial', { succeeded, failed })
})

const columns = computed(() => [
  { type: 'selection' as const, width: 45, fixed: 'left' },
  { prop: 'username', label: t('user.username'), width: 130, required: true, sortable: 'custom' },
  { prop: 'email', label: t('user.email'), minWidth: 180, sortable: 'custom' },
  { prop: 'role', label: t('user.role'), width: 90, sortable: 'custom' },
  { prop: 'enabled', label: t('user.status'), width: 140, sortable: 'custom' },
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

const formDirty = useFormDirty(userForm)

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

const getRoleText = (role: string) => {
  const texts: Record<string, string> = {
    admin: t('user.admin'),
    user: t('user.user'),
    guest: t('user.guest')
  }
  return texts[role] || role
}

function handleSearch() {
  refresh()
}

function handleReset() {
  searchForm.username = ''
  searchForm.role = ''
  refresh()
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
  dialogVisible.value = true
  nextTick(() => { formDirty.captureSnapshot() })
}

function handleEdit(row: User) {
  dialogTitle.value = t('common.edit')
  userForm.id = row.id
  userForm.username = row.username
  userForm.email = row.email
  userForm.role = row.role
  userForm.enabled = row.enabled
  userForm.confirmPassword = ''
  dialogVisible.value = true
  nextTick(() => { formDirty.captureSnapshot() })
}

async function handleBatchDelete() {
  await batchDelete.execute(selectedUsers.value)
  clearSelection(proTableRef.value?.tableRef)
  refresh()
}

async function handleDelete(row: User) {
  try {
    await ElMessageBox.confirm(t('user.confirmDelete'), t('common.confirm'), { type: 'warning' })
    await userApi.delete(row.id)
    ElMessage.success(t('user.deleteSuccess'))
    refresh()
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
    refresh()
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
  refresh()
})
</script>

<style scoped>
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

.status-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-label {
  font-size: 12px;
  font-weight: 500;
}

.status-active {
  color: var(--el-color-success);
}

.status-disabled {
  color: var(--el-color-danger);
}
</style>
