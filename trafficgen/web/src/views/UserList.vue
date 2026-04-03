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

      <!-- 搜索栏 -->
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
        <el-form-item :label="t('user.status')">
          <el-select v-model="searchForm.status" :placeholder="t('common.select')" clearable>
            <el-option :label="t('user.active')" value="active" />
            <el-option :label="t('user.disabled')" value="disabled" />
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

      <!-- 用户表格 -->
      <el-table :data="users" v-loading="loading" border stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" :label="t('user.username')" width="150" />
        <el-table-column prop="email" :label="t('user.email')" width="200" />
        <el-table-column prop="role" :label="t('user.role')" width="120">
          <template #default="{ row }">
            <el-tag :type="getRoleType(row.role)">{{ getRoleText(row.role) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="t('user.status')" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'danger'">
              {{ row.status === 'active' ? t('user.active') : t('user.disabled') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" :label="t('user.createdAt')" width="180" />
        <el-table-column prop="last_login" :label="t('user.lastLogin')" width="180" />
        <el-table-column :label="t('common.action')" width="250" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="handleEdit(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="warning" @click="handleResetPassword(row)">{{ t('user.resetPassword') }}</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">{{ t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <Pagination
        :total="total"
        :page="currentPage"
        :limit="pageSize"
        @pagination="handlePagination"
      />
    </el-card>

    <!-- 创建/编辑用户对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="500px"
      @close="handleDialogClose"
    >
      <el-form
        ref="formRef"
        :model="userForm"
        :rules="rules"
        label-width="100px"
      >
        <el-form-item :label="t('user.username')" prop="username">
          <el-input v-model="userForm.username" :placeholder="t('user.usernamePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('user.email')" prop="email">
          <el-input v-model="userForm.email" :placeholder="t('user.emailPlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('user.password')" prop="password" v-if="!userForm.id">
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
        <el-form-item :label="t('user.status')" prop="status">
          <el-radio-group v-model="userForm.status">
            <el-radio label="active">{{ t('user.active') }}</el-radio>
            <el-radio label="disabled">{{ t('user.disabled') }}</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import { Plus, Search, Refresh } from '@element-plus/icons-vue'
import Pagination from '@/components/Pagination.vue'

const { t } = useI18n()

interface User {
  id: string
  username: string
  email: string
  role: string
  status: string
  created_at: string
  last_login: string
}

const loading = ref(false)
const users = ref<User[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)

const searchForm = reactive({
  username: '',
  role: '',
  status: ''
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
  status: 'active'
})

const rules: FormRules = {
  username: [
    { required: true, message: t('user.usernamePlaceholder'), trigger: 'blur' },
    { min: 3, max: 20, message: '3-20 characters', trigger: 'blur' }
  ],
  email: [
    { required: true, message: t('user.emailPlaceholder'), trigger: 'blur' },
    { type: 'email', message: t('user.emailPlaceholder'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('user.passwordPlaceholder'), trigger: 'blur' },
    { min: 6, max: 20, message: '6-20 characters', trigger: 'blur' }
  ],
  role: [
    { required: true, message: t('user.selectRole'), trigger: 'change' }
  ],
  status: [
    { required: true, message: t('common.select'), trigger: 'change' }
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

const fetchUsers = async () => {
  loading.value = true
  try {
    // 模拟 API 调用
    await new Promise(resolve => setTimeout(resolve, 500))

    // 模拟数据
    users.value = [
      {
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
        status: 'active',
        created_at: '2026-01-01 10:00:00',
        last_login: '2026-04-02 09:30:00'
      },
      {
        id: '2',
        username: 'user1',
        email: 'user1@example.com',
        role: 'user',
        status: 'active',
        created_at: '2026-02-15 14:20:00',
        last_login: '2026-04-01 16:45:00'
      }
    ]
    total.value = 2
  } catch (error) {
    ElMessage.error(t('error.serverError'))
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  currentPage.value = 1
  fetchUsers()
}

const handleReset = () => {
  searchForm.username = ''
  searchForm.role = ''
  searchForm.status = ''
  handleSearch()
}

const handlePagination = (params: { page: number; limit: number }) => {
  currentPage.value = params.page
  pageSize.value = params.limit
  fetchUsers()
}

const handleCreate = () => {
  dialogTitle.value = t('user.createUser')
  userForm.id = ''
  userForm.username = ''
  userForm.email = ''
  userForm.password = ''
  userForm.role = 'user'
  userForm.status = 'active'
  dialogVisible.value = true
}

const handleEdit = (row: User) => {
  dialogTitle.value = t('common.edit')
  userForm.id = row.id
  userForm.username = row.username
  userForm.email = row.email
  userForm.role = row.role
  userForm.status = row.status
  dialogVisible.value = true
}

const handleDelete = (row: User) => {
  ElMessageBox.confirm(t('user.confirmDelete'), t('common.confirm'), {
    confirmButtonText: t('common.confirm'),
    cancelButtonText: t('common.cancel'),
    type: 'warning'
  }).then(() => {
    ElMessage.success(t('user.deleteSuccess'))
    fetchUsers()
  }).catch(() => {
    // 取消删除
  })
}

const handleResetPassword = (row: User) => {
  ElMessageBox.confirm(t('user.confirmResetPassword'), t('common.confirm'), {
    confirmButtonText: t('common.confirm'),
    cancelButtonText: t('common.cancel'),
    type: 'warning'
  }).then(() => {
    ElMessage.success(t('user.resetPasswordSuccess'))
  }).catch(() => {
    // 取消重置
  })
}

const handleSubmit = async () => {
  if (!formRef.value) return

  await formRef.value.validate((valid) => {
    if (valid) {
      ElMessage.success(userForm.id ? t('user.updateSuccess') : t('user.createSuccess'))
      dialogVisible.value = false
      fetchUsers()
    }
  })
}

const handleDialogClose = () => {
  formRef.value?.resetFields()
}

onMounted(() => {
  fetchUsers()
})
</script>

<style scoped>
.user-list {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-form {
  margin-bottom: 20px;
}
</style>
