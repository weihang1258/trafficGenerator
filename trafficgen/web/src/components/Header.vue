<template>
  <div class="header-content">
    <div class="logo">
      <el-icon :size="24"><Connection /></el-icon>
      <span class="title">Traffic Generator</span>
    </div>
    <div class="header-actions">
      <!-- 语言切换 -->
      <el-dropdown @command="handleLanguageChange" class="language-dropdown">
        <span class="el-dropdown-link">
          <el-icon><Globe /></el-icon>
          {{ currentLanguageLabel }}
          <el-icon class="el-icon--right"><ArrowDown /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="zh-CN" :disabled="locale === 'zh-CN'">
              简体中文
            </el-dropdown-item>
            <el-dropdown-item command="en-US" :disabled="locale === 'en-US'">
              English
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>

      <!-- 用户菜单 -->
      <el-dropdown @command="handleCommand">
        <span class="el-dropdown-link">
          <el-icon><User /></el-icon>
          {{ username }}
          <el-icon class="el-icon--right"><ArrowDown /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="settings">
              <el-icon><Setting /></el-icon>
              {{ t('menu.settings') }}
            </el-dropdown-item>
            <el-dropdown-item command="logout" divided>
              <el-icon><SwitchButton /></el-icon>
              {{ t('login.logout') }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Connection, User, ArrowDown, Setting, SwitchButton, Globe } from '@element-plus/icons-vue'
import { setLocale } from '@/i18n'

const { t, locale } = useI18n()
const router = useRouter()
const username = ref('admin')

const currentLanguageLabel = computed(() => {
  return locale.value === 'zh-CN' ? '简体中文' : 'English'
})

const handleLanguageChange = (command: string) => {
  setLocale(command)
  ElMessage.success(command === 'zh-CN' ? '语言切换成功' : 'Language changed successfully')
}

const handleCommand = (command: string) => {
  if (command === 'settings') {
    router.push('/settings')
  } else if (command === 'logout') {
    ElMessageBox.confirm(t('login.logout') + '?', t('common.warning'), {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning'
    }).then(() => {
      // 清除 token
      localStorage.removeItem('token')
      ElMessage.success(t('login.logout') + t('common.success'))
      router.push('/login')
    }).catch(() => {
      // 取消退出
    })
  }
}
</script>

<style scoped>
.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 100%;
  padding: 0 20px;
}

.logo {
  display: flex;
  align-items: center;
  gap: 10px;
}

.title {
  font-size: 18px;
  font-weight: bold;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 20px;
}

.language-dropdown {
  margin-right: 10px;
}

.el-dropdown-link {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  color: white;
}
</style>