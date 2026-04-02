<template>
  <div class="sidebar-menu">
    <el-menu
      :default-active="activeMenu"
      :router="true"
      background-color="#545c64"
      text-color="#fff"
      active-text-color="#409eff"
    >
      <el-menu-item index="/dashboard">
        <el-icon><Odometer /></el-icon>
        <span>{{ t('menu.dashboard') }}</span>
      </el-menu-item>

      <el-sub-menu index="tasks">
        <template #title>
          <el-icon><Document /></el-icon>
          <span>{{ t('menu.taskManagement') }}</span>
        </template>
        <el-menu-item index="/tasks">{{ t('menu.taskList') }}</el-menu-item>
        <el-menu-item index="/tasks/create">{{ t('menu.createTask') }}</el-menu-item>
      </el-sub-menu>

      <el-menu-item index="/strategies">
        <el-icon><Collection /></el-icon>
        <span>{{ t('menu.strategyManagement') }}</span>
      </el-menu-item>

      <el-menu-item index="/interfaces">
        <el-icon><Monitor /></el-icon>
        <span>{{ t('menu.interfaceManagement') }}</span>
      </el-menu-item>

      <el-menu-item index="/history">
        <el-icon><Clock /></el-icon>
        <span>{{ t('menu.history') }}</span>
      </el-menu-item>

      <el-menu-item index="/settings">
        <el-icon><Setting /></el-icon>
        <span>{{ t('menu.settings') }}</span>
      </el-menu-item>
    </el-menu>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  Odometer,
  Document,
  Collection,
  Monitor,
  Clock,
  Setting
} from '@element-plus/icons-vue'

const { t } = useI18n()
const route = useRoute()

const activeMenu = computed(() => {
  return route.path
})
</script>

<style scoped>
.sidebar-menu {
  border-right: none;
}

.el-menu {
  border-right: none;
}

.el-menu-item.is-active {
  background-color: #434a50 !important;
}
</style>
