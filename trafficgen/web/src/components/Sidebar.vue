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
        <span>仪表盘</span>
      </el-menu-item>

      <el-sub-menu index="tasks">
        <template #title>
          <el-icon><Document /></el-icon>
          <span>任务管理</span>
        </template>
        <el-menu-item index="/tasks">任务列表</el-menu-item>
        <el-menu-item index="/tasks/create">创建任务</el-menu-item>
      </el-sub-menu>

      <el-menu-item index="/strategies">
        <el-icon><Collection /></el-icon>
        <span>策略管理</span>
      </el-menu-item>

      <el-menu-item index="/interfaces">
        <el-icon><Monitor /></el-icon>
        <span>网卡管理</span>
      </el-menu-item>

      <el-menu-item index="/history">
        <el-icon><Clock /></el-icon>
        <span>历史记录</span>
      </el-menu-item>

      <el-menu-item index="/settings">
        <el-icon><Setting /></el-icon>
        <span>系统设置</span>
      </el-menu-item>
    </el-menu>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  Odometer,
  Document,
  Collection,
  Monitor,
  Clock,
  Setting
} from '@element-plus/icons-vue'

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
