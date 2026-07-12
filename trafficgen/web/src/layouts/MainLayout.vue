<template>
  <el-container class="main-layout">
    <!-- Collapsible Sidebar -->
    <el-aside :width="isCollapsed ? '64px' : '220px'" class="sidebar" :class="{ open: isMobileOpen }">
      <div class="logo" :class="{ collapsed: isCollapsed }">
        <el-icon :size="24"><Connection /></el-icon>
        <span v-show="!isCollapsed" class="logo-text">{{ t('app.title') }}</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        router
        :collapse="isCollapsed"
        :collapse-transition="false"
        class="sidebar-menu"
      >
        <template v-for="route in menuRoutes" :key="route.path">
          <el-menu-item :index="'/' + route.path">
            <el-icon><component :is="route.meta?.icon" /></el-icon>
            <template #title>
              <span>{{ t(route.meta?.title as string) }}</span>
            </template>
          </el-menu-item>
        </template>
      </el-menu>
    </el-aside>

    <!-- Mobile overlay -->
    <div v-if="isMobileOpen" class="mobile-overlay" @click="isMobileOpen = false" />

    <el-container class="content-container">
      <el-header class="header">
        <div class="header-left">
          <el-button link class="collapse-btn" @click="toggleSidebar">
            <el-icon :size="20"><Fold v-if="!isCollapsed" /><Expand v-else /></el-icon>
          </el-button>
          <el-breadcrumb separator="/">
            <el-breadcrumb-item :to="{ path: '/dashboard' }">{{ t('menu.dashboard') }}</el-breadcrumb-item>
            <el-breadcrumb-item v-if="parentRoute" :to="parentRoute.to">
              {{ parentRoute.label }}
            </el-breadcrumb-item>
            <el-breadcrumb-item v-if="route.path !== '/dashboard'">
              {{ t(route.meta?.title as string) }}
            </el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <el-tooltip :content="isDark ? t('settings.lightMode') : t('settings.darkMode')" placement="bottom">
            <el-button link circle @click="toggleDark">
              <el-icon><component :is="isDark ? Sunny : Moon" /></el-icon>
            </el-button>
          </el-tooltip>
          <el-dropdown @command="handleCommand">
            <span class="user-dropdown">
              <el-icon><User /></el-icon>
              <span class="username">{{ userStore.username }}</span>
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="settings">{{ t('menu.settings') }}</el-dropdown-item>
                <el-dropdown-item command="logout" divided>{{ t('login.logout') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="main">
        <router-view />
      </el-main>
      <ShortcutHelp ref="shortcutHelpRef" />
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useUserStore } from '@/stores/user'
import { Connection, User, ArrowDown, Fold, Expand, Sunny, Moon } from '@element-plus/icons-vue'
import ShortcutHelp from '@/components/ShortcutHelp.vue'
import { useKeyboardShortcuts } from '@/composables/useKeyboardShortcuts'
import { useDarkMode } from '@/composables/useDarkMode'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const userStore = useUserStore()
const { getShortcutsList } = useKeyboardShortcuts()
const { isDark, toggleDark } = useDarkMode()
const shortcutHelpRef = ref()

const activeMenu = computed(() => {
  const path = route.path
  if (path.startsWith('/tasks')) return '/tasks'
  return path
})
const isCollapsed = ref(false)

const parentRoute = computed(() => {
  const path = route.path
  if (path === '/tasks/create' || path.match(/^\/tasks\/[^/]+$/)) {
    return { to: '/tasks', label: t('menu.taskManagement') }
  }
  return null
})
const isMobileOpen = ref(false)
const shortcutsList = computed(() => getShortcutsList())

const menuRoutes = computed(() => {
  const mainRoute = router.options.routes.find(r => r.path === '/')
  return mainRoute?.children?.filter(r => !r.meta?.hidden) || []
})

function handleCommand(command: string) {
  switch (command) {
    case 'settings':
      router.push('/settings')
      break
    case 'logout':
      userStore.logout()
      router.push('/login')
      break
  }
}

function toggleSidebar() {
  const isMobile = window.innerWidth <= 768
  if (isMobile) {
    isMobileOpen.value = !isMobileOpen.value
  } else {
    isCollapsed.value = !isCollapsed.value
  }
}
</script>

<style scoped>
.main-layout {
  height: 100vh;
  overflow: hidden;
}

.content-container {
  height: 100vh;
  overflow: hidden;
}

.content-container :deep(.el-main) {
  --el-main-padding: 16px 20px;
}

.sidebar {
  background-color: var(--tg-bg-card, #FFFFFF);
  border-right: 1px solid var(--tg-border-light, #E5E7EB);
  transition: width 0.3s ease;
  overflow-y: auto;
  overflow-x: hidden;
}

.sidebar-menu {
  border-right: none;
  --el-menu-bg-color: transparent;
  --el-menu-text-color: var(--tg-text-secondary, #64748B);
  --el-menu-active-color: var(--tg-primary, #2563EB);
  --el-menu-hover-bg-color: var(--tg-bg-hover, #F1F5F9);
}

.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: var(--tg-text-primary, #0F172A);
  font-size: 16px;
  font-weight: bold;
  border-bottom: 1px solid var(--tg-border-light, #E5E7EB);
}

.header {
  background-color: var(--tg-bg-card);
  box-shadow: var(--tg-shadow-sm);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  height: var(--el-header-height);
}

.header-left {
  display: flex;
  align-items: center;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 4px;
}

.user-dropdown {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
}

.main {
  background-color: var(--tg-bg-page);
  overflow-y: auto;
}

.logo-text {
  white-space: nowrap;
  overflow: hidden;
  transition: opacity 0.3s ease;
}

.collapse-btn {
  margin-right: 12px;
  padding: 4px 8px;
}

.username {
  margin-left: 4px;
}

.mobile-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: var(--tg-bg-overlay, rgba(0, 0, 0, 0.5));
  z-index: 999;
}

@media (max-width: 768px) {
  .sidebar {
    position: fixed;
    left: 0;
    top: 0;
    height: 100vh;
    z-index: 1000;
    width: 220px !important;
    transform: translateX(-100%);
    transition: transform 0.3s ease;
  }

  .sidebar.open {
    transform: translateX(0);
  }

  .main {
    padding: 12px;
  }

  .header {
    padding: 0 12px;
  }
}
</style>