import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    meta: { requiresAuth: true },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: 'menu.dashboard', icon: 'Odometer' }
      },
      {
        path: 'strategies',
        name: 'Strategies',
        component: () => import('@/views/StrategyList.vue'),
        meta: { title: 'menu.strategyManagement', icon: 'Setting' }
      },
      {
        path: 'tasks',
        name: 'Tasks',
        component: () => import('@/views/TaskList.vue'),
        meta: { title: 'menu.taskManagement', icon: 'List' }
      },
      {
        path: 'tasks/create',
        name: 'TaskCreate',
        component: () => import('@/views/TaskCreate.vue'),
        meta: { title: 'menu.createTask', icon: 'Plus', hidden: true }
      },
      {
        path: 'tasks/:id',
        name: 'TaskDetail',
        component: () => import('@/views/TaskDetail.vue'),
        meta: { title: 'task.taskDetail', icon: 'Document', hidden: true }
      },
      {
        path: 'interfaces',
        name: 'Interfaces',
        component: () => import('@/views/InterfaceList.vue'),
        meta: { title: 'menu.interfaceManagement', icon: 'Connection' }
      },
      {
        path: 'history',
        name: 'History',
        component: () => import('@/views/History.vue'),
        meta: { title: 'menu.history', icon: 'Clock' }
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: 'menu.settings', icon: 'Tools' }
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/UserList.vue'),
        meta: { title: 'menu.userManagement', icon: 'User' }
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/dashboard'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation guard
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  const expiresAt = localStorage.getItem('token_expires_at')
  const isExpired = expiresAt ? Date.now() / 1000 > Number(expiresAt) : true

  // Clear expired tokens
  if (token && isExpired) {
    localStorage.removeItem('token')
    localStorage.removeItem('token_expires_at')
  }

  const hasValidToken = token && !isExpired

  if (to.meta.requiresAuth !== false && !hasValidToken) {
    next('/login')
  } else if (to.path === '/login' && hasValidToken) {
    next('/')
  } else {
    next()
  }
})

export default router
