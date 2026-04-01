# 前端设计 - API封装

**文档版本**: v1.0  
**更新日期**: 2026-04-01

---

## 1. Axios实例配置

```typescript
// src/api/request.ts
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { ElMessage } from 'element-plus'

const instance: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
instance.interceptors.response.use(
  (response: AxiosResponse) => {
    const { code, data, message } = response.data
    if (code === 0) {
      return data
    } else {
      ElMessage.error(message || 'Request failed')
      return Promise.reject(new Error(message))
    }
  },
  (error) => {
    if (error.response?.status === 401) {
      ElMessage.error('Unauthorized, please login')
      // 跳转登录页
      window.location.href = '/login'
    } else if (error.response?.status === 429) {
      ElMessage.error('Rate limit exceeded')
    } else {
      ElMessage.error(error.message || 'Network error')
    }
    return Promise.reject(error)
  }
)

export default instance
```

---

## 2. API模块封装

```typescript
// src/api/task.ts
import request from './request'

export interface Task {
  id: string
  name: string
  status: string
  progress: number
}

export interface CreateTaskRequest {
  name: string
  description?: string
  spec: any
}

export const taskApi = {
  // 创建任务
  create(data: CreateTaskRequest) {
    return request.post<{ task_id: string }>('/tasks', data)
  },
  
  // 获取任务
  get(id: string) {
    return request.get<Task>(`/tasks/${id}`)
  },
  
  // 任务列表
  list(params: { page: number; size: number; status?: string }) {
    return request.get<{ tasks: Task[]; total: number }>('/tasks', { params })
  },
  
  // 启动任务
  start(id: string) {
    return request.post(`/tasks/${id}/start`)
  },
  
  // 停止任务
  stop(id: string) {
    return request.post(`/tasks/${id}/stop`)
  },
  
  // 删除任务
  delete(id: string) {
    return request.delete(`/tasks/${id}`)
  }
}
```

---

## 3. 使用示例

```typescript
// src/views/TaskList.vue
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { taskApi } from '@/api/task'

const tasks = ref<Task[]>([])
const loading = ref(false)

const fetchTasks = async () => {
  loading.value = true
  try {
    const { tasks: data, total } = await taskApi.list({ page: 1, size: 20 })
    tasks.value = data
  } catch (error) {
    console.error('Fetch tasks failed:', error)
  } finally {
    loading.value = false
  }
}

const handleStart = async (id: string) => {
  try {
    await taskApi.start(id)
    ElMessage.success('Task started')
    fetchTasks()
  } catch (error) {
    // 错误已在拦截器处理
  }
}

onMounted(() => {
  fetchTasks()
})
</script>
```

---

## 4. 类型定义

```typescript
// src/types/api.ts
export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

export interface PaginationParams {
  page: number
  size: number
}

export interface PaginationResponse<T> {
  items: T[]
  total: number
  page: number
  size: number
}
```
