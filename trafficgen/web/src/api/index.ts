import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { ElMessage } from 'element-plus'
import i18n from '@/i18n'

const t = (key: string) => {
  try { return i18n.global.t(key) } catch { return key }
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1'

const request: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

request.interceptors.request.use(
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

request.interceptors.response.use(
  (response: AxiosResponse) => {
    const { data } = response
    if (typeof data !== 'object' || data === null || data.code === undefined) {
      return data
    }
    if (data.code !== 0) {
      ElMessage.error(data.message || t('error.serverError'))
      return Promise.reject(new Error(data.message || t('error.serverError')))
    }
    return data
  },
  (error) => {
    if (error.response) {
      const { status } = error.response
      const serverMsg = error.response.data?.message || ''
      switch (status) {
        case 400:
          ElMessage.error(serverMsg || t('error.badRequest'))
          break
        case 401:
          // Don't redirect on auth pages — let the component handle the error
          const isAuthRequest = error.config?.url?.includes('/auth/login') || error.config?.url?.includes('/auth/register')
          if (!isAuthRequest) {
            ElMessage.error(t('error.unauthorized'))
            localStorage.removeItem('token')
            localStorage.removeItem('token_expires_at')
            // Use router push instead of hard redirect to preserve Vue state
            import('@/router').then(({ default: router }) => {
              router.push('/login')
            })
          }
          break
        case 403:
          ElMessage.error(t('error.forbidden'))
          break
        case 404:
          ElMessage.error(t('error.notFound'))
          break
        case 500:
          ElMessage.error(t('error.serverError'))
          break
        default:
          ElMessage.error(serverMsg || error.message || t('error.networkError'))
      }
    } else {
      ElMessage.error(t('error.networkError'))
    }
    return Promise.reject(error)
  }
)

export default request

// API response types
export interface ApiResponse<T = any> {
  code: number
  message: string
  data?: T
}

// Flow Control / Output Config — deprecated aliases. Single truth is
// ./schema-types.ts (generated from schemas/v1 by tools/webgen.py).
// Backend accepts only flows|bps|time; cps/ratio were dropped server-side.
import type { FlowControl as SchemaFlowControl, OutputConfig as SchemaOutputConfig, OutputType as SchemaOutputType, Strategy as SchemaStrategy, Task as SchemaTask } from './schema-types'
export type FlowControlRequest = SchemaFlowControl
export type OutputConfigRequest = SchemaOutputConfig

// Task = generated base (task.json) plus UI-only live-view extra stats
// (progress snapshot assembled by the task handler, not in task.json).
export interface Task extends SchemaTask {
  stats?: TaskStats
}

export interface TaskStats {
  packets_sent: number
  bytes_sent: number
  flows_count: number
  current_pps: number
  current_bps: number
}

export interface CreateTaskRequest {
  name: string
  strategy_ids: string[]
  output_type: SchemaOutputType
  output_config: OutputConfigRequest
  flow_control?: FlowControlRequest
}

export const taskApi = {
  list: (params?: { page?: number; size?: number; status?: string; protocol?: string; sort_by?: string; sort_order?: string }) =>
    request.get<any, ApiResponse<{ items: Task[]; total: number; page: number; size: number }>>('/tasks', { params }),

  get: (id: string) =>
    request.get<any, ApiResponse<Task>>(`/tasks/${id}`),

  create: (data: CreateTaskRequest) =>
    request.post<any, ApiResponse<{ id: string }>>('/tasks', data),

  start: (id: string) =>
    request.post<any, ApiResponse<null>>(`/tasks/${id}/start`),

  stop: (id: string) =>
    request.post<any, ApiResponse<null>>(`/tasks/${id}/stop`),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/tasks/${id}`)
}

// System API
export interface SystemStatus {
  running: boolean
  cpu_usage: number
  memory_mb: number
  active_tasks: number
  buffer_status: Record<string, any>
  uptime: number
}

export const systemApi = {
  getStatus: () =>
    request.get<any, ApiResponse<SystemStatus>>('/system/status'),

  getProtocols: () =>
    request.get<any, ApiResponse<string[]>>('/system/protocols'),

  getStats: () =>
    request.get<any, ApiResponse<Record<string, any>>>('/system/stats')
}

// Interface API
export interface PortAllocation {
  port: number
  task_id: string
  allocated_at: string
}

export interface NetworkInterface {
  name: string
  mac: string
  ips: string[]
  is_up: boolean
  link_up: boolean
  mtu: number
  description: string
  is_virtual: boolean
  in_use: boolean
  allocations?: PortAllocation[]
}

export const interfaceApi = {
  list: () =>
    request.get<any, ApiResponse<NetworkInterface[]>>('/interfaces'),

  discover: () =>
    request.post<any, ApiResponse<null>>('/interfaces/discover')
}

// Auth API
export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expires_at: number
  user_id: string
  username: string
}

export const authApi = {
  login: (data: LoginRequest) =>
    request.post<any, ApiResponse<LoginResponse>>('/auth/login', data),

  register: (data: LoginRequest & { email?: string }) =>
    request.post<any, ApiResponse<LoginResponse>>('/auth/register', data),

  validate: () =>
    request.get<any, ApiResponse<{ valid: boolean; user_id: string; username: string }>>('/auth/validate'),

  logout: () =>
    request.post<any, ApiResponse<null>>('/auth/logout'),

  refresh: () =>
    request.post<any, ApiResponse<LoginResponse>>('/auth/refresh')
}

// Strategy API
// Deprecated alias: single truth is SchemaStrategy in ./schema-types.ts.
export type Strategy = SchemaStrategy

export interface TaskBrief {
  id: string
  name: string
  status: string
}

export const strategyApi = {
  list: (params?: { page?: number; size?: number }) =>
    request.get<any, ApiResponse<Strategy[]>>('/strategies', { params }),

  get: (id: string) =>
    request.get<any, ApiResponse<Strategy>>(`/strategies/${id}`),

  getTasks: (id: string) =>
    request.get<any, ApiResponse<TaskBrief[]>>(`/strategies/${id}/tasks`),

  create: (data: { name: string; protocol: string; config: Record<string, any>; flow_control?: FlowControlRequest }) =>
    request.post<any, ApiResponse<{ id: string }>>('/strategies', data),

  update: (id: string, data: Partial<Strategy>) =>
    request.put<any, ApiResponse<null>>(`/strategies/${id}`, data),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/strategies/${id}`)
}

// Port API
export interface Port {
  id: string
  name: string
  type: string      // "libpcap" or "dpdk"
  pci_address: string
  status: string    // "idle", "using", "maintenance"
  current_task_id: string
  created_at: number
  updated_at: number
}

export const portApi = {
  list: () =>
    request.get<any, ApiResponse<Port[]>>('/ports')
}

// Port Group API
export interface PortConfig {
  interface: string
  weight: number
}

export interface PortGroup {
  id: string
  name: string
  ports_config: PortConfig[]
  created_at: number
  updated_at: number
}

export const portGroupApi = {
  list: () =>
    request.get<any, ApiResponse<PortGroup[]>>('/port-groups'),

  get: (id: string) =>
    request.get<any, ApiResponse<PortGroup>>(`/port-groups/${id}`),

  create: (data: { ports: PortConfig[] }) =>
    request.post<any, ApiResponse<{ id: string; name: string }>>('/port-groups', data),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/port-groups/${id}`)
}

// Settings API
export interface Settings {
  max_tasks: number
  buffer_size: number
  log_level: string
}

export const settingsApi = {
  get: () =>
    request.get<any, ApiResponse<Settings>>('/settings'),

  update: (data: Partial<Settings>) =>
    request.put<any, ApiResponse<null>>('/settings', data)
}

// User Management API (admin only)
export interface User {
  id: string
  username: string
  email: string
  role: string
  enabled: boolean
  created_at: number
  updated_at: number
  last_login: number
}

export const userApi = {
  list: (params?: { username?: string; role?: string; status?: string; page?: number; size?: number }) =>
    request.get<any, ApiResponse<User[]>>('/users', { params }),

  update: (id: string, data: Partial<User>) =>
    request.put<any, ApiResponse<null>>(`/users/${id}`, data),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/users/${id}`),

  resetPassword: (id: string) =>
    request.post<any, ApiResponse<null>>(`/users/${id}/reset-password`)
}

// History API
export interface HistoryRecord {
  task_id: string
  name: string
  protocol: string
  status: string
  packets_sent: number
  bytes_sent: number
  duration: number
  created_at: number
  updated_at: number
}

export const historyApi = {
  list: (params?: { start_time?: number; end_time?: number; status?: string; sort_by?: string; sort_order?: string; page?: number; size?: number }) =>
    request.get<any, ApiResponse<HistoryRecord[]>>('/history', { params })
}
