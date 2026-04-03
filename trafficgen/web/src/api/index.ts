import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { ElMessage } from 'element-plus'
import i18n from '@/i18n'

// Get translate function
const t = (key: string) => i18n.global.t(key)

// Get API base URL from environment variable
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1'

// Create axios instance
const request: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor
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

// Response interceptor
request.interceptors.response.use(
  (response: AxiosResponse) => {
    const { data } = response
    if (data.code !== 0) {
      ElMessage.error(data.message || t('error.serverError'))
      return Promise.reject(new Error(data.message || t('error.serverError')))
    }
    return data
  },
  (error) => {
    if (error.response) {
      const { status } = error.response
      switch (status) {
        case 401:
          ElMessage.error(t('error.unauthorized'))
          localStorage.removeItem('token')
          window.location.href = '/login'
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
          ElMessage.error(error.message || t('error.networkError'))
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

// Task API
export interface Task {
  id: string
  name: string
  description: string
  protocol: string
  status: string
  progress: number
  stats: TaskStats
  created_at: number
  started_at?: number
  completed_at?: number
  error?: string
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
  description?: string
  protocol: string
  spec: FlowSpec
  interface?: string
  output_mode?: string
  pcap_file?: string
}

export interface FlowSpec {
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  src_mac?: string
  dst_mac?: string
  tcp?: TCPConfig
  udp?: UDPConfig
  http?: HTTPConfig
  dns?: DNSConfig
  icmp?: ICMPConfig
  payload?: string
  count?: number
}

export interface TCPConfig {
  handshake: boolean
  termination: boolean
  mss: number
  window_size: number
}

export interface UDPConfig {
  response: boolean
}

export interface HTTPConfig {
  method: string
  uri: string
  headers: Record<string, string>
  body: string
  keep_alive: boolean
  transactions: number
  think_time: number
}

export interface DNSConfig {
  domain: string
  query_type: number
  response: boolean
  response_ip?: string
}

export interface ICMPConfig {
  type: number
  code: number
  sequence: number
  data: string
}

// Task API functions
export const taskApi = {
  list: (params: { page?: number; size?: number; status?: string; protocol?: string }) =>
    request.get<any, ApiResponse<{ tasks: Task[]; total: number; page: number; size: number }>>('/tasks', { params }),

  get: (id: string) =>
    request.get<any, ApiResponse<Task>>(`/tasks/${id}`),

  create: (data: CreateTaskRequest) =>
    request.post<any, ApiResponse<{ task_id: string }>>('/tasks', data),

  start: (id: string) =>
    request.post<any, ApiResponse<null>>(`/tasks/${id}/start`),

  stop: (id: string) =>
    request.post<any, ApiResponse<null>>(`/tasks/${id}/stop`),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/tasks/${id}`),

  getPackets: (id: string, params: { count?: number; mode?: string }) =>
    request.get<any, ApiResponse<{ packets: number }>>(`/tasks/${id}/packets`, { params })
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
export interface NetworkInterface {
  name: string
  mac: string
  ip: string
  is_up: boolean
  link_up: boolean
  mtu: number
  description: string
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
}

export const authApi = {
  login: (data: LoginRequest) =>
    request.post<any, ApiResponse<LoginResponse>>('/auth/login', data),

  logout: () =>
    request.post<any, ApiResponse<null>>('/auth/logout'),

  refresh: () =>
    request.post<any, ApiResponse<LoginResponse>>('/auth/refresh')
}

// Strategy API
export interface Strategy {
  id: string
  name: string
  protocol: string
  config: Record<string, any>
  created_at: number
  updated_at: number
}

export const strategyApi = {
  list: (params: { page?: number; size?: number }) =>
    request.get<any, ApiResponse<{ strategies: Strategy[]; total: number }>>('/strategies', { params }),

  get: (id: string) =>
    request.get<any, ApiResponse<Strategy>>(`/strategies/${id}`),

  create: (data: { name: string; protocol: string; config: Record<string, any> }) =>
    request.post<any, ApiResponse<{ id: string }>>('/strategies', data),

  update: (id: string, data: Partial<Strategy>) =>
    request.put<any, ApiResponse<null>>(`/strategies/${id}`, data),

  delete: (id: string) =>
    request.delete<any, ApiResponse<null>>(`/strategies/${id}`)
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
