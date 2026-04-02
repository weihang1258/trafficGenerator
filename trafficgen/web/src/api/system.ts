import request from './index'

export interface SystemHealth {
  status: string
  timestamp: string
}

export interface BufferStatus {
  combined: {
    count: number
    size: number
    usage: number
  }
}

export interface SystemInfo {
  version: string
  uptime: number
  go_version: string
  os: string
  arch: string
}

/**
 * 健康检查
 */
export function healthCheck(): Promise<SystemHealth> {
  return request({
    url: '/system/health',
    method: 'get'
  })
}

/**
 * 获取系统指标
 */
export function getMetrics(): Promise<string> {
  return request({
    url: '/system/metrics',
    method: 'get',
    responseType: 'text'
  })
}

/**
 * 获取缓冲区状态
 */
export function getBufferStatus(): Promise<BufferStatus> {
  return request({
    url: '/buffer/status',
    method: 'get'
  })
}

/**
 * 获取系统信息
 */
export function getSystemInfo(): Promise<SystemInfo> {
  return request({
    url: '/system/info',
    method: 'get'
  })
}

/**
 * 获取系统日志
 */
export function getSystemLogs(params?: {
  level?: string
  limit?: number
  offset?: number
}): Promise<string[]> {
  return request({
    url: '/system/logs',
    method: 'get',
    params
  })
}
