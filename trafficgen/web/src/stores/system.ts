import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { healthCheck, getBufferStatus, getSystemInfo, getSystemLogs } from '@/api/system'
import type { BufferStatus, SystemInfo } from '@/api/system'

export const useSystemStore = defineStore('system', () => {
  // State
  const health = ref<{ status: string; timestamp: string } | null>(null)
  const bufferStatus = ref<BufferStatus | null>(null)
  const systemInfo = ref<SystemInfo | null>(null)
  const logs = ref<string[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Getters
  const isHealthy = computed(() => {
    return health.value?.status === 'healthy'
  })

  const bufferUsage = computed(() => {
    if (!bufferStatus.value) return 0
    return bufferStatus.value.combined.usage
  })

  const bufferCount = computed(() => {
    if (!bufferStatus.value) return 0
    return bufferStatus.value.combined.count
  })

  const bufferSize = computed(() => {
    if (!bufferStatus.value) return 0
    return bufferStatus.value.combined.size
  })

  const uptime = computed(() => {
    if (!systemInfo.value) return 0
    return systemInfo.value.uptime
  })

  const uptimeFormatted = computed(() => {
    const seconds = uptime.value
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)

    if (days > 0) {
      return `${days}天 ${hours}小时 ${minutes}分钟`
    } else if (hours > 0) {
      return `${hours}小时 ${minutes}分钟`
    } else {
      return `${minutes}分钟`
    }
  })

  // Actions
  const checkHealth = async () => {
    try {
      const response = await healthCheck()
      health.value = response
      return response
    } catch (err: any) {
      error.value = err.message || '健康检查失败'
      throw err
    }
  }

  const fetchBufferStatus = async () => {
    try {
      const status = await getBufferStatus()
      bufferStatus.value = status
      return status
    } catch (err: any) {
      error.value = err.message || '获取缓冲区状态失败'
      throw err
    }
  }

  const fetchSystemInfo = async () => {
    try {
      const info = await getSystemInfo()
      systemInfo.value = info
      return info
    } catch (err: any) {
      error.value = err.message || '获取系统信息失败'
      throw err
    }
  }

  const fetchLogs = async (params?: { level?: string; limit?: number; offset?: number }) => {
    loading.value = true
    error.value = null

    try {
      const response = await getSystemLogs(params)
      logs.value = response
      return response
    } catch (err: any) {
      error.value = err.message || '获取系统日志失败'
      throw err
    } finally {
      loading.value = false
    }
  }

  const refreshAll = async () => {
    loading.value = true
    error.value = null

    try {
      await Promise.all([
        checkHealth(),
        fetchBufferStatus(),
        fetchSystemInfo()
      ])
    } catch (err: any) {
      error.value = err.message || '刷新系统状态失败'
      throw err
    } finally {
      loading.value = false
    }
  }

  const clearError = () => {
    error.value = null
  }

  return {
    // State
    health,
    bufferStatus,
    systemInfo,
    logs,
    loading,
    error,

    // Getters
    isHealthy,
    bufferUsage,
    bufferCount,
    bufferSize,
    uptime,
    uptimeFormatted,

    // Actions
    checkHealth,
    fetchBufferStatus,
    fetchSystemInfo,
    fetchLogs,
    refreshAll,
    clearError
  }
})