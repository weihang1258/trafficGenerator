import { ref, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { createWebSocket } from '@/utils/websocket'
import type { Task, TaskStats } from '@/api'

/** WebSocket progress update message data (after flattening) */
interface WSProgressData {
  task_id?: string
  progress?: number
  stats?: TaskStats
  timestamp?: number
}

/** WebSocket task completion/failure message data (after flattening) */
interface WSTaskEventData {
  task_id?: string
  status?: string
  progress?: number
  timestamp?: number
}

export function useTaskWebSocket() {
  const { t } = useI18n()
  const connected = ref(false)
  const taskStatus = ref<Task | null>(null)
  const progress = ref<number>(0)
  const stats = ref<TaskStats | null>(null)
  const error = ref<string | null>(null)
  const subscribedTaskId = ref<string | null>(null)

  // Build WebSocket URL - read token from localStorage at connection time
  // to ensure fresh token after re-login (not stale from composable init)
  const buildWsUrl = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const token = localStorage.getItem('token') || ''
    return `${protocol}//${host}/ws${token ? '?token=' + encodeURIComponent(token) : ''}`
  }

  // Create WebSocket client - pass function so URL is resolved at connect time
  const ws = createWebSocket({
    url: buildWsUrl,
    reconnect: true,
    reconnectInterval: 3000,
    reconnectAttempts: 10,
    heartbeatInterval: 30000
  })

  // Handle connection open
  ws.onOpen(() => {
    connected.value = true
    error.value = null
    // Re-subscribe to previously subscribed task after reconnect
    if (subscribedTaskId.value) {
      ws.send({
        type: 'subscribe',
        task_id: subscribedTaskId.value
      })
    }
  })

  // Handle connection close
  ws.onClose(() => {
    connected.value = false
  })

  // Handle errors
  ws.onError(() => {
    error.value = t('error.networkError')
  })

  // Handle status updates (task status changed)
  ws.on('status_update', (data: Record<string, unknown>) => {
    taskStatus.value = data as unknown as Task
  })

  // Handle stats updates
  ws.on('stats_update', (data: Record<string, unknown>) => {
    if (data.stats) {
      stats.value = data.stats as TaskStats
    }
  })

  // Handle progress updates
  // After websocket.ts flattening, data contains: task_id, progress, stats, timestamp
  ws.on('progress_update', (data: WSProgressData) => {
    progress.value = data.progress || 0
    if (data.stats) {
      stats.value = data.stats
    }
  })

  // Handle task completion
  ws.on('task_completed', (data: WSTaskEventData) => {
    if (data.task_id) {
      progress.value = 100
    }
    taskStatus.value = { ...taskStatus.value, ...data } as unknown as Task
  })

  // Handle task failure
  ws.on('task_failed', (data: WSTaskEventData) => {
    taskStatus.value = { ...taskStatus.value, ...data } as unknown as Task
  })

  // Connect
  const connect = async () => {
    try {
      await ws.connect()
    } catch (err) {
      console.error('[TaskWebSocket] Connect failed:', err)
      error.value = t('error.networkError')
    }
  }

  // Disconnect
  const disconnect = () => {
    ws.disconnect()
  }

  // Subscribe to specific task
  const subscribeTask = (id: string) => {
    subscribedTaskId.value = id
    ws.send({
      type: 'subscribe',
      task_id: id
    })
  }

  // Unsubscribe from task
  const unsubscribeTask = (id: string) => {
    subscribedTaskId.value = null
    ws.send({
      type: 'unsubscribe',
      task_id: id
    })
  }

  // Cleanup on unmount
  onUnmounted(() => {
    disconnect()
  })

  return {
    connected,
    taskStatus,
    progress,
    stats,
    error,
    connect,
    disconnect,
    subscribeTask,
    unsubscribeTask
  }
}
