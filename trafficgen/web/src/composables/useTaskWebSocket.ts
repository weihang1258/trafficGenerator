import { ref, onUnmounted } from 'vue'
import { createWebSocket } from '@/utils/websocket'
import type { Task } from '@/api'

export function useTaskWebSocket(taskId?: string) {
  const connected = ref(false)
  const taskStatus = ref<Task | null>(null)
  const error = ref<string | null>(null)

  // Get WebSocket URL
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const wsUrl = taskId
    ? `${protocol}//${host}/ws/tasks/${taskId}`
    : `${protocol}//${host}/ws/tasks`

  // Create WebSocket client
  const ws = createWebSocket({
    url: wsUrl,
    reconnect: true,
    reconnectInterval: 3000,
    reconnectAttempts: 10,
    heartbeatInterval: 30000
  })

  // Handle connection open
  ws.onOpen(() => {
    connected.value = true
    error.value = null
    console.log('[TaskWebSocket] Connected')
  })

  // Handle connection close
  ws.onClose(() => {
    connected.value = false
    console.log('[TaskWebSocket] Disconnected')
  })

  // Handle errors
  ws.onError((err) => {
    error.value = 'WebSocket connection error'
    console.error('[TaskWebSocket] Error:', err)
  })

  // Handle task status updates
  ws.on('task_status', (data) => {
    taskStatus.value = data as Task
  })

  // Handle task update messages
  ws.on('task_update', (data) => {
    taskStatus.value = data as Task
  })

  // Connect
  const connect = async () => {
    try {
      await ws.connect()
    } catch (err) {
      console.error('[TaskWebSocket] Connect failed:', err)
      error.value = 'Failed to connect to WebSocket'
    }
  }

  // Disconnect
  const disconnect = () => {
    ws.disconnect()
  }

  // Subscribe to specific task
  const subscribeTask = (id: string) => {
    ws.send({
      type: 'subscribe',
      task_id: id
    })
  }

  // Unsubscribe from task
  const unsubscribeTask = (id: string) => {
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
    error,
    connect,
    disconnect,
    subscribeTask,
    unsubscribeTask
  }
}
