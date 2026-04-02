/**
 * WebSocket 客户端封装
 * 支持自动重连、心跳机制、消息队列
 */

type MessageHandler = (data: any) => void
type ErrorHandler = (error: Event) => void
type ConnectionHandler = () => void

interface WebSocketOptions {
  url: string
  reconnect?: boolean
  reconnectInterval?: number
  reconnectAttempts?: number
  heartbeatInterval?: number
  maxMessageSize?: number
}

class WebSocketClient {
  private ws: WebSocket | null = null
  private options: Required<WebSocketOptions>
  private reconnectCount = 0
  private reconnectTimer: number | null = null
  private heartbeatTimer: number | null = null
  private messageQueue: any[] = []
  private messageHandlers: Map<string, MessageHandler[]> = new Map()
  private errorHandlers: ErrorHandler[] = []
  private openHandlers: ConnectionHandler[] = []
  private closeHandlers: ConnectionHandler[] = []
  private isConnecting = false
  private isManualClose = false

  constructor(options: WebSocketOptions) {
    this.options = {
      reconnect: true,
      reconnectInterval: 3000,
      reconnectAttempts: 10,
      heartbeatInterval: 30000,
      maxMessageSize: 65536,
      ...options
    }
  }

  /**
   * 连接 WebSocket
   */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        resolve()
        return
      }

      if (this.isConnecting) {
        reject(new Error('WebSocket is connecting'))
        return
      }

      this.isConnecting = true
      this.isManualClose = false

      try {
        this.ws = new WebSocket(this.options.url)

        this.ws.onopen = () => {
          console.log('[WebSocket] Connected')
          this.isConnecting = false
          this.reconnectCount = 0
          this.startHeartbeat()
          this.flushMessageQueue()
          this.openHandlers.forEach(handler => handler())
          resolve()
        }

        this.ws.onmessage = (event) => {
          this.handleMessage(event.data)
        }

        this.ws.onerror = (error) => {
          console.error('[WebSocket] Error:', error)
          this.isConnecting = false
          this.errorHandlers.forEach(handler => handler(error))
          reject(error)
        }

        this.ws.onclose = (event) => {
          console.log('[WebSocket] Closed:', event.code, event.reason)
          this.isConnecting = false
          this.stopHeartbeat()
          this.closeHandlers.forEach(handler => handler())

          if (!this.isManualClose && this.options.reconnect) {
            this.reconnect()
          }
        }
      } catch (error) {
        this.isConnecting = false
        reject(error)
      }
    })
  }

  /**
   * 断开连接
   */
  disconnect(): void {
    this.isManualClose = true
    this.stopHeartbeat()
    this.stopReconnect()

    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  /**
   * 重新连接
   */
  private reconnect(): void {
    if (this.reconnectCount >= this.options.reconnectAttempts) {
      console.error('[WebSocket] Max reconnect attempts reached')
      return
    }

    this.reconnectCount++
    console.log(`[WebSocket] Reconnecting (${this.reconnectCount}/${this.options.reconnectAttempts})...`)

    this.reconnectTimer = window.setTimeout(() => {
      this.connect().catch(error => {
        console.error('[WebSocket] Reconnect failed:', error)
      })
    }, this.options.reconnectInterval)
  }

  /**
   * 停止重连
   */
  private stopReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  /**
   * 启动心跳
   */
  private startHeartbeat(): void {
    this.stopHeartbeat()

    this.heartbeatTimer = window.setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.send({ type: 'ping', timestamp: Date.now() })
      }
    }, this.options.heartbeatInterval)
  }

  /**
   * 停止心跳
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  /**
   * 发送消息
   */
  send(data: any): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn('[WebSocket] Connection not open, message queued')
      this.messageQueue.push(data)
      return false
    }

    try {
      const message = typeof data === 'string' ? data : JSON.stringify(data)

      if (message.length > this.options.maxMessageSize) {
        console.error('[WebSocket] Message size exceeds limit')
        return false
      }

      this.ws.send(message)
      return true
    } catch (error) {
      console.error('[WebSocket] Send error:', error)
      return false
    }
  }

  /**
   * 刷新消息队列
   */
  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift()
      this.send(message)
    }
  }

  /**
   * 处理消息
   */
  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data)

      // 处理 pong 响应
      if (message.type === 'pong') {
        return
      }

      // 根据 type 分发消息
      const { type, ...payload } = message
      const handlers = this.messageHandlers.get(type) || []
      handlers.forEach(handler => handler(payload))

      // 通配符处理器
      const wildcardHandlers = this.messageHandlers.get('*') || []
      wildcardHandlers.forEach(handler => handler(message))
    } catch (error) {
      console.error('[WebSocket] Parse message error:', error)
    }
  }

  /**
   * 订阅消息
   */
  on(type: string, handler: MessageHandler): void {
    const handlers = this.messageHandlers.get(type) || []
    handlers.push(handler)
    this.messageHandlers.set(type, handlers)
  }

  /**
   * 取消订阅
   */
  off(type: string, handler?: MessageHandler): void {
    if (!handler) {
      this.messageHandlers.delete(type)
      return
    }

    const handlers = this.messageHandlers.get(type) || []
    const index = handlers.indexOf(handler)
    if (index > -1) {
      handlers.splice(index, 1)
    }
  }

  /**
   * 订阅错误
   */
  onError(handler: ErrorHandler): void {
    this.errorHandlers.push(handler)
  }

  /**
   * 订阅连接打开
   */
  onOpen(handler: ConnectionHandler): void {
    this.openHandlers.push(handler)
  }

  /**
   * 订阅连接关闭
   */
  onClose(handler: ConnectionHandler): void {
    this.closeHandlers.push(handler)
  }

  /**
   * 获取连接状态
   */
  getReadyState(): number {
    return this.ws ? this.ws.readyState : WebSocket.CLOSED
  }

  /**
   * 是否已连接
   */
  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN
  }
}

/**
 * 创建 WebSocket 客户端
 */
export function createWebSocket(options: WebSocketOptions): WebSocketClient {
  return new WebSocketClient(options)
}

/**
 * 默认导出
 */
export default WebSocketClient
