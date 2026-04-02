import { describe, it, expect, beforeEach, vi } from 'vitest'
import WebSocketClient, { createWebSocket } from '@/utils/websocket'

describe('WebSocket Client', () => {
  let client: WebSocketClient
  let mockWebSocket: WebSocket

  beforeEach(() => {
    // Mock WebSocket
    mockWebSocket = {
      readyState: WebSocket.CONNECTING,
      send: vi.fn(),
      close: vi.fn(),
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null
    } as any

    global.WebSocket = vi.fn(() => mockWebSocket) as any

    client = createWebSocket({
      url: 'ws://localhost:8080/ws',
      reconnect: true,
      reconnectInterval: 1000,
      reconnectAttempts: 3,
      heartbeatInterval: 5000
    })
  })

  describe('connect', () => {
    it('should create WebSocket connection', async () => {
      const promise = client.connect()

      // Simulate successful connection
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)

      await promise

      expect(client.isConnected()).toBe(true)
    })

    it('should reject if already connecting', async () => {
      const promise1 = client.connect()

      // Try to connect again while connecting
      await expect(client.connect()).rejects.toThrow('WebSocket is connecting')

      // Clean up
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise1
    })
  })

  describe('send', () => {
    it('should send message when connected', async () => {
      // Connect first
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      const message = { type: 'test', data: 'hello' }
      const result = client.send(message)

      expect(result).toBe(true)
      expect(mockWebSocket.send).toHaveBeenCalledWith(JSON.stringify(message))
    })

    it('should queue message when not connected', () => {
      mockWebSocket.readyState = WebSocket.CLOSED

      const message = { type: 'test' }
      const result = client.send(message)

      expect(result).toBe(false)
    })

    it('should reject message exceeding size limit', async () => {
      // Connect first
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Create large message
      const largeMessage = { data: 'x'.repeat(100000) }
      const result = client.send(largeMessage)

      expect(result).toBe(false)
    })
  })

  describe('on/off', () => {
    it('should register message handler', async () => {
      const handler = vi.fn()
      client.on('test', handler)

      // Connect
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Simulate message
      const message = { type: 'test', data: 'hello' }
      mockWebSocket.onmessage!({ data: JSON.stringify(message) } as MessageEvent)

      expect(handler).toHaveBeenCalledWith({ data: 'hello' })
    })

    it('should remove message handler', async () => {
      const handler = vi.fn()
      client.on('test', handler)
      client.off('test', handler)

      // Connect
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Simulate message
      const message = { type: 'test', data: 'hello' }
      mockWebSocket.onmessage!({ data: JSON.stringify(message) } as MessageEvent)

      expect(handler).not.toHaveBeenCalled()
    })
  })

  describe('disconnect', () => {
    it('should close connection', async () => {
      // Connect first
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      client.disconnect()

      expect(mockWebSocket.close).toHaveBeenCalled()
      expect(client.isConnected()).toBe(false)
    })

    it('should not reconnect after manual disconnect', async () => {
      // Connect first
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      client.disconnect()

      // Simulate close event
      mockWebSocket.onclose!({ code: 1000, reason: 'Normal closure' } as CloseEvent)

      // Wait for potential reconnect
      await new Promise(resolve => setTimeout(resolve, 1500))

      expect(global.WebSocket).toHaveBeenCalledTimes(1)
    })
  })

  describe('heartbeat', () => {
    it('should send ping messages periodically', async () => {
      vi.useFakeTimers()

      // Connect
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Fast-forward time
      vi.advanceTimersByTime(5000)

      expect(mockWebSocket.send).toHaveBeenCalledWith(
        expect.stringContaining('"type":"ping"')
      )

      vi.useRealTimers()
    })
  })

  describe('reconnect', () => {
    it('should attempt to reconnect on connection loss', async () => {
      vi.useFakeTimers()

      // Connect
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Simulate connection loss
      mockWebSocket.readyState = WebSocket.CLOSED
      mockWebSocket.onclose!({ code: 1006, reason: 'Abnormal closure' } as CloseEvent)

      // Fast-forward to reconnect attempt
      vi.advanceTimersByTime(1000)

      expect(global.WebSocket).toHaveBeenCalledTimes(2)

      vi.useRealTimers()
    })

    it('should stop reconnecting after max attempts', async () => {
      vi.useFakeTimers()

      // Connect
      const promise = client.connect()
      mockWebSocket.readyState = WebSocket.OPEN
      mockWebSocket.onopen!({} as Event)
      await promise

      // Simulate multiple connection losses
      for (let i = 0; i < 5; i++) {
        mockWebSocket.readyState = WebSocket.CLOSED
        mockWebSocket.onclose!({ code: 1006, reason: 'Abnormal closure' } as CloseEvent)
        vi.advanceTimersByTime(1000)
      }

      // Should only attempt 3 reconnects (max attempts)
      expect(global.WebSocket).toHaveBeenCalledTimes(4) // Initial + 3 reconnects

      vi.useRealTimers()
    })
  })
})

describe('createWebSocket', () => {
  it('should create WebSocketClient instance', () => {
    const client = createWebSocket({
      url: 'ws://localhost:8080/ws'
    })

    expect(client).toBeInstanceOf(WebSocketClient)
  })
})
