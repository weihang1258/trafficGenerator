// Package websocket provides WebSocket functionality for real-time updates.
package websocket

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Message types.
const (
	TypeStatusUpdate = "status_update"
	TypeStatsUpdate  = "stats_update"
	TypeError        = "error"
	TypeCompleted    = "completed"
	TypeHeartbeat    = "heartbeat"
)

// Message represents a WebSocket message.
type Message struct {
	Type      string      `json:"type"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// Client represents a WebSocket client.
type Client struct {
	conn     *websocket.Conn
	send     chan []byte
	hub      *Hub
	taskID   string // Subscribed task ID (empty for all)
	mu       sync.Mutex
	lastPing time.Time
}

// Hub maintains active WebSocket connections.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			zap.L().Debug("client connected", zap.Int("total", len(h.clients)))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			zap.L().Debug("client disconnected", zap.Int("total", len(h.clients)))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends a message to all clients.
func (h *Hub) Broadcast(msg Message) {
	msg.Timestamp = time.Now().Unix()
	data, err := json.Marshal(msg)
	if err != nil {
		zap.L().Error("failed to marshal message", zap.Error(err))
		return
	}
	h.broadcast <- data
}

// BroadcastToTask sends a message to clients subscribed to a task.
func (h *Hub) BroadcastToTask(taskID string, msg Message) {
	msg.Timestamp = time.Now().Unix()
	data, err := json.Marshal(msg)
	if err != nil {
		zap.L().Error("failed to marshal message", zap.Error(err))
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if client.taskID == "" || client.taskID == taskID {
			select {
			case client.send <- data:
			default:
				// Client buffer full, skip
			}
		}
	}
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Upgrader is the WebSocket upgrader.
var Upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

// Handler handles WebSocket connections.
type Handler struct {
	hub *Hub
}

// NewHandler creates a new WebSocket handler.
func NewHandler(hub *Hub) *Handler {
	return &Handler{hub: hub}
}

// Handle handles WebSocket connections.
func (h *Handler) Handle(c *gin.Context) {
	conn, err := Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		zap.L().Error("websocket upgrade failed", zap.Error(err))
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
		hub:  h.hub,
	}

	client.hub.register <- client

	// Start read and write goroutines
	go client.writePump()
	go client.readPump()
}

// readPump pumps messages from the WebSocket connection.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536) // 64KB max message size
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		// Handle incoming message
		var msg struct {
			Type   string `json:"type"`
			TaskID string `json:"task_id,omitempty"`
		}
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "subscribe":
			c.mu.Lock()
			c.taskID = msg.TaskID
			c.mu.Unlock()
			// Send subscription confirmation
			resp, _ := json.Marshal(Message{Type: "subscribed", Timestamp: time.Now().Unix()})
			c.send <- resp
		case "unsubscribe":
			c.mu.Lock()
			c.taskID = ""
			c.mu.Unlock()
			// Send unsubscription confirmation
			resp, _ := json.Marshal(Message{Type: "unsubscribed", Timestamp: time.Now().Unix()})
			c.send <- resp
		case "ping":
			resp, _ := json.Marshal(Message{Type: "pong", Timestamp: time.Now().Unix()})
			c.send <- resp
		}
	}
}

// writePump pumps messages to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Batch messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
