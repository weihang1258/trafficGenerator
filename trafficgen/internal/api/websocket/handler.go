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

	"github.com/trafficgen/trafficgen/pkg/auth"
)

// Message types sent from server to client.
const (
	TypeStatusUpdate   = "status_update"   // Task status changed
	TypeStatsUpdate    = "stats_update"    // Task stats updated
	TypeProgressUpdate = "progress_update" // Task progress updated (0-100%)
	TypeTaskCompleted  = "task_completed"  // Task completed successfully
	TypeTaskFailed     = "task_failed"     // Task failed with error
	TypeError          = "error"           // Generic error message
	TypeHeartbeat      = "heartbeat"       // Heartbeat/ping message
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
	done     chan struct{} // closed when client is being removed
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
	mu         sync.Mutex
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
				close(client.done) // signal to BroadcastToTask
				// Note: client.send is closed by writePump when done is signaled
			}
			h.mu.Unlock()
			zap.L().Debug("client disconnected", zap.Int("total", len(h.clients)))

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case <-client.done:
					// Client already being removed
					delete(h.clients, client)
				case client.send <- message:
				default:
					// Client buffer full, mark for removal
					close(client.done)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
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

	h.mu.Lock()
	for client := range h.clients {
		if client.taskID == "" || client.taskID == taskID {
			select {
			case <-client.done:
				// Client being removed, skip
				delete(h.clients, client)
			case client.send <- data:
			default:
				// Client buffer full, mark for removal
				close(client.done)
				delete(h.clients, client)
			}
		}
	}
	h.mu.Unlock()
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
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
	hub        *Hub
	jwtManager *auth.JWTManager
}

// NewHandler creates a new WebSocket handler.
func NewHandler(hub *Hub) *Handler {
	return &Handler{hub: hub}
}

// SetJWTManager sets the JWT manager for authenticating WebSocket connections.
func (h *Handler) SetJWTManager(jwtManager *auth.JWTManager) {
	h.jwtManager = jwtManager
}

// Hub returns the underlying Hub for external use (e.g., broadcasting from engine callbacks).
func (h *Handler) Hub() *Hub {
	return h.hub
}

// Handle handles WebSocket connections.
// Validates JWT token from query parameter before upgrading.
func (h *Handler) Handle(c *gin.Context) {
	// Validate JWT token from query parameter
	if h.jwtManager != nil {
		tokenString := c.Query("token")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		claims, err := h.jwtManager.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		_ = claims // userID available via claims.UserID for future per-user filtering
	}

	conn, err := Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		zap.L().Error("websocket upgrade failed", zap.Error(err))
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
		done: make(chan struct{}),
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
		if r := recover(); r != nil {
			zap.L().Debug("websocket read recovered", zap.Any("error", r))
		}
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
		select {
		case <-c.done:
			return
		default:
		}

		_, message, err := c.conn.ReadMessage()
		if err != nil {
			return
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
			resp, _ := json.Marshal(Message{Type: "subscribed", Timestamp: time.Now().Unix()})
			select {
			case c.send <- resp:
			case <-c.done:
				return
			}
		case "unsubscribe":
			c.mu.Lock()
			c.taskID = ""
			c.mu.Unlock()
			resp, _ := json.Marshal(Message{Type: "unsubscribed", Timestamp: time.Now().Unix()})
			select {
			case c.send <- resp:
			case <-c.done:
				return
			}
		case "ping":
			resp, _ := json.Marshal(Message{Type: "pong", Timestamp: time.Now().Unix()})
			select {
			case c.send <- resp:
			case <-c.done:
				return
			}
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

		case <-c.done:
			// Hub is removing this client, drain remaining messages and close
			c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
