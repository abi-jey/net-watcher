// Net Watcher - WebSocket Hub for real-time event streaming
package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

// Client represents a WebSocket client connection
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	clients      map[*Client]bool
	broadcast    chan []byte
	register     chan *Client
	unregister   chan *Client
	mutex        sync.RWMutex
	logger       *log.Logger
	db           *database.DB
	lastEventID  uint
	pollInterval time.Duration
	stopChan     chan struct{}
}

// NewHub creates a new WebSocket hub
func NewHub(logger *log.Logger, db *database.DB) *Hub {
	hub := &Hub{
		clients:      make(map[*Client]bool),
		broadcast:    make(chan []byte, 256),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		logger:       logger,
		db:           db,
		pollInterval: 2 * time.Second,
		stopChan:     make(chan struct{}),
	}
	globalHub = hub
	// Register as the global event publisher
	database.SetEventPublisher(hub)

	// Initialize lastEventID from the database
	if db != nil {
		var maxID uint
		if err := db.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&maxID).Error; err == nil {
			hub.lastEventID = maxID
			hub.logger.Debug("[WS] Initialized lastEventID", "id", maxID)
		}
	}

	return hub
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			clientCount := len(h.clients)
			h.mutex.Unlock()
			h.logger.Info("[WS] Client connected", "total_clients", clientCount)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			clientCount := len(h.clients)
			h.mutex.Unlock()
			h.logger.Info("[WS] Client disconnected", "total_clients", clientCount)

		case message := <-h.broadcast:
			h.mutex.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// Client buffer full, disconnect
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.clients)
}

// StartPolling starts the database polling goroutine
func (h *Hub) StartPolling() {
	if h.db == nil {
		h.logger.Warn("[WS] Database not set, polling disabled")
		return
	}
	go h.pollLoop()
	h.logger.Info("[WS] Database polling started", "interval", h.pollInterval)
}

// StopPolling stops the database polling goroutine
func (h *Hub) StopPolling() {
	close(h.stopChan)
}

// pollLoop periodically checks for new events in the database
func (h *Hub) pollLoop() {
	ticker := time.NewTicker(h.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopChan:
			h.logger.Info("[WS] Polling stopped")
			return
		case <-ticker.C:
			if h.ClientCount() == 0 {
				continue // No clients, skip polling
			}
			h.pollNewEvents()
		}
	}
}

// pollNewEvents queries the database for events newer than lastEventID
func (h *Hub) pollNewEvents() {
	var events []database.NetworkEvent
	result := h.db.Where("id > ?", h.lastEventID).Order("id ASC").Limit(100).Find(&events)
	if result.Error != nil {
		h.logger.Error("[WS] Failed to poll events", "error", result.Error)
		return
	}

	if len(events) == 0 {
		return
	}

	h.logger.Debug("[WS] Polled new events", "count", len(events), "from_id", h.lastEventID)

	for _, event := range events {
		h.PublishEvent(&event)
		if event.ID > h.lastEventID {
			h.lastEventID = event.ID
		}
	}
}

// PublishEvent sends an event to all connected clients
// Implements database.EventPublisher interface
func (h *Hub) PublishEvent(event interface{}) {
	if h.ClientCount() == 0 {
		return
	}

	data, err := json.Marshal(map[string]interface{}{
		"type":      "event",
		"data":      event,
		"timestamp": time.Now().UnixMilli(),
	})
	if err != nil {
		h.logger.Error("Failed to marshal event for broadcast", "error", err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		h.logger.Warn("[WS] Broadcast channel full, dropping event")
	}
}

// ServeWs handles WebSocket requests from clients
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	h.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Debug("[WS] Read error", "error", err)
			}
			break
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			_, _ = w.Write(message)

			// Batch pending messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				_, _ = w.Write([]byte("\n"))
				_, _ = w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
