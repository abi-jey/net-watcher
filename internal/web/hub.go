// Net Watcher - WebSocket Hub for real-time event streaming
package web

import (
	"encoding/json"
	"fmt"
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
	// CheckOrigin is left nil: gorilla/websocket then accepts only same-origin
	// browser connections, so other sites cannot stream audit events.
}

// Client represents a WebSocket client connection
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
	// filter selects the events this client receives (nil: all), from the
	// same query parameters as /api/events.
	filter *expr
}

// hubMessage is one message for clients; an event goes only to clients
// whose filter matches it.
type hubMessage struct {
	data  []byte
	event *database.NetworkEvent
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	clients      map[*Client]bool
	broadcast    chan hubMessage
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
		broadcast:    make(chan hubMessage, 1024),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		logger:       logger,
		db:           db,
		pollInterval: 2 * time.Second,
		stopChan:     make(chan struct{}),
	}
	// Register as the global event publisher
	database.SetEventPublisher(hub)

	if db != nil {
		hub.tailFromNow()
	}
	return hub
}

// tailFromNow starts the live tail after the newest stored event: events
// stored while nobody watched are history, for searching, not a backlog to
// replay or report as skipped.
func (h *Hub) tailFromNow() {
	var maxID uint
	if err := h.db.Raw("SELECT COALESCE(MAX(id), 0) FROM network_events").Scan(&maxID).Error; err != nil {
		h.logger.Error("[WS] Failed to read the newest event", "error", err)
		return
	}
	h.lastEventID = maxID
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
			// The write lock: a client that cannot keep up is removed while
			// ClientCount may be reading the map.
			h.mutex.Lock()
			for client := range h.clients {
				if message.event != nil && !client.filter.matches(message.event) {
					continue
				}
				select {
				case client.send <- message.data:
				default:
					// Client buffer full, disconnect
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mutex.Unlock()
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

	idle := false
	for {
		select {
		case <-h.stopChan:
			h.logger.Info("[WS] Polling stopped")
			return
		case <-ticker.C:
			if h.ClientCount() == 0 {
				idle = true
				continue
			}
			if idle {
				idle = false
				h.tailFromNow()
			}
			h.pollNewEvents()
		}
	}
}

// livePollLimit bounds each poll. The live view is a tail, not an audit
// trail: when more events arrived than fit, the newest are sent and the gap is
// announced, so the view never falls further behind the capture rate. A
// busy two-node cluster stores 40-100 events a second.
const livePollLimit = 1000

// pollNewEvents sends the newest events after lastEventID.
func (h *Hub) pollNewEvents() {
	var events []database.NetworkEvent
	result := h.db.Where("id > ?", h.lastEventID).Order("id DESC").Limit(livePollLimit).Find(&events)
	if result.Error != nil {
		h.logger.Error("[WS] Failed to poll events", "error", result.Error)
		return
	}
	if len(events) == 0 {
		return
	}
	newest, oldest := events[0].ID, events[len(events)-1].ID
	if h.lastEventID > 0 && oldest > h.lastEventID+1 && len(events) == livePollLimit {
		h.publish(map[string]interface{}{"type": "skipped", "count": oldest - h.lastEventID - 1, "timestamp": time.Now().UnixMilli()})
	}
	for i := len(events) - 1; i >= 0; i-- {
		message, err := eventMessage(&events[i])
		if err != nil {
			continue
		}
		// This goroutine only polls, so it waits for room instead of
		// dropping events.
		select {
		case h.broadcast <- message:
		case <-h.stopChan:
			return
		}
	}
	h.lastEventID = newest
}

func (h *Hub) publish(message map[string]interface{}) {
	data, err := json.Marshal(message)
	if err != nil {
		return
	}
	select {
	case h.broadcast <- hubMessage{data: data}:
	default:
		h.logger.Warn("[WS] Broadcast channel full, dropping message")
	}
}

// PublishEvent sends an event to the clients whose filter matches it.
// Implements database.EventPublisher interface
func (h *Hub) PublishEvent(event interface{}) {
	if h.ClientCount() == 0 {
		return
	}
	var stored *database.NetworkEvent
	switch e := event.(type) {
	case *database.NetworkEvent:
		stored = e
	case database.NetworkEvent:
		stored = &e
	default:
		h.logger.Error("Cannot broadcast event", "type", fmt.Sprintf("%T", event))
		return
	}
	message, err := eventMessage(stored)
	if err != nil {
		h.logger.Error("Failed to marshal event for broadcast", "error", err)
		return
	}
	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("[WS] Broadcast channel full, dropping event")
	}
}

func eventMessage(event *database.NetworkEvent) (hubMessage, error) {
	data, err := json.Marshal(map[string]interface{}{"type": "event", "data": event, "timestamp": time.Now().UnixMilli()})
	return hubMessage{data: data, event: event}, err
}

// ServeWs handles WebSocket requests from clients
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	filter, err := eventsRequestFilter(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}

	client := &Client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 1024),
		filter: filter,
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
		_ = c.conn.Close()
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
		_ = c.conn.Close()
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

			// Queued messages share the frame, one JSON message per line.
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
