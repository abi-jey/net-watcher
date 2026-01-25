package web

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

//go:embed all:static
var staticFiles embed.FS

// Server represents the web server
type Server struct {
	db      *database.DB
	port    int
	server  *http.Server
	logger  *log.Logger
	version string
	hub     *Hub
}

// NewServer creates a new web server instance
func NewServer(db *database.DB, port int, logger *log.Logger, version string) *Server {
	hub := NewHub(logger, db)
	go hub.Run()
	hub.StartPolling() // Start polling for cross-process event detection

	return &Server{
		db:      db,
		port:    port,
		logger:  logger,
		version: version,
		hub:     hub,
	}
}

// Start starts the web server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/event-types", s.handleEventTypes)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/top-hosts", s.handleTopHosts)
	mux.HandleFunc("/api/traffic-timeline", s.handleTrafficTimeline)
	mux.HandleFunc("/api/ws", s.hub.ServeWs)

	// Serve static files (React app)
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to create static file system: %w", err)
	}

	// Serve the React app for all non-API routes
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: s.loggingMiddleware(corsMiddleware(mux)),
	}

	s.logger.Info("Starting web server", "port", s.port, "url", fmt.Sprintf("http://localhost:%d", s.port))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// corsMiddleware adds CORS headers for development
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs all incoming HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(lrw, r)

		duration := time.Since(start)

		// Only log API requests to reduce noise
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.logger.Info("API request",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", lrw.statusCode,
				"duration", duration.Round(time.Microsecond),
			)
		}
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker for WebSocket support
func (lrw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := lrw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

// EventsResponse represents the paginated events response
type EventsResponse struct {
	Events     []database.NetworkEvent `json:"events"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"pageSize"`
	TotalPages int                     `json:"totalPages"`
}

// StatsResponse represents database statistics
type StatsResponse struct {
	TotalEvents int64            `json:"totalEvents"`
	EventCounts map[string]int64 `json:"eventCounts"`
	LastEvent   *time.Time       `json:"lastEvent,omitempty"`
	FirstEvent  *time.Time       `json:"firstEvent,omitempty"`
}

// handleEvents returns paginated and filtered events
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Pagination
	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(query.Get("pageSize"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Filters
	eventType := query.Get("eventType")
	srcIP := query.Get("srcIP")
	dstIP := query.Get("dstIP")
	searchQuery := query.Get("q")
	startDate := query.Get("startDate")
	endDate := query.Get("endDate")

	// Build query
	dbQuery := s.db.Model(&database.NetworkEvent{})

	// Handle multi-select event types (comma-separated)
	if eventType != "" {
		types := strings.Split(eventType, ",")
		if len(types) == 1 {
			dbQuery = dbQuery.Where("event_type = ?", types[0])
		} else {
			dbQuery = dbQuery.Where("event_type IN ?", types)
		}
	}
	if srcIP != "" {
		dbQuery = dbQuery.Where("src_ip LIKE ?", "%"+srcIP+"%")
	}
	if dstIP != "" {
		dbQuery = dbQuery.Where("dst_ip LIKE ?", "%"+dstIP+"%")
	}
	if searchQuery != "" {
		search := "%" + searchQuery + "%"
		dbQuery = dbQuery.Where(
			"src_ip LIKE ? OR dst_ip LIKE ? OR hostname LIKE ? OR dns_query LIKE ? OR tls_sni LIKE ?",
			search, search, search, search, search,
		)
	}
	if startDate != "" {
		if t, err := time.Parse("2006-01-02", startDate); err == nil {
			dbQuery = dbQuery.Where("timestamp >= ?", t)
		}
	}
	if endDate != "" {
		if t, err := time.Parse("2006-01-02", endDate); err == nil {
			dbQuery = dbQuery.Where("timestamp <= ?", t.Add(24*time.Hour))
		}
	}

	// Get total count
	var total int64
	dbQuery.Count(&total)

	// Get paginated results
	var events []database.NetworkEvent
	offset := (page - 1) * pageSize
	dbQuery.Order("timestamp DESC").Limit(pageSize).Offset(offset).Find(&events)

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	response := EventsResponse{
		Events:     events,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleStats returns database statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var total int64
	s.db.Model(&database.NetworkEvent{}).Count(&total)

	// Count by event type
	type eventCount struct {
		EventType string
		Count     int64
	}
	var counts []eventCount
	s.db.Model(&database.NetworkEvent{}).
		Select("event_type, count(*) as count").
		Group("event_type").
		Scan(&counts)

	eventCounts := make(map[string]int64)
	for _, c := range counts {
		eventCounts[c.EventType] = c.Count
	}

	// Get first and last event timestamps
	var firstEvent, lastEvent database.NetworkEvent
	s.db.Model(&database.NetworkEvent{}).Order("timestamp ASC").First(&firstEvent)
	s.db.Model(&database.NetworkEvent{}).Order("timestamp DESC").First(&lastEvent)

	response := StatsResponse{
		TotalEvents: total,
		EventCounts: eventCounts,
	}

	if firstEvent.ID != 0 {
		response.FirstEvent = &firstEvent.Timestamp
	}
	if lastEvent.ID != 0 {
		response.LastEvent = &lastEvent.Timestamp
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleEventTypes returns available event types
func (s *Server) handleEventTypes(w http.ResponseWriter, r *http.Request) {
	var types []string
	s.db.Model(&database.NetworkEvent{}).
		Distinct("event_type").
		Pluck("event_type", &types)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types)
}

// VersionResponse represents version information
type VersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"buildTime,omitempty"`
}

// handleVersion returns the application version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	response := VersionResponse{
		Version: s.version,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TopHostEntry represents a single host entry in the top hosts response
type TopHostEntry struct {
	Host       string `json:"host"`
	EventCount int64  `json:"eventCount"`
	ByteCount  int64  `json:"byteCount"`
}

// TopHostsResponse represents the top hosts response
type TopHostsResponse struct {
	Hosts    []TopHostEntry `json:"hosts"`
	Total    int64          `json:"total"`
	Metric   string         `json:"metric"`
	HostType string         `json:"hostType"`
}

// handleTopHosts returns top hosts by traffic or event count
func (s *Server) handleTopHosts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Parameters
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 10
	}

	metric := query.Get("metric") // "events" or "traffic"
	if metric != "traffic" {
		metric = "events"
	}

	hostType := query.Get("type") // "hostname", "srcIP", "dstIP"
	if hostType != "srcIP" && hostType != "dstIP" {
		hostType = "hostname"
	}

	// Determine which column to group by
	var groupColumn string
	switch hostType {
	case "srcIP":
		groupColumn = "src_ip"
	case "dstIP":
		groupColumn = "dst_ip"
	default:
		groupColumn = "hostname"
	}

	// Build query based on metric
	var results []TopHostEntry

	if metric == "traffic" {
		// Order by total bytes
		s.db.Model(&database.NetworkEvent{}).
			Select(groupColumn + " as host, count(*) as event_count, COALESCE(sum(byte_count), 0) as byte_count").
			Where(groupColumn + " != '' AND " + groupColumn + " IS NOT NULL").
			Group(groupColumn).
			Order("byte_count DESC").
			Limit(limit).
			Scan(&results)
	} else {
		// Order by event count
		s.db.Model(&database.NetworkEvent{}).
			Select(groupColumn + " as host, count(*) as event_count, COALESCE(sum(byte_count), 0) as byte_count").
			Where(groupColumn + " != '' AND " + groupColumn + " IS NOT NULL").
			Group(groupColumn).
			Order("event_count DESC").
			Limit(limit).
			Scan(&results)
	}

	// Get total unique hosts
	var total int64
	s.db.Model(&database.NetworkEvent{}).
		Where(groupColumn + " != '' AND " + groupColumn + " IS NOT NULL").
		Distinct(groupColumn).
		Count(&total)

	response := TopHostsResponse{
		Hosts:    results,
		Total:    total,
		Metric:   metric,
		HostType: hostType,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TrafficDataPoint represents a single time-series data point
type TrafficDataPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	BytesIn    int64     `json:"bytesIn"`
	BytesOut   int64     `json:"bytesOut"`
	EventCount int64     `json:"eventCount"`
}

// TrafficTimelineResponse represents the traffic timeline response
type TrafficTimelineResponse struct {
	Data       []TrafficDataPoint `json:"data"`
	StartTime  time.Time          `json:"startTime"`
	EndTime    time.Time          `json:"endTime"`
	BucketSize string             `json:"bucketSize"`
	TotalIn    int64              `json:"totalIn"`
	TotalOut   int64              `json:"totalOut"`
}

// handleTrafficTimeline returns time-series traffic data
func (s *Server) handleTrafficTimeline(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Parse date range
	now := time.Now()
	var startTime, endTime time.Time

	if start := query.Get("start"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			startTime = t
		} else if t, err := time.Parse("2006-01-02", start); err == nil {
			startTime = t
		}
	}
	if end := query.Get("end"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			endTime = t
		} else if t, err := time.Parse("2006-01-02", end); err == nil {
			endTime = t.Add(24*time.Hour - time.Second)
		}
	}

	// Default to last 24 hours if not specified
	if startTime.IsZero() {
		startTime = now.Add(-24 * time.Hour)
	}
	if endTime.IsZero() {
		endTime = now
	}

	// Ensure end is after start
	if endTime.Before(startTime) {
		startTime, endTime = endTime, startTime
	}

	// Calculate duration and determine bucket size
	duration := endTime.Sub(startTime)
	var bucketSize string
	var bucketDuration time.Duration
	var sqlFormat string

	switch {
	case duration <= 4*time.Hour:
		bucketSize = "5min"
		bucketDuration = 5 * time.Minute
		sqlFormat = "%Y-%m-%d %H:%M"
	case duration <= 24*time.Hour:
		bucketSize = "30min"
		bucketDuration = 30 * time.Minute
		sqlFormat = "%Y-%m-%d %H:%M"
	case duration <= 7*24*time.Hour:
		bucketSize = "2hour"
		bucketDuration = 2 * time.Hour
		sqlFormat = "%Y-%m-%d %H:00"
	case duration <= 30*24*time.Hour:
		bucketSize = "6hour"
		bucketDuration = 6 * time.Hour
		sqlFormat = "%Y-%m-%d %H:00"
	case duration <= 90*24*time.Hour:
		bucketSize = "1day"
		bucketDuration = 24 * time.Hour
		sqlFormat = "%Y-%m-%d"
	default:
		bucketSize = "1week"
		bucketDuration = 7 * 24 * time.Hour
		sqlFormat = "%Y-%W"
	}

	// Query aggregated data
	type bucketData struct {
		Bucket     string
		BytesIn    int64
		BytesOut   int64
		EventCount int64
	}

	var buckets []bucketData

	// SQLite date formatting for grouping
	s.db.Model(&database.NetworkEvent{}).
		Select(`strftime('`+sqlFormat+`', timestamp) as bucket,
			COALESCE(SUM(CASE WHEN src_ip LIKE '192.168.%' OR src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' THEN byte_count ELSE 0 END), 0) as bytes_out,
			COALESCE(SUM(CASE WHEN dst_ip LIKE '192.168.%' OR dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' THEN byte_count ELSE 0 END), 0) as bytes_in,
			COUNT(*) as event_count`).
		Where("timestamp >= ? AND timestamp <= ?", startTime, endTime).
		Group("bucket").
		Order("bucket ASC").
		Scan(&buckets)

	// Convert to response format with proper timestamps
	data := make([]TrafficDataPoint, 0, len(buckets))
	var totalIn, totalOut int64

	for _, b := range buckets {
		var ts time.Time
		// Parse bucket string back to time
		switch bucketSize {
		case "5min", "30min":
			ts, _ = time.Parse("2006-01-02 15:04", b.Bucket)
		case "2hour", "6hour":
			ts, _ = time.Parse("2006-01-02 15:00", b.Bucket)
		case "1day":
			ts, _ = time.Parse("2006-01-02", b.Bucket)
		case "1week":
			// Parse year-week format
			ts, _ = time.Parse("2006-01-02", b.Bucket+"-1") // Approximate
		}

		if ts.IsZero() {
			continue
		}

		data = append(data, TrafficDataPoint{
			Timestamp:  ts,
			BytesIn:    b.BytesIn,
			BytesOut:   b.BytesOut,
			EventCount: b.EventCount,
		})
		totalIn += b.BytesIn
		totalOut += b.BytesOut
	}

	// Fill in missing buckets with zero values for a complete timeline
	filledData := fillTimeGaps(data, startTime, endTime, bucketDuration)

	response := TrafficTimelineResponse{
		Data:       filledData,
		StartTime:  startTime,
		EndTime:    endTime,
		BucketSize: bucketSize,
		TotalIn:    totalIn,
		TotalOut:   totalOut,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// fillTimeGaps fills in missing time buckets with zero values
func fillTimeGaps(data []TrafficDataPoint, start, end time.Time, bucketDuration time.Duration) []TrafficDataPoint {
	if len(data) == 0 {
		return data
	}

	// Create a map for quick lookup
	dataMap := make(map[int64]TrafficDataPoint)
	for _, d := range data {
		// Round to bucket
		bucket := d.Timestamp.Truncate(bucketDuration).Unix()
		dataMap[bucket] = d
	}

	// Generate complete timeline
	var result []TrafficDataPoint
	current := start.Truncate(bucketDuration)

	for current.Before(end) || current.Equal(end) {
		bucket := current.Unix()
		if dp, exists := dataMap[bucket]; exists {
			result = append(result, dp)
		} else {
			result = append(result, TrafficDataPoint{
				Timestamp:  current,
				BytesIn:    0,
				BytesOut:   0,
				EventCount: 0,
			})
		}
		current = current.Add(bucketDuration)

		// Safety limit
		if len(result) > 1000 {
			break
		}
	}

	return result
}
