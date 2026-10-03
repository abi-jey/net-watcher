package web

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/abja/net-watcher/internal/kube"
	"github.com/charmbracelet/log"
	"gorm.io/gorm"
)

//go:embed all:static
var staticFiles embed.FS

// Server represents the web server
type Server struct {
	db         *database.DB
	port       int
	server     *http.Server
	logger     *log.Logger
	version    string
	hub        *Hub
	Host       string
	Kubernetes *kube.Index
	OwnedCIDRs []netip.Prefix
}

// NewServer creates a new web server instance
func NewServer(db *database.DB, port int, logger *log.Logger, version string) *Server {
	hub := NewHub(logger, db)
	go hub.Run()
	hub.StartPolling() // Start polling for cross-process event detection

	return &Server{
		db:         db,
		port:       port,
		logger:     logger,
		version:    version,
		hub:        hub,
		Kubernetes: kube.New(nil),
	}
}

// Start starts the web server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", cacheGET(35*time.Second, s.handleStats))
	mux.HandleFunc("/api/event-types", s.handleEventTypes)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/top-hosts", cacheGET(65*time.Second, s.handleTopHosts))
	mux.HandleFunc("/api/traffic-timeline", cacheGET(65*time.Second, s.handleTrafficTimeline))
	mux.HandleFunc("/api/ws", s.hub.ServeWs)
	mux.HandleFunc("/api/network-map", s.handleNetworkMap)
	mux.HandleFunc("/api/dns-evidence", s.handleDNSEvidence)

	// Serve static files (React app)
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to create static file system: %w", err)
	}

	// Serve the React app for all non-API routes
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	s.server = &http.Server{
		Addr:    net.JoinHostPort(s.Host, strconv.Itoa(s.port)),
		Handler: s.loggingMiddleware(corsMiddleware(mux)),
	}

	s.logger.Info("Starting web server", "port", s.port, "url", fmt.Sprintf("http://localhost:%d", s.port))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
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
	Aggregation database.AggregationStatus `json:"aggregation"`
	TotalEvents int64                      `json:"totalEvents"`
	EventCounts map[string]int64           `json:"eventCounts"`
	LastEvent   *time.Time                 `json:"lastEvent,omitempty"`
	FirstEvent  *time.Time                 `json:"firstEvent,omitempty"`
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
	dbQuery := s.db.WithContext(r.Context()).Model(&database.NetworkEvent{})

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
	err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		if srcIP == "" && dstIP == "" && searchQuery == "" && startDate == "" && endDate == "" {
			ready, err := database.SummariesReady(tx)
			if err != nil {
				return err
			}
			if ready {
				counts := tx.Model(&database.HourlyEvent{})
				if eventType != "" {
					counts = counts.Where("event_type IN ?", strings.Split(eventType, ","))
				}
				return counts.Select("COALESCE(SUM(event_count), 0)").Scan(&total).Error
			}
		}
		// Reuse the filtered statement on this snapshot rather than acquiring a
		// second pooled connection while the count transaction is active.
		filtered := tx.Model(&database.NetworkEvent{})
		if where, ok := dbQuery.Statement.Clauses["WHERE"]; ok {
			filtered = filtered.Clauses(where.Expression)
		}
		return filtered.Count(&total).Error
	})
	if err != nil {
		http.Error(w, "could not count events", http.StatusServiceUnavailable)
		return
	}

	// Get paginated results
	var events []database.NetworkEvent
	offset := (page - 1) * pageSize
	if err := dbQuery.Order("timestamp DESC").Limit(pageSize).Offset(offset).Find(&events).Error; err != nil {
		http.Error(w, "could not read events", http.StatusServiceUnavailable)
		return
	}

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
	_ = json.NewEncoder(w).Encode(response)
}

// handleStats returns database statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var response StatsResponse
	err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		response.Aggregation, err = database.SummaryStatus(tx)
		if err != nil {
			return err
		}
		response.EventCounts, response.TotalEvents, err = database.EventCounts(tx)
		if err != nil {
			return err
		}
		var first, last database.NetworkEvent
		if err := tx.Select("id, timestamp").Order("timestamp ASC").First(&first).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := tx.Select("id, timestamp").Order("timestamp DESC").First(&last).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if first.ID != 0 {
			response.FirstEvent = &first.Timestamp
		}
		if last.ID != 0 {
			response.LastEvent = &last.Timestamp
		}
		return nil
	})
	if err != nil {
		http.Error(w, "could not read statistics", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleEventTypes returns available event types
func (s *Server) handleEventTypes(w http.ResponseWriter, r *http.Request) {
	types := []string{}
	err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		ready, err := database.SummariesReady(tx)
		if err != nil {
			return err
		}
		if !ready {
			return tx.Model(&database.NetworkEvent{}).Distinct("event_type").Pluck("event_type", &types).Error
		}
		return tx.Model(&database.HourlyEvent{}).Distinct("event_type").Pluck("event_type", &types).Error
	})
	if err != nil {
		http.Error(w, "could not read event types", http.StatusServiceUnavailable)
		return
	}
	sort.Strings(types)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(types)
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
type TopHostEntry = database.HostTotal

// TopHostsResponse represents the top hosts response
type TopHostsResponse struct {
	Aggregation database.AggregationStatus `json:"aggregation"`
	Hosts       []TopHostEntry             `json:"hosts"`
	Total       int64                      `json:"total"`
	Metric      string                     `json:"metric"`
	HostType    string                     `json:"hostType"`
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

	var start, end time.Time
	if value := query.Get("hours"); value != "" && value != "all" {
		hours, err := strconv.Atoi(value)
		if err != nil || hours < 1 || hours > 24*365 {
			http.Error(w, "invalid hours", http.StatusBadRequest)
			return
		}
		end = time.Now().UTC()
		start = end.Add(-time.Duration(hours) * time.Hour)
	}
	var results []TopHostEntry
	var total int64
	var aggregation database.AggregationStatus
	err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		aggregation, err = database.SummaryStatus(tx)
		if err != nil {
			return err
		}
		results, total, err = database.TopHosts(tx, hostType, start, end, limit, metric == "traffic")
		return err
	})
	if err != nil {
		http.Error(w, "could not read top hosts", http.StatusServiceUnavailable)
		return
	}

	response := TopHostsResponse{
		Aggregation: aggregation,
		Hosts:       results,
		Total:       total,
		Metric:      metric,
		HostType:    hostType,
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
	Aggregation database.AggregationStatus `json:"aggregation"`
	Data        []TrafficDataPoint         `json:"data"`
	StartTime   time.Time                  `json:"startTime"`
	EndTime     time.Time                  `json:"endTime"`
	BucketSize  string                     `json:"bucketSize"`
	TotalIn     int64                      `json:"totalIn"`
	TotalOut    int64                      `json:"totalOut"`
}

// handleTrafficTimeline returns time-series traffic data
func (s *Server) handleTrafficTimeline(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Parse date range
	now := time.Now().UTC()
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
			endTime = t.Add(24 * time.Hour)
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

	switch {
	case duration <= 4*time.Hour:
		bucketSize = "5min"
		bucketDuration = 5 * time.Minute
	case duration <= 24*time.Hour:
		bucketSize = "1hour"
		bucketDuration = time.Hour
	case duration <= 7*24*time.Hour:
		bucketSize = "2hour"
		bucketDuration = 2 * time.Hour
	case duration <= 30*24*time.Hour:
		bucketSize = "6hour"
		bucketDuration = 6 * time.Hour
	case duration <= 90*24*time.Hour:
		bucketSize = "1day"
		bucketDuration = 24 * time.Hour
	default:
		bucketSize = "1week"
		bucketDuration = 7 * 24 * time.Hour
	}
	if duration <= 0 || duration > 366*24*time.Hour {
		http.Error(w, "traffic range must be positive and at most one year", http.StatusBadRequest)
		return
	}
	seconds := int64(bucketDuration / time.Second)
	var buckets map[int64]*database.TrafficBucket
	var aggregation database.AggregationStatus
	err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		var err error
		aggregation, err = database.SummaryStatus(tx)
		if err != nil {
			return err
		}
		buckets, err = database.TrafficTotals(tx, startTime, endTime, seconds, s.isLocalTrafficAddress)
		return err
	})
	if err != nil {
		http.Error(w, "could not read traffic timeline", http.StatusServiceUnavailable)
		return
	}
	// Align gaps with the same epoch-based boundaries used by SQL, not with the
	// arbitrary minute/second chosen in the date picker.
	first := startTime.Unix() - ((startTime.Unix()%seconds + seconds) % seconds)
	data := make([]TrafficDataPoint, 0)
	var totalIn, totalOut int64
	for at := first; time.Unix(at, 0).Before(endTime); at += seconds {
		point := TrafficDataPoint{Timestamp: time.Unix(at, 0).UTC()}
		if bucket := buckets[at]; bucket != nil {
			point.BytesIn, point.BytesOut, point.EventCount = bucket.BytesIn, bucket.BytesOut, bucket.EventCount
		}
		totalIn += point.BytesIn
		totalOut += point.BytesOut
		data = append(data, point)
	}

	response := TrafficTimelineResponse{
		Aggregation: aggregation,
		Data:        data,
		StartTime:   startTime,
		EndTime:     endTime,
		BucketSize:  bucketSize,
		TotalIn:     totalIn,
		TotalOut:    totalOut,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) isLocalTrafficAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if address.IsPrivate() {
		return true
	}
	for _, prefix := range s.OwnedCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
