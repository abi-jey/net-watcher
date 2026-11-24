package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
	"github.com/gorilla/websocket"
)

// Each live tail receives the events its filter selects, as the events API
// would; queued messages arrive one JSON message per line.
func TestLiveTailSendsEachClientItsMatches(t *testing.T) {
	hub := NewHub(log.Default(), nil)
	go hub.Run()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeWs))
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http")

	if _, response, err := websocket.DefaultDialer.Dial(base+"?f="+url.QueryEscape("port = https"), nil); err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad filter: %v %v", err, response)
	}
	connect := func(query string) *websocket.Conn {
		conn, _, err := websocket.DefaultDialer.Dial(base+"?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	dns := connect("f=" + url.QueryEscape("port = 53 and -coredns"))
	legacy := connect("namespace=web")
	everything := connect("")
	for deadline := time.Now().Add(5 * time.Second); hub.ClientCount() < 3; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("clients did not register")
		}
	}
	events := []database.NetworkEvent{
		{ID: 1, EventType: "DNS", DstPort: 53, SrcName: "api-1"},
		{ID: 2, EventType: "DNS", DstPort: 53, SrcName: "coredns-1"},
		{ID: 3, EventType: "TCP_START", DstPort: 443, SrcNamespace: "web"},
		{ID: 4, EventType: "DNS", DstPort: 53, DstNamespace: "web"},
	}
	for i := range events {
		hub.PublishEvent(&events[i])
	}
	read := func(conn *websocket.Conn, want int) []uint {
		var ids []uint
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for len(ids) < want {
			_, frame, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("after %v: %v", ids, err)
			}
			for _, line := range strings.Split(string(frame), "\n") {
				var message struct {
					Type string
					Data database.NetworkEvent
				}
				if err := json.Unmarshal([]byte(line), &message); err != nil {
					t.Fatalf("line %q: %v", line, err)
				}
				ids = append(ids, message.Data.ID)
			}
		}
		// Nothing else arrives.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, frame, err := conn.ReadMessage(); err == nil {
			t.Fatalf("unexpected %s", frame)
		}
		return ids
	}
	for name, test := range map[string]struct {
		conn *websocket.Conn
		want string
	}{"dns": {dns, "[1 4]"}, "legacy namespace": {legacy, "[3 4]"}, "everything": {everything, "[1 2 3 4]"}} {
		if got := fmt.Sprint(read(test.conn, strings.Count(test.want, " ")+1)); got != test.want {
			t.Errorf("%s: got %s, want %s", name, got, test.want)
		}
	}
}

// A live tail starts at the newest event: events stored while nobody watched
// are neither replayed nor reported as skipped.
func TestLiveTailStartsAfterIdleWithoutSkips(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	insert := func(n int) {
		events := make([]database.NetworkEvent, n)
		for i := range events {
			events[i] = database.NetworkEvent{Timestamp: time.Now().UTC(), EventType: "DNS", DstPort: 53}
		}
		if err := db.InsertBatch(events); err != nil {
			t.Fatal(err)
		}
	}
	insert(5)
	hub := NewHub(log.Default(), db)
	hub.pollInterval = 20 * time.Millisecond
	go hub.Run()
	hub.StartPolling()
	defer hub.StopPolling()

	// Far more than one poll's limit arrives while nobody watches.
	insert(livePollLimit + 200)
	time.Sleep(100 * time.Millisecond)

	server := httptest.NewServer(http.HandlerFunc(hub.ServeWs))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for deadline := time.Now().Add(5 * time.Second); hub.ClientCount() < 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("client did not register")
		}
	}
	time.Sleep(100 * time.Millisecond)
	insert(3)

	var types []string
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for count := 0; count < 3; {
		_, frame, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("after %v: %v", types, err)
		}
		for _, line := range strings.Split(string(frame), "\n") {
			var message struct{ Type string }
			if err := json.Unmarshal([]byte(line), &message); err != nil {
				t.Fatalf("line %q: %v", line, err)
			}
			types = append(types, message.Type)
			if message.Type == "event" {
				count++
			}
		}
	}
	if fmt.Sprint(types) != "[event event event]" {
		t.Fatalf("got %v, want only the three new events", types)
	}
}
