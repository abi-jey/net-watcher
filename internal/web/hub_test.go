package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
