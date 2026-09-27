package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnalyticsCacheCoalescesReadsAndExpires(t *testing.T) {
	var calls atomic.Int32
	handler := cacheGET(80*time.Millisecond, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"events":1}`))
	})
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			handler(r, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
			if r.Code != http.StatusOK || r.Body.String() != `{"events":1}` || r.Header().Get("Content-Type") != "application/json" {
				t.Errorf("cached response: status=%d body=%q headers=%v", r.Code, r.Body.String(), r.Header())
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate read queries = %d", calls.Load())
	}
	time.Sleep(90 * time.Millisecond)
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if calls.Load() != 2 {
		t.Fatalf("stale stats were not refreshed: calls=%d", calls.Load())
	}
}

func TestAnalyticsCacheDoesNotKeepErrors(t *testing.T) {
	var calls int
	handler := cacheGET(time.Minute, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	for range 2 {
		handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/top-hosts", nil))
	}
	if calls != 2 {
		t.Fatal("an error response was cached")
	}
}
