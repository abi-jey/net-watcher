package web

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

type cachedResponse struct {
	status  int
	header  http.Header
	body    []byte
	expires time.Time
}

type responseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (b *responseBuffer) Header() http.Header { return b.header }
func (b *responseBuffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *responseBuffer) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(data)
}

func writeCached(w http.ResponseWriter, response cachedResponse) {
	for key, values := range response.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.status)
	_, _ = w.Write(response.body)
}

// cacheGET coalesces identical in-flight analytics queries and bounds repeated
// scans; each wrapped endpoint has its own lock so other use cases remain live.
func cacheGET(ttl time.Duration, handler http.HandlerFunc) http.HandlerFunc {
	var mu sync.Mutex
	entries := map[string]cachedResponse{}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			handler(w, r)
			return
		}
		mu.Lock()
		locked := true
		defer func() {
			if locked {
				mu.Unlock()
			}
		}()
		key := r.URL.RawQuery
		if response, ok := entries[key]; ok && time.Now().Before(response.expires) {
			mu.Unlock()
			locked = false
			writeCached(w, response)
			return
		}
		if err := r.Context().Err(); err != nil {
			mu.Unlock()
			locked = false
			return
		}
		buffer := &responseBuffer{header: make(http.Header)}
		handler(buffer, r)
		if buffer.status == 0 {
			buffer.status = http.StatusOK
		}
		response := cachedResponse{status: buffer.status, header: buffer.header.Clone(), body: buffer.body.Bytes()}
		if response.status == http.StatusOK && r.Context().Err() == nil {
			response.expires = time.Now().Add(ttl)
			entries[key] = response
		}
		if len(entries) > 32 {
			for oldKey, entry := range entries {
				if oldKey != key && time.Now().After(entry.expires) {
					delete(entries, oldKey)
				}
			}
			for oldKey := range entries {
				if len(entries) <= 32 {
					break
				}
				if oldKey != key {
					delete(entries, oldKey)
				}
			}
		}
		mu.Unlock()
		locked = false
		writeCached(w, response)
	}
}
