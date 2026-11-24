package web

import (
	"net/url"
	"testing"
)

// requestFilter reads a request's filter, failing the test on an error.
func requestFilter(t testing.TB, query url.Values) *expr {
	t.Helper()
	filter, err := eventsRequestFilter(query)
	if err != nil {
		t.Fatalf("filter %v: %v", query, err)
	}
	return filter
}
