package watcher

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestInterfaceGoneTellsRemovedLinksFromFailures(t *testing.T) {
	saved, savedRecheck := interfaceByIndex, interfaceRecheck
	t.Cleanup(func() { interfaceByIndex, interfaceRecheck = saved, savedRecheck })
	interfaceRecheck = []time.Duration{0, time.Millisecond, time.Millisecond}
	captured := net.Interface{Index: 7, Name: "lxc70d1fbabc699", Flags: net.FlagUp}

	for _, tc := range []struct {
		name    string
		current func(calls int) (*net.Interface, error)
		want    bool
	}{
		{"deleted", func(int) (*net.Interface, error) { return nil, errors.New("no such network interface") }, true},
		{"index reused by another link", func(int) (*net.Interface, error) {
			return &net.Interface{Index: 7, Name: "lxcnew", Flags: net.FlagUp}, nil
		}, true},
		{"brought down", func(int) (*net.Interface, error) { return &net.Interface{Index: 7, Name: captured.Name}, nil }, true},
		{"deleted after the poll failed", func(calls int) (*net.Interface, error) {
			if calls < 2 {
				return &captured, nil
			}
			return nil, errors.New("no such network interface")
		}, true},
		{"still up: a real failure", func(int) (*net.Interface, error) { return &captured, nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			interfaceByIndex = func(index int) (*net.Interface, error) {
				if index != captured.Index {
					t.Fatalf("looked up index %d, want %d", index, captured.Index)
				}
				calls++
				return tc.current(calls)
			}
			if got := interfaceGone(context.Background(), captured); got != tc.want {
				t.Fatalf("interfaceGone = %v, want %v", got, tc.want)
			}
		})
	}
}
