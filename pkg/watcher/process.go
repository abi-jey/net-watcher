package watcher

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abja/net-watcher/internal/database"
	"github.com/charmbracelet/log"
)

const (
	processLookupBudget = 20 * time.Millisecond
	processMaxFDLinks   = 512
	processMaxPIDs      = 512
)

type processIdentity struct {
	PID     int
	Command string
}

type processAttributor struct {
	root        string
	hostIPs     map[string]bool
	jobs        chan database.NetworkEvent
	onEvent     func(database.NetworkEvent)
	logger      *log.Logger
	workers     sync.WaitGroup
	queued      atomic.Uint64
	matched     atomic.Uint64
	socketFound atomic.Uint64
	budgetHit   atomic.Uint64
	fdLimited   atomic.Uint64
	rateLimited atomic.Uint64
	expired     atomic.Uint64
	queueFull   atomic.Uint64
}

func newProcessAttributor(root string, logger *log.Logger, onEvent func(database.NetworkEvent)) (*processAttributor, error) {
	if _, err := os.Stat(filepath.Join(root, "net", "tcp")); err != nil {
		return nil, fmt.Errorf("host proc TCP table: %w", err)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := make(map[string]bool)
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			local[network.IP.String()] = true
		}
	}
	lookup := &processAttributor{root: root, hostIPs: local, jobs: make(chan database.NetworkEvent, 32), onEvent: onEvent, logger: logger}
	lookup.workers.Add(1)
	go lookup.run()
	return lookup, nil
}

func (a *processAttributor) enqueue(event database.NetworkEvent) bool {
	if !a.hostIPs[event.SrcIP] && !a.hostIPs[event.DstIP] {
		return false
	}
	select {
	case a.jobs <- event:
		return true
	default:
		a.queueFull.Add(1)
		return false
	}
}

func (a *processAttributor) stop() {
	close(a.jobs)
	a.workers.Wait()
	a.report()
}

func (a *processAttributor) report() {
	queued, matched := a.queued.Swap(0), a.matched.Swap(0)
	socketFound, budgetHit, fdLimited := a.socketFound.Swap(0), a.budgetHit.Swap(0), a.fdLimited.Swap(0)
	rateLimited, expired, queueFull := a.rateLimited.Swap(0), a.expired.Swap(0), a.queueFull.Swap(0)
	if queued+rateLimited+expired+queueFull > 0 {
		a.logger.Info("Host process attribution", "attempted", queued, "socket_found", socketFound, "matched", matched, "budget_hit", budgetHit, "fd_limited", fdLimited, "rate_limited", rateLimited, "expired", expired, "queue_full", queueFull)
	}
}

func (a *processAttributor) run() {
	defer a.workers.Done()
	// Two lookups per second, with a burst of two. No /proc work runs on a
	// packet-processing goroutine, and unmatched events are still persisted.
	tokens, last := 2, time.Now()
	for event := range a.jobs {
		refill := int(time.Since(last) / (500 * time.Millisecond))
		if refill > 0 {
			tokens = min(2, tokens+refill)
			last = last.Add(time.Duration(refill) * 500 * time.Millisecond)
		}
		switch {
		case time.Since(event.Timestamp) > 500*time.Millisecond:
			a.expired.Add(1)
		case tokens == 0:
			a.rateLimited.Add(1)
		default:
			tokens--
			a.queued.Add(1)
			if result, ok := a.lookup(event, time.Now().Add(processLookupBudget)); ok {
				event.ProcessPID, event.ProcessCommand = result.PID, result.Command
				a.matched.Add(1)
			}
		}
		a.onEvent(event)
	}
}

func (a *processAttributor) lookup(event database.NetworkEvent, deadline time.Time) (processIdentity, bool) {
	localIP, localPort, remoteIP, remotePort := event.SrcIP, event.SrcPort, event.DstIP, event.DstPort
	if !a.hostIPs[localIP] {
		localIP, localPort, remoteIP, remotePort = event.DstIP, event.DstPort, event.SrcIP, event.SrcPort
	}
	inode, uid := findSocketInode(a.root, localIP, localPort, remoteIP, remotePort, deadline)
	if inode == "" {
		if time.Now().After(deadline) {
			a.budgetHit.Add(1)
		}
		return processIdentity{}, false
	}
	a.socketFound.Add(1)
	if time.Now().After(deadline) {
		a.budgetHit.Add(1)
		return processIdentity{}, false
	}
	processes, err := os.ReadDir(a.root)
	if err != nil {
		return processIdentity{}, false
	}
	target := "socket:[" + inode + "]"
	checked, followed := 0, 0
	for _, process := range processes {
		if time.Now().After(deadline) || checked >= processMaxPIDs || followed >= processMaxFDLinks {
			break
		}
		pid, err := strconv.Atoi(process.Name())
		if err != nil || pid < 1 {
			continue
		}
		checked++
		path := filepath.Join(a.root, process.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uid {
			continue
		}
		fds, err := os.Open(filepath.Join(path, "fd"))
		if err != nil {
			continue
		}
		for time.Now().Before(deadline) && followed < processMaxFDLinks {
			names, err := fds.Readdirnames(32)
			for _, name := range names {
				if time.Now().After(deadline) || followed >= processMaxFDLinks {
					break
				}
				followed++
				link, err := os.Readlink(filepath.Join(path, "fd", name))
				if err != nil || link != target {
					continue
				}
				command, err := os.ReadFile(filepath.Join(path, "comm"))
				fds.Close()
				if err == nil {
					return processIdentity{PID: pid, Command: strings.TrimSpace(string(command))}, true
				}
				return processIdentity{PID: pid}, true
			}
			if err != nil || len(names) == 0 {
				break
			}
		}
		fds.Close()
	}
	if time.Now().After(deadline) {
		a.budgetHit.Add(1)
	}
	if checked >= processMaxPIDs || followed >= processMaxFDLinks {
		a.fdLimited.Add(1)
	}
	return processIdentity{}, false
}

func findSocketInode(root, localIP string, localPort uint16, remoteIP string, remotePort uint16, deadline time.Time) (string, uint32) {
	local, localErr := netip.ParseAddr(localIP)
	remote, remoteErr := netip.ParseAddr(remoteIP)
	if localErr != nil || remoteErr != nil || local.Is6() != remote.Is6() {
		return "", 0
	}
	table := "tcp"
	if local.Is6() {
		table = "tcp6"
	}
	file, err := os.Open(filepath.Join(root, "net", table))
	if err != nil {
		return "", 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && time.Now().Before(deadline) {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		from, fromPort, fromOK := parseProcAddress(fields[1])
		to, toPort, toOK := parseProcAddress(fields[2])
		if !fromOK || !toOK || from != local || to != remote || fromPort != localPort || toPort != remotePort || fields[9] == "0" {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err == nil {
			return fields[9], uint32(uid)
		}
	}
	return "", 0
}

func parseProcAddress(value string) (netip.Addr, uint16, bool) {
	hexIP, hexPort, ok := strings.Cut(value, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	decoded, err := hex.DecodeString(hexIP)
	if err != nil || (len(decoded) != 4 && len(decoded) != 16) {
		return netip.Addr{}, 0, false
	}
	for start := 0; start < len(decoded); start += 4 {
		decoded[start], decoded[start+3] = decoded[start+3], decoded[start]
		decoded[start+1], decoded[start+2] = decoded[start+2], decoded[start+1]
	}
	if len(decoded) == 4 {
		return netip.AddrFrom4([4]byte(decoded)), uint16(port), true
	}
	return netip.AddrFrom16([16]byte(decoded)), uint16(port), true
}
