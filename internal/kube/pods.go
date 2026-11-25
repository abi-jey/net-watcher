package kube

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// historyRetention keeps ended assignments long enough to attribute events
	// that were buffered or delayed (process attribution, write retries).
	historyRetention = 15 * time.Minute
	// clockSkew tolerates small differences between packet timestamps and the
	// API server's creation timestamps.
	clockSkew = time.Second
)

// assignment records that a pod held an address during [start, end). A zero
// end means the pod still holds it. start comes from the pod's creation
// timestamp (an address cannot predate its pod); end is when the release was
// observed, an upper bound whose precision depends on watch versus polling.
type assignment struct {
	endpoint Endpoint
	// probes describes the pod's network probes by the port they connect to.
	probes map[int]string
	start  time.Time
	end    time.Time
}

type podState struct {
	ips      []string
	endpoint Endpoint
	lastSeen time.Time
}

// podHistory tracks which pod held each address over time. Callers hold the
// Index lock.
type podHistory struct {
	byIP       map[string][]*assignment
	byUID      map[string]*podState
	tombstones map[string]time.Time // UID -> when deletion was observed.
	containers map[string]*ContainerRef
}

// ContainerRef names the container a runtime container ID belongs to.
type ContainerRef struct {
	Namespace, Pod, UID, Name string
	seen                      time.Time
}

// containerRetention keeps names for containers that stopped recently, so
// processes still exiting can be named.
const containerRetention = 10 * time.Minute

func newPodHistory() *podHistory {
	return &podHistory{byIP: map[string][]*assignment{}, byUID: map[string]*podState{}, tombstones: map[string]time.Time{}, containers: map[string]*ContainerRef{}}
}

// recordContainers indexes container IDs of every pod, host-network pods
// included: their processes share the node's network namespace.
func (h *podHistory) recordContainers(object Object, at time.Time) {
	m := object.Metadata
	for _, list := range [][]ContainerStatus{object.Status.ContainerStatuses, object.Status.InitContainerStatuses, object.Status.EphemeralContainerStatuses} {
		for _, status := range list {
			id := ContainerID(status.ContainerID)
			if id == "" {
				continue
			}
			h.containers[id] = &ContainerRef{Namespace: m.Namespace, Pod: m.Name, UID: m.UID, Name: status.Name, seen: at}
		}
	}
}

// ContainerID strips the runtime scheme from a status containerID.
func ContainerID(value string) string {
	if _, id, found := strings.Cut(value, "://"); found {
		return id
	}
	return value
}

// Container names the container with a runtime ID, if a pod reported it.
func (i *Index) Container(id string) (ContainerRef, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	ref, ok := i.pods.containers[id]
	if !ok {
		return ContainerRef{}, false
	}
	return *ref, true
}

func (h *podHistory) active() int { return len(h.byUID) }

func podIPs(object Object) []string {
	seen := map[string]bool{}
	var ips []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	add(object.Status.PodIP)
	for _, address := range object.Status.PodIPs {
		add(address.IP)
	}
	return ips
}

func podEndpoint(object Object, owners map[string]Owner, at time.Time) Endpoint {
	m := object.Metadata
	endpoint := Endpoint{Kind: "pod", Namespace: m.Namespace, Name: m.Name, UID: m.UID, Node: object.Spec.NodeName, ObservedAt: at}
	if len(m.OwnerReferences) > 0 {
		endpoint.Owner = m.OwnerReferences[0]
		if owner, ok := owners[endpoint.Owner.UID]; ok {
			endpoint.Owner = owner
		} else if owner, ok := deploymentFromReplicaSet(endpoint.Owner, m.Labels); ok {
			endpoint.Owner = owner
		}
	}
	return endpoint
}

// deploymentFromReplicaSet resolves a Deployment-managed ReplicaSet that has
// not been listed yet (a watched pod can arrive before the next inventory
// list). The Deployment controller names its ReplicaSets
// "<deployment>-<pod-template-hash>" and labels their pods with that hash, so
// the owner follows exactly when both agree. The Deployment UID stays unknown.
func deploymentFromReplicaSet(owner Owner, labels map[string]string) (Owner, bool) {
	hash := labels["pod-template-hash"]
	if owner.Kind != "ReplicaSet" || hash == "" || !strings.HasSuffix(owner.Name, "-"+hash) {
		return owner, false
	}
	name := strings.TrimSuffix(owner.Name, "-"+hash)
	if name == "" {
		return owner, false
	}
	return Owner{Kind: "Deployment", Name: name}, true
}

// terminal reports whether a pod no longer holds its addresses. Completed and
// failed pods keep status.podIP in the API although the address is released
// and may already belong to another pod.
func terminal(object Object) bool {
	return object.Status.Phase == "Succeeded" || object.Status.Phase == "Failed"
}

// apply records one observation of a pod. deleted marks a watch DELETED event.
func (h *podHistory) apply(object Object, deleted bool, owners map[string]Owner, at time.Time) {
	h.recordContainers(object, at)
	uid := object.Metadata.UID
	if uid == "" || object.Spec.HostNetwork {
		return
	}
	if _, gone := h.tombstones[uid]; gone {
		return
	}
	if deleted || terminal(object) {
		h.release(uid, at)
		h.tombstones[uid] = at
		return
	}
	ips := podIPs(object)
	state := h.byUID[uid]
	if state == nil {
		state = &podState{}
		h.byUID[uid] = state
	}
	state.endpoint = podEndpoint(object, owners, at)
	probes := podProbes(object)
	state.lastSeen = at
	current := map[string]bool{}
	for _, ip := range ips {
		current[ip] = true
	}
	for _, ip := range state.ips {
		if !current[ip] {
			h.end(uid, ip, at)
		}
	}
	start := object.Metadata.CreationTimestamp
	if start.IsZero() || start.After(at) {
		start = at
	}
	for _, ip := range ips {
		if a := h.activeFor(uid, ip); a == nil {
			h.byIP[ip] = append(h.byIP[ip], &assignment{endpoint: state.endpoint, probes: probes, start: start})
		} else {
			a.endpoint, a.probes = state.endpoint, probes
		}
	}
	state.ips = ips
}

func (h *podHistory) activeFor(uid, ip string) *assignment {
	for _, a := range h.byIP[ip] {
		if a.endpoint.UID == uid && a.end.IsZero() {
			return a
		}
	}
	return nil
}

func (h *podHistory) end(uid, ip string, at time.Time) {
	if a := h.activeFor(uid, ip); a != nil {
		a.end = at
	}
}

func (h *podHistory) release(uid string, at time.Time) {
	state := h.byUID[uid]
	if state == nil {
		return
	}
	for _, ip := range state.ips {
		h.end(uid, ip, at)
	}
	delete(h.byUID, uid)
}

// reconcile applies a full pod list requested at listedAt. Pods absent from the
// list are released only if nothing newer than the list request has been seen
// for them, so a slow list cannot undo watch events.
func (h *podHistory) reconcile(pods []Object, owners map[string]Owner, listedAt, at time.Time) {
	seen := map[string]bool{}
	for _, pod := range pods {
		seen[pod.Metadata.UID] = true
		h.apply(pod, false, owners, at)
	}
	for uid, state := range h.byUID {
		if !seen[uid] && state.lastSeen.Before(listedAt) {
			h.release(uid, at)
			h.tombstones[uid] = at
		}
	}
	h.prune(at)
}

func (h *podHistory) prune(now time.Time) {
	for id, ref := range h.containers {
		if now.Sub(ref.seen) > containerRetention {
			delete(h.containers, id)
		}
	}
	cutoff := now.Add(-historyRetention)
	for ip, list := range h.byIP {
		kept := list[:0]
		for _, a := range list {
			if a.end.IsZero() || a.end.After(cutoff) {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 {
			delete(h.byIP, ip)
		} else {
			h.byIP[ip] = kept
		}
	}
	for uid, at := range h.tombstones {
		if at.Before(cutoff) {
			delete(h.tombstones, uid)
		}
	}
}

// resolve returns the pod holding ip at time at. With several candidates the
// most recently started pod is returned as ambiguous with the others listed.
func (h *podHistory) resolve(ip string, at time.Time) (Endpoint, string, bool) {
	matches := h.holders(ip, at)
	if len(matches) == 0 {
		return Endpoint{}, "", false
	}
	sort.Slice(matches, func(x, y int) bool { return matches[x].start.After(matches[y].start) })
	endpoint := matches[0].endpoint
	if len(matches) == 1 {
		return endpoint, ConfidenceExact, true
	}
	for _, other := range matches[1:] {
		endpoint.Alternatives = append(endpoint.Alternatives, Candidate{Namespace: other.endpoint.Namespace, Name: other.endpoint.Name, UID: other.endpoint.UID})
	}
	return endpoint, ConfidenceAmbiguous, true
}

// holders are the pods that may have held ip at time at.
func (h *podHistory) holders(ip string, at time.Time) []*assignment {
	var matches []*assignment
	for _, a := range h.byIP[ip] {
		if a.start.After(at.Add(clockSkew)) {
			continue
		}
		if !a.end.IsZero() && a.end.Add(clockSkew).Before(at) {
			continue
		}
		matches = append(matches, a)
	}
	return matches
}

// Probe names the network probes that a connection from node to ip:port at
// time at matches: the one pod holding ip then runs on node and probes that
// port. The kubelet probes only its own node's pods, from the node's
// addresses, so such a connection is likely one of its checks; another
// process on the node reaching that port looks the same on the wire. The
// result is "container:kind[,kind]" (liveness, readiness, startup), several
// containers joined by "; ", or "" for no match, another node, or an address
// that changed hands around that time.
func (i *Index) Probe(ip string, port uint16, node string, at time.Time) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	holders := i.pods.holders(ip, at)
	if node == "" || len(holders) != 1 || holders[0].endpoint.Node != node {
		return ""
	}
	return holders[0].probes[int(port)]
}

// podProbes maps each port the pod's network probes connect to on its own
// address to the containers and kinds of probe there.
func podProbes(object Object) map[int]string {
	byPort := map[int]map[string][]string{}
	for _, container := range append(append([]Container{}, object.Spec.Containers...), object.Spec.InitContainers...) {
		for _, probe := range []struct {
			kind  string
			probe *Probe
		}{{"liveness", container.LivenessProbe}, {"readiness", container.ReadinessProbe}, {"startup", container.StartupProbe}} {
			port := probePort(container, probe.probe)
			if port <= 0 || port > 65535 {
				continue
			}
			if byPort[port] == nil {
				byPort[port] = map[string][]string{}
			}
			byPort[port][container.Name] = append(byPort[port][container.Name], probe.kind)
		}
	}
	if len(byPort) == 0 {
		return nil
	}
	probes := make(map[int]string, len(byPort))
	for port, containers := range byPort {
		var described []string
		for _, name := range sortedNames(containers) {
			described = append(described, name+":"+strings.Join(containers[name], ","))
		}
		probes[port] = strings.Join(described, "; ")
	}
	return probes
}

// probePort is the port a probe connects to on the pod's address; 0 for an
// exec probe, a probe of another host, or a port name the container lacks
// (the kubelet then fails the probe without connecting).
func probePort(container Container, probe *Probe) int {
	var target *ProbeTarget
	switch {
	case probe == nil:
		return 0
	case probe.GRPC != nil:
		return probe.GRPC.Port
	case probe.HTTPGet != nil:
		target = probe.HTTPGet
	case probe.TCPSocket != nil:
		target = probe.TCPSocket
	default:
		return 0
	}
	if target.Host != "" {
		return 0
	}
	var number int
	if json.Unmarshal(target.Port, &number) == nil {
		return number
	}
	var name string
	if json.Unmarshal(target.Port, &name) == nil {
		for _, port := range container.Ports {
			if port.Name == name {
				return port.ContainerPort
			}
		}
	}
	return 0
}

func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// PodWatcher is implemented by sources that can stream pod changes.
type PodWatcher interface {
	// ListPods returns all pods and the resourceVersion to watch from.
	ListPods(context.Context) ([]Object, string, error)
	// WatchPods streams changes from resourceVersion until the stream ends,
	// returning the last resourceVersion seen.
	WatchPods(ctx context.Context, resourceVersion string, handle func(eventType string, object Object)) (string, error)
}

// errWatchExpired means the resourceVersion is too old; the caller must relist.
var errWatchExpired = errors.New("watch resourceVersion expired")

// RunPodWatch keeps the pod history current from a watch stream, relisting
// when the stream expires and backing off on errors. Without a PodWatcher
// source it returns immediately and periodic Refresh remains the only input.
func (i *Index) RunPodWatch(ctx context.Context) {
	watcher, ok := i.source.(PodWatcher)
	if !ok {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		listedAt := time.Now()
		pods, version, err := watcher.ListPods(ctx)
		if err == nil {
			i.mu.Lock()
			i.pods.reconcile(pods, i.owners, listedAt, time.Now())
			i.status.Pods = i.pods.active()
			i.mu.Unlock()
			for err == nil && ctx.Err() == nil {
				i.setWatching(true, "")
				version, err = watcher.WatchPods(ctx, version, func(eventType string, object Object) {
					i.mu.Lock()
					defer i.mu.Unlock()
					i.pods.apply(object, eventType == "DELETED", i.owners, time.Now())
					i.status.Pods = i.pods.active()
				})
				if err == nil {
					backoff = time.Second // Normal server-side timeout; resume from version.
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		i.setWatching(false, err.Error())
		if errors.Is(err, errWatchExpired) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (i *Index) setWatching(watching bool, message string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status.Watching, i.status.WatchError = watching, message
}

func (s *clusterSource) ListPods(ctx context.Context) ([]Object, string, error) {
	var result []Object
	next, version := "", ""
	for {
		query := url.Values{"limit": {"500"}}
		if next != "" {
			query.Set("continue", next)
		}
		response, err := s.get(ctx, s.client, "/api/v1/pods?"+query.Encode())
		if err != nil {
			return nil, "", err
		}
		var list List
		err = json.NewDecoder(response.Body).Decode(&list)
		_ = response.Body.Close()
		if err != nil {
			return nil, "", fmt.Errorf("decode Kubernetes pods: %w", err)
		}
		for _, item := range list.Items {
			item.Kind = "Pod"
			result = append(result, item)
		}
		version = list.Metadata.ResourceVersion
		next = list.Metadata.Continue
		if next == "" {
			return result, version, nil
		}
	}
}

func (s *clusterSource) get(ctx context.Context, client *http.Client, path string) (*http.Response, error) {
	token, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read service-account token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request to the Kubernetes API failed: %w", err)
	}
	if response.StatusCode == http.StatusGone {
		_ = response.Body.Close()
		return nil, errWatchExpired
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("listing %s from the Kubernetes API: HTTP %d", strings.SplitN(path, "?", 2)[0], response.StatusCode)
	}
	return response, nil
}

type watchEvent struct {
	Type   string
	Object json.RawMessage
}

func (s *clusterSource) WatchPods(ctx context.Context, version string, handle func(string, Object)) (string, error) {
	query := url.Values{"watch": {"1"}, "resourceVersion": {version}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"300"}}
	response, err := s.get(ctx, s.watchClient, "/api/v1/pods?"+query.Encode())
	if err != nil {
		return version, err
	}
	defer func() { _ = response.Body.Close() }()
	decoder := json.NewDecoder(bufio.NewReader(response.Body))
	for {
		var event watchEvent
		if err := decoder.Decode(&event); err != nil {
			if ctx.Err() != nil {
				return version, ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				return version, nil
			}
			return version, fmt.Errorf("decode pod watch: %w", err)
		}
		switch event.Type {
		case "ERROR":
			var status struct{ Code int }
			_ = json.Unmarshal(event.Object, &status)
			if status.Code == http.StatusGone {
				return version, errWatchExpired
			}
			return version, fmt.Errorf("pod watch error: HTTP %d", status.Code)
		case "ADDED", "MODIFIED", "DELETED", "BOOKMARK":
			var object Object
			if err := json.Unmarshal(event.Object, &object); err != nil {
				return version, fmt.Errorf("decode pod watch object: %w", err)
			}
			if object.Metadata.ResourceVersion != "" {
				version = object.Metadata.ResourceVersion
			}
			if event.Type != "BOOKMARK" {
				object.Kind = "Pod"
				handle(event.Type, object)
			}
		}
	}
}
