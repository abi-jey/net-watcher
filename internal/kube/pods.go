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
	start    time.Time
	end      time.Time
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
}

func newPodHistory() *podHistory {
	return &podHistory{byIP: map[string][]*assignment{}, byUID: map[string]*podState{}, tombstones: map[string]time.Time{}}
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
		if h.activeFor(uid, ip) == nil {
			h.byIP[ip] = append(h.byIP[ip], &assignment{endpoint: state.endpoint, start: start})
		} else {
			h.activeFor(uid, ip).endpoint = state.endpoint
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
