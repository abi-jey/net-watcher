package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func pod(uid, name string, created time.Time, phase string, ips ...string) Object {
	object := Object{Kind: "Pod"}
	object.Metadata = Metadata{Name: name, Namespace: "demo", UID: uid, CreationTimestamp: created,
		OwnerReferences: []Owner{{Kind: "ReplicaSet", Name: "api-rs", UID: "rs1"}}}
	object.Status.Phase = phase
	if len(ips) > 0 {
		object.Status.PodIP = ips[0]
	}
	for _, ip := range ips {
		object.Status.PodIPs = append(object.Status.PodIPs, struct{ IP string }{ip})
	}
	return object
}

func replicaSet() Object {
	object := Object{Kind: "ReplicaSet"}
	object.Metadata = Metadata{Name: "api-rs", UID: "rs1", OwnerReferences: []Owner{{Kind: "Deployment", Name: "api", UID: "d1"}}}
	return object
}

// The core audit case: a pod is replaced and its address reused. Each event
// must be attributed to the pod that held the address at capture time.
func TestAttributionFollowsAddressReuseByTime(t *testing.T) {
	index := New(nil)
	t0 := time.Now().Add(-10 * time.Minute)
	index.Replace([]Object{replicaSet(), pod("old", "api-1", t0, "Running", "10.0.0.7")}, t0.Add(time.Second))
	deletedAt := t0.Add(5 * time.Minute)
	index.mu.Lock()
	index.pods.apply(pod("old", "api-1", t0, "Running", "10.0.0.7"), true, index.owners, deletedAt)
	index.pods.apply(pod("new", "api-2", deletedAt.Add(10*time.Second), "Running", "10.0.0.7"), false, index.owners, deletedAt.Add(12*time.Second))
	index.status.LastSync = time.Now()
	index.mu.Unlock()

	before := index.Attribute("10.0.0.7", 0, "", t0.Add(2*time.Minute))
	if before.UID != "old" || before.Confidence != ConfidenceExact || before.Workload != "Deployment/api" || before.Namespace != "demo" {
		t.Fatalf("before replacement: %+v", before)
	}
	after := index.Attribute("10.0.0.7", 0, "", deletedAt.Add(time.Minute))
	if after.UID != "new" || after.Confidence != ConfidenceExact {
		t.Fatalf("after replacement: %+v", after)
	}
	if gap := index.Attribute("10.0.0.7", 0, "", deletedAt.Add(5*time.Second)); gap.UID != "" {
		t.Fatalf("address attributed while unassigned: %+v", gap)
	}
}

// When the release of the old pod is only observed after the new pod was
// created (polling), the overlap must be reported as ambiguous, not guessed.
func TestOverlappingAssignmentsAreAmbiguous(t *testing.T) {
	index := New(nil)
	t0 := time.Now().Add(-10 * time.Minute)
	index.Replace([]Object{pod("old", "api-1", t0, "Running", "10.0.0.7")}, t0)
	created := t0.Add(5 * time.Minute)
	listed := created.Add(20 * time.Second)
	index.replace([]Object{pod("new", "api-2", created, "Running", "10.0.0.7")}, listed, listed)
	index.mu.Lock()
	index.status.LastSync = time.Now()
	index.mu.Unlock()
	attribution := index.Attribute("10.0.0.7", 0, "", created.Add(10*time.Second))
	if attribution.UID != "new" || attribution.Confidence != ConfidenceAmbiguous {
		t.Fatalf("overlap: %+v", attribution)
	}
	var endpoint Endpoint
	_ = json.Unmarshal([]byte(attribution.Context), &endpoint)
	if len(endpoint.Alternatives) != 1 || endpoint.Alternatives[0].UID != "old" {
		t.Fatalf("alternatives: %+v", endpoint.Alternatives)
	}
	if late := index.Attribute("10.0.0.7", 0, "", listed.Add(time.Minute)); late.Confidence != ConfidenceExact || late.UID != "new" {
		t.Fatalf("after overlap: %+v", late)
	}
}

// Completed pods keep status.podIP although the address is released.
func TestCompletedPodsDoNotClaimTheirOldAddress(t *testing.T) {
	index := New(nil)
	now := time.Now()
	index.Replace([]Object{pod("job", "backup-29", now.Add(-time.Hour), "Succeeded", "10.0.0.9")}, now)
	if got := index.Attribute("10.0.0.9", 0, "", now); got.UID != "" {
		t.Fatalf("completed pod attributed: %+v", got)
	}
	index.Replace([]Object{pod("job", "backup-29", now.Add(-time.Hour), "Succeeded", "10.0.0.9"), pod("live", "web-1", now.Add(-time.Minute), "Running", "10.0.0.9")}, now)
	if got := index.Attribute("10.0.0.9", 0, "", now); got.UID != "live" || got.Confidence != ConfidenceExact {
		t.Fatalf("live pod not attributed: %+v", got)
	}
}

// A list requested before a watch event must not undo it, and a stale list
// must not resurrect a pod the watch saw deleted.
func TestSlowListDoesNotUndoWatchEvents(t *testing.T) {
	index := New(nil)
	t0 := time.Now().Add(-time.Minute)
	listedAt := t0
	index.mu.Lock()
	index.pods.apply(pod("fresh", "api-3", t0.Add(time.Second), "Running", "10.0.0.11"), false, index.owners, t0.Add(2*time.Second))
	index.pods.apply(pod("gone", "api-0", t0.Add(-time.Hour), "Running", "10.0.0.12"), false, index.owners, t0.Add(-time.Minute))
	index.pods.apply(pod("gone", "api-0", t0.Add(-time.Hour), "Running", "10.0.0.12"), true, index.owners, t0.Add(3*time.Second))
	index.mu.Unlock()
	// The list was requested before both events and still contains "gone" but not "fresh".
	index.replace([]Object{pod("gone", "api-0", t0.Add(-time.Hour), "Running", "10.0.0.12")}, listedAt, t0.Add(4*time.Second))
	now := t0.Add(5 * time.Second)
	if got := index.Attribute("10.0.0.11", 0, "", now); got.UID != "fresh" {
		t.Fatalf("watch-created pod released by slow list: %+v", got)
	}
	if got := index.Attribute("10.0.0.12", 0, "", now); got.UID != "" {
		t.Fatalf("deleted pod resurrected by slow list: %+v", got)
	}
}

func TestDualStackAndHostNetwork(t *testing.T) {
	index := New(nil)
	now := time.Now()
	host := pod("host", "agent", now.Add(-time.Hour), "Running", "192.0.2.10")
	host.Spec.HostNetwork = true
	node := Object{Kind: "Node"}
	node.Metadata = Metadata{Name: "node-a", UID: "n1"}
	node.Status.Addresses = []struct{ Type, Address string }{{"InternalIP", "192.0.2.10"}}
	index.Replace([]Object{host, node, pod("dual", "api-1", now.Add(-time.Hour), "Running", "10.0.0.7", "fd00::7")}, now)
	if v6 := index.Attribute("fd00::7", 0, "", now); v6.UID != "dual" || v6.Confidence != ConfidenceExact {
		t.Fatalf("IPv6: %+v", v6)
	}
	if n := index.Attribute("192.0.2.10", 0, "", now); n.Kind != "node" || n.Confidence != ConfidenceNode {
		t.Fatalf("host network: %+v", n)
	}
}

// The watch stream is applied incrementally, survives a server-side timeout,
// and relists when the resourceVersion expires.
func TestPodWatchAppliesEventsAndRelistsOnExpiry(t *testing.T) {
	created := time.Now().UTC().Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)
	podJSON := func(uid, ip, phase string) string {
		return fmt.Sprintf(`{"metadata":{"name":"%s","namespace":"demo","uid":"%s","creationTimestamp":"%s","resourceVersion":"7"},"status":{"phase":"%s","podIP":"%s"}}`, uid, uid, created, phase, ip)
	}
	var mu sync.Mutex
	lists, watches := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Query().Get("watch") == "" {
			lists++
			mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"metadata":{"resourceVersion":"5"},"items":[%s]}`, podJSON("a", "10.0.0.1", "Running"))
			return
		}
		watches++
		current := watches
		mu.Unlock()
		flusher := w.(http.Flusher)
		switch current {
		case 1:
			_, _ = fmt.Fprintf(w, `{"type":"ADDED","object":%s}`+"\n", podJSON("b", "10.0.0.2", "Running"))
			_, _ = fmt.Fprintf(w, `{"type":"DELETED","object":%s}`+"\n", podJSON("a", "10.0.0.1", "Running"))
			flusher.Flush()
		case 2:
			_, _ = fmt.Fprint(w, `{"type":"ERROR","object":{"kind":"Status","code":410}}`+"\n")
		default:
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := &clusterSource{base: server.URL, client: server.Client(), watchClient: server.Client(), tokenFile: tokenFile}
	index := New(source)
	index.mu.Lock()
	index.status.LastSync = time.Now()
	index.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); index.RunPodWatch(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		ready := lists >= 2 && watches >= 3
		mu.Unlock()
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b := index.Attribute("10.0.0.2", 0, "", time.Now()); b.UID != "b" {
		t.Errorf("watched pod missing: %+v", b)
	}
	if a := index.Attribute("10.0.0.1", 0, "", time.Now().Add(time.Hour)); a.UID != "" {
		t.Errorf("deleted pod still attributed later: %+v", a)
	}
	mu.Lock()
	if lists < 2 {
		t.Errorf("did not relist after 410: lists=%d", lists)
	}
	mu.Unlock()
	if !index.Status().Watching {
		t.Errorf("status not watching: %+v", index.Status())
	}
	cancel()
	<-done
}

// A watched pod can arrive before its ReplicaSet is listed; the workload must
// still be the Deployment so workload views do not split.
func TestWatchedPodResolvesDeploymentBeforeReplicaSetIsListed(t *testing.T) {
	index := New(nil)
	now := time.Now()
	index.Replace(nil, now)
	object := pod("p1", "probe-5f56699564-ljbkw", now.Add(-time.Second), "Running", "10.0.1.162")
	object.Metadata.OwnerReferences = []Owner{{Kind: "ReplicaSet", Name: "probe-5f56699564", UID: "rs-unlisted"}}
	object.Metadata.Labels = map[string]string{"pod-template-hash": "5f56699564"}
	index.mu.Lock()
	index.pods.apply(object, false, index.owners, now)
	index.mu.Unlock()
	if got := index.Attribute("10.0.1.162", 0, "", now); got.Workload != "Deployment/probe" {
		t.Fatalf("workload = %q", got.Workload)
	}
	standalone := pod("p2", "batch-x", now.Add(-time.Second), "Running", "10.0.1.163")
	standalone.Metadata.OwnerReferences = []Owner{{Kind: "ReplicaSet", Name: "batch", UID: "rs2"}}
	index.mu.Lock()
	index.pods.apply(standalone, false, index.owners, now)
	index.mu.Unlock()
	if got := index.Attribute("10.0.1.163", 0, "", now); got.Workload != "ReplicaSet/batch" {
		t.Fatalf("unlabelled ReplicaSet guessed: %q", got.Workload)
	}
}

// A connection from a pod's own node to a port its probes target matches
// those probes, decoded from the API's JSON as a list or watch delivers it.
func TestProbesMatchConnectionsFromThePodsNode(t *testing.T) {
	const body = `{"kind":"Pod","metadata":{"name":"keda-operator-1","namespace":"keda","uid":"p1","creationTimestamp":"2026-01-01T00:00:00Z"},
	"spec":{"nodeName":"abja","containers":[
		{"name":"keda-operator","ports":[{"name":"probes","containerPort":8081,"protocol":"TCP"}],
		 "livenessProbe":{"httpGet":{"path":"/healthz","port":"probes","scheme":"HTTP"},"periodSeconds":10},
		 "readinessProbe":{"httpGet":{"path":"/readyz","port":8081}}},
		{"name":"sidecar","readinessProbe":{"tcpSocket":{"port":9000}},"livenessProbe":{"exec":{"command":["true"]}},"startupProbe":{"grpc":{"port":9090}}},
		{"name":"elsewhere","livenessProbe":{"httpGet":{"host":"192.0.2.1","port":80}}},
		{"name":"misnamed","livenessProbe":{"tcpSocket":{"port":"missing"}}}],
	 "initContainers":[{"name":"native-sidecar","restartPolicy":"Always","readinessProbe":{"tcpSocket":{"port":8081}}}]},
	"status":{"phase":"Running","podIP":"10.0.1.84"}}`
	var object Object
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatal(err)
	}
	index := New(nil)
	at := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	index.Replace([]Object{object}, at)
	for _, c := range []struct {
		port uint16
		node string
		at   time.Time
		want string
	}{
		{8081, "abja", at, "keda-operator:liveness,readiness; native-sidecar:readiness"},
		{9000, "abja", at, "sidecar:readiness"},
		{9090, "abja", at, "sidecar:startup"},
		{80, "abja", at, ""},                                              // probes another host
		{8080, "abja", at, ""},                                            // no probe there
		{8081, "desktop", at, ""},                                         // the kubelet probes only its own node's pods
		{8081, "", at, ""},                                                // the source is not a known node
		{8081, "abja", time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), ""}, // before the pod existed
	} {
		if got := index.Probe("10.0.1.84", c.port, c.node, c.at); got != c.want {
			t.Errorf("Probe(%d from %q at %s) = %q, want %q", c.port, c.node, c.at.Format(time.RFC3339), got, c.want)
		}
	}

	// An address that changed hands around that time matches nothing.
	other := pod("p2", "other", at.Add(-time.Hour), "Running", "10.0.1.84")
	other.Spec.NodeName = "abja"
	index.mu.Lock()
	index.pods.apply(other, false, index.owners, at)
	index.mu.Unlock()
	if got := index.Probe("10.0.1.84", 8081, "abja", at); got != "" {
		t.Errorf("ambiguous address matched %q", got)
	}
}
