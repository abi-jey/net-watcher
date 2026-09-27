package kube

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const inventoryFixture = `{"items":[
 {"kind":"ReplicaSet","metadata":{"name":"worker-rs","uid":"rs1","ownerReferences":[{"kind":"Deployment","name":"worker","uid":"deploy1"}]}},
 {"kind":"Pod","metadata":{"name":"worker-one","namespace":"demo","uid":"pod1","ownerReferences":[{"kind":"ReplicaSet","name":"worker-rs","uid":"rs1"}]},"spec":{"nodeName":"node-a"},"status":{"podIP":"10.2.0.8","podIPs":[{"ip":"10.2.0.8"},{"ip":"fd00::8"}]}},
 {"kind":"Pod","metadata":{"name":"host-agent","namespace":"system","uid":"hostpod"},"spec":{"hostNetwork":true},"status":{"podIP":"192.0.2.10"}},
 {"kind":"Node","metadata":{"name":"node-a","uid":"node1"},"status":{"addresses":[{"address":"192.0.2.10","type":"InternalIP"}]}},
 {"kind":"CiliumNode","metadata":{"name":"node-a"},"spec":{"addresses":[{"type":"CiliumInternalIP","ip":"10.2.0.155"},{"type":"Unknown","ip":"203.0.113.11"}]}},
 {"kind":"Service","metadata":{"name":"worker","namespace":"demo","uid":"svc1"},"spec":{"clusterIP":"10.96.0.20","ports":[{"port":80,"nodePort":30080,"protocol":"TCP"}]}},
 {"kind":"EndpointSlice","metadata":{"namespace":"demo","labels":{"kubernetes.io/service-name":"worker"}},"endpoints":[{"addresses":["10.2.0.8"]}],"ports":[{"port":8080,"protocol":"TCP"}]}
]}`

func TestInventoryPodsServicesNodesAndCaptureSnapshots(t *testing.T) {
	var list List
	if err := json.Unmarshal([]byte(inventoryFixture), &list); err != nil {
		t.Fatal(err)
	}
	index := New(nil)
	index.Replace(list.Items, time.Now())
	lookup := func(ip string, port uint16) Endpoint {
		t.Helper()
		var endpoint Endpoint
		if err := json.Unmarshal([]byte(index.Lookup(ip, port, "TCP")), &endpoint); err != nil {
			t.Fatal(err)
		}
		return endpoint
	}
	pod := lookup("10.2.0.8", 8080)
	if pod.Kind != "pod" || pod.Namespace != "demo" || pod.Owner.Kind != "Deployment" || pod.Owner.Name != "worker" || len(pod.Services) != 1 {
		t.Fatalf("wrong pod context: %+v", pod)
	}
	if lookup("fd00::8", 1).UID != "pod1" {
		t.Fatal("IPv6 pod missing")
	}
	if lookup("10.96.0.20", 80).Kind != "service" {
		t.Fatal("service VIP missing")
	}
	node := lookup("192.0.2.10", 30080)
	if node.Kind != "node" || len(node.Services) != 1 {
		t.Fatalf("host-network attribution or NodePort is wrong: %+v", node)
	}
	if ciliumHost := lookup("10.2.0.155", 0); ciliumHost.Kind != "node" || ciliumHost.Name != "node-a" || ciliumHost.UID != "node1" {
		t.Fatalf("Cilium host address was not attributed to its node: %+v", ciliumHost)
	}
	if index.Lookup("203.0.113.11", 443, "TCP") != "" {
		t.Fatal("unrecognized CiliumNode address was attributed")
	}
	if len(lookup("10.2.0.8", 9090).Services) != 0 {
		t.Fatal("service attributed on wrong backend port")
	}
	if index.Lookup("203.0.113.10", 443, "TCP") != "" {
		t.Fatal("external address gained cluster metadata")
	}
	old := index.Lookup("10.2.0.8", 8080, "TCP")
	for n := range list.Items {
		if list.Items[n].Kind == "Pod" && !list.Items[n].Spec.HostNetwork {
			list.Items[n].Metadata.UID = "replacement"
		}
	}
	index.Replace(list.Items, time.Now())
	if lookup("10.2.0.8", 8080).UID != "replacement" {
		t.Fatal("replacement not discovered")
	}
	var captured Endpoint
	_ = json.Unmarshal([]byte(old), &captured)
	if captured.UID != "pod1" {
		t.Fatal("historical snapshot changed")
	}
	index.Replace(list.Items, time.Now().Add(-2*time.Minute))
	if index.Lookup("10.2.0.8", 8080, "TCP") != "" {
		t.Fatal("stale inventory used for new observations")
	}
}

type failingSource struct{}

func (failingSource) List(context.Context) ([]Object, error) {
	return nil, errors.New("discovery unavailable")
}
func TestDiscoveryFailureIsVisible(t *testing.T) {
	index := New(failingSource{})
	if index.Refresh(context.Background()) == nil || index.Status().Error == "" || !index.Status().Enabled {
		t.Fatal("failure not surfaced")
	}
}

func TestCiliumNodeDiscoveryIsOptional(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/cilium.io/v2/ciliumnodes" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	source := &clusterSource{base: server.URL, client: server.Client(), tokenFile: tokenFile}
	if _, err := source.List(t.Context()); err != nil {
		t.Fatalf("optional Cilium CRD blocked core inventory: %v", err)
	}
}
